"""Authorization-server logic plugged into the MCP SDK's OAuth handlers.

The SDK's AuthorizationHandler / TokenHandler / RegistrationHandler / RevocationHandler parse
and validate the HTTP requests (including PKCE and redirect_uri consistency); this provider
decides who the clients are, issues and checks codes and tokens, and binds every grant to one
person's Odoo login and encrypted API key.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
from collections.abc import Callable
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from pydantic import AnyUrl

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from ..config import Settings
from ..errors import OdooError
from ..odoo_client import OdooClient, OdooCredentials, OdooIdentity
from .cimd import CIMDResolver, looks_like_cimd
from .clients import (
    MAX_REDIRECT_URIS,
    SCOPE,
    SUPPORTED_GRANT_TYPES,
    OdooOAuthClient,
    clean_client_name,
    is_redirect_allowed,
)
from .crypto import DecryptionError, Sealer, hash_token, new_token
from .store import REFRESH_REUSE_GRACE_SECONDS, ExchangeResult, Grant, NewTokens, OAuthStore, PendingAuthorization

logger = logging.getLogger(__name__)

PENDING_TTL_SECONDS = 600
CODE_TTL_SECONDS = 300
PURGE_INTERVAL_SECONDS = 300
TOUCH_INTERVAL_SECONDS = 60
MAX_PENDING_AUTHORIZATIONS = 5000
MAX_REGISTERED_CLIENTS = 20_000
MAX_STATE_LENGTH = 2048
MAX_TOKEN_LENGTH = 256
_CODE_CHALLENGE = re.compile(r"[A-Za-z0-9\-._~]{43,128}")

# Called with (login, reason) after a grant is revoked, so the owners can be told about the sign-out.
RevokeHook = Callable[[str, str], None]


class TemporarilyUnavailable(Exception):
    """Odoo could not be reached. The client should retry later with the same refresh token."""


class StoredAuthCode(AuthorizationCode):
    grant_id: str
    code_hash: str


class StoredRefreshToken(RefreshToken):
    grant_id: str
    token_hash: str
    rotated_at: float | None = None


def normalise_url(value: str) -> str | None:
    """Lowercase scheme and host, drop default ports and trailing slashes (RFC 8707 comparison)."""
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        return None
    if parts.username or parts.password or parts.fragment or not parts.hostname:
        return None
    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, {"https": 443, "http": 80}.get(scheme)) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path.rstrip("/"), parts.query, ""))


class OdooAuthProvider(OAuthAuthorizationServerProvider[StoredAuthCode, StoredRefreshToken, AccessToken]):
    def __init__(
        self,
        settings: Settings,
        http: httpx.AsyncClient,
        store: OAuthStore,
        sealer: Sealer,
        *,
        public_url: str,
        clock: Callable[[], float] = time.time,
        on_revoke: RevokeHook | None = None,
    ):
        self.store = store
        self.issuer = public_url
        self.resource_url = f"{public_url}/mcp"
        self._settings = settings
        self._http = http
        self._sealer = sealer
        self._clock = clock
        self._allowed_redirects = tuple(settings.mcp_allowed_redirect_uris)
        self._cimd = CIMDResolver(http, settings.mcp_cimd_allowed_hosts, self._allowed_redirects)
        self._access_ttl = settings.mcp_access_token_ttl_seconds
        self._refresh_ttl = settings.mcp_refresh_token_ttl_seconds
        self._last_purge = float("-inf")
        self._last_touch: dict[str, float] = {}
        self._on_revoke = on_revoke or (lambda login, reason: None)

    # ------------------------------------------------------------------ clients

    async def get_client(self, client_id: str) -> OdooOAuthClient | None:
        if not client_id or len(client_id) > 512:
            return None
        if looks_like_cimd(client_id):
            return await self._cimd.resolve(client_id)
        row = await asyncio.to_thread(self.store.get_client, client_id)
        if row is None:
            return None
        metadata_json, secret_enc = row
        data = json.loads(metadata_json)
        if secret_enc is not None:
            try:
                data["client_secret"] = self._sealer.open(f"client:{client_id}", secret_enc)
            except DecryptionError:
                logger.error("Client %s has a secret that cannot be decrypted (was MCP_SECRET changed?)", client_id)
                return None
        return OdooOAuthClient.build(data, allowed_redirects=self._allowed_redirects)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(uri) for uri in client_info.redirect_uris or []]
        if not uris or len(uris) > MAX_REDIRECT_URIS:
            raise RegistrationError("invalid_redirect_uri", f"Provide between 1 and {MAX_REDIRECT_URIS} redirect_uris")
        if not all(is_redirect_allowed(uri, self._allowed_redirects) for uri in uris):
            raise RegistrationError(
                "invalid_redirect_uri",
                "redirect_uris must be callback URLs this server allows "
                "(for example https://claude.ai/api/mcp/auth_callback, or http://localhost on any port)",
            )
        if await asyncio.to_thread(self.store.count_clients) >= MAX_REGISTERED_CLIENTS:
            logger.error("Refusing client registration: %d clients are registered already", MAX_REGISTERED_CLIENTS)
            raise RegistrationError("invalid_client_metadata", "This server is not accepting new registrations")

        # RFC 7591 section 3.2.1 lets the server replace requested metadata; the response echoes this record.
        client_info.scope = SCOPE
        client_info.grant_types = [g for g in SUPPORTED_GRANT_TYPES if g in client_info.grant_types]
        client_info.client_name = clean_client_name(client_info.client_name)

        secret = client_info.client_secret
        secret_enc = self._sealer.seal(f"client:{client_info.client_id}", secret) if secret else None
        metadata = client_info.model_dump(mode="json", exclude_none=True, exclude={"client_secret"})
        await asyncio.to_thread(
            self.store.insert_client, client_info.client_id, json.dumps(metadata), secret_enc, self._clock()
        )
        logger.info("Registered OAuth client %s (%s)", client_info.client_id, client_info.client_name or "unnamed")

    # ------------------------------------------------------------------ authorization

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        resource = self._check_resource(params.resource)
        if not _CODE_CHALLENGE.fullmatch(params.code_challenge):
            raise AuthorizeError("invalid_request", "code_challenge must be an S256 PKCE challenge")
        if params.state is not None and len(params.state) > MAX_STATE_LENGTH:
            raise AuthorizeError("invalid_request", "state is too long")

        now = self._clock()
        await self.maybe_purge(now)
        if await asyncio.to_thread(self.store.count_pending, now) >= MAX_PENDING_AUTHORIZATIONS:
            raise AuthorizeError("temporarily_unavailable", "Too many sign-ins are in progress; try again shortly")

        if isinstance(client, OdooOAuthClient):
            client_name, verified_host = client.display_name, client.verified_host
        else:
            client_name, verified_host = clean_client_name(client.client_name) or "An application", None

        request_id = new_token()
        await asyncio.to_thread(
            self.store.insert_pending,
            PendingAuthorization(
                id_hash=hash_token(request_id),
                client_id=client.client_id,
                client_name=client_name,
                verified_host=verified_host,
                redirect_uri=str(params.redirect_uri),
                redirect_uri_explicit=params.redirect_uri_provided_explicitly,
                state=params.state,
                scopes=" ".join(params.scopes or [SCOPE]),
                code_challenge=params.code_challenge,
                resource=resource,
                failures=0,
                created_at=now,
                expires_at=now + PENDING_TTL_SECONDS,
            ),
        )
        return f"{self.issuer}/oauth/login?{urlencode({'request': request_id})}"

    def _check_resource(self, resource: str | None) -> str:
        if resource is not None and normalise_url(resource) != normalise_url(self.resource_url):
            raise AuthorizeError("invalid_target", f"This server only issues tokens for {self.resource_url}")
        return self.resource_url

    async def get_pending(self, request_id: str) -> PendingAuthorization | None:
        return await asyncio.to_thread(self.store.get_pending, hash_token(request_id), self._clock())

    async def record_failure(self, pending: PendingAuthorization) -> int:
        return await asyncio.to_thread(self.store.record_pending_failure, pending.id_hash)

    async def discard_pending(self, pending: PendingAuthorization) -> None:
        await asyncio.to_thread(self.store.delete_pending, pending.id_hash)

    def denial_redirect(self, pending: PendingAuthorization, description: str) -> str:
        return construct_redirect_uri(
            pending.redirect_uri,
            error="access_denied",
            error_description=description,
            state=pending.state,
            iss=self.issuer,
        )

    async def verify_odoo_identity(self, login: str, api_key: str) -> OdooIdentity:
        """Checks the login/API key pair with Odoo. Raises OdooError."""
        settings = self._settings
        client = OdooClient(
            OdooCredentials(settings.odoo_url, settings.odoo_db, login, api_key),
            self._http,
            protocol=settings.odoo_protocol,
            timeout=settings.odoo_timeout_seconds,
        )
        return await client.verify_login_matches()

    async def complete_authorization(
        self, pending: PendingAuthorization, identity: OdooIdentity, api_key: str
    ) -> str | None:
        """Creates the grant and a single-use code; returns the client redirect (None if already consumed)."""
        now = self._clock()
        grant_id = secrets.token_urlsafe(16)
        code = new_token()
        grant = Grant(
            grant_id=grant_id,
            client_id=pending.client_id,
            client_name=pending.client_name,
            odoo_uid=identity.uid,
            login=identity.login,
            display_name=identity.name,
            odoo_url=self._settings.odoo_url,
            odoo_db=self._settings.odoo_db,
            api_key_enc=self._sealer.seal(f"grant:{grant_id}", api_key),
            scopes=pending.scopes,
            resource=pending.resource,
            created_at=now,
            last_used_at=now,
            revoked_at=None,
            revoked_reason=None,
        )
        created = await asyncio.to_thread(
            self.store.create_grant_with_code,
            pending_id_hash=pending.id_hash,
            grant=grant,
            code_hash=hash_token(code),
            code_expires_at=now + CODE_TTL_SECONDS,
        )
        if not created:
            return None
        logger.info("Odoo user %s (uid %s) connected %s; grant %s", identity.login, identity.uid, pending.client_name, grant_id)
        return construct_redirect_uri(pending.redirect_uri, code=code, state=pending.state, iss=self.issuer)

    # ------------------------------------------------------------------ authorization codes

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> StoredAuthCode | None:
        if not authorization_code or len(authorization_code) > MAX_TOKEN_LENGTH:
            return None
        stored = await asyncio.to_thread(self.store.get_code, hash_token(authorization_code))
        if stored is None or not stored.grant.active or stored.grant.client_id != client.client_id:
            return None
        # A used code is still returned, so exchange_authorization_code can detect the replay.
        return StoredAuthCode(
            code=authorization_code,
            scopes=stored.grant.scopes.split(),
            expires_at=stored.expires_at,
            client_id=stored.grant.client_id,
            code_challenge=stored.code_challenge,
            redirect_uri=AnyUrl(stored.redirect_uri),
            redirect_uri_provided_explicitly=stored.redirect_uri_explicit,
            resource=stored.grant.resource,
            subject=str(stored.grant.odoo_uid),
            grant_id=stored.grant.grant_id,
            code_hash=stored.code_hash,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: StoredAuthCode
    ) -> OAuthToken:
        if authorization_code.client_id != client.client_id:
            raise TokenError("invalid_grant", "authorization code does not exist")
        now = self._clock()
        access, refresh = new_token(), new_token()
        result = await asyncio.to_thread(
            self.store.consume_code, authorization_code.code_hash, now, self._new_tokens(access, refresh, now)
        )
        if result is ExchangeResult.REPLAYED:
            logger.warning("Authorization code replayed for grant %s; grant revoked", authorization_code.grant_id)
            await asyncio.to_thread(self._signed_out, authorization_code.grant_id, "authorization code reused")
            raise TokenError("invalid_grant", "authorization code was already used; the connection has been revoked")
        if result is not ExchangeResult.OK:
            raise TokenError("invalid_grant", "authorization code is invalid or has expired")
        return self._token_response(access, refresh)

    # ------------------------------------------------------------------ refresh tokens

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> StoredRefreshToken | None:
        if not refresh_token or len(refresh_token) > MAX_TOKEN_LENGTH:
            return None
        stored = await asyncio.to_thread(self.store.get_token, hash_token(refresh_token), "refresh")
        if stored is None or not stored.grant.active:
            return None
        grant = stored.grant
        return StoredRefreshToken(
            token=refresh_token,
            client_id=grant.client_id,
            scopes=grant.scopes.split(),
            expires_at=int(stored.expires_at),
            resource=grant.resource,
            subject=str(grant.odoo_uid),
            grant_id=grant.grant_id,
            token_hash=stored.token_hash,
            rotated_at=stored.rotated_at,
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: StoredRefreshToken, scopes: list[str]
    ) -> OAuthToken:
        rotated_at = refresh_token.rotated_at
        if rotated_at is not None and self._clock() - rotated_at > REFRESH_REUSE_GRACE_SECONDS:
            # Replay of a long-retired refresh token: someone else may hold a copy. Kill the whole grant.
            logger.warning("Retired refresh token replayed for grant %s; grant revoked", refresh_token.grant_id)
            await self._revoke(refresh_token.grant_id, "refresh token reused")
            raise TokenError("invalid_grant", "refresh token was already used; the connection has been revoked")
        grant = await asyncio.to_thread(self.store.get_grant, refresh_token.grant_id)
        if grant is None or not grant.active or grant.client_id != client.client_id:
            raise TokenError("invalid_grant", "refresh token does not exist")
        if not self._same_odoo(grant):
            await self._revoke(grant.grant_id, "Odoo server changed")
            raise TokenError("invalid_grant", "the Odoo server changed; sign in again")
        try:
            api_key = self._sealer.open(f"grant:{grant.grant_id}", grant.api_key_enc or b"")
        except DecryptionError:
            await self._revoke(grant.grant_id, "credentials could not be decrypted")
            raise TokenError("invalid_grant", "stored credentials are unusable; sign in again") from None

        try:
            identity = await self.verify_odoo_identity(grant.login, api_key)
        except OdooError as exc:
            if exc.kind == "auth":
                await self._revoke(grant.grant_id, "Odoo rejected the API key")
                raise TokenError("invalid_grant", "Odoo no longer accepts this API key; sign in again") from None
            logger.warning("Could not re-check grant %s with Odoo during refresh (%s)", grant.grant_id, exc.kind)
            raise TemporarilyUnavailable() from None
        except Exception:
            logger.exception("Unexpected error re-checking grant %s with Odoo", grant.grant_id)
            raise TemporarilyUnavailable() from None
        if identity.uid != grant.odoo_uid or not identity.is_internal_user:
            await self._revoke(grant.grant_id, "Odoo user changed or is no longer an internal user")
            raise TokenError("invalid_grant", "this Odoo account can no longer use the connector; sign in again")

        now = self._clock()
        access, new_refresh = new_token(), new_token()
        result = await asyncio.to_thread(
            self.store.rotate_refresh_token, refresh_token.token_hash, now, self._new_tokens(access, new_refresh, now)
        )
        if result is ExchangeResult.REUSED:
            logger.info(
                "Refresh token for grant %s used again within %d s of its rotation (client retry or parallel "
                "refresh); issued a new pair",
                grant.grant_id, REFRESH_REUSE_GRACE_SECONDS,
            )
        elif result is ExchangeResult.REPLAYED:
            logger.warning("Retired refresh token replayed for grant %s; grant revoked", grant.grant_id)
            await asyncio.to_thread(self._signed_out, grant.grant_id, "refresh token reused", grant.login)
            raise TokenError("invalid_grant", "refresh token was already used; the connection has been revoked")
        elif result is not ExchangeResult.OK:
            raise TokenError("invalid_grant", "refresh token is invalid or has expired")
        await self.maybe_purge(now)
        return self._token_response(access, new_refresh)

    # ------------------------------------------------------------------ access tokens

    async def load_access_token(self, token: str) -> AccessToken | None:
        if not token or len(token) > MAX_TOKEN_LENGTH:
            return None
        stored = await asyncio.to_thread(self.store.get_token, hash_token(token), "access")
        now = self._clock()
        if stored is None or stored.expires_at <= now or not stored.grant.active or not self._same_odoo(stored.grant):
            return None
        grant = stored.grant
        await self._touch(grant.grant_id, now)
        return AccessToken(
            token=token,
            client_id=grant.client_id,
            scopes=grant.scopes.split(),
            expires_at=int(stored.expires_at),
            resource=grant.resource,
            subject=str(grant.odoo_uid),
            claims={"login": grant.login, "grant_id": grant.grant_id, "iss": self.issuer},
        )

    def credentials_for(self, access_token: AccessToken) -> OdooCredentials:
        """Decrypts the Odoo credentials bound to a live access token (synchronous: one indexed lookup)."""
        stored = self.store.get_token(hash_token(access_token.token), "access")
        if stored is None or stored.expires_at <= self._clock() or not stored.grant.active:
            raise OdooError("this Claude connection was revoked or has expired", kind="auth")
        grant = stored.grant
        if not self._same_odoo(grant):
            raise OdooError("the Odoo server changed since this connection was made", kind="auth")
        try:
            api_key = self._sealer.open(f"grant:{grant.grant_id}", grant.api_key_enc or b"")
        except DecryptionError:
            raise OdooError("the stored credentials could not be decrypted", kind="auth") from None
        return OdooCredentials(url=grant.odoo_url, db=grant.odoo_db, login=grant.login, api_key=api_key)

    # ------------------------------------------------------------------ revocation

    async def revoke_token(self, token: AccessToken | StoredRefreshToken) -> None:
        grant_id = token.grant_id if isinstance(token, StoredRefreshToken) else (token.claims or {}).get("grant_id")
        if isinstance(grant_id, str):
            await self._revoke(grant_id, "revoked by the client")

    def revoke_for_access_token(self, access_token: AccessToken, reason: str) -> bool:
        claims = access_token.claims or {}
        grant_id = claims.get("grant_id")
        if not isinstance(grant_id, str):
            return False
        return self._revoke_now(grant_id, reason, claims.get("login"))

    async def _revoke(self, grant_id: str, reason: str) -> None:
        await asyncio.to_thread(self._revoke_now, grant_id, reason)

    def _revoke_now(self, grant_id: str, reason: str, login: str | None = None) -> bool:
        revoked = self.store.revoke_grant(grant_id, reason, self._clock())
        if revoked:
            self._signed_out(grant_id, reason, login)
        return revoked

    def _signed_out(self, grant_id: str, reason: str, login: str | None = None) -> None:
        """Reports a revoked grant to the on_revoke hook. Never raises: the revocation already happened."""
        try:
            if login is None:
                grant = self.store.get_grant(grant_id)
                login = grant.login if grant is not None else "?"
            self._on_revoke(login, reason)
        except Exception:
            logger.exception("Could not report the revocation of grant %s", grant_id)

    # ------------------------------------------------------------------ helpers

    def _same_odoo(self, grant: Grant) -> bool:
        # Never send an API key to a server other than the one the person entered it for.
        settings = self._settings
        if grant.odoo_url != settings.odoo_url:
            return False
        # JSON-2 does not need a database name, so adding or changing ODOO_DB must not end existing sign-ins.
        if settings.odoo_protocol == "jsonrpc" and grant.odoo_db and settings.odoo_db:
            return grant.odoo_db == settings.odoo_db
        return True

    def _new_tokens(self, access: str, refresh: str, now: float) -> NewTokens:
        return NewTokens(
            access_hash=hash_token(access),
            access_expires_at=now + self._access_ttl,
            refresh_hash=hash_token(refresh),
            refresh_expires_at=now + self._refresh_ttl,
        )

    def _token_response(self, access: str, refresh: str) -> OAuthToken:
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=self._access_ttl,
            scope=SCOPE,
            refresh_token=refresh,
        )

    async def _touch(self, grant_id: str, now: float) -> None:
        last = self._last_touch.get(grant_id)
        if last is not None and now - last < TOUCH_INTERVAL_SECONDS:
            return
        self._last_touch[grant_id] = now
        if len(self._last_touch) > 50_000:
            self._last_touch.clear()
        try:
            await asyncio.to_thread(self.store.touch_grant, grant_id, now)
        except Exception as exc:  # only housekeeping: it must not fail the request
            logger.warning("Could not record the last use of grant %s (%s)", grant_id, type(exc).__name__)

    async def maybe_purge(self, now: float) -> None:
        if now - self._last_purge < PURGE_INTERVAL_SECONDS:
            return
        self._last_purge = now
        await asyncio.to_thread(self.purge, now)

    def purge(self, now: float) -> None:
        """Deletes expired records and wipes dead grants. Best-effort: never raises."""
        try:
            revoked = self.store.purge(now)
        except Exception:
            logger.exception("Purging expired OAuth records failed")
            return
        for grant_id in revoked:
            self._signed_out(grant_id, "expired")
