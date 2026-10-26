"""OAuth 2.1 authorization server for the company-wide connector.

Each person signs in with their own Odoo login and Odoo API key; the key is verified with
Odoo, encrypted at rest, and bound to the OAuth grant, so Odoo's per-user permissions apply
to everything Claude does on their behalf.

Usage (see server.py):

    oauth = build_oauth(settings, http)
    mcp = MCPServer(..., token_verifier=oauth.token_verifier, auth=oauth.auth_settings)
    for route in oauth.routes:
        mcp.custom_route(route.path, methods=sorted(route.methods))(route.endpoint)
    ...
    creds = oauth.credentials_for(get_access_token())
"""

from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from starlette.routing import Route

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings

from ..config import Settings
from ..odoo_client import OdooCredentials
from .clients import LOOPBACK_HOSTS, SCOPE
from .crypto import MIN_SECRET_LENGTH, CsrfSigner, Sealer
from .login_page import LoginPage
from .provider import OdooAuthProvider, RevokeHook, normalise_url
from .routes import build_routes
from .store import OAuthStore

__all__ = [
    "SCOPE", "OAuthComponents", "OdooTokenVerifier", "build_oauth", "database_path", "make_store", "public_base_url",
]


class OdooTokenVerifier(TokenVerifier):
    """Resolves bearer tokens for the MCP endpoint. Revocation takes effect on the next request."""

    def __init__(self, provider: OdooAuthProvider):
        self._provider = provider

    async def verify_token(self, token: str) -> AccessToken | None:
        return await self._provider.load_access_token(token)


class OAuthComponents:
    def __init__(
        self,
        *,
        provider: OdooAuthProvider,
        auth_settings: AuthSettings,
        routes: list[Route],
    ):
        self.provider = provider
        self.store = provider.store
        self.token_verifier: TokenVerifier = OdooTokenVerifier(provider)
        self.auth_settings = auth_settings
        self.routes = routes
        self._closed = False

    def credentials_for(self, access_token: AccessToken) -> OdooCredentials:
        """The Odoo credentials bound to this token. Raises OdooError(kind="auth") if revoked or expired."""
        return self.provider.credentials_for(access_token)

    def revoke(self, access_token: AccessToken, reason: str) -> bool:
        """Revokes the grant behind a token, e.g. after Odoo rejected its API key mid-session."""
        return self.provider.revoke_for_access_token(access_token, reason)

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            self.store.close()


def public_base_url(settings: Settings) -> str:
    """MCP_PUBLIC_URL as a canonical origin: lowercase, no default port, no trailing slash."""
    raw = (settings.mcp_public_url or "").strip()
    parts = urlsplit(raw)
    normalised = normalise_url(raw) if raw else None
    if not normalised or parts.path.strip("/") or parts.query:
        raise ValueError("MCP_PUBLIC_URL must be the public origin of this server, e.g. https://odoo-mcp.example.com")
    if parts.scheme.lower() != "https" and not (parts.scheme.lower() == "http" and parts.hostname in LOOPBACK_HOSTS):
        raise ValueError("MCP_PUBLIC_URL must use https:// (plain http is only allowed for localhost)")
    return normalised


def make_store(settings: Settings):
    """Redis when configured (serverless / several instances), otherwise a local SQLite file."""
    if settings.mcp_redis_url:
        from .redis_store import RedisOAuthStore

        return RedisOAuthStore(settings.mcp_redis_url.get_secret_value())
    return OAuthStore(database_path(settings))


def database_path(settings: Settings) -> Path:
    return Path(settings.mcp_data_dir) / "oauth.sqlite3"


def build_oauth(settings: Settings, http: httpx.AsyncClient, *, on_revoke: RevokeHook | None = None) -> OAuthComponents:
    """on_revoke(login, reason) is called after any grant is revoked (default: nothing)."""
    public_url = public_base_url(settings)
    secret = settings.mcp_secret.get_secret_value() if settings.mcp_secret else ""
    if len(secret) < MIN_SECRET_LENGTH:
        raise ValueError(f"MCP_SECRET must be a random string of at least {MIN_SECRET_LENGTH} characters")

    store = make_store(settings)
    provider = OdooAuthProvider(settings, http, store, Sealer(secret), public_url=public_url, on_revoke=on_revoke)
    provider.purge(time.time())  # best-effort: a storage hiccup must not stop the instance from starting
    auth_settings = AuthSettings(
        issuer_url=public_url,  # type: ignore[arg-type]  # plain str: a prebuilt AnyHttpUrl gains a trailing slash
        resource_server_url=f"{public_url}/mcp",  # type: ignore[arg-type]
        required_scopes=[SCOPE],
        validate_token_resource=True,
    )
    login_page = LoginPage(provider, settings, CsrfSigner(secret), public_url=public_url)
    routes = build_routes(
        provider, login_page, auth_settings, public_url=public_url, trust_proxy_headers=settings.mcp_trust_proxy_headers
    )
    return OAuthComponents(provider=provider, auth_settings=auth_settings, routes=routes)
