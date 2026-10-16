"""Thin async client for Odoo's external API.

Two wire protocols are supported:
  * json2   - Odoo 19+: POST /json/2/<model>/<method> with a bearer API key.
  * jsonrpc - Odoo <= 18 (deprecated in 19, removed in 22): POST /jsonrpc execute_kw.

"auto" tries json2 first and falls back to jsonrpc when the route does not exist.
This module knows nothing about safety rules; callers must go through OdooService.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import http.cookiejar
import itertools
from dataclasses import dataclass, field
from typing import Any

import httpx

from . import __version__
from .errors import OdooError
from .policy import HARD_BLOCKED_MODELS, HARD_BLOCKED_PREFIXES

USER_AGENT = f"sahajta-odoo-mcp/{__version__}"

# Last line of defence, independent of the policy module: these never leave this process.
_NEVER_SENT = ("unlink", "uninstall", "sudo")

# Read-only methods may be retried once when Odoo is busy; changes are never retried automatically.
_SAFE_TO_RETRY = frozenset(
    {
        "search", "search_read", "search_count", "read", "fields_get", "name_search", "get_views",
        "formatted_read_group", "read_group", "context_get", "default_get", "get_available_models",
    }
)
# Odoo Online's acceptable-use policy asks for throttled, non-parallel API calls; all users of one
# Odoo share these gates.
_GATES: dict[tuple[str, int, int], asyncio.Semaphore] = {}


def _gate(url: str, size: int) -> asyncio.Semaphore:
    key = (url, size, id(asyncio.get_running_loop()))
    if key not in _GATES:
        _GATES[key] = asyncio.Semaphore(size)
    return _GATES[key]


def new_http_client(*, verify: bool = True) -> httpx.AsyncClient:
    """HTTP client that never stores cookies: one person's Odoo session must never ride along on
    another person's call (and JSON-2 rejects requests carrying a foreign session)."""
    jar = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[]))
    return httpx.AsyncClient(
        verify=verify,
        follow_redirects=False,
        cookies=jar,
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )

# Odoo exception class name -> our error kind
_KIND_BY_NAME = {
    "AccessDenied": "auth",
    "AccessError": "access",
    "MissingError": "missing",
    "UserError": "user_error",
    "ValidationError": "validation",
    "RedirectWarning": "user_error",
    "LockError": "user_error",
    "ConcurrencyError": "user_error",
    "SessionExpiredException": "auth",
    # Odoo 19 reports bad field names / bad arguments as plain Python errors (HTTP 500).
    "ValueError": "validation",
    "TypeError": "validation",
    "KeyError": "validation",
}


@dataclass(frozen=True)
class OdooCredentials:
    url: str
    db: str | None
    login: str
    api_key: str = field(repr=False)


@dataclass(frozen=True)
class OdooIdentity:
    uid: int
    login: str
    name: str
    tz: str
    lang: str
    company_id: int | None
    company_name: str | None
    is_internal_user: bool
    server_version: str
    protocol: str


class OdooClient:
    def __init__(
        self,
        creds: OdooCredentials,
        http: httpx.AsyncClient,
        *,
        protocol: str = "auto",
        timeout: float = 30.0,
        max_parallel: int = 1,
        cache=None,
    ):
        self.creds = creds
        self._http = http
        self._protocol = protocol
        self._timeout = timeout
        self._max_parallel = max(1, max_parallel)
        # JSON-2 replaces the server-side context with the one sent, so lang/tz go on every call.
        self._base_context: dict = {}
        # Optional shared cache (Redis on serverless): lets a fresh server instance skip the identity calls.
        self._cache = cache
        self._probe_ctx: dict | None = None
        self._uid: int | None = None
        self._identity: OdooIdentity | None = None
        self._lock = asyncio.Lock()
        self._ids = itertools.count(1)

    @property
    def protocol(self) -> str:
        return self._protocol

    # ------------------------------------------------------------------ public API

    async def call(
        self,
        model: str,
        method: str,
        *,
        ids: list[int] | None = None,
        context: dict | None = None,
        **kwargs: Any,
    ) -> Any:
        """Call a public model method with named arguments only."""
        lowered = method.lower()
        if method.startswith("_") or any(part in lowered for part in _NEVER_SENT):
            raise OdooError(f"refusing to send '{method}' to Odoo", kind="access")
        if model in HARD_BLOCKED_MODELS or model.startswith(HARD_BLOCKED_PREFIXES):
            raise OdooError(f"refusing to call blocked model '{model}'", kind="access")
        await self._ensure_protocol()
        if self._base_context:
            context = {**self._base_context, **(context or {})}
        for attempt in (1, 2):
            try:
                async with _gate(self.creds.url, self._max_parallel):
                    if self._protocol == "json2":
                        return await self._call_json2(model, method, ids=ids, context=context, kwargs=kwargs)
                    return await self._call_jsonrpc(model, method, ids=ids, context=context, kwargs=kwargs)
            except OdooError as exc:
                if attempt == 1 and exc.kind in ("rate_limited", "unavailable") and method in _SAFE_TO_RETRY:
                    await asyncio.sleep(2.0)
                    continue
                raise
        raise AssertionError("unreachable")

    async def identity(self) -> OdooIdentity:
        if self._identity is not None:
            return self._identity
        async with self._lock:
            if self._identity is not None:
                return self._identity
            cache_key = "identity:v1:" + hashlib.sha256(
                f"{self.creds.url}|{self.creds.db}|{self.creds.login}|{self.creds.api_key}".encode()
            ).hexdigest()
            cached = self._cache.get_json(cache_key) if self._cache is not None else None
            if cached:
                try:
                    identity = OdooIdentity(**cached["identity"])
                    protocol, base_context = cached["protocol"], dict(cached["base_context"])
                except (KeyError, TypeError, ValueError):
                    identity = None  # unreadable entry (e.g. older format): look the identity up again
                if identity is not None:
                    self._protocol = protocol
                    self._uid = identity.uid if protocol == "jsonrpc" else self._uid
                    self._base_context = base_context
                    self._identity = identity
                    return self._identity
            await self._ensure_protocol_locked()
            # the JSON-2 probe already returned context_get; don't ask twice
            ctx = self._probe_ctx if self._probe_ctx is not None else await self.call("res.users", "context_get")
            uid = ctx.get("uid") if isinstance(ctx, dict) else None
            if not isinstance(uid, int):
                uid = self._uid
            if not isinstance(uid, int):
                raise OdooError("could not determine which Odoo user this API key belongs to", kind="auth")
            rows = await self.call("res.users", "read", ids=[uid], fields=["login", "name", "share", "company_id"])
            if not rows:
                raise OdooError("the Odoo user for this API key was not found", kind="auth")
            row = rows[0]
            company = row.get("company_id") or None
            self._base_context = {
                key: ctx[key] for key in ("lang", "tz") if isinstance(ctx, dict) and ctx.get(key)
            }
            self._identity = OdooIdentity(
                uid=uid,
                login=row.get("login") or "",
                name=row.get("name") or "",
                tz=(ctx.get("tz") if isinstance(ctx, dict) else None) or "UTC",
                lang=(ctx.get("lang") if isinstance(ctx, dict) else None) or "en_US",
                company_id=company[0] if company else None,
                company_name=company[1] if company else None,
                is_internal_user=not row.get("share", False),
                server_version=await self.server_version(),
                protocol=self._protocol,
            )
            if self._cache is not None:
                self._cache.set_json(
                    cache_key,
                    {"protocol": self._protocol, "base_context": self._base_context, "identity": dataclasses.asdict(self._identity)},
                    600,
                )
            return self._identity

    async def server_version(self) -> str:
        try:
            response = await self._http.get(f"{self.creds.url}/web/version", timeout=self._timeout)
            if response.status_code == 200:
                return str(response.json().get("version", "unknown"))
        except (httpx.HTTPError, ValueError):
            pass
        try:
            info = await self._jsonrpc("common", "version", [])
            return str(info.get("server_version", "unknown"))
        except OdooError:
            return "unknown"

    # ------------------------------------------------------------------ protocol detection

    async def _ensure_protocol(self) -> None:
        if self._protocol in ("json2", "jsonrpc") and (self._protocol == "json2" or self._uid is not None):
            return
        async with self._lock:
            await self._ensure_protocol_locked()

    async def _ensure_protocol_locked(self) -> None:
        if self._protocol == "json2":
            return
        if self._protocol == "jsonrpc":
            if self._uid is None:
                await self._authenticate_jsonrpc()
            return
        # auto: probe the JSON-2 route. Odoo <= 18 answers 404, or (with the web module) a redirect to the
        # login page, or some non-JSON page: all mean "no JSON-2 here".
        try:
            probe = await self._call_json2("res.users", "context_get", ids=None, context=None, kwargs={})
            self._protocol = "json2"
            self._probe_ctx = probe if isinstance(probe, dict) else None
        except OdooError as exc:
            no_json2 = exc.status == 404 or (exc.status is not None and 300 <= exc.status < 400) or exc.odoo_name is None
            if no_json2 and exc.kind != "auth":
                self._protocol = "jsonrpc"
                await self._authenticate_jsonrpc()
            else:
                raise

    async def _authenticate_jsonrpc(self) -> None:
        if not self.creds.db:
            raise OdooError("ODOO_DB must be set to use the legacy JSON-RPC protocol", kind="auth")
        uid = await self._jsonrpc("common", "authenticate", [self.creds.db, self.creds.login, self.creds.api_key, {}])
        if not isinstance(uid, int) or not uid:
            raise OdooError(
                "login or API key is wrong (on Odoo 20+ the key must have the 'RPC' scope; keys made before an "
                "upgrade to Odoo 20 must be recreated)",
                kind="auth",
            )
        self._uid = uid

    async def verify_login_matches(self) -> OdooIdentity:
        """Check that the API key belongs to the login the person typed (used at sign-in)."""
        identity = await self.identity()
        if identity.login.strip().lower() != self.creds.login.strip().lower():
            raise OdooError("this API key belongs to a different Odoo user than the login entered", kind="auth")
        return identity

    # ------------------------------------------------------------------ JSON-2

    async def _call_json2(self, model: str, method: str, *, ids, context, kwargs) -> Any:
        body: dict[str, Any] = dict(kwargs)
        if ids:
            body["ids"] = list(ids)
        if context:
            body["context"] = context
        headers = {
            "Authorization": f"bearer {self.creds.api_key}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
        }
        if self.creds.db:
            headers["X-Odoo-Database"] = self.creds.db
        url = f"{self.creds.url}/json/2/{model}/{method}"
        try:
            response = await self._http.post(url, json=body, headers=headers, timeout=self._timeout)
        except httpx.TimeoutException as exc:
            raise OdooError(f"{model}.{method} timed out", kind="timeout") from exc
        except httpx.HTTPError as exc:
            raise OdooError(type(exc).__name__, kind="network") from exc
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError as exc:
                raise OdooError("Odoo returned a non-JSON response", kind="server", status=200) from exc
        raise _json2_error(response)

    # ------------------------------------------------------------------ legacy JSON-RPC

    async def _call_jsonrpc(self, model: str, method: str, *, ids, context, kwargs) -> Any:
        if self._uid is None:
            await self._authenticate_jsonrpc()
        args: list[Any] = [list(ids)] if ids else []
        kw = dict(kwargs)
        # Odoo <= 18 overrides name the first parameter of these differently (vals/values, fields/fields_list/
        # default_fields, args/domain), so legacy calls pass it positionally.
        if method == "create" and "vals_list" in kw:
            args = [kw.pop("vals_list")]
        elif method == "write" and "vals" in kw:
            args = [*args, kw.pop("vals")]
        elif method == "default_get" and "fields" in kw:
            args = [kw.pop("fields")]
        elif method == "name_search":
            args = [kw.pop("name", ""), kw.pop("domain", None) or [], kw.pop("operator", "ilike"), kw.pop("limit", 100)]
        if context:
            kw["context"] = context
        return await self._jsonrpc(
            "object", "execute_kw", [self.creds.db, self._uid, self.creds.api_key, model, method, args, kw]
        )

    async def _jsonrpc(self, service: str, method: str, args: list) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {"service": service, "method": method, "args": args},
            "id": next(self._ids),
        }
        try:
            response = await self._http.post(
                f"{self.creds.url}/jsonrpc",
                json=payload,
                headers={"User-Agent": USER_AGENT},
                timeout=self._timeout,
            )
        except httpx.TimeoutException as exc:
            raise OdooError(f"{service}.{method} timed out", kind="timeout") from exc
        except httpx.HTTPError as exc:
            raise OdooError(type(exc).__name__, kind="network") from exc
        if response.status_code == 429:
            raise OdooError("", kind="rate_limited", status=429)
        if response.status_code in (502, 503, 504):
            raise OdooError(f"HTTP {response.status_code}", kind="unavailable", status=response.status_code)
        if response.status_code != 200:
            raise OdooError(f"HTTP {response.status_code}", kind="server", status=response.status_code)
        try:
            data = response.json()
        except ValueError as exc:
            raise OdooError("Odoo returned a non-JSON response", kind="server") from exc
        if "error" in data:
            err = data["error"] or {}
            details = err.get("data") or {}
            name = str(details.get("name") or "")
            short = name.rsplit(".", 1)[-1]
            message = details.get("message") or err.get("message") or "unknown error"
            kind = _KIND_BY_NAME.get(short, "server")
            if "doesn't exist" in str(message) or "does not exist" in str(message):
                kind = "missing"
            raise OdooError(_clean_message(message), kind=kind, odoo_name=name)
        return data.get("result")


def _json2_error(response: httpx.Response) -> OdooError:
    status = response.status_code
    name = ""
    message = ""
    try:
        body = response.json()
        if isinstance(body, dict):
            name = str(body.get("name") or "")
            message = str(body.get("message") or "")
    except ValueError:
        message = f"unexpected non-JSON answer (HTTP {status})"  # never echo an HTML page into the AI's context
    short = name.rsplit(".", 1)[-1]
    if status == 401:
        kind = "auth"
        message = (message or "Invalid API key") + (
            " (on Odoo 19.4/20+ the key must be created with the 'RPC' scope, and keys made before an upgrade to "
            "Odoo 20 must be recreated; also check it has not expired)"
        )
    elif status == 403:
        kind = "access"
    elif status == 404:
        kind = "missing"
    elif status == 429:
        kind = "rate_limited"
    elif status in (502, 503, 504):
        kind = "unavailable"
    elif status == 409:
        kind = "user_error"
    elif status in (400, 422):
        kind = _KIND_BY_NAME.get(short, "validation")
    elif short in _KIND_BY_NAME:
        kind = _KIND_BY_NAME[short]
    else:
        kind = "server"
    if kind == "server" and not message:
        message = f"HTTP {status}"
    return OdooError(_clean_message(message), kind=kind, status=status, odoo_name=name or None)


def _clean_message(message: str) -> str:
    """Odoo messages can be long and include tracebacks in debug mode; keep the human part."""
    message = str(message).strip()
    for marker in ("Traceback (most recent call last)", "\n\n\n"):
        if marker in message:
            message = message.split(marker, 1)[0].strip()
    return message[:1500]
