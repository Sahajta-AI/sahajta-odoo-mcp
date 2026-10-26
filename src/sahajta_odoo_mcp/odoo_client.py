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
import email.utils
import hashlib
import http.cookiejar
import itertools
import logging
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from . import __version__, deadline
from .errors import OdooError
from .policy import HARD_BLOCKED_MODELS, HARD_BLOCKED_PREFIXES

logger = logging.getLogger(__name__)

USER_AGENT = f"sahajta-odoo-mcp/{__version__}"

# Last line of defence, independent of the policy module: these never leave this process.
_NEVER_SENT = ("unlink", "uninstall", "sudo")

# Read-only methods are retried when Odoo is busy; changes are never retried automatically.
_SAFE_TO_RETRY = frozenset(
    {
        "search", "search_read", "search_count", "read", "fields_get", "name_search", "get_views",
        "formatted_read_group", "read_group", "context_get", "default_get", "get_available_models",
        "has_access", "onchange",  # previews: onchange computes a new record in memory, as Odoo's own forms do
    }
)
# Waits before the 2nd and 3rd attempt, each varied by +-30% so that parallel serverless instances
# turned away together do not all come back at the same moment and collide again.
_RETRY_WAITS = (2.0, 4.0)
_MAX_WAIT = 8.0
_MAX_TOTAL_WAIT = 15.0
# Near the end of a tool call each request still gets this long, so a quick answer can arrive.
_MIN_TIMEOUT = 5.0
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

    def _request_timeout(self) -> float:
        """The configured timeout, cut to the time left in the current tool call (never below _MIN_TIMEOUT)."""
        left = deadline.seconds_left()
        return self._timeout if left is None else min(self._timeout, max(_MIN_TIMEOUT, left))

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
        waited = 0.0
        for attempt in itertools.count(1):
            try:
                async with _gate(self.creds.url, self._max_parallel):
                    # A change may wait here behind other calls; once its send-by time has passed it must not go
                    # out, or the platform could cut the request off half-way.
                    if deadline.send_by_passed():
                        raise OdooError("the change waited too long for its turn", kind="late", maybe_applied=False)
                    if self._protocol == "json2":
                        return await self._call_json2(model, method, ids=ids, context=context, kwargs=kwargs)
                    return await self._call_jsonrpc(model, method, ids=ids, context=context, kwargs=kwargs)
            except OdooError as exc:
                wait = _retry_wait(exc, attempt, waited) if method in _SAFE_TO_RETRY else None
                if wait is None or not _fits_in_call(wait):
                    raise
                await asyncio.sleep(wait)
                waited += wait
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
            # Odoo accepted the key (HTTP 200) but the answer is odd, e.g. a proxy's error page: that says
            # nothing about the key, so it must never be taken as "the key is invalid".
            if not isinstance(uid, int):
                raise OdooError("Odoo's answer did not say which user this API key belongs to", kind="server", status=200)
            rows = await self.call("res.users", "read", ids=[uid], fields=["login", "name", "share", "company_id"])
            if not rows:
                raise OdooError("Odoo did not return the user this API key belongs to", kind="server", status=200)
            row = rows[0]
            company = row.get("company_id") or None
            self._base_context = {
                key: ctx[key] for key in ("lang", "tz") if isinstance(ctx, dict) and ctx.get(key)
            }
            self._identity = OdooIdentity(
                uid=uid,
                login=row.get("login") or "",
                name=row.get("name") or "",
                tz=(ctx.get("tz") if isinstance(ctx, dict) else None) or "",  # empty: MCP_DEFAULT_TIMEZONE applies
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
            response = await self._http.get(f"{self.creds.url}/web/version", timeout=self._request_timeout())
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
        # login page, or a non-JSON page: all mean "no JSON-2 here". Anything else (busy, down, timeout,
        # network) says nothing about the route and is passed on as it is; reading Odoo.com's 429 as
        # "no JSON-2" once sent Odoo 19 users down the legacy path and signed them out.
        waited = 0.0
        for attempt in itertools.count(1):
            try:
                async with _gate(self.creds.url, self._max_parallel):
                    probe = await self._call_json2("res.users", "context_get", ids=None, context=None, kwargs={})
                self._protocol = "json2"
                self._probe_ctx = probe if isinstance(probe, dict) else None
                return
            except OdooError as exc:
                wait = _retry_wait(exc, attempt, waited)
                if wait is not None and _fits_in_call(wait):
                    await asyncio.sleep(wait)
                    waited += wait
                    continue
                route_missing = exc.status == 404 or (exc.status is not None and 300 <= exc.status < 400) or (
                    exc.status == 200 and exc.odoo_name is None
                )
                if not route_missing:
                    raise
                if not self.creds.db:
                    # The legacy protocol needs a database name, so falling back could never work; and a
                    # maintenance page also looks like "no JSON-2". The probe's own error says what happened.
                    logger.warning("JSON-2 check answered HTTP %s; set ODOO_DB to allow the JSON-RPC fallback", exc.status)
                    raise
                self._protocol = "jsonrpc"
                await self._authenticate_jsonrpc()
                return

    async def _authenticate_jsonrpc(self) -> None:
        if not self.creds.db:
            # a server setting, not the person's key: never a reason to end their sign-in. The setting's name is
            # for the operator's log only.
            logger.warning("ODOO_DB must be set to use the legacy JSON-RPC protocol")
            raise OdooError("the legacy JSON-RPC protocol needs the Odoo database name, which is not set", kind="config")
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
            response = await self._http.post(url, json=body, headers=headers, timeout=self._request_timeout())
        except httpx.HTTPError as exc:
            raise _transport_error(exc, f"{model}.{method}") from exc
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
                timeout=self._request_timeout(),
            )
        except httpx.HTTPError as exc:
            raise _transport_error(exc, f"{service}.{method}") from exc
        if response.status_code == 429:
            raise OdooError("", kind="rate_limited", status=429, retry_after=_retry_after(response))
        if response.status_code in (502, 503, 504):
            raise OdooError(
                f"HTTP {response.status_code}", kind="unavailable", status=response.status_code,
                retry_after=_retry_after(response),
            )
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
    return OdooError(
        _clean_message(message), kind=kind, status=status, odoo_name=name or None, retry_after=_retry_after(response)
    )


def _transport_error(exc: httpx.HTTPError, what: str) -> OdooError:
    """Only a failure to connect proves the request never reached Odoo; after that (a timeout while
    waiting for the answer, a dropped connection) Odoo may have carried it out."""
    sent = not isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout))
    if isinstance(exc, httpx.TimeoutException):
        return OdooError(f"{what} timed out", kind="timeout", maybe_applied=sent)
    return OdooError(type(exc).__name__, kind="network", maybe_applied=sent)


def _retry_after(response: httpx.Response) -> float | None:
    """Seconds from a Retry-After header (a number or an HTTP date), if there is one."""
    value = response.headers.get("retry-after", "").strip()
    if value.isascii() and value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


def _retry_wait(exc: OdooError, attempt: int, waited: float) -> float | None:
    """Seconds to wait before retrying a read Odoo turned away as busy, or None to give up."""
    if exc.kind not in ("rate_limited", "unavailable") or attempt > len(_RETRY_WAITS):
        return None
    wait = _RETRY_WAITS[attempt - 1] * random.uniform(0.7, 1.3)
    if exc.retry_after is not None:
        if exc.retry_after > _MAX_WAIT:
            return None  # Odoo wants a longer pause than the person should be kept waiting for
        wait = max(wait, exc.retry_after * random.uniform(1.0, 1.3))  # never sooner than Odoo asked
    wait = min(wait, _MAX_WAIT)
    return wait if waited + wait <= _MAX_TOTAL_WAIT else None


def _fits_in_call(wait: float) -> bool:
    """A retry wait must end before the tool call's soft time limit: each request's waits are capped, but
    several requests in one call add up past the platform's limit."""
    left = deadline.seconds_left()
    return left is None or wait <= left


def _clean_message(message: str) -> str:
    """Odoo messages can be long and include tracebacks in debug mode; keep the human part."""
    message = str(message).strip()
    for marker in ("Traceback (most recent call last)", "\n\n\n"):
        if marker in message:
            message = message.split(marker, 1)[0].strip()
    return message[:1500]
