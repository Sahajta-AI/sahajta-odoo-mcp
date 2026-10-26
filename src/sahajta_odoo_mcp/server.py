"""Builds the MCP server in its two modes.

stdio : one person, credentials from environment variables (Claude Desktop / Claude Code on a laptop).
http  : company-wide Claude connector; every person signs in with their own Odoo API key (OAuth).
"""

from __future__ import annotations

import asyncio
import hmac
import os
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import __version__
from .audit import AuditLog
from .config import Settings
from .confirm import ConfirmationSigner
from .errors import OdooError
from .odoo_client import OdooClient, OdooCredentials, new_http_client
from .policy import SafetyPolicy
from .ratelimit import RateLimiter
from .schema import SchemaCache
from .service import OdooService, Shared
from .state import MemoryState, RedisState, redis_client
from .usage import UsageLog
from .tools import INSTRUCTIONS, register_tools

SERVER_NAME = "sahajta-odoo"
SERVER_TITLE = "Sahajta Odoo"
_SERVICE_TTL_SECONDS = 600


def build_shared(settings: Settings, secret: bytes, http: httpx.AsyncClient | None = None) -> Shared:
    redis_conn = redis_client(settings.mcp_redis_url.get_secret_value()) if settings.mcp_redis_url else None
    state = RedisState(redis_conn) if redis_conn is not None else MemoryState()
    usage = UsageLog(redis_conn) if redis_conn is not None else None
    return Shared(
        settings=settings,
        policy=SafetyPolicy(settings),
        schema=SchemaCache(shared=state),
        signer=ConfirmationSigner(secret, state=state),
        audit=AuditLog(settings.mcp_audit_log_file, usage=usage),
        limiter=RateLimiter(settings.mcp_reads_per_minute, settings.mcp_writes_per_minute, state=state),
        http=http or new_http_client(verify=settings.odoo_verify_tls),
        button_cache={},
        state=state,
        usage=usage,
    )


def _new_server(**auth_kwargs) -> MCPServer:
    return MCPServer(
        name=SERVER_NAME,
        title=SERVER_TITLE,
        description="Read and (if enabled) safely update Odoo ERP data. Records can never be deleted.",
        instructions=INSTRUCTIONS,
        version=__version__,
        # No server-to-client notifications here (the tool list never changes), so no
        # `subscriptions/listen` streams: on serverless hosts they only sit open until the platform kills them.
        subscriptions=False,
        **auth_kwargs,
    )


def create_stdio_server(settings: Settings, http: httpx.AsyncClient | None = None) -> MCPServer:
    settings.require_stdio_settings()
    secret = settings.mcp_secret.get_secret_value().encode() if settings.mcp_secret else os.urandom(32)
    shared = build_shared(settings, secret, http)
    client = OdooClient(
        OdooCredentials(settings.odoo_url, settings.odoo_db, settings.odoo_login or "", settings.odoo_api_key.get_secret_value()),
        shared.http,
        protocol=settings.odoo_protocol,
        timeout=settings.odoo_timeout_seconds,
        max_parallel=settings.odoo_max_parallel_requests,
        cache=shared.state,
    )
    holder: dict[str, OdooService] = {}

    async def get_service() -> OdooService:
        if "service" not in holder:
            identity = await client.identity()
            if not identity.is_internal_user:
                raise ToolError("This Odoo account is a portal/customer account; use an internal employee account.")
            holder["service"] = OdooService(shared, client, identity)
        return holder["service"]

    mcp = _new_server()
    register_tools(mcp, get_service, settings)
    return mcp


def create_http_app(settings: Settings, http: httpx.AsyncClient | None = None):
    """Returns the ASGI app for the company-wide connector."""
    from .oauth import build_oauth  # imported lazily: stdio mode does not need it

    settings.require_http_settings()
    shared = build_shared(settings, settings.mcp_secret.get_secret_value().encode(), http)

    def record_signout(login: str, reason: str) -> None:
        # Every ended sign-in lands in the usage log, so the owners can be alerted.
        shared.audit.record(user=login, uid=None, tool="signout", outcome="error", detail=reason)

    oauth = build_oauth(settings, shared.http, on_revoke=record_signout)
    services: OrderedDict[str, tuple[float, OdooService]] = OrderedDict()

    async def get_service() -> OdooService:
        token = get_access_token()
        if token is None:
            raise ToolError("Not signed in. Reconnect the Odoo connector in Claude.")
        key = str((token.claims or {}).get("grant_id") or token.token)
        now = time.monotonic()
        hit = services.get(key)
        if hit and hit[0] > now:
            return hit[1]
        login = str((token.claims or {}).get("login", "?"))
        try:
            creds = oauth.credentials_for(token)
        except OdooError as exc:
            # Our own record says no (e.g. the token expired since the check a moment ago). Odoo was not asked,
            # so this says nothing about the API key: revoke nothing.
            shared.audit.record(user=login, uid=None, tool="connect", outcome="error", detail=f"{exc.kind}: {exc}")
            raise ToolError(f"{exc}. Try again; if this keeps happening, reconnect the Odoo connector in Claude.") from exc
        client = OdooClient(
            creds, shared.http, protocol=settings.odoo_protocol, timeout=settings.odoo_timeout_seconds,
            max_parallel=settings.odoo_max_parallel_requests, cache=shared.state,
        )
        try:
            identity = await client.identity()
        except OdooError as exc:
            shared.audit.record(user=login, uid=None, tool="connect", outcome="error", detail=f"{exc.kind}: {exc}")
            if exc.kind == "auth":
                # Odoo itself rejected the key (revoked or expired): end this sign-in so Claude asks the person to reconnect.
                oauth.revoke(token, "Odoo rejected the API key")
                raise ToolError(f"{exc}. Reconnect the Odoo connector in Claude.") from exc
            raise ToolError(f"{exc}. Nothing was changed; try again in a moment.") from exc
        if not identity.is_internal_user:
            raise ToolError("This Odoo account is a portal/customer account and cannot use this connector.")
        service = OdooService(shared, client, identity)
        services[key] = (now + _SERVICE_TTL_SECONDS, service)
        while len(services) > 500:
            services.popitem(last=False)
        return service

    mcp = _new_server(token_verifier=oauth.token_verifier, auth=oauth.auth_settings)
    register_tools(mcp, get_service, settings)
    for route in oauth.routes:
        mcp.custom_route(route.path, methods=sorted(route.methods or ["GET"]), name=route.name)(route.endpoint)

    @mcp.custom_route("/admin/usage", methods=["GET"], include_in_schema=False)
    async def admin_usage(request: Request) -> JSONResponse:
        """Usage report for the operator. Needs MCP_ADMIN_TOKEN as a bearer token; 404 when disabled."""
        expected = settings.mcp_admin_token.get_secret_value() if settings.mcp_admin_token else ""
        if not expected or shared.usage is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        header = request.headers.get("authorization", "")
        supplied = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": 'Bearer realm="admin"'})
        try:
            days = max(1, min(int(request.query_params.get("days", "7")), 30))
        except ValueError:
            return JSONResponse({"error": "days must be a number from 1 to 30"}, status_code=400)
        report = await asyncio.to_thread(shared.usage.report, days)
        return JSONResponse(report, headers={"Cache-Control": "no-store"})

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    host = urlparse(settings.mcp_public_url).netloc
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host, f"{host.split(':')[0]}:*"],
        allowed_origins=[f"https://{host}", "https://claude.ai", "https://claude.com"],
    )
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=transport_security,
        host=settings.mcp_host,
    )
    inner_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(starlette_app):
        async with inner_lifespan(starlette_app):
            try:
                yield
            finally:
                await oauth.aclose()
                await shared.http.aclose()

    app.router.lifespan_context = lifespan
    return _NoListenStream(app)


class _NoListenStream:
    """Declines the optional GET /mcp notification stream (allowed by the MCP spec: 405).

    This server never sends server-initiated messages, and serverless hosts cut long-lived
    requests off after their time limit, so an open stream would only hang there.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/mcp" and scope["method"] == "GET":
            await send({"type": "http.response.start", "status": 405, "headers": [(b"allow", b"POST"), (b"content-length", b"0")]})
            await send({"type": "http.response.body", "body": b""})
            return
        await self.app(scope, receive, send)
