"""HTTP endpoints of the authorization server.

Every endpoint is a plain `async def endpoint(request) -> Response`, so each Route can be
re-registered with `MCPServer.custom_route(route.path, methods=sorted(route.methods))(route.endpoint)`.
The SDK's own handler classes do the OAuth protocol work; these wrappers add what
`create_auth_routes` would have added (CORS, request-body limits) plus per-IP rate limits.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from urllib.parse import parse_qsl

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import Message

from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.handlers.register import RegistrationHandler
from mcp.server.auth.handlers.revoke import RevocationHandler
from mcp.server.auth.handlers.token import TokenHandler
from mcp.server.auth.json_response import PydanticJSONResponse
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.shared.auth import OAuthMetadata, ProtectedResourceMetadata

from .clients import SCOPE, SUPPORTED_GRANT_TYPES
from .limits import SlidingWindow, client_ip
from .login_page import LOGIN_PATH, LoginPage
from .provider import OdooAuthProvider, TemporarilyUnavailable

logger = logging.getLogger(__name__)

BODY_LIMIT = 64 * 1024
LOGIN_BODY_LIMIT = 16 * 1024
AUTHORIZE_PER_IP = 120
REGISTER_PER_IP = 60
RATE_WINDOW_SECONDS = 600
CLIENT_AUTH_METHODS = ["none", "client_secret_post", "client_secret_basic"]
_CORS_ALLOW_HEADERS = "Authorization, Content-Type, MCP-Protocol-Version"
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

Endpoint = Callable[[Request], Awaitable[Response]]


class _BodyTooLarge(Exception):
    pass


def authorization_server_metadata(public_url: str) -> OAuthMetadata:
    return OAuthMetadata(
        issuer=public_url,  # type: ignore[arg-type]  # a plain str keeps the exact form (no trailing slash)
        authorization_endpoint=f"{public_url}/authorize",  # type: ignore[arg-type]
        token_endpoint=f"{public_url}/token",  # type: ignore[arg-type]
        registration_endpoint=f"{public_url}/register",  # type: ignore[arg-type]
        revocation_endpoint=f"{public_url}/revoke",  # type: ignore[arg-type]
        revocation_endpoint_auth_methods_supported=CLIENT_AUTH_METHODS,
        scopes_supported=[SCOPE],
        response_types_supported=["code"],
        response_modes_supported=["query"],
        grant_types_supported=list(SUPPORTED_GRANT_TYPES),
        token_endpoint_auth_methods_supported=CLIENT_AUTH_METHODS,
        code_challenge_methods_supported=["S256"],
        client_id_metadata_document_supported=True,
        authorization_response_iss_parameter_supported=True,
    )


def protected_resource_metadata(auth: AuthSettings) -> ProtectedResourceMetadata:
    # Built exactly as the SDK builds the path-suffixed document, so both URLs serve the same JSON.
    assert auth.resource_server_url is not None
    return ProtectedResourceMetadata(
        resource=auth.resource_server_url,
        authorization_servers=[auth.issuer_url],
        scopes_supported=auth.required_scopes,
    )


def build_routes(
    provider: OdooAuthProvider,
    login_page: LoginPage,
    auth: AuthSettings,
    *,
    public_url: str,
    trust_proxy_headers: bool,
) -> list[Route]:
    as_metadata = authorization_server_metadata(public_url)
    pr_metadata = protected_resource_metadata(auth)
    client_authenticator = ClientAuthenticator(provider)
    authorize_handler = AuthorizationHandler(provider)
    token_handler = TokenHandler(provider, client_authenticator)
    registration_handler = RegistrationHandler(
        provider, options=ClientRegistrationOptions(enabled=True, default_scopes=[SCOPE])
    )
    revocation_handler = RevocationHandler(provider, client_authenticator)
    authorize_limit = SlidingWindow(AUTHORIZE_PER_IP, RATE_WINDOW_SECONDS)
    register_limit = SlidingWindow(REGISTER_PER_IP, RATE_WINDOW_SECONDS)

    def ip(request: Request) -> str:
        return client_ip(request, trust_proxy_headers)

    async def oauth_authorization_server_metadata(request: Request) -> Response:
        if request.method == "OPTIONS":
            return _preflight("GET, OPTIONS")
        return _cors(PydanticJSONResponse(as_metadata, headers={"Cache-Control": "public, max-age=3600"}))

    async def oauth_protected_resource_metadata(request: Request) -> Response:
        if request.method == "OPTIONS":
            return _preflight("GET, OPTIONS")
        return _cors(PydanticJSONResponse(pr_metadata, headers={"Cache-Control": "public, max-age=3600"}))

    async def oauth_authorize(request: Request) -> Response:
        if not authorize_limit.allow(ip(request)):
            return _error(429, "temporarily_unavailable", "Too many authorization requests; try again in a few minutes")
        if request.method == "POST":
            try:
                request = await _buffered(request, BODY_LIMIT)
            except _BodyTooLarge:
                return _error(413, "invalid_request", "Request body too large")
        return await authorize_handler.handle(request)

    async def oauth_token(request: Request) -> Response:
        if request.method == "OPTIONS":
            return _preflight("POST, OPTIONS")
        try:
            response = await token_handler.handle(await _buffered(request, BODY_LIMIT))
        except _BodyTooLarge:
            response = _error(413, "invalid_request", "Request body too large")
        except TemporarilyUnavailable:
            # Not invalid_grant: the client must keep its refresh token and retry later.
            response = _error(
                503,
                "temporarily_unavailable",
                "Odoo could not be reached to re-check this connection; try again shortly",
                {"Retry-After": "30"},
            )
        except Exception:
            logger.exception("Token endpoint failed")
            response = _error(500, "server_error", "Unexpected server error")
        return _cors(response)

    async def oauth_register(request: Request) -> Response:
        if request.method == "OPTIONS":
            return _preflight("POST, OPTIONS")
        if not register_limit.allow(ip(request)):
            return _cors(_error(429, "temporarily_unavailable", "Too many registrations; try again later"))
        try:
            response = await registration_handler.handle(await _buffered(request, BODY_LIMIT))
        except _BodyTooLarge:
            response = _error(413, "invalid_client_metadata", "Request body too large")
        return _cors(response)

    async def oauth_revoke(request: Request) -> Response:
        if request.method == "OPTIONS":
            return _preflight("POST, OPTIONS")
        try:
            response = await revocation_handler.handle(
                await _buffered(request, BODY_LIMIT, transform=_with_client_secret_field)
            )
        except _BodyTooLarge:
            response = _error(413, "invalid_request", "Request body too large")
        return _cors(response)

    async def oauth_login(request: Request) -> Response:
        if request.method == "POST":
            try:
                request = await _buffered(request, LOGIN_BODY_LIMIT)
            except _BodyTooLarge:
                return _error(413, "invalid_request", "Request body too large")
        return await login_page.handle(request)

    return [
        Route("/.well-known/oauth-authorization-server", oauth_authorization_server_metadata, methods=["GET", "OPTIONS"]),
        Route("/.well-known/oauth-protected-resource", oauth_protected_resource_metadata, methods=["GET", "OPTIONS"]),
        Route("/authorize", oauth_authorize, methods=["GET", "POST"]),
        Route(LOGIN_PATH, oauth_login, methods=["GET", "POST"]),
        Route("/token", oauth_token, methods=["POST", "OPTIONS"]),
        Route("/register", oauth_register, methods=["POST", "OPTIONS"]),
        Route("/revoke", oauth_revoke, methods=["POST", "OPTIONS"]),
    ]


async def _buffered(
    request: Request, limit: int, transform: Callable[[Request, bytes], bytes] | None = None
) -> Request:
    """Reads the body with a size cap and returns a Request that replays it to the handler."""
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise _BodyTooLarge()
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise _BodyTooLarge()
        chunks.append(chunk)
    body = b"".join(chunks)
    if transform is not None:
        body = transform(request, body)
    replayed = False

    async def receive() -> Message:
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await request.receive()

    return Request(request.scope, receive)


def _with_client_secret_field(request: Request, body: bytes) -> bytes:
    # The SDK's RevocationRequest declares `client_secret: str | None` without a default, so a
    # public client that (correctly) omits it gets a 400. Supply an empty one; ClientAuthenticator
    # still demands the real secret from confidential clients.
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        return body
    if any(key == "client_secret" for key, _ in parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)):
        return body
    return body + (b"&" if body else b"") + b"client_secret="


def _error(status_code: int, error: str, description: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers={**_NO_STORE, **(headers or {})},
    )


def _cors(response: Response) -> Response:
    # These endpoints never use cookies or ambient credentials, so any origin may call them.
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


def _preflight(methods: str) -> Response:
    return Response(
        status_code=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": methods,
            "Access-Control-Allow-Headers": _CORS_ALLOW_HEADERS,
            "Access-Control-Max-Age": "86400",
        },
    )
