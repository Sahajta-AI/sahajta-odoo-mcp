"""End-to-end tests of the OAuth authorization server, served by a real MCPServer app.

Odoo and the CIMD host are mocked with respx (assert_all_mocked), so no test can reach a
real network host.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import secrets
import sqlite3
import stat
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import redis
import respx
from starlette.testclient import TestClient

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from sahajta_odoo_mcp.config import Settings
from sahajta_odoo_mcp.errors import OdooError
from sahajta_odoo_mcp.oauth import OAuthComponents, build_oauth
from sahajta_odoo_mcp.oauth.admin import main as admin_main
from sahajta_odoo_mcp.oauth.login_page import GENERIC_FAILURE, IP_LIMITED, PORTAL_FAILURE
from sahajta_odoo_mcp.oauth.redis_store import RedisOAuthStore
from sahajta_odoo_mcp.oauth.store import REFRESH_REUSE_GRACE_SECONDS, OAuthStore

PUBLIC = "https://mcp.example.com"
RESOURCE = f"{PUBLIC}/mcp"
ODOO = "https://odoo.example.com"
CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"
CLAUDE_CODE_CIMD = "https://claude.ai/oauth/claude-code-client-metadata"
SECRET = "test-secret-" + "k" * 28  # 40 characters

PRIYA_KEY = "4f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c"
RAVI_KEY = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
PORTAL_KEY = "1234567890abcdef1234567890abcdef12345678"
UNKNOWN_KEY = "0000000000000000000000000000000000000000"

USERS = {
    PRIYA_KEY: {"id": 7, "login": "priya@sahajta.ai", "name": "Priya", "share": False, "company_id": [1, "Sahajta AI"]},
    RAVI_KEY: {"id": 8, "login": "ravi@sahajta.ai", "name": "Ravi", "share": False, "company_id": [1, "Sahajta AI"]},
    PORTAL_KEY: {"id": 9, "login": "customer@example.com", "name": "Customer", "share": True, "company_id": [1, "Sahajta AI"]},
}
UNAUTHORIZED = {"name": "werkzeug.exceptions.Unauthorized", "message": "Invalid apikey"}

CLAUDE_CODE_DOC = {
    "client_id": CLAUDE_CODE_CIMD,
    "client_name": "Claude Code",
    "client_uri": "https://claude.ai",
    "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
}


# ---------------------------------------------------------------------------------- fixtures


class FakeOdoo:
    """JSON-2 endpoints of an Odoo 19 server, keyed by API key."""

    def __init__(self, router: respx.MockRouter):
        self.down = False
        self.revoked_keys: set[str] = set()
        self.context_get = router.post(f"{ODOO}/json/2/res.users/context_get").mock(side_effect=self._context_get)
        self.read = router.post(f"{ODOO}/json/2/res.users/read").mock(side_effect=self._read)
        router.get(f"{ODOO}/web/version").mock(return_value=httpx.Response(200, json={"version": "19.0"}))

    def _user(self, request: httpx.Request) -> dict | None:
        if self.down:
            raise httpx.ConnectError("connection refused", request=request)
        auth = request.headers.get("authorization", "")
        key = auth.split(" ", 1)[1] if auth.lower().startswith("bearer ") else ""
        return None if key in self.revoked_keys else USERS.get(key)

    def _context_get(self, request: httpx.Request) -> httpx.Response:
        user = self._user(request)
        if user is None:
            return httpx.Response(401, json=UNAUTHORIZED)
        return httpx.Response(200, json={"uid": user["id"], "tz": "Asia/Kolkata", "lang": "en_US"})

    def _read(self, request: httpx.Request) -> httpx.Response:
        user = self._user(request)
        if user is None:
            return httpx.Response(401, json=UNAUTHORIZED)
        return httpx.Response(200, json=[user])


@dataclass
class Env:
    client: TestClient
    oauth: OAuthComponents
    odoo: FakeOdoo
    router: respx.MockRouter
    settings: Settings
    data_dir: Path
    signouts: list[tuple[str, str]] = field(default_factory=list)  # (login, reason) per revoked grant

    @property
    def db_path(self) -> Path:
        return self.data_dir / "oauth.sqlite3"

    def db(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)


def make_settings(tmp_path: Path, **overrides) -> Settings:
    values = {
        "odoo_url": ODOO,
        "odoo_db": "sahajta",
        "odoo_protocol": "json2",
        "mcp_public_url": PUBLIC,
        "mcp_secret": SECRET,
        "mcp_data_dir": str(tmp_path / "data"),
        "mcp_access_mode": "read_only",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
def make_env(tmp_path: Path) -> Iterator[Callable[..., Env]]:
    cleanups: list[Callable[[], object]] = []

    def factory(**overrides) -> Env:
        settings = make_settings(tmp_path, **overrides)
        router = respx.mock(assert_all_called=False, assert_all_mocked=True)
        router.start()
        cleanups.append(router.stop)
        odoo = FakeOdoo(router)
        signouts: list[tuple[str, str]] = []
        oauth = build_oauth(settings, httpx.AsyncClient(), on_revoke=lambda login, reason: signouts.append((login, reason)))
        cleanups.append(lambda: asyncio.run(oauth.aclose()))

        mcp = MCPServer("odoo-test", token_verifier=oauth.token_verifier, auth=oauth.auth_settings)

        @mcp.tool()
        def whoami() -> str:
            token = get_access_token()
            assert token is not None
            creds = oauth.credentials_for(token)
            return f"{creds.login}|{creds.db}|{creds.url}|{token.subject}"

        # Exactly how server.py registers the routes.
        for route in oauth.routes:
            mcp.custom_route(route.path, methods=sorted(route.methods or ["GET"]), name=route.name)(route.endpoint)

        app = mcp.streamable_http_app(
            stateless_http=True,
            json_response=True,
            transport_security=TransportSecuritySettings(allowed_hosts=["mcp.example.com"], allowed_origins=[PUBLIC]),
        )
        client = TestClient(app, base_url=PUBLIC, follow_redirects=False)
        client.__enter__()
        cleanups.append(lambda: client.__exit__(None, None, None))
        return Env(client, oauth, odoo, router, settings, tmp_path / "data", signouts)

    yield factory
    for cleanup in reversed(cleanups):
        cleanup()


@pytest.fixture
def env(make_env: Callable[..., Env]) -> Env:
    return make_env()


# ---------------------------------------------------------------------------------- helpers


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def register(env: Env, redirect_uris: list[str] | None = None, **extra) -> httpx.Response:
    body = {
        "redirect_uris": redirect_uris or [CLAUDE_CALLBACK],
        "client_name": "Claude",
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        **extra,
    }
    return env.client.post("/register", json=body)


def register_client_id(env: Env, **kwargs) -> str:
    response = register(env, **kwargs)
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


def authorize(
    env: Env,
    client_id: str,
    redirect_uri: str,
    challenge: str,
    *,
    state: str = "state-123",
    resource: str | None = RESOURCE,
) -> httpx.Response:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "scope": "odoo",
    }
    if resource is not None:
        params["resource"] = resource
    return env.client.get("/authorize", params=params)


@dataclass
class LoginForm:
    response: httpx.Response
    request_id: str
    csrf: str
    html: str = field(repr=False)


def open_login(env: Env, login_url: str) -> LoginForm:
    assert login_url.startswith(f"{PUBLIC}/oauth/login?request="), login_url
    response = env.client.get(login_url)
    assert response.status_code == 200, response.text
    request_id = re.search(r'name="request" value="([^"]+)"', response.text).group(1)  # type: ignore[union-attr]
    csrf = re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)  # type: ignore[union-attr]
    return LoginForm(response, request_id, csrf, response.text)


def start_login(env: Env, client_id: str, redirect_uri: str, challenge: str, state: str = "state-123") -> LoginForm:
    response = authorize(env, client_id, redirect_uri, challenge, state=state)
    assert response.status_code == 302, response.text
    return open_login(env, response.headers["location"])


def submit(
    env: Env, form: LoginForm, login: str = "priya@sahajta.ai", api_key: str = PRIYA_KEY, csrf: str | None = None
) -> httpx.Response:
    data = {"request": form.request_id, "csrf": form.csrf if csrf is None else csrf, "login": login, "api_key": api_key}
    return env.client.post("/oauth/login", data=data)


def code_from(response: httpx.Response, redirect_uri: str, state: str = "state-123") -> str:
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    assert location.startswith(redirect_uri + "?"), location
    query = parse_qs(urlsplit(location).query)
    assert query["state"] == [state]
    assert query["iss"] == [PUBLIC]
    return query["code"][0]


def sign_in(
    env: Env,
    client_id: str,
    redirect_uri: str = CLAUDE_CALLBACK,
    *,
    login: str = "priya@sahajta.ai",
    api_key: str = PRIYA_KEY,
) -> tuple[str, str]:
    verifier, challenge = pkce()
    form = start_login(env, client_id, redirect_uri, challenge)
    return code_from(submit(env, form, login, api_key), redirect_uri), verifier


def exchange(env: Env, client_id: str, code: str, verifier: str, redirect_uri: str = CLAUDE_CALLBACK, **extra):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": RESOURCE,
        **extra,
    }
    return env.client.post("/token", data=data)


def refresh(env: Env, client_id: str, refresh_token: str) -> httpx.Response:
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id, "resource": RESOURCE}
    return env.client.post("/token", data=data)


def connect(env: Env) -> tuple[str, dict]:
    client_id = register_client_id(env)
    code, verifier = sign_in(env, client_id)
    response = exchange(env, client_id, code, verifier)
    assert response.status_code == 200, response.text
    return client_id, response.json()


def call_whoami(env: Env, access_token: str | None) -> httpx.Response:
    headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"}
    if access_token is not None:
        headers["Authorization"] = f"Bearer {access_token}"
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "whoami", "arguments": {}}}
    return env.client.post("/mcp", json=body, headers=headers)


def verify(env: Env, token: str):
    return asyncio.run(env.oauth.token_verifier.verify_token(token))


def advance_clock(env: Env, seconds: float) -> None:
    """Moves the authorization server's clock forward (tokens keep their absolute expiry times)."""
    env.oauth.provider._clock = lambda: time.time() + seconds


def grant_rows(env: Env) -> list[tuple]:
    with env.db() as conn:
        return conn.execute("SELECT login, revoked_at, revoked_reason, api_key_enc IS NULL FROM grants").fetchall()


def error_banner(html: str) -> str:
    match = re.search(r'<div class="error" role="alert">(.*?)</div>', html, re.S)
    assert match, "expected an error banner"
    return match.group(1)


# ---------------------------------------------------------------------------------- metadata


def test_authorization_server_metadata(env: Env):
    response = env.client.get("/.well-known/oauth-authorization-server")
    assert response.status_code == 200
    meta = response.json()
    assert meta["issuer"] == PUBLIC
    assert meta["authorization_endpoint"] == f"{PUBLIC}/authorize"
    assert meta["token_endpoint"] == f"{PUBLIC}/token"
    assert meta["registration_endpoint"] == f"{PUBLIC}/register"
    assert meta["revocation_endpoint"] == f"{PUBLIC}/revoke"
    assert meta["client_id_metadata_document_supported"] is True
    assert {"none", "client_secret_post", "client_secret_basic"} <= set(meta["token_endpoint_auth_methods_supported"])
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert meta["response_types_supported"] == ["code"]
    assert meta["grant_types_supported"] == ["authorization_code", "refresh_token"]
    assert meta["scopes_supported"] == ["odoo"]
    assert response.headers["access-control-allow-origin"] == "*"

    preflight = env.client.options("/.well-known/oauth-authorization-server")
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == "*"


def test_protected_resource_metadata_served_at_both_paths(env: Env):
    suffixed = env.client.get("/.well-known/oauth-protected-resource/mcp")
    root = env.client.get("/.well-known/oauth-protected-resource")
    assert suffixed.status_code == root.status_code == 200
    assert root.json() == suffixed.json()
    assert root.json()["resource"] == RESOURCE
    assert root.json()["authorization_servers"] == [PUBLIC]
    assert root.json()["scopes_supported"] == ["odoo"]


def test_unauthenticated_mcp_request_is_challenged(env: Env):
    for token in (None, "not-a-real-token"):
        response = call_whoami(env, token)
        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        assert challenge.startswith("Bearer ")
        assert f'resource_metadata="{PUBLIC}/.well-known/oauth-protected-resource/mcp"' in challenge


# ---------------------------------------------------------------------------------- registration (DCR)


def test_dcr_accepts_claude_callback(env: Env):
    response = register(env)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["redirect_uris"] == [CLAUDE_CALLBACK]
    assert body["scope"] == "odoo"
    assert body["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in body


def test_dcr_rejects_redirects_outside_the_allowlist(env: Env):
    for uris in (
        ["https://evil.com/callback"],
        [CLAUDE_CALLBACK, "https://evil.com/callback"],
        ["https://claude.ai.evil.com/api/mcp/auth_callback"],
        ["http://localhost.evil.com:8080/callback"],
        ["http://evil.com@localhost:8080/callback"],
        ["https://claude.ai/api/mcp/auth_callback#frag"],
    ):
        response = register(env, redirect_uris=uris)
        assert response.status_code == 400, uris
        assert response.json()["error"] == "invalid_redirect_uri"
    with env.db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 0


def test_dcr_accepts_loopback_on_any_port(env: Env):
    for uri in ("http://localhost:4567/callback", "http://127.0.0.1:9/cb", "http://localhost/callback"):
        assert register(env, redirect_uris=[uri]).status_code == 201, uri


def test_dcr_confidential_client_secret_is_required_and_encrypted(env: Env):
    response = register(env, token_endpoint_auth_method="client_secret_post")
    assert response.status_code == 201
    client_id, client_secret = response.json()["client_id"], response.json()["client_secret"]
    code, verifier = sign_in(env, client_id)

    assert exchange(env, client_id, code, verifier, client_secret="wrong").status_code == 401
    ok = exchange(env, client_id, code, verifier, client_secret=client_secret)
    assert ok.status_code == 200, ok.text
    raw = b"".join(p.read_bytes() for p in env.data_dir.iterdir())
    assert client_secret.encode() not in raw


# ---------------------------------------------------------------------------------- happy path


def test_full_flow_issues_tokens_bound_to_the_odoo_user(env: Env):
    client_id, tokens = connect(env)
    assert tokens["token_type"] == "Bearer"
    assert tokens["expires_in"] == 3600
    assert tokens["scope"] == "odoo"
    assert tokens["refresh_token"]

    access = verify(env, tokens["access_token"])
    assert access is not None
    assert access.client_id == client_id
    assert access.scopes == ["odoo"]
    assert access.resource == RESOURCE
    assert access.subject == "7"
    assert access.claims["login"] == "priya@sahajta.ai"
    assert access.claims["iss"] == PUBLIC
    assert access.claims["grant_id"]
    assert access.expires_at and access.expires_at > time.time() + 3500

    creds = env.oauth.credentials_for(access)
    assert (creds.url, creds.db, creds.login, creds.api_key) == (ODOO, "sahajta", "priya@sahajta.ai", PRIYA_KEY)

    # And through the real MCP endpoint, the tool sees the same person.
    response = call_whoami(env, tokens["access_token"])
    assert response.status_code == 200, response.text
    assert response.json()["result"]["content"][0]["text"] == f"priya@sahajta.ai|sahajta|{ODOO}|7"


def test_login_page_content_and_security_headers(env: Env):
    client_id = register_client_id(env, client_name='<script>alert("x")</script>')
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)
    page, headers = form.html, form.response.headers

    assert "<title>Connect Claude to Sahajta Odoo</title>" in page
    assert "<script>" not in page
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in page
    assert "name not verified" in page
    assert "claude.ai" in page  # where the person will be sent back to
    assert "it can never delete records" in page
    assert "Account Security" in page and "New API Key" in page
    assert re.search(r'<input id="api_key" name="api_key" type="password"[^>]*autocomplete="off"', page)
    assert ODOO.removeprefix("https://") in page

    csp = headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "style-src 'unsafe-inline'" in csp
    assert "form-action 'self' https://claude.ai;" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    cookie = headers["set-cookie"].lower()
    assert cookie.startswith("__host-sahajta-oauth=")
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie and "path=/" in cookie


def test_cancel_link_returns_access_denied_to_the_client(env: Env):
    client_id = register_client_id(env)
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge, state="s-9")
    href = re.search(r'<a class="cancel" href="([^"]+)"', form.html).group(1).replace("&amp;", "&")  # type: ignore[union-attr]
    assert href.startswith(CLAUDE_CALLBACK + "?")
    query = parse_qs(urlsplit(href).query)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["s-9"]


# ---------------------------------------------------------------------------------- code exchange


def test_wrong_pkce_verifier_is_rejected(env: Env):
    client_id = register_client_id(env)
    code, _ = sign_in(env, client_id)
    wrong_verifier, _ = pkce()
    response = exchange(env, client_id, code, wrong_verifier)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_code_reuse_fails_and_revokes_the_grant(env: Env):
    client_id = register_client_id(env)
    code, verifier = sign_in(env, client_id)
    first = exchange(env, client_id, code, verifier)
    assert first.status_code == 200
    second = exchange(env, client_id, code, verifier)
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"
    # RFC 6749 4.1.2: tokens issued from a replayed code are revoked.
    assert call_whoami(env, first.json()["access_token"]).status_code == 401
    assert refresh(env, client_id, first.json()["refresh_token"]).status_code == 400
    assert env.signouts == [("priya@sahajta.ai", "authorization code reused")]


def test_expired_code_is_rejected(env: Env):
    client_id = register_client_id(env)
    code, verifier = sign_in(env, client_id)
    with env.db() as conn:
        conn.execute("UPDATE auth_codes SET expires_at = ?", (time.time() - 1,))
    response = exchange(env, client_id, code, verifier)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_code_cannot_be_redeemed_by_another_client(env: Env):
    client_id = register_client_id(env)
    other_client = register_client_id(env)
    code, verifier = sign_in(env, client_id)
    response = exchange(env, other_client, code, verifier)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_redirect_uri_must_match_at_token_exchange(env: Env):
    client_id = register_client_id(env, redirect_uris=[CLAUDE_CALLBACK, "https://claude.com/api/mcp/auth_callback"])
    code, verifier = sign_in(env, client_id)
    response = exchange(env, client_id, code, verifier, redirect_uri="https://claude.com/api/mcp/auth_callback")
    assert response.status_code == 400


# ---------------------------------------------------------------------------------- sign-in form


def test_csrf_token_mismatch_is_rejected(env: Env):
    client_id = register_client_id(env)
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)

    assert submit(env, form, csrf="forged" + form.csrf[6:]).status_code == 403
    # A valid token without the browser cookie it was issued with (a cross-site forged post).
    cookies = dict(env.client.cookies)
    env.client.cookies.clear()
    assert submit(env, form).status_code == 403
    assert env.odoo.context_get.call_count == 0
    for name, value in cookies.items():
        env.client.cookies.set(name, value)
    code_from(submit(env, form), CLAUDE_CALLBACK)


def test_wrong_key_rerenders_the_form_with_a_generic_error(env: Env):
    client_id = register_client_id(env)
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)

    wrong_key = submit(env, form, "priya@sahajta.ai", UNKNOWN_KEY)
    unknown_login = submit(env, form, "nobody@sahajta.ai", UNKNOWN_KEY)
    for response in (wrong_key, unknown_login):
        assert response.status_code == 400
        assert error_banner(response.text) == GENERIC_FAILURE
        assert UNKNOWN_KEY not in response.text
        assert response.headers["cache-control"] == "no-store"
    assert 'value="priya@sahajta.ai"' in wrong_key.text
    # The form keeps working after a failure.
    code_from(submit(env, form), CLAUDE_CALLBACK)


def test_key_belonging_to_another_login_is_rejected(env: Env):
    client_id = register_client_id(env)
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)
    response = submit(env, form, "priya@sahajta.ai", RAVI_KEY)
    assert response.status_code == 400
    assert error_banner(response.text) == GENERIC_FAILURE
    assert grant_rows(env) == []


def test_portal_user_is_rejected(env: Env):
    client_id = register_client_id(env)
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)
    response = submit(env, form, "customer@example.com", PORTAL_KEY)
    assert response.status_code == 400
    assert error_banner(response.text) == PORTAL_FAILURE.replace("'", "&#x27;")
    assert grant_rows(env) == []


def test_login_domain_allowlist(make_env: Callable[..., Env]):
    env = make_env(mcp_allowed_login_domains=["sahajta.ai"])
    client_id = register_client_id(env)
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)

    response = submit(env, form, "customer@example.com", PORTAL_KEY)
    assert response.status_code == 400
    assert "@sahajta.ai" in error_banner(response.text)
    assert env.odoo.context_get.call_count == 0  # refused before contacting Odoo
    code_from(submit(env, form), CLAUDE_CALLBACK)


def test_odoo_outage_during_sign_in_is_not_counted_as_a_failure(env: Env):
    client_id = register_client_id(env)
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)
    env.odoo.down = True
    for _ in range(6):
        response = submit(env, form)
        assert response.status_code == 503
        assert "couldn" in error_banner(response.text)
    env.odoo.down = False
    code_from(submit(env, form), CLAUDE_CALLBACK)


def test_five_failures_end_the_sign_in(env: Env):
    client_id = register_client_id(env)
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)
    for _ in range(4):
        assert submit(env, form, api_key=UNKNOWN_KEY).status_code == 400
    final = submit(env, form, api_key=UNKNOWN_KEY)
    assert final.status_code == 429
    assert "Too many failed attempts" in final.text
    # The request is gone, even with the right key.
    assert submit(env, form).status_code == 400
    assert "expired" in env.client.get(f"/oauth/login?request={form.request_id}").text


def test_failures_are_rate_limited_per_ip(env: Env):
    client_id = register_client_id(env)
    for _ in range(4):  # 4 sign-ins x 5 failures = 20 failures from this IP
        _, challenge = pkce()
        form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)
        for _ in range(5):
            submit(env, form, api_key=UNKNOWN_KEY)
    calls_before = env.odoo.context_get.call_count
    _, challenge = pkce()
    form = start_login(env, client_id, CLAUDE_CALLBACK, challenge)
    response = submit(env, form)  # correct credentials, but this IP is cooling down
    assert response.status_code == 429
    assert error_banner(response.text) == IP_LIMITED
    assert env.odoo.context_get.call_count == calls_before


def test_unknown_or_expired_sign_in_request(env: Env):
    response = env.client.get("/oauth/login?request=" + "x" * 43)
    assert response.status_code == 400
    assert "expired" in response.text
    assert response.headers["x-frame-options"] == "DENY"


# ---------------------------------------------------------------------------------- resource indicators


def test_resource_mismatch_is_rejected(env: Env):
    client_id = register_client_id(env)
    _, challenge = pkce()
    response = authorize(env, client_id, CLAUDE_CALLBACK, challenge, resource="https://other.example.com/mcp")
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert response.headers["location"].startswith(CLAUDE_CALLBACK)
    assert query["error"] == ["invalid_target"]
    assert query["state"] == ["state-123"]

    for equivalent in ("https://MCP.example.com/mcp/", "https://mcp.example.com:443/mcp"):
        ok = authorize(env, client_id, CLAUDE_CALLBACK, challenge, resource=equivalent)
        assert ok.headers["location"].startswith(f"{PUBLIC}/oauth/login?"), equivalent


# ---------------------------------------------------------------------------------- refresh and revocation


def test_refresh_rotates_and_replay_revokes_the_grant(env: Env):
    client_id, first = connect(env)
    rotated = refresh(env, client_id, first["refresh_token"])
    assert rotated.status_code == 200, rotated.text
    second = rotated.json()
    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"] != first["access_token"]
    assert call_whoami(env, second["access_token"]).status_code == 200

    advance_clock(env, REFRESH_REUSE_GRACE_SECONDS + 1)
    replay = refresh(env, client_id, first["refresh_token"])
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    # The whole grant is gone: the newest tokens stop working too.
    assert call_whoami(env, second["access_token"]).status_code == 401
    assert refresh(env, client_id, second["refresh_token"]).status_code == 400
    [(login, revoked_at, reason, key_wiped)] = grant_rows(env)
    assert revoked_at is not None and reason == "refresh token reused" and key_wiped
    assert env.signouts == [("priya@sahajta.ai", "refresh token reused")]


def test_refresh_token_reused_within_the_grace_window_gets_new_tokens(env: Env, caplog: pytest.LogCaptureFixture):
    """A retry after a lost response must not sign the person out."""
    client_id, first = connect(env)
    second = refresh(env, client_id, first["refresh_token"]).json()
    advance_clock(env, REFRESH_REUSE_GRACE_SECONDS - 5)
    with caplog.at_level(logging.INFO, logger="sahajta_odoo_mcp.oauth.provider"):
        retry = refresh(env, client_id, first["refresh_token"])
    assert retry.status_code == 200, retry.text
    third = retry.json()
    assert third["refresh_token"] not in (first["refresh_token"], second["refresh_token"])
    assert any(r.levelno == logging.INFO and "used again within" in r.getMessage() for r in caplog.records)
    for tokens in (second, third):  # nothing was revoked: both new pairs work
        assert call_whoami(env, tokens["access_token"]).status_code == 200
    assert refresh(env, client_id, third["refresh_token"]).status_code == 200
    [(_, revoked_at, _, _)] = grant_rows(env)
    assert revoked_at is None and env.signouts == []
    for secret in (first["refresh_token"], third["access_token"], third["refresh_token"]):
        assert not any(secret in r.getMessage() for r in caplog.records)


def test_parallel_refreshes_with_the_same_token_both_succeed(env: Env):
    """Two requests that both loaded the token before either rotated it (the race inside the store)."""
    client_id, tokens = connect(env)
    provider = env.oauth.provider

    async def race():
        client = await provider.get_client(client_id)
        loaded = [await provider.load_refresh_token(client, tokens["refresh_token"]) for _ in range(2)]
        return await asyncio.gather(*(provider.exchange_refresh_token(client, token, ["odoo"]) for token in loaded))

    first, second = asyncio.run(race())
    assert first.refresh_token != second.refresh_token
    for result in (first, second):
        assert call_whoami(env, result.access_token).status_code == 200
    [(_, revoked_at, _, _)] = grant_rows(env)
    assert revoked_at is None and env.signouts == []


def test_refresh_revokes_the_grant_when_odoo_rejects_the_key(env: Env):
    client_id, tokens = connect(env)
    env.odoo.revoked_keys.add(PRIYA_KEY)
    response = refresh(env, client_id, tokens["refresh_token"])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert call_whoami(env, tokens["access_token"]).status_code == 401
    [(_, revoked_at, reason, key_wiped)] = grant_rows(env)
    assert revoked_at is not None and "Odoo rejected" in reason and key_wiped
    assert env.signouts == [("priya@sahajta.ai", "Odoo rejected the API key")]


def test_refresh_during_odoo_outage_is_temporary(env: Env):
    client_id, tokens = connect(env)
    env.odoo.down = True
    response = refresh(env, client_id, tokens["refresh_token"])
    assert response.status_code == 503
    assert response.json()["error"] == "temporarily_unavailable"
    assert response.headers["retry-after"]
    env.odoo.down = False
    # The same refresh token still works: nothing was rotated or revoked.
    assert refresh(env, client_id, tokens["refresh_token"]).status_code == 200
    assert env.signouts == []


def test_revocation_endpoint_revokes_the_grant(env: Env):
    client_id, tokens = connect(env)
    access = verify(env, tokens["access_token"])
    response = env.client.post("/revoke", data={"token": tokens["access_token"], "client_id": client_id})
    assert response.status_code == 200
    assert call_whoami(env, tokens["access_token"]).status_code == 401
    assert refresh(env, client_id, tokens["refresh_token"]).status_code == 400
    with pytest.raises(OdooError) as excinfo:
        env.oauth.credentials_for(access)
    assert excinfo.value.kind == "auth"
    assert env.signouts == [("priya@sahajta.ai", "revoked by the client")]


def test_revocation_with_refresh_token(env: Env):
    client_id, tokens = connect(env)
    response = env.client.post(
        "/revoke",
        data={"token": tokens["refresh_token"], "token_type_hint": "refresh_token", "client_id": client_id},
    )
    assert response.status_code == 200
    assert call_whoami(env, tokens["access_token"]).status_code == 401


def test_expired_access_token_is_rejected(env: Env):
    _, tokens = connect(env)
    with env.db() as conn:
        conn.execute("UPDATE tokens SET expires_at = ? WHERE kind = 'access'", (time.time() - 1,))
    assert verify(env, tokens["access_token"]) is None
    assert call_whoami(env, tokens["access_token"]).status_code == 401


def test_last_used_write_failure_does_not_fail_the_request(env: Env, monkeypatch: pytest.MonkeyPatch):
    _, tokens = connect(env)

    def store_down(*args, **kwargs):
        raise redis.ConnectionError("connection reset")

    monkeypatch.setattr(env.oauth.store, "touch_grant", store_down)
    assert verify(env, tokens["access_token"]) is not None
    assert call_whoami(env, tokens["access_token"]).status_code == 200


def test_setting_odoo_db_later_keeps_existing_sign_ins(make_env: Callable[..., Env]):
    """JSON-2 needs no database name; an operator adding ODOO_DB later must not sign everyone out."""
    env = make_env(odoo_db=None)
    client_id, tokens = connect(env)
    later = build_oauth(make_settings(env.data_dir.parent, odoo_db="sahajta"), httpx.AsyncClient())
    try:
        access = asyncio.run(later.token_verifier.verify_token(tokens["access_token"]))
        assert access is not None
        assert later.credentials_for(access).db is None  # the key goes where the person entered it

        async def refresh_on_the_new_settings():
            client = await later.provider.get_client(client_id)
            stored = await later.provider.load_refresh_token(client, tokens["refresh_token"])
            return await later.provider.exchange_refresh_token(client, stored, ["odoo"])

        assert asyncio.run(refresh_on_the_new_settings()).access_token
        [(_, revoked_at, _, _)] = grant_rows(env)
        assert revoked_at is None
    finally:
        asyncio.run(later.aclose())


def test_changing_the_odoo_url_still_refuses_existing_sign_ins(env: Env):
    _, tokens = connect(env)
    moved = build_oauth(make_settings(env.data_dir.parent, odoo_url="https://other-odoo.example.com"), httpx.AsyncClient())
    try:
        assert asyncio.run(moved.token_verifier.verify_token(tokens["access_token"])) is None
    finally:
        asyncio.run(moved.aclose())


def test_expired_grants_are_reported_as_sign_outs(env: Env):
    connect(env)
    env.oauth.provider.purge(time.time() + env.settings.mcp_refresh_token_ttl_seconds + 1)
    [(_, revoked_at, reason, key_wiped)] = grant_rows(env)
    assert revoked_at is not None and reason == "expired" and key_wiped
    assert env.signouts == [("priya@sahajta.ai", "expired")]


def test_start_up_purge_failure_does_not_stop_the_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    def store_down(self, now):
        raise redis.ConnectionError("connection reset")

    monkeypatch.setattr(OAuthStore, "purge", store_down)
    monkeypatch.setattr(RedisOAuthStore, "purge", store_down)
    with caplog.at_level(logging.ERROR, logger="sahajta_odoo_mcp.oauth.provider"):
        oauth = build_oauth(make_settings(tmp_path), httpx.AsyncClient())
    try:
        assert "Purging expired OAuth records failed" in caplog.text
        assert oauth.routes and oauth.token_verifier is not None
    finally:
        asyncio.run(oauth.aclose())


# ---------------------------------------------------------------------------------- CIMD


def mock_cimd(env: Env, doc: dict | None = None, url: str = CLAUDE_CODE_CIMD) -> respx.Route:
    return env.router.get(url).mock(return_value=httpx.Response(200, json=doc or CLAUDE_CODE_DOC))


def test_cimd_client_with_loopback_redirect_on_a_random_port(env: Env):
    route = mock_cimd(env)
    redirect_uri = "http://localhost:3118/callback"
    verifier, challenge = pkce()
    form = start_login(env, CLAUDE_CODE_CIMD, redirect_uri, challenge)
    assert "Claude Code" in form.html
    assert "verified by claude.ai" in form.html
    assert "an app on this computer (localhost:3118)" in form.html
    assert "form-action 'self' http://localhost:3118;" in form.response.headers["content-security-policy"]

    code = code_from(submit(env, form), redirect_uri)
    response = exchange(env, CLAUDE_CODE_CIMD, code, verifier, redirect_uri=redirect_uri)
    assert response.status_code == 200, response.text
    access = verify(env, response.json()["access_token"])
    assert access is not None and access.client_id == CLAUDE_CODE_CIMD
    assert route.call_count == 1  # cached across /authorize and /token


def test_cimd_loopback_matching_is_port_agnostic_only(env: Env):
    mock_cimd(env)
    _, challenge = pkce()
    for bad in ("http://localhost:3118/other", "http://evil.example:3118/callback", "https://localhost:3118/callback"):
        response = authorize(env, CLAUDE_CODE_CIMD, bad, challenge)
        assert response.status_code == 400, bad
        assert response.json()["error"] == "invalid_request"
    assert authorize(env, CLAUDE_CODE_CIMD, "http://127.0.0.1:50000/callback", challenge).status_code == 302


def test_cimd_is_never_fetched_from_other_hosts(env: Env):
    evil = env.router.get(url__regex=r"https://(?!claude\.ai/).*").mock(
        return_value=httpx.Response(200, json={"client_id": "x", "redirect_uris": [CLAUDE_CALLBACK]})
    )
    _, challenge = pkce()
    for client_id in (
        "https://evil.example/client.json",
        "https://claude.ai.evil.example/oauth/client",
        "https://claude.ai@evil.example/oauth/client",
        "https://claude.ai:8443/oauth/client",
        "http://claude.ai/oauth/claude-code-client-metadata",
        "https://claude.ai/../evil",
        "https://claude.ai/oauth/x?redirect=https://evil.example",
    ):
        response = authorize(env, client_id, CLAUDE_CALLBACK, challenge)
        assert response.status_code == 400, client_id
    assert not evil.called
    assert len(env.router.calls) == 0


def test_cimd_document_must_match_its_url_and_allowlist(env: Env):
    _, challenge = pkce()
    mismatched = "https://claude.ai/oauth/mismatched"
    mock_cimd(env, {**CLAUDE_CODE_DOC, "client_id": "https://claude.ai/oauth/other"}, url=mismatched)
    assert authorize(env, mismatched, "http://localhost:3118/callback", challenge).status_code == 400

    evil_redirects = "https://claude.ai/oauth/evil-redirects"
    mock_cimd(env, {**CLAUDE_CODE_DOC, "client_id": evil_redirects, "redirect_uris": ["https://evil.example/cb"]}, url=evil_redirects)
    assert authorize(env, evil_redirects, "https://evil.example/cb", challenge).status_code == 400

    with_secret = "https://claude.ai/oauth/with-secret"
    mock_cimd(env, {**CLAUDE_CODE_DOC, "client_id": with_secret, "client_secret": "s"}, url=with_secret)
    assert authorize(env, with_secret, "http://localhost:3118/callback", challenge).status_code == 400

    not_json = "https://claude.ai/oauth/not-json"
    env.router.get(not_json).mock(return_value=httpx.Response(200, text="<html></html>"))
    assert authorize(env, not_json, "http://localhost:3118/callback", challenge).status_code == 400

    redirected = "https://claude.ai/oauth/redirected"
    env.router.get(redirected).mock(return_value=httpx.Response(302, headers={"Location": "https://evil.example/doc"}))
    assert authorize(env, redirected, "http://localhost:3118/callback", challenge).status_code == 400

    too_big = "https://claude.ai/oauth/too-big"
    mock_cimd(env, {**CLAUDE_CODE_DOC, "client_id": too_big, "padding": "x" * 70_000}, url=too_big)
    assert authorize(env, too_big, "http://localhost:3118/callback", challenge).status_code == 400


# ---------------------------------------------------------------------------------- storage


def test_secrets_never_stored_in_plaintext(env: Env):
    client_id, tokens = connect(env)
    rotated = refresh(env, client_id, tokens["refresh_token"]).json()
    raw = b"".join(p.read_bytes() for p in env.data_dir.iterdir() if p.is_file())
    for secret in (PRIYA_KEY, tokens["access_token"], tokens["refresh_token"], rotated["access_token"], rotated["refresh_token"]):
        assert secret.encode() not in raw
    assert b"priya@sahajta.ai" in raw  # sanity check: the file really holds the grant


def test_data_files_are_private(env: Env):
    connect(env)
    assert stat.S_IMODE(env.data_dir.stat().st_mode) == 0o700
    for path in env.data_dir.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path


def test_schema_version_is_recorded(env: Env):
    with env.db() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_changing_the_secret_invalidates_stored_credentials(env: Env, make_env: Callable[..., Env]):
    _, tokens = connect(env)
    access = verify(env, tokens["access_token"])
    other = build_oauth(make_settings(env.data_dir.parent, mcp_secret="another-secret-" + "z" * 30), httpx.AsyncClient())
    try:
        with pytest.raises(OdooError) as excinfo:
            other.credentials_for(access)
        assert excinfo.value.kind == "auth"
        assert PRIYA_KEY not in str(excinfo.value)
    finally:
        asyncio.run(other.aclose())


# ---------------------------------------------------------------------------------- admin CLI


def test_admin_cli_lists_and_revokes(env: Env, capsys: pytest.CaptureFixture[str]):
    _, tokens = connect(env)

    assert admin_main(["list"], settings=env.settings) == 0
    listing = capsys.readouterr().out
    assert "priya@sahajta.ai" in listing and "Priya" in listing and "Claude" in listing
    assert PRIYA_KEY not in listing and tokens["access_token"] not in listing

    assert admin_main(["revoke-all"], settings=env.settings) == 1  # needs --yes
    capsys.readouterr()
    assert call_whoami(env, tokens["access_token"]).status_code == 200

    assert admin_main(["revoke", "--login", "PRIYA@sahajta.ai"], settings=env.settings) == 0
    assert "Revoked 1" in capsys.readouterr().out
    assert call_whoami(env, tokens["access_token"]).status_code == 401

    assert admin_main(["list"], settings=env.settings) == 0
    assert "No active connections" in capsys.readouterr().out
    assert admin_main(["list", "--all"], settings=env.settings) == 0
    assert "revoked by an administrator" in capsys.readouterr().out


def test_admin_cli_revoke_by_grant_and_all(env: Env, capsys: pytest.CaptureFixture[str]):
    _, first = connect(env)
    _, second = connect(env)
    grant_id = verify(env, first["access_token"]).claims["grant_id"]
    assert admin_main(["revoke", "--grant", grant_id], settings=env.settings) == 0
    assert call_whoami(env, first["access_token"]).status_code == 401
    assert call_whoami(env, second["access_token"]).status_code == 200
    assert admin_main(["revoke-all", "--yes"], settings=env.settings) == 0
    assert "Revoked 1" in capsys.readouterr().out
    assert call_whoami(env, second["access_token"]).status_code == 401


# ---------------------------------------------------------------------------------- abuse limits


def test_oversized_bodies_are_refused(env: Env):
    huge = "x" * (70 * 1024)
    assert env.client.post("/token", data={"grant_type": "authorization_code", "code": huge}).status_code == 413
    assert env.client.post("/revoke", data={"token": huge, "client_id": "c"}).status_code == 413
    assert env.client.post("/oauth/login", data={"request": "r", "api_key": "y" * 20_000}).status_code == 413
    body = b'{"redirect_uris": ["' + b"a" * 70_000 + b'"]}'
    assert env.client.post("/register", content=body, headers={"content-type": "application/json"}).status_code == 413


def test_confidential_client_must_authenticate_to_revoke(env: Env):
    registered = register(env, token_endpoint_auth_method="client_secret_post").json()
    client_id, client_secret = registered["client_id"], registered["client_secret"]
    code, verifier = sign_in(env, client_id)
    tokens = exchange(env, client_id, code, verifier, client_secret=client_secret).json()

    assert env.client.post("/revoke", data={"token": tokens["access_token"], "client_id": client_id}).status_code == 401
    assert call_whoami(env, tokens["access_token"]).status_code == 200
    ok = env.client.post(
        "/revoke", data={"token": tokens["access_token"], "client_id": client_id, "client_secret": client_secret}
    )
    assert ok.status_code == 200
    assert call_whoami(env, tokens["access_token"]).status_code == 401


def test_another_clients_token_cannot_be_revoked(env: Env):
    _, tokens = connect(env)
    stranger = register_client_id(env)
    assert env.client.post("/revoke", data={"token": tokens["access_token"], "client_id": stranger}).status_code == 200
    assert call_whoami(env, tokens["access_token"]).status_code == 200
