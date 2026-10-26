"""Unit tests for the OAuth building blocks: redirect rules, CIMD URL rules, crypto, limits, storage."""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from pydantic import AnyUrl
from starlette.requests import Request

from mcp.shared.auth import InvalidRedirectUriError
from sahajta_odoo_mcp.config import DEFAULT_REDIRECT_URIS, Settings
from sahajta_odoo_mcp.oauth import public_base_url
from sahajta_odoo_mcp.oauth.cimd import CIMDResolver
from sahajta_odoo_mcp.oauth.clients import OdooOAuthClient, is_redirect_allowed, redirect_uri_matches
from sahajta_odoo_mcp.oauth.crypto import CsrfSigner, DecryptionError, Sealer, hash_token
from sahajta_odoo_mcp.oauth.limits import SlidingWindow, client_ip
from sahajta_odoo_mcp.oauth.login_page import _csp_origin
from sahajta_odoo_mcp.oauth.provider import OdooAuthProvider, normalise_url
from sahajta_odoo_mcp.oauth.store import REFRESH_REUSE_GRACE_SECONDS, Grant, NewTokens, OAuthStore, PendingAuthorization

SECRET = "unit-test-secret-" + "q" * 23


# ---------------------------------------------------------------------------------- redirect rules


@pytest.mark.parametrize(
    ("uri", "allowed"),
    [
        ("https://claude.ai/api/mcp/auth_callback", True),
        ("https://claude.com/api/mcp/auth_callback", True),
        ("https://CLAUDE.ai/api/mcp/auth_callback", True),
        ("https://claude.ai/api/mcp/auth_callback/", False),
        ("https://claude.ai/api/mcp/other", False),
        ("https://claude.ai/api/mcp/auth_callback?x=1", False),
        ("http://claude.ai/api/mcp/auth_callback", False),
        ("https://claude.ai:8443/api/mcp/auth_callback", False),
        ("http://localhost:3118/callback", True),
        ("http://localhost/callback", True),
        ("http://127.0.0.1:65535/anything/at/all", True),
        ("https://localhost:3118/callback", False),
        ("http://localhost.evil.com/callback", False),
        ("http://evil.com@localhost:3000/cb", False),
        ("http://localhost:3000@evil.com/cb", False),
        ("http://localhost:99999/cb", False),
        ("http://localhost:3000/cb#frag", False),
        ("http://localhost:3000/c b", False),
        ("javascript:alert(1)", False),
        ("", False),
    ],
)
def test_redirect_allowlist(uri: str, allowed: bool):
    assert is_redirect_allowed(uri, DEFAULT_REDIRECT_URIS) is allowed


def test_wildcard_pattern_with_a_path():
    assert is_redirect_allowed("http://localhost:4000/callback", ["http://localhost:*/callback"])
    assert not is_redirect_allowed("http://localhost:4000/other", ["http://localhost:*/callback"])


@pytest.mark.parametrize(
    ("registered", "requested", "matches"),
    [
        ("http://localhost/callback", "http://localhost:3118/callback", True),
        ("http://127.0.0.1/callback", "http://127.0.0.1:50000/callback", True),
        ("http://localhost:1234/callback", "http://localhost:5678/callback", True),
        ("http://localhost/callback", "http://127.0.0.1:3118/callback", False),
        ("http://localhost/callback", "http://localhost:3118/callback2", False),
        ("http://localhost/callback", "http://localhost:3118/callback?x=1", False),
        ("http://localhost/callback", "https://localhost:3118/callback", False),
        ("https://claude.ai/api/mcp/auth_callback", "https://claude.ai:444/api/mcp/auth_callback", False),
        ("https://claude.ai/api/mcp/auth_callback", "https://claude.ai/api/mcp/auth_callback", True),
        ("https://app.example/cb", "https://app.example:8443/cb", False),
    ],
)
def test_loopback_port_is_ignored_only_for_loopback(registered: str, requested: str, matches: bool):
    assert redirect_uri_matches(registered, requested) is matches


def test_client_enforces_registration_and_allowlist():
    client = OdooOAuthClient.build(
        {"client_id": "c", "redirect_uris": ["http://localhost/callback", "https://app.example/cb"]},
        allowed_redirects=DEFAULT_REDIRECT_URIS,
    )
    assert str(client.validate_redirect_uri(AnyUrl("http://localhost:3118/callback"))) == "http://localhost:3118/callback"
    with pytest.raises(InvalidRedirectUriError):
        client.validate_redirect_uri(AnyUrl("http://localhost:3118/nope"))
    with pytest.raises(InvalidRedirectUriError):  # registered, but not on the server's allowlist
        client.validate_redirect_uri(AnyUrl("https://app.example/cb"))
    with pytest.raises(InvalidRedirectUriError):  # two registered: must say which
        client.validate_redirect_uri(None)
    assert client.validate_scope("odoo offline_access openid") == ["odoo"]
    assert client.validate_scope(None) == ["odoo"]


# ---------------------------------------------------------------------------------- CIMD URLs


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://claude.ai/oauth/claude-code-client-metadata", True),
        ("https://claude.com/oauth/mcp-client.json", True),
        ("https://claude.ai", False),
        ("https://claude.ai/", False),
        ("https://Claude.ai/oauth/x", False),
        ("http://claude.ai/oauth/x", False),
        ("https://claude.ai:443/oauth/x", False),
        ("https://claude.ai.evil.example/oauth/x", False),
        ("https://evil.example/claude.ai/oauth/x", False),
        ("https://user@claude.ai/oauth/x", False),
        ("https://claude.ai/oauth/x?y=1", False),
        ("https://claude.ai/oauth/x#y", False),
        ("https://claude.ai/oauth/../x", False),
        ("https://claude.ai/oauth/%2e%2e/x", False),
        ("https://claude.ai/oauth\\x", False),
        (" https://claude.ai/oauth/x", False),
    ],
)
def test_cimd_url_rules(url: str, allowed: bool):
    resolver = CIMDResolver(httpx.AsyncClient(), ["claude.ai", "claude.com"], DEFAULT_REDIRECT_URIS)
    assert resolver.is_allowed_url(url) is allowed


# ---------------------------------------------------------------------------------- crypto


def test_sealed_values_are_bound_to_their_context():
    sealer = Sealer(SECRET)
    token = sealer.seal("grant:a", "the-api-key")
    assert b"the-api-key" not in token
    assert sealer.open("grant:a", token) == "the-api-key"
    with pytest.raises(DecryptionError):
        sealer.open("grant:b", token)
    with pytest.raises(DecryptionError):
        Sealer(SECRET + "x").open("grant:a", token)
    with pytest.raises(DecryptionError):
        sealer.open("grant:a", b"garbage")


def test_short_secret_is_refused():
    with pytest.raises(ValueError):
        Sealer("too-short")


def test_csrf_tokens_bind_request_and_browser():
    signer = CsrfSigner(SECRET)
    token = signer.token("request-1", "nonce-a")
    assert signer.verify("request-1", "nonce-a", token)
    assert not signer.verify("request-2", "nonce-a", token)
    assert not signer.verify("request-1", "nonce-b", token)
    assert not signer.verify("request-1", "nonce-a", token + "x")
    assert not signer.verify("request-1", "nonce-a", "é")


# ---------------------------------------------------------------------------------- URLs and headers


def test_normalise_url():
    assert normalise_url("https://MCP.example.com:443/mcp/") == "https://mcp.example.com/mcp"
    assert normalise_url("https://mcp.example.com:8443/mcp") == "https://mcp.example.com:8443/mcp"
    assert normalise_url("https://mcp.example.com/mcp#x") is None
    assert normalise_url("https://u:p@mcp.example.com/mcp") is None


def _settings(tmp_path: Path, **overrides) -> Settings:
    values = {"odoo_url": "https://odoo.example.com", "mcp_secret": SECRET, "mcp_data_dir": str(tmp_path)}
    return Settings(_env_file=None, **(values | overrides))


def test_public_base_url_validation(tmp_path: Path):
    assert public_base_url(_settings(tmp_path, mcp_public_url="https://MCP.example.com/")) == "https://mcp.example.com"
    assert public_base_url(_settings(tmp_path, mcp_public_url="http://localhost:8000")) == "http://localhost:8000"
    for bad in (None, "", "http://mcp.example.com", "https://mcp.example.com/sub", "https://mcp.example.com/?a=1"):
        with pytest.raises(ValueError):
            public_base_url(_settings(tmp_path, mcp_public_url=bad))


def test_csp_origin():
    assert _csp_origin("https://claude.ai/api/mcp/auth_callback") == "https://claude.ai"
    assert _csp_origin("http://localhost:3118/callback") == "http://localhost:3118"
    assert _csp_origin("http://[::1]:3118/callback") == "http://[::1]:3118"
    assert _csp_origin("cursor://callback") == "cursor:"
    assert _csp_origin("https://claude.ai;script-src *") is None


# ---------------------------------------------------------------------------------- limits


def test_sliding_window():
    now = [1000.0]
    window = SlidingWindow(3, 60, clock=lambda: now[0])
    assert all(window.allow("ip") for _ in range(3))
    assert not window.allow("ip")
    assert window.exceeded("ip")
    assert window.allow("other-ip")
    now[0] += 61
    assert not window.exceeded("ip")


def test_sliding_window_memory_is_bounded():
    window = SlidingWindow(1, 60, max_keys=10)
    for i in range(100):
        window.add(str(i))
    assert len(window._events) == 10


def _request(headers: dict[str, str], peer: str = "10.0.0.5") -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": (peer, 1234),
    }
    return Request(scope)


def test_client_ip_only_trusts_forwarded_for_when_configured():
    request = _request({"X-Forwarded-For": "1.2.3.4, 203.0.113.9"})
    assert client_ip(request, trust_proxy_headers=False) == "10.0.0.5"
    assert client_ip(request, trust_proxy_headers=True) == "203.0.113.9"
    assert client_ip(_request({}), trust_proxy_headers=True) == "10.0.0.5"


# ---------------------------------------------------------------------------------- storage


def _grant(now: float, grant_id: str = "g1") -> Grant:
    return Grant(
        grant_id=grant_id,
        client_id="c",
        client_name="Claude",
        odoo_uid=7,
        login="priya@sahajta.ai",
        display_name="Priya",
        odoo_url="https://odoo.example.com",
        odoo_db="sahajta",
        api_key_enc=b"ciphertext",
        scopes="odoo",
        resource="https://mcp.example.com/mcp",
        created_at=now,
        last_used_at=now,
        revoked_at=None,
        revoked_reason=None,
    )


def _pending(now: float, id_hash: str = "p1") -> PendingAuthorization:
    return PendingAuthorization(
        id_hash=id_hash,
        client_id="c",
        client_name="Claude",
        verified_host=None,
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        redirect_uri_explicit=True,
        state="s",
        scopes="odoo",
        code_challenge="x" * 43,
        resource="https://mcp.example.com/mcp",
        failures=0,
        created_at=now,
        expires_at=now + 600,
    )


def test_store_lifecycle_and_purge(tmp_path: Path):
    store = OAuthStore(tmp_path / "db" / "oauth.sqlite3")
    try:
        now = time.time()
        store.insert_pending(_pending(now))
        assert store.create_grant_with_code(pending_id_hash="p1", grant=_grant(now), code_hash="c1", code_expires_at=now + 300)
        # A double-submitted form cannot mint a second grant.
        assert not store.create_grant_with_code(
            pending_id_hash="p1", grant=_grant(now, "g2"), code_hash="c2", code_expires_at=now + 300
        )
        tokens = NewTokens(hash_token("a"), now + 3600, hash_token("r"), now + 7200)
        assert store.consume_code("c1", now, tokens).value == "ok"

        # Nothing is purged while tokens are alive.
        assert store.purge(now + 100) == []
        assert store.get_grant("g1").active  # type: ignore[union-attr]

        # Once every token has expired the grant is dead: its key is wiped.
        assert store.purge(now + 7201) == ["g1"]
        grant = store.get_grant("g1")
        assert grant is not None and not grant.active and grant.api_key_enc is None
        assert grant.revoked_reason == "expired"
        assert store.get_token(hash_token("r"), "refresh") is None

        # Revoked grants are kept for a while for the audit trail, then deleted.
        store.purge(now + 91 * 24 * 3600)
        assert store.get_grant("g1") is None
    finally:
        store.close()


def test_store_refresh_rotation_grace_and_replay(tmp_path: Path):
    store = OAuthStore(tmp_path / "oauth.sqlite3")
    try:
        now = time.time()
        store.insert_pending(_pending(now))
        store.create_grant_with_code(pending_id_hash="p1", grant=_grant(now), code_hash="c1", code_expires_at=now + 300)
        store.consume_code("c1", now, NewTokens("a1", now + 3600, "r1", now + 7200))
        assert store.rotate_refresh_token("r1", now, NewTokens("a2", now + 3600, "r2", now + 7200)).value == "ok"
        # Used again soon after (a retry, or two refreshes racing): a new pair, nothing revoked.
        assert store.rotate_refresh_token("r1", now + 60, NewTokens("a3", now + 3600, "r3", now + 7200)).value == "reused"
        assert store.get_token("r2", "refresh") is not None and store.get_token("r3", "refresh") is not None
        assert store.get_grant("g1").active  # type: ignore[union-attr]
        # The window counts from the rotation, not from the last reuse; after it, reuse kills the grant.
        late = now + REFRESH_REUSE_GRACE_SECONDS + 1
        assert store.rotate_refresh_token("r1", late, NewTokens("a4", now + 3600, "r4", now + 7200)).value == "replayed"
        assert store.get_token("r2", "refresh") is None and not store.get_grant("g1").active  # type: ignore[union-attr]
    finally:
        store.close()


@pytest.mark.parametrize(
    ("grant_url", "grant_db", "protocol", "settings_db", "same"),
    [
        ("https://odoo.example.com", None, "json2", "sahajta", True),  # ODOO_DB added later
        ("https://odoo.example.com", "sahajta", "json2", None, True),
        ("https://odoo.example.com", "old", "auto", "new", True),
        ("https://odoo.example.com", None, "jsonrpc", "sahajta", True),
        ("https://odoo.example.com", "sahajta", "jsonrpc", "sahajta", True),
        ("https://odoo.example.com", "old", "jsonrpc", "new", False),
        ("https://other.example.com", "sahajta", "json2", "sahajta", False),
        ("https://other.example.com", None, "jsonrpc", None, False),
    ],
)
def test_same_odoo(tmp_path: Path, grant_url: str, grant_db: str | None, protocol: str, settings_db: str | None, same: bool):
    settings = _settings(tmp_path, odoo_db=settings_db, odoo_protocol=protocol)
    provider = OdooAuthProvider(settings, httpx.AsyncClient(), None, Sealer(SECRET), public_url="https://mcp.example.com")  # type: ignore[arg-type]
    grant = replace(_grant(time.time()), odoo_url=grant_url, odoo_db=grant_db)
    assert provider._same_odoo(grant) is same


def test_store_purges_expired_pending_requests(tmp_path: Path):
    store = OAuthStore(tmp_path / "oauth.sqlite3")
    try:
        now = time.time()
        store.insert_pending(_pending(now))
        assert store.get_pending("p1", now) is not None
        assert store.get_pending("p1", now + 601) is None
        store.purge(now + 601)
        assert store.count_pending(now) == 0
    finally:
        store.close()


def test_store_refuses_newer_schema(tmp_path: Path):
    path = tmp_path / "oauth.sqlite3"
    OAuthStore(path).close()
    import sqlite3

    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA user_version = 99")
    with pytest.raises(RuntimeError, match="newer version"):
        OAuthStore(path)

