"""When the company-wide connector (server.py) may end a person's sign-in, and that every sign-out is logged.

Odoo is mocked with respx (assert_all_mocked); nothing reaches a network host.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import httpx
import respx
from starlette.testclient import TestClient

from sahajta_odoo_mcp.config import Settings
from sahajta_odoo_mcp.oauth.provider import OdooAuthProvider
from sahajta_odoo_mcp.server import create_http_app
from test_oauth import ODOO, PRIYA_KEY, PUBLIC, SECRET, FakeOdoo, connect


@contextmanager
def running_app(tmp_path: Path) -> Iterator[SimpleNamespace]:
    settings = Settings(
        _env_file=None,
        odoo_url=ODOO,
        odoo_db="sahajta",
        odoo_protocol="json2",
        mcp_public_url=PUBLIC,
        mcp_secret=SECRET,
        mcp_data_dir=str(tmp_path / "data"),
        mcp_access_mode="read_only",
        mcp_redis_url=None,
        mcp_audit_log_file=str(tmp_path / "audit.jsonl"),
    )
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        odoo = FakeOdoo(router)
        with TestClient(create_http_app(settings, httpx.AsyncClient()), base_url=PUBLIC, follow_redirects=False) as client:
            yield SimpleNamespace(client=client, odoo=odoo)


def call_tool(client: TestClient, access_token: str) -> httpx.Response:
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-11-25",
        "Authorization": f"Bearer {access_token}",
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "odoo_whoami", "arguments": {}}}
    return client.post("/mcp", json=body, headers=headers)


def audit_events(tmp_path: Path, tool: str) -> list[dict]:
    path = tmp_path / "audit.jsonl"
    lines = path.read_text().splitlines() if path.exists() else []
    return [event for event in map(json.loads, lines) if event["tool"] == tool]


def test_token_expiring_after_the_check_does_not_end_the_sign_in(tmp_path: Path, monkeypatch):
    """A cold instance: the access token expires between the verifier's check and the service being built."""
    providers: list[OdooAuthProvider] = []
    original = OdooAuthProvider.load_access_token

    async def check_then_expire(self, token):
        result = await original(self, token)
        if result is not None and not providers:
            providers.append(self)
            self._clock = lambda: time.time() + 2 * 3600  # a moment later the token has expired
        return result

    monkeypatch.setattr(OdooAuthProvider, "load_access_token", check_then_expire)
    with running_app(tmp_path) as env:
        _, tokens = connect(env)
        odoo_calls = env.odoo.context_get.call_count
        response = call_tool(env.client, tokens["access_token"])
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result["isError"] is True and "reconnect the odoo connector" in result["content"][0]["text"].lower()
        assert env.odoo.context_get.call_count == odoo_calls  # Odoo was never asked about the key

        provider = providers[0]
        [grant] = provider.store.list_grants()  # still active: nothing was revoked
        assert grant.login == "priya@sahajta.ai"
        provider._clock = time.time
        assert call_tool(env.client, tokens["access_token"]).status_code == 200  # the token itself still verifies
    assert audit_events(tmp_path, "signout") == []
    [connect_error] = audit_events(tmp_path, "connect")
    assert connect_error["outcome"] == "error" and connect_error["detail"].startswith("auth: ")


def test_odoo_rejecting_the_key_ends_the_sign_in_and_is_logged(tmp_path: Path):
    with running_app(tmp_path) as env:
        _, tokens = connect(env)
        env.odoo.revoked_keys.add(PRIYA_KEY)
        response = call_tool(env.client, tokens["access_token"])
        result = response.json()["result"]
        assert result["isError"] is True and "Reconnect the Odoo connector" in result["content"][0]["text"]
        assert call_tool(env.client, tokens["access_token"]).status_code == 401  # the sign-in is gone
    [signout] = audit_events(tmp_path, "signout")
    assert signout["user"] == "priya@sahajta.ai" and signout["uid"] is None
    assert signout["outcome"] == "error" and signout["detail"] == "Odoo rejected the API key"
    audit = (tmp_path / "audit.jsonl").read_text()
    for secret in (PRIYA_KEY, tokens["access_token"], tokens["refresh_token"]):
        assert secret not in audit


def test_signing_out_from_claude_is_logged(tmp_path: Path):
    with running_app(tmp_path) as env:
        client_id, tokens = connect(env)
        assert env.client.post("/revoke", data={"token": tokens["access_token"], "client_id": client_id}).status_code == 200
    [signout] = audit_events(tmp_path, "signout")
    assert signout["user"] == "priya@sahajta.ai" and signout["detail"] == "revoked by the client"


ACCESS_DENIED = httpx.Response(400, json={"name": "odoo.exceptions.AccessDenied", "message": "Access Denied"})


def test_an_access_denied_that_is_not_a_401_does_not_end_the_sign_in(tmp_path: Path):
    """Only Odoo refusing the key itself (HTTP 401) may end a sign-in, also while a cold instance starts."""
    with running_app(tmp_path) as env:
        _, tokens = connect(env)
        env.odoo.context_get.side_effect = None
        env.odoo.context_get.return_value = ACCESS_DENIED
        result = call_tool(env.client, tokens["access_token"]).json()["result"]
        assert result["isError"] is True and "Reconnect" not in result["content"][0]["text"]
        assert "Nothing was changed" in result["content"][0]["text"]
        assert call_tool(env.client, tokens["access_token"]).status_code == 200  # still signed in
    assert audit_events(tmp_path, "signout") == []


def test_an_access_denied_during_refresh_is_temporary(tmp_path: Path):
    with running_app(tmp_path) as env:
        client_id, tokens = connect(env)
        env.odoo.context_get.side_effect = None
        env.odoo.context_get.return_value = ACCESS_DENIED
        data = {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id}
        assert env.client.post("/token", data=data).status_code == 503
        assert call_tool(env.client, tokens["access_token"]).status_code == 200  # still signed in
    assert audit_events(tmp_path, "signout") == []
