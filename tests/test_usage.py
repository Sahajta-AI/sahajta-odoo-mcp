"""30-day usage history: metadata only, bounded, never breaks a request, readable only with the admin token."""

import json

import fakeredis
import httpx
import pytest
import respx
from mcp.client import Client

import sahajta_odoo_mcp.usage as usage_module
from conftest import build_settings
from sahajta_odoo_mcp.__main__ import _usage
from sahajta_odoo_mcp.server import create_stdio_server
from sahajta_odoo_mcp.usage import UsageLog, format_report, sanitize_detail
from test_performance_paths import (  # noqa: F401  (fixtures)
    COUNT_ARGS, KEY_A, LOGIN, PUBLIC, BrokenRedis, fresh_gates, http_app, odoo, router, shared_redis,
)

ADMIN = "admin-token-" + "x" * 36


def make_log():
    return UsageLog(fakeredis.FakeRedis(decode_responses=True))


def test_events_hold_metadata_only():
    log = make_log()
    log.record({"user": "a@x", "tool": "odoo_update", "outcome": "error", "model": "crm.lead", "ids": [1, 2, 3],
                "fields": ["priority", "name"],
                "detail": "Request rejected: crm.lead.priority: '9' is not a valid choice for \"Acme Corp\""})
    (event,) = log.events(1)
    assert event["records"] == 3 and event["fields"] == ["name", "priority"]
    assert "'9'" not in event["detail"] and "Acme" not in event["detail"] and "not a valid choice" in event["detail"]
    assert "ids" not in event  # counts only, not record ids


def test_successful_calls_store_no_detail():
    log = make_log()
    log.record({"user": "a@x", "tool": "odoo_search", "outcome": "ok", "model": "crm.lead", "detail": "anything"})
    assert "detail" not in log.events(1)[0]


def test_sanitize_detail_blanks_quotes_and_bounds_length():
    assert sanitize_detail("x 'secret' y \"other\"") == "x '…' y '…'"
    assert len(sanitize_detail("z" * 1000)) == 200
    assert sanitize_detail(None) is None


def test_events_older_than_the_retention_are_dropped(monkeypatch):
    log = make_log()
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(usage_module.time, "time", lambda: clock["t"])
    log.record({"user": "a", "tool": "odoo_count", "outcome": "ok"})
    clock["t"] += 31 * 86400
    log.record({"user": "a", "tool": "odoo_count", "outcome": "ok"})
    assert len(log._r.zrange(log._key, 0, -1)) == 1


def test_event_count_is_capped(monkeypatch):
    monkeypatch.setattr(usage_module, "MAX_EVENTS", 5)
    log = make_log()
    for _ in range(12):
        log.record({"user": "a", "tool": "odoo_count", "outcome": "ok"})
    assert log._r.zcard(log._key) == 5


def test_recording_never_raises():
    import redis
    UsageLog(BrokenRedis(redis.ConnectionError("down"))).record({"user": "a", "tool": "odoo_count", "outcome": "ok"})


def test_report_aggregates_and_formats():
    log = make_log()
    for tool, outcome, model, ids in [
        ("odoo_search", "ok", "crm.lead", None), ("odoo_search", "ok", "crm.lead", None),
        ("odoo_create", "ok", "crm.lead", None), ("odoo_update", "ok", "crm.lead", [1, 2]),
        ("odoo_search", "blocked", "ir.config_parameter", None), ("odoo_update", "error", "sale.order", [5]),
        ("connect", "error", None, None),
    ]:
        log.record({"user": "s@x", "tool": tool, "outcome": outcome, "model": model, "ids": ids, "detail": "boom"})
    report = log.report(7)
    assert report["tool_calls"] == 6 and report["errors"] == 2 and report["blocked"] == 1
    assert report["changes"] == {"created": 1, "updated": 2}
    assert report["by_tool"]["odoo_search"] == {"ok": 2, "blocked": 1}
    assert report["by_user"] == {"s@x": 6}
    assert report["top_models"][0] == ["crm.lead", 4] or report["top_models"][0] == ("crm.lead", 4)
    assert len(report["problems"]) == 3
    text = format_report(json.loads(json.dumps(report)))
    assert "Tool calls: 6" in text and "blocked by safety rules: 1" in text and "Recent problems:" in text


async def test_tool_calls_and_blocked_calls_are_recorded_end_to_end(odoo, shared_redis):
    settings = build_settings(odoo_protocol="auto", odoo_login=LOGIN, odoo_api_key=KEY_A, mcp_redis_url="redis://fake:6379")
    async with httpx.AsyncClient() as http, Client(create_stdio_server(settings, http)) as client:
        assert not (await client.call_tool("odoo_count", COUNT_ARGS)).is_error
        assert (await client.call_tool("odoo_search", {"model": "ir.config_parameter"})).is_error
    report = UsageLog(shared_redis.client()).report(1)
    assert report["by_tool"]["odoo_count"] == {"ok": 1}
    assert report["by_tool"]["odoo_search"] == {"blocked": 1}
    problem = report["problems"][-1]
    assert problem["outcome"] == "blocked" and "config_parameter" not in problem.get("detail", "")


def test_admin_report_requires_the_admin_token(tmp_path, shared_redis):
    with http_app(tmp_path, mcp_redis_url="redis://fake:6379", mcp_admin_token=ADMIN) as client:
        assert client.get("/admin/usage").status_code == 401
        assert client.get("/admin/usage", headers={"Authorization": "Bearer wrong"}).status_code == 401
        ok = client.get("/admin/usage?days=99", headers={"Authorization": f"Bearer {ADMIN}"})
        assert ok.status_code == 200 and ok.json()["period_days"] == 30
        assert ok.headers["cache-control"] == "no-store"
        assert client.get("/admin/usage?days=abc", headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 400


@pytest.mark.parametrize("overrides", [{"mcp_redis_url": "redis://fake:6379"}, {"mcp_admin_token": ADMIN}])
def test_admin_report_is_off_without_token_or_redis(tmp_path, shared_redis, overrides):
    with http_app(tmp_path, **overrides) as client:
        assert client.get("/admin/usage", headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 404


def test_usage_command_prints_the_report(capsys):
    settings = build_settings(mcp_public_url=PUBLIC, mcp_admin_token=ADMIN)
    report = make_log().report(7)
    with respx.mock(assert_all_mocked=True) as mock:
        route = mock.get(f"{PUBLIC}/admin/usage").mock(return_value=httpx.Response(200, json=json.loads(json.dumps(report))))
        _usage(settings, 7, as_json=False)
    assert route.calls.last.request.headers["authorization"] == f"Bearer {ADMIN}"
    assert "Sahajta Odoo connector: usage over the last 7 day(s)" in capsys.readouterr().out
