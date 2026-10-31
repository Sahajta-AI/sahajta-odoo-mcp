"""End-to-end tests against a real, disposable Odoo with demo data (never production!).

Run with:
  ODOO_TEST_URL=http://127.0.0.1:8069 ODOO_TEST_DB=odoo_test \
  ODOO_TEST_LOGIN=ai.tester ODOO_TEST_API_KEY=... pytest -m integration
The test user should be a plain employee with Sales/CRM rights (not an admin).
"""

import json
import os
import uuid

import pytest
from mcp.client import Client

from sahajta_odoo_mcp.config import Settings
from sahajta_odoo_mcp.server import create_stdio_server

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not os.environ.get("ODOO_TEST_API_KEY"), reason="no live Odoo test server configured"),
]


def make_settings(**overrides) -> Settings:
    values = dict(
        odoo_url=os.environ.get("ODOO_TEST_URL", "http://127.0.0.1:8069"),
        odoo_db=os.environ.get("ODOO_TEST_DB", "odoo_test"),
        odoo_login=os.environ.get("ODOO_TEST_LOGIN", "ai.tester"),
        odoo_api_key=os.environ.get("ODOO_TEST_API_KEY"),
        odoo_protocol=os.environ.get("ODOO_TEST_PROTOCOL", "auto"),
        mcp_access_mode="read_write",
        mcp_audit_log_file=None,
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)  # never pick up the local .env (production values)


async def call(client: Client, tool: str, **args):
    result = await client.call_tool(tool, args)
    text = result.content[0].text if result.content else ""
    try:
        return result.is_error, json.loads(text)
    except ValueError:
        return result.is_error, text


def live(test):
    """Run the test body with a connected in-process MCP client (opened and closed in the same task)."""

    async def wrapper():
        async with Client(create_stdio_server(make_settings())) as client:
            await test(client)

    wrapper.__name__ = test.__name__
    wrapper.__doc__ = test.__doc__
    return wrapper


async def test_read_only_mode_hides_change_tools():
    async with Client(create_stdio_server(make_settings(mcp_access_mode="read_only"))) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert "odoo_search" in names
    assert not {n for n in names if n.startswith(("odoo_create", "odoo_update", "odoo_run", "odoo_preview", "odoo_add"))}
    assert not any("delete" in n or "unlink" in n for n in names)


@live
async def test_tool_annotations(odoo):
    tools = {t.name: t for t in (await odoo.list_tools()).tools}
    for name, tool in tools.items():
        assert tool.annotations and tool.annotations.title, name
        if name in ("odoo_create", "odoo_update", "odoo_run_action", "odoo_add_note", "odoo_delete",
                    "odoo_change_followers", "odoo_send_message"):
            assert tool.annotations.destructive_hint is True and tool.annotations.read_only_hint is False
        else:
            assert tool.annotations.read_only_hint is True, name


@live
async def test_discovery_and_reads(odoo):
    err, models = await call(odoo, "odoo_list_models", query="lead")
    assert not err and any(m["model"] == "crm.lead" for m in models["models"])
    err, desc = await call(odoo, "odoo_describe_model", model="crm.lead", query="stage")
    assert not err and any(f["name"] == "stage_id" for f in desc["fields"])
    err, found = await call(odoo, "odoo_search", model="crm.lead", domain=[["type", "=", "opportunity"]], limit=2)
    assert not err and found["returned"] == 2 and found["total_matching"] >= 2
    err, groups = await call(odoo, "odoo_aggregate", model="crm.lead", group_by=["stage_id"], measures=["expected_revenue:sum"])
    assert not err and groups["groups"]


@live
async def test_reads_refuse_secrets_and_hallucinations(odoo):
    err, text = await call(odoo, "odoo_search", model="ir.config_parameter")
    assert err and "blocked" in text
    err, text = await call(odoo, "odoo_search", model="res.users", fields=["login", "password"])
    assert err and "credential" in text
    err, text = await call(odoo, "odoo_search", model="res.users", domain=[["api_key_ids.name", "!=", False]])
    assert err and "credential" in text
    err, text = await call(odoo, "odoo_search", model="crm.lead", domain=[["stage_naem", "=", 1]])
    assert err and "Did you mean: stage_id" in text
    err, text = await call(odoo, "odoo_search", model="crm.leads")
    assert err and "does not exist" in text
    err, read = await call(odoo, "odoo_read", model="res.partner", ids=[1, 987654321], fields=["name"])
    assert not err and read["not_found_ids"] == [987654321]
    err, users = await call(odoo, "odoo_search", model="res.users", limit=5)
    assert not err
    for user in users["records"]:
        assert not any(k in user for k in ("password", "api_key_ids", "totp_secret", "signup_token"))


async def _partner_id(odoo) -> int:
    err, found = await call(odoo, "odoo_search", model="res.partner", domain=[["is_company", "=", True]], fields=["name"], limit=1)
    assert not err and found["records"]
    return found["records"][0]["id"]


@live
async def test_create_requires_preview_and_exact_token(odoo):
    partner = await _partner_id(odoo)
    name = f"MCP test lead {uuid.uuid4().hex[:6]}"
    records = [{"name": name, "partner_id": partner, "expected_revenue": 1234.5, "type": "opportunity"}]

    err, text = await call(odoo, "odoo_create", model="crm.lead", records=records)
    assert err and "confirm_token" in text

    err, preview = await call(odoo, "odoo_preview_create", model="crm.lead", records=records)
    assert not err and preview["confirm_token"]
    rendered = json.dumps(preview)
    assert name in rendered and '"name"' in rendered

    tampered = [{**records[0], "expected_revenue": 999999}]
    err, text = await call(odoo, "odoo_create", model="crm.lead", records=tampered, confirm_token=preview["confirm_token"])
    assert err and "does not match" in text

    err, created = await call(odoo, "odoo_create", model="crm.lead", records=records, confirm_token=preview["confirm_token"])
    assert not err and len(created["created"]) == 1
    assert created["created"][0]["name"] == name


@live
async def test_create_rejects_invented_ids_and_fields(odoo):
    err, text = await call(odoo, "odoo_preview_create", model="crm.lead", records=[{"name": "x", "partner_id": 987654321}])
    assert err and "do not exist" in text
    err, text = await call(odoo, "odoo_preview_create", model="crm.lead", records=[{"name": "x", "customer_name": "Bob"}])
    assert err and "is not a field" in text
    err, text = await call(odoo, "odoo_preview_create", model="crm.lead", records=[{"name": "x", "priority": "9"}])
    assert err and "not a valid choice" in text
    err, text = await call(odoo, "odoo_preview_create", model="res.users", records=[{"name": "Eve", "login": "eve"}])
    assert err and "Blocked" in text


async def _new_lead(odoo) -> int:
    records = [{"name": f"MCP update test {uuid.uuid4().hex[:6]}", "type": "opportunity"}]
    _, preview = await call(odoo, "odoo_preview_create", model="crm.lead", records=records)
    _, created = await call(odoo, "odoo_create", model="crm.lead", records=records, confirm_token=preview["confirm_token"])
    return created["created"][0]["id"]


@live
async def test_update_flow_and_staleness(odoo):
    lead = await _new_lead(odoo)
    values = {"expected_revenue": 5000, "description": "Updated by the MCP test"}
    err, preview = await call(odoo, "odoo_preview_update", model="crm.lead", ids=[lead], values=values)
    assert not err and preview["changes"][0]["id"] == lead

    # someone else changes the same field after the preview -> token must be refused
    _, other = await call(odoo, "odoo_preview_update", model="crm.lead", ids=[lead], values={"expected_revenue": 42})
    err, _ = await call(odoo, "odoo_update", model="crm.lead", ids=[lead], values={"expected_revenue": 42}, confirm_token=other["confirm_token"])
    assert not err
    err, text = await call(odoo, "odoo_update", model="crm.lead", ids=[lead], values=values, confirm_token=preview["confirm_token"])
    assert err and "modified" in text

    _, preview = await call(odoo, "odoo_preview_update", model="crm.lead", ids=[lead], values=values)
    err, updated = await call(odoo, "odoo_update", model="crm.lead", ids=[lead], values=values, confirm_token=preview["confirm_token"])
    assert not err and updated["updated"][0]["expected_revenue"] == 5000


@live
async def test_dangerous_writes_are_refused(odoo):
    lead = await _new_lead(odoo)
    cases = [
        ({"active": False}, "archive"),
        ({"stage_id": 987654321}, "do not exist"),
        ({"create_uid": 1}, "automatically"),
        ({"tag_ids": [[2, 1, 0]]}, "DELETE"),
    ]
    for values, expected in cases:
        err, text = await call(odoo, "odoo_preview_update", model="crm.lead", ids=[lead], values=values)
        assert err and expected in text, (values, text)

    err, orders = await call(odoo, "odoo_search", model="sale.order", domain=[["state", "=", "draft"]], fields=["order_line"], limit=1)
    order = orders["records"][0]
    line = order["order_line"][0]
    # removing a line ([2, id, 0]) is allowed on a quotation (still a draft) and shown in the preview
    err, preview = await call(odoo, "odoo_preview_update", model="sale.order", ids=[order["id"]],
                              values={"order_line": [[2, line, 0]]})
    assert not err and "confirm_token" in preview, preview
    for values, expected in [
        ({"state": "sale"}, "workflow"),
        ({"order_line": [[5, 0, 0]]}, "[2, line_id, 0]"),  # clearing every line is refused; one line at a time
        ({"order_line": [[6, 0, []]]}, "[2, line_id, 0]"),
        ({"order_line": [line]}, "replace"),
        ({"order_line": [[1, 987654321, {"product_uom_qty": 3}]]}, "does not belong"),
    ]:
        err, text = await call(odoo, "odoo_preview_update", model="sale.order", ids=[order["id"]], values=values)
        assert err and expected in text, (values, text)


@live
async def test_sale_order_with_lines_and_confirm_button(odoo):
    partner = await _partner_id(odoo)
    err, products = await call(odoo, "odoo_search", model="product.product", domain=[["sale_ok", "=", True]], fields=["name"], limit=2)
    assert not err and len(products["records"]) == 2
    lines = [{"product_id": p["id"], "product_uom_qty": 2} for p in products["records"]]
    records = [{"partner_id": partner, "order_line": lines}]
    err, preview = await call(odoo, "odoo_preview_create", model="sale.order", records=records)
    assert not err, preview
    err, created = await call(odoo, "odoo_create", model="sale.order", records=records, confirm_token=preview["confirm_token"])
    assert not err, created
    order_id = created["created"][0]["id"]

    err, actions = await call(odoo, "odoo_list_actions", model="sale.order")
    by_method = {a.get("method"): a for a in actions["actions"] if a["kind"] == "method"}
    assert by_method["action_confirm"]["ai_can_run"] is True
    assert by_method["action_cancel"]["ai_can_run"] is False
    assert by_method.get("payment_action_capture", {}).get("ai_can_run") in (None, False)

    err, text = await call(odoo, "odoo_preview_action", model="sale.order", ids=[order_id], method="unlink")
    assert err and "Blocked" in text
    err, text = await call(odoo, "odoo_preview_action", model="sale.order", ids=[order_id], method="action_cancel")
    assert err and "cancel" in text.lower()
    err, text = await call(odoo, "odoo_preview_action", model="sale.order", ids=[order_id], method="_action_confirm")
    assert err and "Blocked" in text
    err, text = await call(odoo, "odoo_preview_action", model="sale.order", ids=[order_id], method="action_quotation_send")
    assert err and "e-mail" in text

    err, preview = await call(odoo, "odoo_preview_action", model="sale.order", ids=[order_id], method="action_confirm")
    assert not err, preview
    err, done = await call(odoo, "odoo_run_action", model="sale.order", ids=[order_id], method="action_confirm", confirm_token=preview["confirm_token"])
    assert not err, done
    assert done["records_now"][0]["state"] == "sale"


@live
async def test_internal_note(odoo):
    lead = await _new_lead(odoo)
    err, result = await call(odoo, "odoo_add_note", model="crm.lead", record_id=lead, note="Checked by MCP test.\n<script>alert(1)</script>")
    assert not err and result["logged_note_id"]
    err, messages = await call(
        odoo, "odoo_search", model="mail.message",
        domain=[["model", "=", "crm.lead"], ["res_id", "=", lead], ["message_type", "=", "comment"]], fields=["body"], limit=1,
    )
    assert not err and "<script>" in messages["records"][0]["body"]  # shown as escaped text, never as HTML


@live
async def test_context_cannot_disable_tracking(odoo):
    lead = await _new_lead(odoo)
    err, text = await call(
        odoo, "odoo_preview_update", model="crm.lead", ids=[lead], values={"probability": 10}, context={"tracking_disable": True}
    )
    assert err and "not allowed" in text
