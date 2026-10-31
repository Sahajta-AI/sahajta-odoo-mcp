"""Deleting: one narrow path, for three kinds of records, checked with Odoo before the approval and at the change.

Also proves that nothing else can delete: the client refuses unlink through call() for every model, and the only
code that reaches its delete path is the delete tool.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import httpx
import pytest
import respx

from conftest import FakeOdoo
from sahajta_odoo_mcp import odoo_client
from sahajta_odoo_mcp.errors import (
    ConfirmationRequired,
    NotSent,
    OdooError,
    OdooMCPError,
    PolicyViolation,
    ValidationFailed,
)
from test_service_offline import make_service
from test_setup_edits_and_lines import odoo19

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

SRC = Path(__file__).resolve().parents[1] / "src" / "sahajta_odoo_mcp"
APPLIED_MAYBE = "Odoo may already have applied this change. Check before doing it again."


@pytest.fixture
def fake() -> FakeOdoo:
    fake = odoo19(FakeOdoo())
    fake.records["account.move"].update({
        72: {"name": "/", "state": "draft", "posted_before": False, "invoice_line_ids": []},
        73: {"name": "BILL/2026/10/0008", "state": "draft", "posted_before": True, "invoice_line_ids": []},  # reset
        74: {"name": "INV/2026/00012", "state": "draft", "posted_before": False, "invoice_line_ids": []},  # numbered
        75: {"name": False, "state": "cancel", "posted_before": False, "invoice_line_ids": []},
    })
    fake.records["sale.order"][7] = {"name": "S00007", "state": "cancel", "partner_id": [1, "Acme Corp"], "order_line": []}
    fake.records["crm.lead"][102] = {"name": "Lost deal", "type": "opportunity", "active": False}
    for model, rid in (("account.move", 72), ("account.move", 73), ("account.move", 74), ("account.move", 75),
                       ("sale.order", 7), ("crm.lead", 102)):
        fake.records[model][rid].setdefault("write_date", "2026-10-15 10:00:00")
    return fake


@pytest.fixture
def svc(fake):
    return make_service(fake)


async def delete(svc, model, ids):
    preview = await svc.preview_delete(model, ids)
    return preview, await svc.delete(model, ids, preview["confirm_token"])


# ====================================================================================== what can be deleted


@pytest.mark.parametrize(
    "model, ids",
    [("account.move", [70]), ("account.move", [72]), ("sale.order", [7]), ("crm.lead", [102]),
     ("account.move", [70, 72])],
    ids=["draft-bill-never-numbered", "draft-named-slash", "cancelled-quotation", "archived-lead", "two-drafts"],
)
async def test_these_records_are_deleted_after_one_approval(svc, fake, model, ids):
    preview, done = await delete(svc, model, ids)
    assert "cannot be undone" in preview["preview"] and "valid 1 hour" in preview["next_step"]
    assert [r["id"] for r in preview["records"]] == ids
    assert all(r["link"].endswith(f"/odoo/{model}/{r['id']}") and r["name"] for r in preview["records"])
    assert fake.deleted == [(model, ids)]
    assert [d["id"] for d in done["deleted"]] == ids and "for good" in done["message"]


@pytest.mark.parametrize(
    "model, rid, needle",
    [
        ("account.move", 71, "is not a draft"),  # posted
        ("account.move", 73, "already had a number"),  # reset to draft: it keeps its number
        ("account.move", 74, "already had a number"),
        ("account.move", 75, "is not a draft"),  # cancelled entry
        ("sale.order", 5, "is not cancelled"),  # a live quotation
        ("crm.lead", 100, "is not archived"),
    ],
)
async def test_everything_else_of_those_kinds_is_refused(svc, fake, model, rid, needle):
    with pytest.raises(PolicyViolation, match=needle) as info:
        await svc.preview_delete(model, [rid])
    assert "Claude can delete only draft invoices" in str(info.value)
    assert fake.deleted == []


async def test_a_reset_draft_is_refused_even_without_a_number_when_it_was_posted_before(svc, fake):
    fake.records["account.move"][73]["name"] = "/"
    with pytest.raises(PolicyViolation, match="was posted before"):
        await svc.preview_delete("account.move", [73])


@pytest.mark.parametrize("model", ["res.partner", "product.product", "account.tax", "account.account",
                                   "ir.attachment", "sale.order.line", "account.move.line", "mail.message",
                                   "res.users", "ir.config_parameter"])
async def test_no_other_kind_of_record_is_ever_deleted(svc, fake, model):
    with pytest.raises(PolicyViolation):
        await svc.preview_delete(model, [1])
    with pytest.raises(PolicyViolation):
        await svc.delete(model, [1], "4102444800.forged")
    assert fake.deleted == []


async def test_one_refused_record_stops_the_whole_delete(svc, fake):
    with pytest.raises(PolicyViolation, match="BILL/2026/10/0007"):
        await svc.preview_delete("account.move", [70, 71])
    assert fake.deleted == []


async def test_files_on_the_records_are_named_in_the_preview(svc, fake):
    fake._m_search_count = lambda model, ids, context, domain=None, **kw: 2 if model == "ir.attachment" else 0
    preview = await svc.preview_delete("account.move", [70])
    assert "2 file(s) attached" in str(preview["warnings"]) and "move it onto another entry first" in str(preview["warnings"])


# ====================================================================================== approval and staleness


async def test_deleting_always_needs_the_approval_even_when_previews_are_optional(fake):
    svc = make_service(fake, mcp_require_preview=False)
    with pytest.raises(ConfirmationRequired):
        await svc.delete("account.move", [70], None)
    assert fake.deleted == []


async def test_the_approval_covers_exactly_the_previewed_records_once(svc, fake):
    preview = await svc.preview_delete("account.move", [70])
    with pytest.raises(ConfirmationRequired, match="does not match"):
        await svc.delete("account.move", [72], preview["confirm_token"])
    with pytest.raises(ConfirmationRequired, match="does not match"):
        await svc.delete("account.move", [70, 72], preview["confirm_token"])
    await svc.delete("account.move", [70], preview["confirm_token"])
    with pytest.raises(OdooMCPError):
        await svc.delete("account.move", [70], preview["confirm_token"])
    assert fake.deleted == [("account.move", [70])]


@pytest.mark.parametrize(
    "model, rid, change, error",
    [("account.move", 70, {"state": "posted"}, PolicyViolation),  # posted after the preview
     ("sale.order", 7, {"state": "draft"}, PolicyViolation),  # restored to a quotation
     ("crm.lead", 102, {"active": True}, PolicyViolation),  # restored
     ("crm.lead", 102, {"name": "Lost deal (renamed)"}, ConfirmationRequired)],  # anything else: the fingerprint
)
async def test_a_record_changed_after_the_preview_is_not_deleted(svc, fake, model, rid, change, error):
    preview = await svc.preview_delete(model, [rid])
    fake.touch(model, rid, **change)
    with pytest.raises(error) as info:
        await svc.delete(model, [rid], preview["confirm_token"])
    assert "nothing was changed" in str(info.value).lower() and fake.deleted == []


async def test_deleting_is_refused_in_read_only_mode_and_beyond_the_action_cap(fake):
    with pytest.raises(PolicyViolation, match="read-only"):
        await make_service(fake, mcp_access_mode="read_only").preview_delete("account.move", [70])
    with pytest.raises(ValidationFailed, match="too many records at once"):
        await make_service(fake, mcp_max_action_records=1).preview_delete("account.move", [70, 72])
    assert fake.deleted == []


async def test_odoos_own_delete_right_is_asked_before_the_approval(svc, fake):
    fake.access[("sale.order", "unlink")] = False
    with pytest.raises(OdooError, match="may not delete sale.order"):
        await svc.preview_delete("sale.order", [7])


# ====================================================================================== when Odoo misbehaves


@pytest.mark.parametrize(
    "refusal, said",
    [(OdooError("", kind="rate_limited", status=429), "Nothing was changed. You can retry with the same confirm_token."),
     (OdooError("You cannot delete this entry", kind="user_error", status=422), "Nothing was changed.")],
)
async def test_a_delete_odoo_turned_away_says_nothing_changed(svc, fake, refusal, said):
    preview = await svc.preview_delete("account.move", [70])
    fake.errors[("account.move", "delete_records")] = refusal
    with pytest.raises(OdooError) as info:
        await svc.delete("account.move", [70], preview["confirm_token"])
    assert str(info.value).endswith(said) and "may already have" not in str(info.value)


async def test_a_delete_with_a_lost_answer_says_it_may_have_happened_and_is_never_repeated(svc, fake):
    preview = await svc.preview_delete("account.move", [70, 72])

    async def lost(model, ids):
        fake.records[model].pop(70)  # Odoo deleted one of them, then the answer was lost
        raise OdooError("account.move.unlink timed out", kind="timeout")

    fake.delete_records = lost
    with pytest.raises(OdooError) as info:
        await svc.delete("account.move", [70, 72], preview["confirm_token"])
    text = str(info.value)
    assert APPLIED_MAYBE in text and "nothing was changed" not in text.lower()
    assert "Still in Odoo: [72]. No longer in Odoo (deleted): [70]." in text
    with pytest.raises(OdooMCPError):  # the same approval never deletes twice
        await svc.delete("account.move", [72], preview["confirm_token"])


async def test_a_delete_is_not_sent_late_in_a_call(svc, fake, monkeypatch):
    from types import SimpleNamespace

    from sahajta_odoo_mcp import service as service_module

    preview = await svc.preview_delete("account.move", [70])
    now = SimpleNamespace(t=1000.0)
    monkeypatch.setattr(service_module, "time", SimpleNamespace(monotonic=lambda: now.t))
    quick = fake.call

    async def slow(*args, **kwargs):
        now.t += 21
        return await quick(*args, **kwargs)

    fake.call = slow
    with pytest.raises(NotSent) as info:
        await svc.delete("account.move", [70], preview["confirm_token"])
    assert str(info.value).endswith("Nothing was changed. You can retry with the same confirm_token.")
    assert fake.deleted == []


# ====================================================================================== nothing else can delete


@pytest.fixture
def router():
    with respx.mock(base_url="https://odoo.example.com", assert_all_called=False, assert_all_mocked=True) as mock:
        yield mock


@pytest.fixture(autouse=True)
def fresh_gates(monkeypatch):
    monkeypatch.setattr(odoo_client, "_GATES", {})


def client(http):
    return odoo_client.OdooClient(
        odoo_client.OdooCredentials("https://odoo.example.com", "testdb", "ai.tester", "k" * 40), http, protocol="json2"
    )


@pytest.mark.parametrize("model", ["account.move", "sale.order", "crm.lead", "res.partner"])
@pytest.mark.parametrize("method", ["unlink", "action_unlink", "unlink_lines"])
async def test_call_refuses_unlink_for_every_model_even_the_deletable_ones(router, model, method):
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError, match="refusing"):
            await client(http).call(model, method, ids=[1])
    assert router.calls.call_count == 0


@pytest.mark.parametrize(
    "model, ids",
    [("res.partner", [1]), ("account.tax", [1]), ("ir.attachment", [1]), ("res.users", [1]), ("sale.order.line", [1]),
     ("account.move", []), ("account.move", [0]), ("account.move", [True]), ("account.move", "1"),
     ("account.move", list(range(1, 102)))],
)
async def test_the_delete_path_checks_the_model_and_ids_itself(router, model, ids):
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError, match="refusing to delete"):
            await client(http).delete_records(model, ids)
    assert router.calls.call_count == 0


async def test_the_delete_path_sends_unlink_once_with_exactly_those_ids(router):
    route = router.post("/json/2/account.move/unlink").mock(return_value=httpx.Response(200, json=True))
    async with httpx.AsyncClient() as http:
        assert await client(http).delete_records("account.move", [70, 72]) is True
    assert route.call_count == 1
    assert json.loads(route.calls[0].request.content)["ids"] == [70, 72]


async def test_the_delete_path_is_never_retried(router):
    route = router.post("/json/2/crm.lead/unlink").mock(return_value=httpx.Response(503, text="busy"))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError):
            await client(http).delete_records("crm.lead", [5])
    assert route.call_count == 1


def _calls_of(attribute: str) -> list[tuple[str, str]]:
    """(module, enclosing function) of every call to .<attribute>(...) in the server's code."""
    found = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for func in ast.walk(tree):
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(func):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == attribute:
                        found.append((path.name, func.name))
    return sorted(set(found))


def test_only_the_delete_tool_reaches_the_delete_path():
    # the lambda inside OdooService.delete is the only caller of OdooClient.delete_records
    assert _calls_of("delete_records") == [("service.py", "delete")]


def test_nothing_outside_the_client_uses_its_private_senders():
    """The client's private methods send without the unlink guard; only the client itself may use them."""
    private = {"_send", "_call_json2", "_call_jsonrpc", "_jsonrpc"}
    used = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "odoo_client.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Attribute) and node.attr in private:
                owner = node.value
                name = owner.attr if isinstance(owner, ast.Attribute) else getattr(owner, "id", "")
                if name != "self":  # OdooService._send is the service's own (it wraps a change), not the client's
                    used.append(f"{path.name}: {name}.{node.attr}")
    assert used == []


def test_unlink_is_named_in_the_client_only_in_its_guard_and_its_delete_path():
    tree = ast.parse((SRC / "odoo_client.py").read_text())
    places = []
    for func in ast.walk(tree):
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(isinstance(n, ast.Constant) and n.value == "unlink" for n in ast.walk(func)):
                places.append(func.name)
    assert places == ["delete_records"]
    assert "unlink" in odoo_client._NEVER_SENT
    assert odoo_client._DELETABLE_MODELS == {"account.move", "sale.order", "crm.lead"}


@pytest.mark.parametrize("method", ["unlink", "action_unlink_lines", "button_delete", "action_remove_lines", "purge"])
async def test_no_button_or_dialog_deletes(svc, fake, method):
    for model, rid in (("account.move", 70), ("sale.order", 7), ("crm.lead", 102)):
        with pytest.raises(OdooMCPError):
            await svc.preview_action(model, [rid], method, None)
        with pytest.raises(OdooMCPError):
            await svc.run_action(model, [rid], method, None, "4102444800.forged")
    assert fake.deleted == [] and not [c for c in fake.calls if "unlink" in c.method or c.method == method]


# ====================================================================================== the tools themselves


async def test_the_delete_tools_exist_only_in_read_write_mode_and_say_what_they_do(fake):
    from test_guide import tool_client

    async with await tool_client(fake, mcp_access_mode="read_only") as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
    assert not {n for n in names if "delete" in n or "unlink" in n}
    async with await tool_client(fake, mcp_access_mode="read_write") as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert tools["odoo_preview_delete"].annotations.read_only_hint is True
        assert tools["odoo_delete"].annotations.destructive_hint is True
        assert "cannot be undone" in tools["odoo_delete"].description
        names = list(tools)
        assert names.index("odoo_preview_delete") == names.index("odoo_run_action") + 1  # right after the buttons
        refused = await client.call_tool("odoo_delete", {"model": "res.partner", "ids": [1], "confirm_token": "1.x"})
        preview = json.loads((await client.call_tool("odoo_preview_delete", {"model": "crm.lead", "ids": [102]})).content[0].text)
        done = await client.call_tool("odoo_delete", {"model": "crm.lead", "ids": [102], "confirm_token": preview["confirm_token"]})
        again = await client.call_tool("odoo_delete", {"model": "crm.lead", "ids": [102], "confirm_token": preview["confirm_token"]})
    assert refused.is_error and "Nothing was changed" in refused.content[0].text
    assert not done.is_error and json.loads(done.content[0].text)["deleted"] == [{"id": 102, "name": "Lost deal"}]
    assert again.is_error and "nothing was changed" in again.content[0].text.lower()
    assert "may already have" not in again.content[0].text
    assert fake.deleted == [("crm.lead", [102])]
