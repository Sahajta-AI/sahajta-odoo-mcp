"""OdooService end to end against an in-memory fake Odoo: preview/confirm flows, buttons, reads, limits.

Every test also asserts (fixture ``no_unlink_ever``) that the fake client never received a method containing
"unlink", whatever the test did.
"""

from __future__ import annotations

import json

import pytest

from conftest import FakeOdoo, build_settings
from sahajta_odoo_mcp import ratelimit as ratelimit_module
from sahajta_odoo_mcp.audit import AuditLog
from sahajta_odoo_mcp.confirm import ConfirmationSigner
from sahajta_odoo_mcp.errors import (
    ConfirmationRequired,
    OdooError,
    PolicyViolation,
    RateLimited,
    ValidationFailed,
)
from sahajta_odoo_mcp.policy import SafetyPolicy
from sahajta_odoo_mcp.ratelimit import RateLimiter
from sahajta_odoo_mcp.schema import SchemaCache
from sahajta_odoo_mcp.service import OdooService, Shared

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

CHANGE_METHODS = {"create", "write", "message_post", "action_confirm", "action_mass_confirm", "action_line_explode"}


def make_shared(audit_file: str | None = None, **overrides) -> Shared:
    settings = build_settings(**{"mcp_access_mode": "read_write", **overrides})
    return Shared(
        settings=settings,
        policy=SafetyPolicy(settings),
        schema=SchemaCache(),
        signer=ConfirmationSigner(b"k" * 32),
        audit=AuditLog(audit_file),
        limiter=RateLimiter(settings.mcp_reads_per_minute, settings.mcp_writes_per_minute),
        http=None,
        button_cache={},
    )


def make_service(fake: FakeOdoo | None = None, shared: Shared | None = None, **overrides) -> OdooService:
    fake = fake or FakeOdoo()
    return OdooService(shared or make_shared(**overrides), fake, fake.identity_obj)


@pytest.fixture
def fake() -> FakeOdoo:
    return FakeOdoo()


@pytest.fixture
def svc(fake) -> OdooService:
    return make_service(fake)


def changes(fake: FakeOdoo) -> list[str]:
    return [f"{c.model}.{c.method}" for c in fake.calls if c.method in CHANGE_METHODS]


LEAD = [{"name": "MCP lead", "partner_id": 1, "expected_revenue": 1234.5, "type": "opportunity"}]


# ======================================================================================= create


async def test_create_needs_the_preview_token(svc, fake):
    with pytest.raises(ConfirmationRequired, match="preview"):
        await svc.create("crm.lead", LEAD, None, None)
    assert changes(fake) == []

    preview = await svc.preview_create("crm.lead", LEAD, None)
    assert changes(fake) == [], "a preview must not change anything"
    shown = preview["records"][0]
    assert shown["Customer (partner_id)"] == {"id": 1, "name": "Acme Corp"}
    assert shown["Type (type)"] == "opportunity (Opportunity)"

    result = await svc.create("crm.lead", LEAD, None, preview["confirm_token"])
    assert changes(fake) == ["crm.lead.create"]
    call = fake.calls_to("create")[0]
    assert call.kwargs["vals_list"] == [
        {"name": "MCP lead", "partner_id": 1, "expected_revenue": 1234.5, "type": "opportunity"}
    ]
    assert call.context is None
    assert result["created"][0]["name"] == "MCP lead"


@pytest.mark.parametrize(
    "tampered",
    [
        [{**LEAD[0], "expected_revenue": 999999}],
        [{**LEAD[0], "partner_id": 3}],
        [{**LEAD[0], "user_id": 8}],
        [{k: v for k, v in LEAD[0].items() if k != "partner_id"}],
        LEAD + LEAD,
    ],
)
async def test_create_refuses_a_token_for_different_values(svc, fake, tampered):
    preview = await svc.preview_create("crm.lead", LEAD, None)
    with pytest.raises(ConfirmationRequired, match="does not match"):
        await svc.create("crm.lead", tampered, None, preview["confirm_token"])
    assert changes(fake) == []


async def test_create_refuses_a_token_for_a_different_model_or_context(svc, fake):
    preview = await svc.preview_create("crm.lead", [{"name": "x", "type": "lead"}], None)
    with pytest.raises(ConfirmationRequired):
        await svc.create("crm.lead", [{"name": "x", "type": "lead"}], {"lang": "fr_FR"}, preview["confirm_token"])
    with pytest.raises(ConfirmationRequired):
        await svc.create("crm.tag", [{"name": "x"}], None, preview["confirm_token"])
    assert changes(fake) == []


async def test_create_token_is_bound_to_the_user(fake):
    shared = make_shared()
    alice = make_service(fake, shared)
    bob_fake = FakeOdoo(uid=8, login="sam")
    bob = make_service(bob_fake, shared)
    preview = await alice.preview_create("crm.lead", LEAD, None)
    with pytest.raises(ConfirmationRequired):
        await bob.create("crm.lead", LEAD, None, preview["confirm_token"])
    assert changes(bob_fake) == []


async def test_create_accepts_equivalent_spelling_of_the_same_change(svc, fake):
    # many2one as [id, name] normalises to the same id, so the token still matches
    preview = await svc.preview_create("crm.lead", LEAD, None)
    same = [{**LEAD[0], "partner_id": [1, "Acme Corp"]}]
    await svc.create("crm.lead", same, None, preview["confirm_token"])
    assert changes(fake) == ["crm.lead.create"]


# Regression test (was a bug, now fixed): BUG: confirm tokens are not single-use (confirm.py/service.py create): one approved create preview can be replayed for 15 minutes, creating duplicate records
async def test_create_token_cannot_be_replayed(svc, fake):
    preview = await svc.preview_create("crm.lead", LEAD, None)
    await svc.create("crm.lead", LEAD, None, preview["confirm_token"])
    with pytest.raises(ConfirmationRequired):
        await svc.create("crm.lead", LEAD, None, preview["confirm_token"])


async def test_create_without_preview_requirement(fake):
    svc = make_service(fake, mcp_require_preview=False)
    await svc.create("crm.lead", LEAD, None, None)
    assert changes(fake) == ["crm.lead.create"]


async def test_create_is_refused_in_read_only_mode(fake):
    svc = make_service(fake, mcp_access_mode="read_only")
    with pytest.raises(PolicyViolation, match="read-only"):
        await svc.preview_create("crm.lead", LEAD, None)
    with pytest.raises(PolicyViolation, match="read-only"):
        await svc.create("crm.lead", LEAD, None, "123.abc")
    assert changes(fake) == []


@pytest.mark.parametrize("model", ["res.users", "res.groups", "ir.config_parameter", "mail.mail", "res.partner.bank"])
async def test_create_on_protected_models_is_refused_before_touching_odoo(fake, model):
    svc = make_service(fake, mcp_require_preview=False)
    with pytest.raises(PolicyViolation):
        await svc.create(model, [{"name": "Eve", "login": "eve"}], None, None)
    assert fake.calls == []


async def test_create_validates_records(svc, fake):
    with pytest.raises(ValidationFailed, match="non-empty list"):
        await svc.preview_create("crm.lead", [], None)
    with pytest.raises(ValidationFailed, match="non-empty list"):
        await svc.preview_create("crm.lead", {"name": "x"}, None)
    with pytest.raises(ValidationFailed, match="limit is 20"):
        await svc.preview_create("crm.lead", [{"name": f"l{i}", "type": "lead"} for i in range(21)], None)
    with pytest.raises(ValidationFailed, match="do not exist"):
        await svc.preview_create("crm.lead", [{"name": "x", "partner_id": 987654321}], None)
    assert changes(fake) == []


async def test_create_context_defaults_are_validated_like_values(svc, fake):
    for ctx, needle in [
        ({"default_state": "sale"}, "workflow"),
        ({"default_partner_id": 987654321}, "do not exist"),
        ({"default_no_such_field": 1}, "does not have"),
        ({"default_amount_total": 5}, "read-only"),
    ]:
        with pytest.raises(ValidationFailed, match=needle):
            await svc.preview_create("sale.order", [{"partner_id": 1, "name": "S1"}], ctx)
    with pytest.raises(PolicyViolation):
        await svc.preview_create("sale.order", [{"partner_id": 1, "name": "S1"}], {"tracking_disable": True})
    assert changes(fake) == []


async def test_create_with_wizard_context(svc, fake):
    ctx = {"active_model": "sale.order", "active_ids": [5, 6]}
    preview = await svc.preview_create("crm.tag", [{"name": "wizard-like"}], ctx)
    await svc.create("crm.tag", [{"name": "wizard-like"}], ctx, preview["confirm_token"])
    assert fake.calls_to("create")[0].context == ctx


LOST_WIZARD = {
    "lead_ids": {"type": "many2many", "string": "Leads", "relation": "crm.lead", "store": True, "readonly": False},
    "lost_feedback": {"type": "text", "string": "Closing Note", "store": True, "readonly": False},
}


async def test_wizard_not_linked_to_its_records_is_refused(svc, fake):
    # "Mark as Lost" gets its leads from the window action's context; without them it silently does nothing
    fake.schema["crm.lead.lost"] = LOST_WIZARD
    ctx = {"active_model": "crm.lead", "active_ids": [100]}
    with pytest.raises(ValidationFailed, match=r'"lead_ids": \[100\]'):
        await svc.preview_create("crm.lead.lost", [{"lost_feedback": "too expensive"}], ctx)
    with pytest.raises(ValidationFailed, match="lead_ids"):
        await svc.preview_create("crm.lead.lost", [{}], ctx)
    preview = await svc.preview_create("crm.lead.lost", [{"lead_ids": [100]}], ctx)
    await svc.create("crm.lead.lost", [{"lead_ids": [100]}], ctx, preview["confirm_token"])
    assert changes(fake) == ["crm.lead.lost.create"]


async def test_wizard_linked_by_odoo_defaults_needs_no_values(svc, fake):
    fake.schema["crm.lead.lost"] = LOST_WIZARD
    fake.defaults["crm.lead.lost"] = {"lead_ids": [[6, 0, [100]]]}
    ctx = {"active_model": "crm.lead", "active_ids": [100]}
    preview = await svc.preview_create("crm.lead.lost", [{}], ctx)
    await svc.create("crm.lead.lost", [{}], ctx, preview["confirm_token"])
    assert fake.calls_to("create")[0].kwargs["vals_list"] == [{}]


async def test_empty_values_need_a_wizard_context(svc, fake):
    with pytest.raises(ValidationFailed, match="non-empty"):
        await svc.preview_create("crm.tag", [{}], None)
    preview = await svc.preview_create("crm.tag", [{}], {"active_model": "sale.order", "active_ids": [5]})
    assert preview["records"] == [{}]


async def test_create_preview_warns_about_missing_required_fields(svc, fake):
    preview = await svc.preview_create("crm.lead", [{"partner_id": 1}], None)
    assert any("Opportunity (name)" in w and "Type (type)" in w for w in preview["warnings"])
    fake.defaults["crm.lead"] = {"type": "lead"}
    preview = await svc.preview_create("crm.lead", [{"partner_id": 1}], None)
    assert all("Type (type)" not in w for w in preview["warnings"])


# ======================================================================================= update


async def test_update_flow(svc, fake):
    values = {"expected_revenue": 5000, "next_call_at": "2026-07-01 10:00:00"}  # user tz Asia/Kolkata
    preview = await svc.preview_update("crm.lead", [100], values, None)
    change = preview["changes"][0]
    assert change["id"] == 100 and change["record"] == "Big deal"
    assert change["current"]["Expected Revenue (expected_revenue)"] == 1000.0
    assert change["new"]["Next Call (next_call_at)"] == "2026-07-01T10:00:00+05:30"
    assert changes(fake) == []

    result = await svc.update("crm.lead", [100], values, None, preview["confirm_token"])
    write = fake.calls_to("write")[0]
    assert write.ids == [100]
    assert write.kwargs["vals"] == {"expected_revenue": 5000, "next_call_at": "2026-07-01 04:30:00"}
    assert result["updated"][0]["expected_revenue"] == 5000


async def test_update_ids_order_and_duplicates_do_not_matter(svc, fake):
    preview = await svc.preview_update("crm.lead", [101, 100], {"probability": 10}, None)
    await svc.update("crm.lead", [100, 101, 100], {"probability": 10}, None, preview["confirm_token"])
    assert sorted(fake.calls_to("write")[0].ids) == [100, 101]


@pytest.mark.parametrize(
    "ids, values",
    [
        ([100], {"probability": 11}),
        ([100], {"probability": 10, "color": 1}),
        ([100, 101], {"probability": 10}),
        ([101], {"probability": 10}),
    ],
)
async def test_update_refuses_a_token_for_a_different_change(svc, fake, ids, values):
    preview = await svc.preview_update("crm.lead", [100], {"probability": 10}, None)
    with pytest.raises(ConfirmationRequired):
        await svc.update("crm.lead", ids, values, None, preview["confirm_token"])
    assert changes(fake) == []


async def test_update_refuses_when_someone_else_edited_the_record(svc, fake):
    preview = await svc.preview_update("crm.lead", [100], {"expected_revenue": 5000}, None)
    fake.touch("crm.lead", 100, expected_revenue=42.0)
    with pytest.raises(ConfirmationRequired, match="modified"):
        await svc.update("crm.lead", [100], {"expected_revenue": 5000}, None, preview["confirm_token"])
    assert changes(fake) == []


async def test_update_refuses_when_a_shown_value_changed_within_the_same_second(svc, fake):
    preview = await svc.preview_update("crm.lead", [100], {"expected_revenue": 5000}, None)
    fake.records["crm.lead"][100]["expected_revenue"] = 7.0  # write_date unchanged (1 s resolution)
    with pytest.raises(ConfirmationRequired):
        await svc.update("crm.lead", [100], {"expected_revenue": 5000}, None, preview["confirm_token"])
    assert changes(fake) == []


async def test_update_token_cannot_be_reused_after_the_write(svc, fake):
    preview = await svc.preview_update("crm.lead", [100], {"expected_revenue": 5000}, None)
    await svc.update("crm.lead", [100], {"expected_revenue": 5000}, None, preview["confirm_token"])
    with pytest.raises(ConfirmationRequired):
        await svc.update("crm.lead", [100], {"expected_revenue": 5000}, None, preview["confirm_token"])
    assert changes(fake) == ["crm.lead.write"]


async def test_update_refuses_missing_ids_without_writing(svc, fake):
    with pytest.raises(ValidationFailed, match=r"\[987654321\]"):
        await svc.preview_update("crm.lead", [100, 987654321], {"probability": 1}, None)
    svc_np = make_service(fake, mcp_require_preview=False)
    with pytest.raises(ValidationFailed, match="do not exist"):
        await svc_np.update("crm.lead", [987654321], {"probability": 1}, None, None)
    assert changes(fake) == []
    # existence is checked including archived records
    assert all(c.context == {"active_test": False} for c in fake.calls_to("search") if c.model == "crm.lead")


@pytest.mark.parametrize("ids", [[], None, 100, [0], [-1], [True], ["100"], [1.0], "100"])
async def test_update_ids_must_be_real_ids(svc, fake, ids):
    with pytest.raises(ValidationFailed):
        await svc.preview_update("crm.lead", ids, {"probability": 1}, None)
    assert changes(fake) == []


async def test_update_record_cap(fake):
    svc = make_service(fake, mcp_max_write_records=2)
    with pytest.raises(ValidationFailed, match="limit is 2"):
        await svc.preview_update("crm.lead", [100, 101, 102], {"probability": 1}, None)


async def test_update_refuses_default_context_keys(svc, fake):
    with pytest.raises(ValidationFailed, match="only apply when creating"):
        await svc.preview_update("crm.lead", [100], {"probability": 1}, {"default_name": "x"})


async def test_update_refuses_dangerous_values(svc, fake):
    for values, needle in [
        ({"active": False}, "archive"),
        ({"stage_id": 987654321}, "do not exist"),
        ({"create_uid": 1}, "automatically"),
        ({"tag_ids": [[2, 1, 0]]}, "DELETE"),
        ({"x_api_key": "k"}, "secret"),
    ]:
        with pytest.raises(ValidationFailed, match=needle):
            await svc.preview_update("crm.lead", [100], values, None)
    for values, needle in [
        ({"state": "sale"}, "workflow"),
        ({"order_line": [[2, 50, 0]]}, "delete"),
        ({"order_line": [[5, 0, 0]]}, "delete"),
        ({"order_line": [[6, 0, []]]}, "delete"),
        ({"order_line": [50]}, "replace"),
        ({"order_line": [[1, 60, {"product_uom_qty": 3}]]}, "does not belong"),
    ]:
        with pytest.raises(ValidationFailed, match=needle):
            await svc.preview_update("sale.order", [5], values, None)
    assert changes(fake) == []


async def test_update_is_refused_in_read_only_mode_and_on_readonly_models(fake):
    with pytest.raises(PolicyViolation):
        await make_service(fake, mcp_access_mode="read_only").update("crm.lead", [100], {"probability": 1}, None, None)
    with pytest.raises(PolicyViolation):
        await make_service(fake, mcp_readonly_models=["crm.*"]).preview_update("crm.lead", [100], {"probability": 1}, None)
    with pytest.raises(PolicyViolation, match="list of records Claude may change"):
        await make_service(fake, mcp_writable_models=["project.task"]).preview_update("crm.lead", [100], {"probability": 1}, None)
    assert changes(fake) == []


async def test_update_preview_shows_line_commands_with_names(svc, fake):
    preview = await svc.preview_update(
        "sale.order", [5], {"order_line": [{"product_id": 11, "product_uom_qty": 1}, [1, 50, {"price_unit": 90}]],
                            "tag_ids": [1, 3]}, None,
    )
    new = preview["changes"][0]["new"]
    assert new["Order Lines (order_line)"][0] == {
        "add new line": {"Product (product_id)": {"id": 11, "name": "Training day"}, "Quantity (product_uom_qty)": 1}
    }
    assert new["Order Lines (order_line)"][1] == {"edit line 50": {"Unit Price (price_unit)": 90}}
    assert new["Tags (tag_ids)"] == [{"set exactly": [{"id": 1, "name": "Hot"}, {"id": 3, "name": "Training"}]}]


# ======================================================================================= buttons


async def test_buttons_are_parsed_from_form_and_list_views(svc, fake):
    buttons = await svc._buttons("sale.order")
    confirm = buttons["method:action_confirm"]
    assert confirm["label"] == "Confirm" and confirm["kind"] == "method"
    # appears twice with two conditions: hidden only when both hold
    assert confirm["visible_when_not"] == "(state not in ('draft', 'sent')) AND (state != 'sent')"
    assert buttons["method:action_cancel"]["asks_confirmation"] == "Are you sure you want to cancel this order?"
    assert buttons["method:action_quotation_send"]["visible_when_not"] == "state != 'draft'"
    assert "visible_when_not" not in buttons["method:payment_action_capture"]
    assert "method:action_mass_confirm" in buttons  # list view header
    wizard = buttons["action:42"]
    assert wizard == {"kind": "wizard", "action_id": 42, "label": "Create Invoice", "opens_model": "sale.advance.payment.inv",
                      "visible_when_not": "invoice_status != 'to invoice'"}
    assert not any("some_unresolved" in k or "Upper" in k for k in buttons)
    assert "method:" not in buttons  # nameless button skipped


async def test_buttons_are_cached_per_user(svc, fake):
    await svc._buttons("sale.order")
    await svc._buttons("sale.order")
    assert len(fake.calls_to("get_views")) == 1
    other = FakeOdoo(uid=8)
    await make_service(other, svc.shared)._buttons("sale.order")
    assert len(other.calls_to("get_views")) == 1


async def test_bad_or_missing_views_are_handled(fake):
    fake.views["crm.lead"] = {"views": {"form": {"arch": "<form><button name='x' type='object'"}, "list": None}}
    assert await make_service(fake)._buttons("crm.lead") == {}
    fake.errors[("crm.tag", "get_views")] = OdooError("no such model", kind="missing")
    with pytest.raises(ValidationFailed, match="cannot load the screens"):
        await make_service(fake)._buttons("crm.tag")


# Regression test (was a bug, now fixed): BUG: service.py _buttons() iterates every <button> in the arch, including buttons of inline x2many sub-views (here sale.order.line's list), and treats them as buttons of the parent model
async def test_buttons_of_embedded_line_views_do_not_count_for_the_parent(svc):
    buttons = await svc._buttons("sale.order")
    assert "method:action_line_explode" not in buttons


async def test_list_actions_reports_what_may_run(svc):
    actions = (await svc.list_actions("sale.order"))["actions"]
    by_method = {a["method"]: a for a in actions if a["kind"] == "method"}
    assert by_method["action_confirm"]["ai_can_run"] is True
    assert by_method["action_preview_sale_order"]["ai_can_run"] is True
    for method in ("action_cancel", "action_quotation_send", "payment_action_capture", "action_draft", "unlink",
                   "_action_private"):
        assert by_method[method]["ai_can_run"] is False and by_method[method]["why_not"], method


async def test_list_actions_in_read_only_mode(fake):
    actions = (await make_service(fake, mcp_access_mode="read_only").list_actions("sale.order"))["actions"]
    assert all(not a["ai_can_run"] for a in actions if a["kind"] == "method")


# ======================================================================================= run_action


async def test_action_flow(svc, fake):
    preview = await svc.preview_action("sale.order", [5], "action_confirm", None)
    assert preview["records"][0]["state"] == "draft"
    assert "button_hidden_when" not in preview  # Odoo's raw condition was noise for the person
    assert changes(fake) == []
    result = await svc.run_action("sale.order", [5], "action_confirm", None, preview["confirm_token"])
    assert changes(fake) == ["sale.order.action_confirm"]
    assert fake.calls_to("action_confirm")[0].ids == [5]
    assert result["records_now"][0]["id"] == 5


async def test_action_preview_shows_odoo_confirmation_text(fake):
    svc = make_service(fake, mcp_allow_cancel_actions=True)
    preview = await svc.preview_action("sale.order", [5], "action_cancel", None)
    assert preview["odoo_confirmation_text"].startswith("Are you sure")


@pytest.mark.parametrize(
    "method, needle",
    [
        ("unlink", "Deleting is not possible through Claude"),
        ("UNLINK", "Deleting is not possible through Claude"),
        ("action_unlink_lines", "Deleting is not possible through Claude"),
        ("_action_confirm", "private"),
        ("_action_private", "private"),
        ("write", "cannot be run as a button"),
        ("copy", "cannot be run as a button"),
        ("message_post", "cannot be run as a button"),
        ("payment_action_capture", "capture"),
        ("action_cancel", "Cancelling is switched off for Claude"),
        ("action_draft", "Resetting to draft is switched off for Claude"),
        ("action_quotation_send", "Sending e-mails or messages to people"),
        ("action_hidden_helper", "not a button"),
        ("Action_Confirm", "not a button"),  # case games: not the button Odoo shows
        ("action_confirm ", "private or invalid"),
        ("button_immediate_uninstall", "install"),
    ],
)
async def test_actions_that_are_refused(svc, fake, method, needle):
    with pytest.raises(PolicyViolation, match=needle):
        await svc.preview_action("sale.order", [5], method, None)
    svc_np = make_service(fake, svc.shared, mcp_require_preview=False)
    with pytest.raises(PolicyViolation):
        await svc_np.run_action("sale.order", [5], method, None, None)
    assert changes(fake) == []


async def test_action_method_must_be_text(svc):
    with pytest.raises(ValidationFailed):
        await svc.preview_action("sale.order", [5], ["action_confirm"], None)


async def test_extra_allowed_methods_open_a_non_button(fake):
    svc = make_service(fake, mcp_extra_allowed_methods=["sale.order:action_hidden_helper"])
    preview = await svc.preview_action("sale.order", [5], "action_hidden_helper", None)
    await svc.run_action("sale.order", [5], "action_hidden_helper", None, preview["confirm_token"])
    assert fake.calls_to("action_hidden_helper")[0].ids == [5]


async def test_action_token_is_bound_to_method_ids_and_state(svc, fake):
    preview = await svc.preview_action("sale.order", [5], "action_confirm", None)
    with pytest.raises(ConfirmationRequired):
        await svc.run_action("sale.order", [5], "action_mass_confirm", None, preview["confirm_token"])
    with pytest.raises(ConfirmationRequired):
        await svc.run_action("sale.order", [5, 6], "action_confirm", None, preview["confirm_token"])
    fake.touch("sale.order", 5, state="sent")
    with pytest.raises(ConfirmationRequired):
        await svc.run_action("sale.order", [5], "action_confirm", None, preview["confirm_token"])
    assert changes(fake) == []


async def test_action_refuses_missing_records(svc, fake):
    with pytest.raises(ValidationFailed, match="do not exist"):
        await svc.preview_action("sale.order", [5, 987654321], "action_confirm", None)
    assert changes(fake) == []


@pytest.mark.parametrize("model", ["res.users", "ir.cron", "mail.mail", "res.partner.bank"])
async def test_actions_on_protected_models_are_refused_before_loading_views(fake, model):
    with pytest.raises(PolicyViolation):
        await make_service(fake).preview_action(model, [1], "action_confirm", None)
    assert fake.calls == []


async def test_action_is_refused_in_read_only_mode(fake):
    svc = make_service(fake, mcp_access_mode="read_only", mcp_require_preview=False)
    with pytest.raises(PolicyViolation):
        await svc.run_action("sale.order", [5], "action_confirm", None, None)
    assert changes(fake) == []


async def test_action_result_wizard_is_explained(svc, fake):
    fake.action_results[("sale.order", "action_confirm")] = {
        "type": "ir.actions.act_window", "res_model": "sale.order.cancel", "target": "new", "res_id": False,
        "name": "Wizard", "context": {"active_ids": [5], "default_order_id": 5, "tracking_disable": True},
    }
    preview = await svc.preview_action("sale.order", [5], "action_confirm", None)
    result = await svc.run_action("sale.order", [5], "action_confirm", None, preview["confirm_token"])
    assert result["opened"]["model"] == "sale.order.cancel"
    assert "sale.order.cancel" in result["next_step"]
    assert "tracking_disable" not in result["next_step"], "only harmless context keys are suggested"


# Regression test (was a bug, now fixed): BUG: service.py _prepare_action() accepts default_<field> context keys without validation (_context_defaults_check only runs for create), so a button can create records with e.g. default_state
async def test_action_context_defaults_are_validated(svc, fake):
    with pytest.raises((ValidationFailed, PolicyViolation)):
        await svc.preview_action("sale.order", [5], "action_confirm", {"default_state": "sale"})


# ======================================================================================= reads


async def test_read_reports_not_found_ids(svc, fake):
    out = await svc.read("res.partner", [1, 987654321], ["name"])
    assert [r["name"] for r in out["records"]] == ["Acme Corp"]
    assert out["not_found_ids"] == [987654321]
    assert any("Do not invent data" in n for n in out["notes"])
    read = [c for c in fake.calls_to("read") if c.model == "res.partner"][-1]
    assert read.ids == [1], "missing ids are never sent to read()"


async def test_read_refuses_secrets_and_blocked_models(svc, fake):
    with pytest.raises(ValidationFailed, match="credential"):
        await svc.read("res.users", [7], ["login", "password"])
    with pytest.raises(PolicyViolation):
        await svc.read("ir.config_parameter", [1], ["key", "value"])
    with pytest.raises(ValidationFailed):
        await svc.read("res.partner", [], ["name"])
    with pytest.raises(ValidationFailed, match="limit is 3"):
        await make_service(fake, mcp_max_read_records=3).read("res.partner", [1, 2, 3, 4], ["name"])


async def test_default_fields_skip_noise_and_secrets(svc, fake):
    fields = await svc._default_fields("crm.lead")
    assert fields[0] == "id"
    assert {"name", "partner_id", "stage_id", "expected_revenue", "type"} <= set(fields)
    assert not any(f.startswith(("message_", "activity_", "access_")) for f in fields)
    assert "x_api_key" not in fields and "access_token" not in fields
    assert len(fields) <= 16


async def test_search_uses_default_fields_and_formats_rows(svc, fake):
    out = await svc.search("crm.lead", None, None, None, None, None, False)
    sent = fake.calls_to("search_read")[0]
    assert "access_token" not in sent.kwargs["fields"] and "message_ids" not in sent.kwargs["fields"]
    assert sent.context == {"bin_size": True}
    big = next(r for r in out["records"] if r["id"] == 100)
    assert big["partner_id"] == {"id": 1, "name": "Acme Corp"}
    small = next(r for r in out["records"] if r["id"] == 101)
    assert small["partner_id"] is None
    assert out["total_matching"] == 2 and out["has_more"] is False


async def test_search_validates_domain_order_and_paging(svc, fake):
    with pytest.raises(ValidationFailed, match="credential"):
        await svc.search("res.users", [["password", "=", "x"]], ["name"], None, None, None, False)
    with pytest.raises(ValidationFailed, match="cannot sort"):
        await svc.search("crm.lead", None, ["name"], None, None, "access_token desc", False)
    with pytest.raises(ValidationFailed, match="order must look like"):
        await svc.search("crm.lead", None, ["name"], None, None, "name; DROP TABLE crm_lead", False)
    with pytest.raises(ValidationFailed, match="cannot sort"):
        await svc.search("crm.lead", None, ["name"], None, None, "nmae desc", False)
    for limit in (0, -1, "5"):
        with pytest.raises(ValidationFailed, match="limit"):
            await svc.search("crm.lead", None, ["name"], limit, None, None, False)
    with pytest.raises(ValidationFailed, match="offset"):
        await svc.search("crm.lead", None, ["name"], None, -1, None, False)
    assert fake.calls_to("search_read") == []


async def test_search_limit_is_capped_and_archived_flag_is_passed(fake):
    svc = make_service(fake, mcp_max_read_records=1)
    out = await svc.search("crm.lead", [["type", "in", ["lead", "opportunity"]]], ["name"], 500, None, "name asc, id desc", True)
    sent = fake.calls_to("search_read")[0]
    assert sent.kwargs["limit"] == 1 and sent.kwargs["order"] == "name asc, id desc"
    assert sent.context == {"bin_size": True, "active_test": False}
    assert out["has_more"] is True and any("offset=1" in n for n in out["notes"])


# Regression test (was a bug, now fixed): BUG (defence in depth): service.py aggregate() passes `order` to Odoo unvalidated, unlike search(); e.g. 'access_token:max desc' orders groups by a secret field
async def test_aggregate_order_is_validated(svc, fake):
    fake.action_results[("crm.lead", "formatted_read_group")] = []
    with pytest.raises(ValidationFailed):
        await svc.aggregate("crm.lead", ["stage_id"], None, None, None, "access_token:max desc", False)


async def test_aggregate_validates_groupby_and_measures(svc, fake):
    for group_by in ([], ["a", "b", "c", "d"], ["access_token"], ["name:month"], ["stage_id:hour"], "stage_id"):
        with pytest.raises(ValidationFailed):
            await svc.aggregate("crm.lead", group_by, None, None, None, None, False)
    for measures in (["access_token:max"], ["name:sum"], ["expected_revenue:median"], ["expected_revenue"]):
        with pytest.raises(ValidationFailed):
            await svc.aggregate("crm.lead", ["stage_id"], measures, None, None, None, False)
    fake.action_results[("crm.lead", "formatted_read_group")] = [
        {"stage_id": [1, "New"], "expected_revenue:sum": 1000.0, "__count": 1}
    ]
    out = await svc.aggregate("crm.lead", ["stage_id"], ["expected_revenue:sum"], None, None, None, False)
    assert out["groups"] == [{"stage_id": {"id": 1, "name": "New"}, "expected_revenue:sum": 1000.0, "count": 1}]


async def test_list_models_hides_blocked_models(svc, fake):
    fake.action_results[("ir.model", "get_available_models")] = [
        {"model": "crm.lead", "display_name": "Lead"},
        {"model": "ir.config_parameter", "display_name": "System Parameter"},
        {"model": "res.users", "display_name": "User"},
        {"model": "res.users.apikeys", "display_name": "API keys"},
    ]
    out = await svc.list_models(None, None)
    names = {m["model"]: m for m in out["models"]}
    assert set(names) == {"crm.lead", "res.users"}
    assert names["crm.lead"]["ai_can_change"] is True and names["res.users"]["ai_can_change"] is False


async def test_list_models_falls_back_for_old_odoo(svc, fake):
    fake.errors[("ir.model", "get_available_models")] = OdooError("no", kind="missing")
    fake.records["ir.model"] = {1: {"model": "crm.lead", "name": "Lead"}, 2: {"model": "ir.cron", "name": "Cron"}}
    out = await svc.list_models("lead", None)
    assert [m["model"] for m in out["models"]] == ["crm.lead"]


async def test_describe_model_hides_secrets_and_explains_write_rules(svc):
    out = await svc.describe_model("crm.lead", None, None)
    fields = {f["name"]: f for f in out["fields"]}
    assert "x_api_key" not in fields and "access_token" not in fields
    assert "message_ids" not in fields and "hidden_technical_fields" in out
    assert fields["name"]["ai_can_write"] is True and fields["name"]["required"] is True
    assert fields["active"]["ai_can_write"] is False and "archiving is switched off" in fields["active"]["why_not"]
    assert fields["x_cron_id"]["ai_can_write"] is False
    with pytest.raises(PolicyViolation):
        await svc.describe_model("res.users.apikeys", None, None)


async def test_whoami_never_claims_delete_rights(svc):
    out = await svc.whoami()
    assert out["permissions"]["can_delete_records"] is False
    assert out["user"]["id"] == 7


# ======================================================================================= notes and messages


async def test_add_note_is_escaped_internal_and_normalises_the_id(svc, fake):
    fake._m_message_post = lambda model, ids, context, **kw: [77]  # some Odoo versions return a list
    out = await svc.add_note("crm.lead", 100, "Checked.\n<script>alert(1)</script>")
    post = fake.calls_to("message_post")[0]
    assert post.kwargs["body"] == "Checked.<br/>&lt;script&gt;alert(1)&lt;/script&gt;"
    assert post.kwargs["subtype_xmlid"] == "mail.mt_note" and post.kwargs["message_type"] == "comment"
    assert "partner_ids" not in post.kwargs
    assert out["logged_note_id"] == 77


async def test_add_note_checks(svc, fake):
    with pytest.raises(ValidationFailed, match="no chatter"):
        await svc.add_note("crm.tag", 1, "hi")
    with pytest.raises(ValidationFailed, match="does not exist"):
        await svc.add_note("crm.lead", 987654321, "hi")
    with pytest.raises(ValidationFailed):
        await svc.add_note("crm.lead", True, "hi")
    with pytest.raises(ValidationFailed, match="empty"):
        await svc.add_note("crm.lead", 100, "   ")
    with pytest.raises(ValidationFailed, match="too long"):
        await svc.add_note("crm.lead", 100, "x" * 20_001)
    with pytest.raises(PolicyViolation):
        await svc.add_note("ir.cron", 1, "hi")
    with pytest.raises(PolicyViolation):
        await make_service(fake, mcp_access_mode="read_only").add_note("crm.lead", 100, "hi")
    assert changes(fake) == []


# Regression test (was a bug, now fixed): BUG: service.py add_note() only calls check_read(), so notes can be posted on models an admin made read-only (MCP_READONLY_MODELS) or left out of MCP_WRITABLE_MODELS
async def test_add_note_respects_model_write_restrictions(fake):
    svc = make_service(fake, mcp_readonly_models=["crm.lead"])
    with pytest.raises(PolicyViolation):
        await svc.add_note("crm.lead", 100, "hi")


async def test_messages_need_the_outbound_flag_and_always_a_token(fake):
    with pytest.raises(PolicyViolation, match="switched off for Claude") as info:
        await make_service(fake).preview_message("crm.lead", 100, "Hello")
    assert "MCP_" not in str(info.value)  # Claude is told in plain words, not the operator's setting name

    svc = make_service(fake, mcp_allow_outbound_messages=True, mcp_require_preview=False)
    fake.followers = [{"partner_id": [2, "Jane Buyer"]}, {"partner_id": [1, "Acme Corp"]}, {"partner_id": False}]
    preview = await svc.preview_message("crm.lead", 100, "Hello <b>Jane</b>")
    assert preview["recipients"] == ["Acme Corp", "Jane Buyer"]
    with pytest.raises(ConfirmationRequired):  # even with MCP_REQUIRE_PREVIEW=false
        await svc.send_message("crm.lead", 100, "Hello <b>Jane</b>", None)
    with pytest.raises(ConfirmationRequired):
        await svc.send_message("crm.lead", 100, "Hello <b>everyone</b>", preview["confirm_token"])
    with pytest.raises(ConfirmationRequired):
        await svc.send_message("crm.lead", 101, "Hello <b>Jane</b>", preview["confirm_token"])
    assert changes(fake) == []
    await svc.send_message("crm.lead", 100, "Hello <b>Jane</b>", preview["confirm_token"])
    post = fake.calls_to("message_post")[0]
    assert post.kwargs["subtype_xmlid"] == "mail.mt_comment"
    assert post.kwargs["body"] == "Hello &lt;b&gt;Jane&lt;/b&gt;"


# Regression test (was a bug, now fixed): BUG: message confirm tokens are not single-use and carry no fingerprint (service.py _message_payload), so an approved message can be re-sent to customers for 15 minutes
async def test_message_token_cannot_be_replayed(fake):
    svc = make_service(fake, mcp_allow_outbound_messages=True)
    preview = await svc.preview_message("crm.lead", 100, "Your quote is ready")
    await svc.send_message("crm.lead", 100, "Your quote is ready", preview["confirm_token"])
    with pytest.raises(ConfirmationRequired):
        await svc.send_message("crm.lead", 100, "Your quote is ready", preview["confirm_token"])


# ======================================================================================= rate limits and audit


async def test_read_rate_limit_trips(fake):
    svc = make_service(fake, mcp_reads_per_minute=3)
    for _ in range(3):
        await svc.whoami()
    with pytest.raises(RateLimited, match="3 per minute"):
        await svc.whoami()


async def test_write_rate_limit_trips_before_anything_is_sent(fake):
    svc = make_service(fake, mcp_writes_per_minute=1, mcp_require_preview=False)
    await svc.update("crm.lead", [100], {"probability": 1}, None, None)
    with pytest.raises(RateLimited):
        await svc.update("crm.lead", [100], {"probability": 2}, None, None)
    assert changes(fake) == ["crm.lead.write"]


def test_rate_limiter_window_slides_and_is_per_user_and_kind(monkeypatch):
    now = {"t": 1000.0}
    import sahajta_odoo_mcp.state as state_module

    monkeypatch.setattr(state_module.time, "monotonic", lambda: now["t"])
    limiter = RateLimiter(reads_per_minute=2, writes_per_minute=1)
    limiter.check("alice", "read")
    limiter.check("alice", "read")
    with pytest.raises(RateLimited):
        limiter.check("alice", "read")
    limiter.check("bob", "read")  # other users are unaffected
    limiter.check("alice", "write")  # writes have their own budget
    now["t"] += 61
    limiter.check("alice", "read")  # window moved on


async def test_audit_log_records_names_never_values(tmp_path, fake):
    log = tmp_path / "audit.jsonl"
    svc = make_service(fake, make_shared(str(log), mcp_require_preview=False))
    await svc.update("crm.lead", [100], {"description": "TOP-SECRET-VALUE"}, None, None)
    await svc.add_note("crm.lead", 100, "ANOTHER-SECRET-NOTE")
    with pytest.raises(PolicyViolation):
        await svc.read("ir.config_parameter", [1], ["value"])
    text = log.read_text()
    assert "TOP-SECRET-VALUE" not in text and "ANOTHER-SECRET-NOTE" not in text
    entries = [json.loads(line) for line in text.splitlines()]
    assert entries[0]["tool"] == "odoo_update" and entries[0]["fields"] == ["description"] and entries[0]["ids"] == [100]
    assert entries[-1]["outcome"] == "blocked"


# ======================================================================================= setup areas, end to end


async def test_a_setting_is_changed_by_a_new_settings_record_then_save(setup_fake):
    svc = make_service(setup_fake)
    values = [{"group_analytic_accounting": True, "quotation_validity_days": 15}]
    preview = await svc.preview_create("res.config.settings", values, None)
    created = await svc.create("res.config.settings", values, None, preview["confirm_token"])
    settings_id = created["created"][0]["id"]
    # Odoo 19 draws the Save button in its web client, so it is not in the view: it is still allowed
    preview = await svc.preview_action("res.config.settings", [settings_id], "execute", None)
    await svc.run_action("res.config.settings", [settings_id], "execute", None, preview["confirm_token"])
    assert [c.ids for c in setup_fake.calls_to("execute")] == [[settings_id]]
    with pytest.raises(PolicyViolation, match="Save button"):
        await svc.preview_action("res.config.settings", [settings_id], "action_open_template_user", None)
    with pytest.raises(ValidationFailed, match="Odoo app"):
        await svc.preview_create("res.config.settings", [{"module_crm": True}], None)
    with pytest.raises(PolicyViolation, match="new settings record"):
        await svc.preview_update("res.config.settings", [settings_id], {"quotation_validity_days": 30}, None)


async def test_a_new_e_mail_template_is_made_only_for_business_records(setup_fake):
    svc = make_service(setup_fake)
    setup_fake.records["ir.model"][95] = {"model": "account.tax", "name": "Tax"}
    values = [{"name": "Follow-up", "model_id": 94, "subject": "Following up on {{ object.name }}", "body_html": "<p>Hi</p>"}]
    preview = await svc.preview_create("mail.template", values, None)
    assert "sends nothing by itself" in " ".join(preview["warnings"])
    created = await svc.create("mail.template", values, None, preview["confirm_token"])
    assert setup_fake.records["mail.template"][created["created"][0]["id"]]["model_id"] == 94
    for model_id in (92, 93, 95):  # res.users (security), mail.template (e-mail setup), account.tax (accounting setup)
        with pytest.raises(PolicyViolation, match="only for business records Claude may change"):
            await svc.preview_create("mail.template", [{**values[0], "model_id": model_id}], None)
    with pytest.raises(ValidationFailed, match="name is required"):
        await svc.preview_create("mail.template", [{"model_id": 94, "subject": "x"}], None)
    with pytest.raises(ValidationFailed, match="model_id is required"):
        await svc.preview_create("mail.template", [{"name": "x", "subject": "x"}], None)
    for name, value in (("email_from", "ceo@elsewhere.example"), ("attachment_ids", [[6, 0, [1]]]), ("mail_server_id", 1)):
        with pytest.raises(ValidationFailed, match="only these fields"):  # no sender, attachments or mail server
            await svc.preview_create("mail.template", [{**values[0], name: value}], None)
    with pytest.raises(ValidationFailed, match="only when the record is created"):  # never moved to another model
        await svc.preview_update("mail.template", [20], {"model_id": 91}, None)
    assert changes(setup_fake) == ["mail.template.create"]


async def test_accounting_setup_changes_are_refused_before_anything_is_sent(setup_fake):
    svc = make_service(setup_fake, mcp_require_preview=False, mcp_allow_archive=True)
    with pytest.raises(PolicyViolation, match="past reports and GST returns"):
        await svc.update("account.tax", [1], {"amount": 12.0}, None, None)
    with pytest.raises(PolicyViolation, match="accounting setup"):
        await svc.run_action("account.tax", [1], "action_archive", None, None)
    assert changes(setup_fake) == []
    created = await svc.create("account.tax", [{"name": "GST 5%", "amount": 5.0}], None, None)
    assert created["created"][0]["id"]


async def test_automation_rules_can_be_described_and_read_without_their_secrets(setup_fake):
    svc = make_service(setup_fake)
    out = await svc.describe_model("base.automation", None, None)
    names = {f["name"] for f in out["fields"]}
    assert {"trigger", "filter_domain", "action_server_ids"} <= names and not {"url", "webhook_uuid"} & names
    assert out["ai_can_change_records"] is True
    with pytest.raises(ValidationFailed, match="cannot group by 'webhook_uuid'"):
        await svc.aggregate("base.automation", ["webhook_uuid"], None, None, None, None, False)
    with pytest.raises(ValidationFailed, match="hidden for safety"):
        await svc.read("ir.actions.server", [400], ["name", "code"])
    rows = (await svc.read("ir.actions.server", [400], ["name", "state"]))["records"]
    assert rows[0]["name"] == "Plan a call"
