"""How the service uses the policy's setup rules: preview warnings, readable values, and checks before a button."""

from __future__ import annotations

import pytest

from conftest import AUDIT_FIELDS, FakeOdoo, _f, add_setup_models
from sahajta_odoo_mcp.errors import OdooMCPError, PolicyViolation, ValidationFailed
from test_service_offline import make_service


@pytest.fixture
def fake() -> FakeOdoo:
    return add_setup_models(FakeOdoo())


async def test_template_previews_warn_that_every_future_email_changes(fake):
    svc = make_service(fake, mcp_access_mode="read_write")
    preview = await svc.preview_update("mail.template", [20], {"email_cc": "accounts@example.com"}, None)
    expected = svc.policy.change_warnings("mail.template", "write", ["email_cc"])
    assert expected and all(warning in str(preview) for warning in expected)


async def test_analytic_distribution_is_shown_in_plain_words(fake):
    fake.records.setdefault("account.move.line", {})[60] = {"name": "Consulting"}
    svc = make_service(fake, mcp_access_mode="read_write")
    preview = await svc.preview_update("account.move.line", [60], {"analytic_distribution": {"7": 60, "8": 40}}, None)
    assert "Project Alpha 60%" in str(preview) and "Project Beta 40%" in str(preview)


async def test_refusals_name_the_configured_admin(fake):
    svc = make_service(fake, mcp_access_mode="read_only", mcp_admin_contact="Pranamya")
    with pytest.raises(OdooMCPError, match="ask Pranamya"):
        await svc.preview_update("crm.lead", [100], {"name": "x"}, None)


async def test_saving_settings_that_would_install_an_app_is_refused(fake):
    fake.records["res.config.settings"] = {70: {"company_id": [1, "Sahajta"], "module_crm": True}}
    fake.defaults["res.config.settings"] = {"module_crm": False}  # CRM is not installed today
    svc = make_service(fake, mcp_access_mode="read_write")
    with pytest.raises(PolicyViolation, match="install or remove an app"):
        await svc.preview_action("res.config.settings", [70], "execute", None)


async def test_saving_settings_that_leave_apps_alone_is_allowed(fake):
    fake.records["res.config.settings"] = {70: {"company_id": [1, "Sahajta"], "module_crm": True}}
    fake.defaults["res.config.settings"] = {"module_crm": True}
    svc = make_service(fake, mcp_access_mode="read_write")
    preview = await svc.preview_action("res.config.settings", [70], "execute", None)
    assert preview["confirm_token"]


async def test_a_payment_dialog_holding_a_saved_card_is_refused_in_two_steps_too(fake):
    fake.schema["account.payment.register"] = {
        **AUDIT_FIELDS,
        "amount": _f("monetary", "Amount"),
        "payment_token_id": _f("many2one", "Saved Payment Token", relation="payment.token"),
    }
    fake.records["account.payment.register"] = {80: {"amount": 100.0, "payment_token_id": [5, "Visa ****4242"]}}
    fake.views["account.payment.register"] = {"views": {"form": {"arch": (
        '<form><footer><button name="action_create_payments" string="Create Payment" type="object"/></footer></form>'
    )}}}
    svc = make_service(fake, mcp_access_mode="read_write")
    with pytest.raises(PolicyViolation, match="saved card"):
        await svc.preview_action("account.payment.register", [80], "action_create_payments", None)


def _with_matching_rules(fake: FakeOdoo) -> FakeOdoo:
    fake.schema["account.reconcile.model"] = {
        **AUDIT_FIELDS,
        "name": _f("char", "Name", required=True),
        "active": _f("boolean", "Active"),
        "match_label_param": _f("char", "Label Parameter"),
        "trigger": _f("selection", "Trigger", selection=[["manual", "Manual"], ["auto_reconcile", "Automated"]]),
    }
    fake.records["account.reconcile.model"] = {90: {"name": "Bank fees", "trigger": "manual", "active": True}}
    return fake


async def test_editing_a_matching_rule_previews_with_its_warnings(fake):
    svc = make_service(_with_matching_rules(fake), mcp_access_mode="read_write")
    preview = await svc.preview_update("account.reconcile.model", [90], {"match_label_param": "BANK CHG"}, None)
    assert "past entries stay as they are" in str(preview) and "Sets this rule to Automated" not in str(preview)
    preview = await svc.preview_update("account.reconcile.model", [90], {"trigger": "auto_reconcile"}, None)
    assert "Sets this rule to Automated" in str(preview)
    await svc.update("account.reconcile.model", [90], {"trigger": "auto_reconcile"}, None, preview["confirm_token"])
    assert fake.records["account.reconcile.model"][90]["trigger"] == "auto_reconcile"


async def test_a_tax_rate_stays_unchangeable(fake):
    svc = make_service(fake, mcp_access_mode="read_write")
    fake.schema["account.tax"]["amount"] = {"type": "float", "string": "Amount", "store": True}
    fake.records["account.tax"] = {1: {"name": "GST 18%", "amount": 18.0}}
    with pytest.raises(ValidationFailed, match="past reports and GST returns"):
        await svc.preview_update("account.tax", [1], {"amount": 12.0}, None)
