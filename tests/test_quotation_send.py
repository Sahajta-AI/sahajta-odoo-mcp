"""Sending a quotation by e-mail in one approval: Odoo's Send button opens its e-mail composer with the quotation
template; the preview shows what Odoo's own composer would send, the commit sends exactly that.

The composer (mail.compose.message) stays read-only for Claude otherwise. Odoo is the in-memory FakeOdoo (conftest);
every test also asserts (fixture ``no_unlink_ever``) that no method containing "unlink" reached it.
"""

from __future__ import annotations

import pytest

from conftest import AUDIT_FIELDS, FakeOdoo, _f
from sahajta_odoo_mcp.errors import ConfirmationRequired, OdooError, PolicyViolation, ValidationFailed
from test_service_offline import make_service

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

CHANGES = {"create", "write", "action_send_mail", "message_post", "action_quotation_sent"}
SENT_BY_ODOO = {  # what Odoo 19's sale.order.action_quotation_send returns for one quotation
    "name": "Send", "type": "ir.actions.act_window", "view_mode": "form", "res_model": "mail.compose.message",
    "views": [[False, "form"]], "view_id": False, "target": "new",
    "context": {
        "default_model": "sale.order", "default_res_ids": [5], "default_composition_mode": "comment",
        "default_email_layout_xmlid": "mail.mail_notification_layout_with_responsible_signature",
        "email_notification_allow_footer": True, "hide_mail_template_management_options": True, "proforma": False,
        "force_email": True, "default_template_id": 20, "mark_so_as_sent": True,
    },
}
COMPOSER_FORM = """
<form string="Compose Email">
  <group>
    <field name="composition_mode" invisible="1"/><field name="model" invisible="1"/><field name="res_ids" invisible="1"/>
    <field name="message_type" invisible="1"/><field name="mail_server_id" invisible="1"/>
    <field name="partner_ids"/><field name="subject"/>
  </group>
  <field name="body"/><field name="attachment_ids"/>
  <footer>
    <button string="Send" name="action_send_mail" type="object" class="btn-primary o_mail_send"/>
    <button string="Discard" special="cancel"/>
    <field name="template_id"/><field name="scheduled_date"/>
  </footer>
</form>
"""
BODY = "<p>Hello,</p><p>Your quotation <strong>S00005</strong> amounting in <strong>₹ 200.00</strong> is ready for review.</p>"


def changes(fake: FakeOdoo) -> list[str]:
    return [f"{c.model}.{c.method}" for c in fake.calls if c.method in CHANGES]


@pytest.fixture
def fake() -> FakeOdoo:
    fake = FakeOdoo()
    fake.schema["mail.compose.message"] = {
        **AUDIT_FIELDS,
        "composition_mode": _f("selection", "Composition mode", selection=[["comment", "Post on a document"], ["mass_mail", "Mass Mailing"]]),
        "model": _f("char", "Related Document Model"),
        "res_ids": _f("text", "Related Document IDs"),
        "message_type": _f("selection", "Type", selection=[["comment", "Comment"]]),
        "mail_server_id": _f("many2one", "Outgoing mail server", relation="ir.mail_server"),
        "partner_ids": _f("many2many", "Additional Contacts", relation="res.partner"),
        "subject": _f("char", "Subject"),
        "body": _f("html", "Contents"),
        "attachment_ids": _f("many2many", "Attachments", relation="ir.attachment"),
        "template_id": _f("many2one", "Use template", relation="mail.template"),
        "scheduled_date": _f("char", "Scheduled Date"),
    }
    fake.schema["mail.template"] = {"name": _f("char", "Name")}
    fake.schema["ir.attachment"] = {"name": _f("char", "Name")}
    fake.records["mail.template"] = {20: {"name": "Sales: Send Quotation"}}
    fake.records["ir.attachment"] = {700: {"name": "Quotation - S00005.pdf"}}
    fake.records["res.partner"][1]["email"] = "accounts@acme.example"
    fake.views["mail.compose.message"] = {"views": {"form": {"arch": COMPOSER_FORM}}}
    fake.action_results[("sale.order", "action_quotation_send")] = SENT_BY_ODOO
    fake.action_results[("mail.compose.message", "action_send_mail")] = {
        "type": "ir.actions.client", "tag": "action_send_mail_callback", "params": {"record_name": "S00005"},
    }
    # what Odoo's composer fills in from the template (its onchange), on top of the button's context
    fake.filled["mail.compose.message"] = {
        "partner_ids": [1], "subject": "Sahajta Quotation (Ref S00005)", "template_id": 20, "attachment_ids": [700],
        "body": BODY, "message_type": "comment",
    }
    return fake


@pytest.fixture
def svc(fake):
    return make_service(fake, mcp_allow_outbound_messages=True)


async def test_the_preview_shows_what_odoo_would_send_and_sends_nothing(svc, fake):
    preview = await svc.preview_action("sale.order", [5], "action_quotation_send", None)
    dialog = preview["dialog"]
    assert dialog["To (partner_ids)"] == ["Acme Corp <accounts@acme.example>"]
    assert dialog["Subject (subject)"] == "Sahajta Quotation (Ref S00005)"
    assert dialog["E-mail template (template_id)"] == "Sales: Send Quotation"
    assert dialog["Attachments (attachment_ids)"] == ["Quotation - S00005.pdf"]
    assert dialog["Message (body)"].startswith("Hello,\nYour quotation S00005 amounting in ₹ 200.00")
    assert changes(fake) == [], "a preview sends and changes nothing"
    assert "marks the quotation as sent" in " ".join(preview["warnings"])
    [button] = fake.calls_to("action_quotation_send")  # only checks the order and picks the template (Odoo 19 source)
    assert button.ids == [5] and button.context["validate_analytic"] is True
    onchange = fake.calls_to("onchange")[-1]
    assert onchange.model == "mail.compose.message" and onchange.context["default_res_ids"] == [5]
    assert {"res_ids", "composition_mode", "model", "message_type"} <= set(onchange.kwargs["fields_spec"])
    assert "mail_server_id" not in onchange.kwargs["fields_spec"]  # points at a blocked model


async def test_the_commit_sends_exactly_what_was_shown_in_one_approval(svc, fake):
    preview = await svc.preview_action("sale.order", [5], "action_quotation_send", None)
    result = await svc.run_action("sale.order", [5], "action_quotation_send", None, preview["confirm_token"])
    assert changes(fake) == ["mail.compose.message.create", "mail.compose.message.action_send_mail"]
    create = fake.calls_to("create")[0]
    assert create.kwargs["vals_list"] == [{
        "partner_ids": [[6, 0, [1]]], "subject": "Sahajta Quotation (Ref S00005)", "template_id": 20,
        "attachment_ids": [[6, 0, [700]]], "body": BODY,
    }]
    assert create.context["default_res_ids"] == [5] and create.context["mark_so_as_sent"] is True
    assert create.context["default_composition_mode"] == "comment" and "validate_analytic" not in create.context
    assert fake.calls_to("action_send_mail")[0].ids == [1000]
    assert len(fake.calls_to("action_quotation_send")) == 2  # preview and commit each asked Odoo; neither sent
    assert "posted the e-mail" in result["e-mail"] and result["records_now"][0]["name"] == "S00005"
    with pytest.raises(ConfirmationRequired):  # one approval, one e-mail
        await svc.run_action("sale.order", [5], "action_quotation_send", None, preview["confirm_token"])
    assert len(fake.calls_to("action_send_mail")) == 1


async def test_a_changed_e_mail_is_not_sent_on_the_old_approval(svc, fake):
    preview = await svc.preview_action("sale.order", [5], "action_quotation_send", None)
    fake.filled["mail.compose.message"]["subject"] = "Something else"  # e.g. the template was edited meanwhile
    with pytest.raises(ConfirmationRequired, match="does not match"):
        await svc.run_action("sale.order", [5], "action_quotation_send", None, preview["confirm_token"])
    assert changes(fake) == []


async def test_the_approval_covers_the_whole_e_mail_not_only_the_start_shown(svc, fake):
    long_body = BODY + "<p>" + "Terms and conditions apply. " * 80 + "</p>"
    fake.filled["mail.compose.message"]["body"] = long_body
    preview = await svc.preview_action("sale.order", [5], "action_quotation_send", None)
    assert preview["dialog"]["Message (body)"].endswith(" …"), "the preview shows only the start of a long body"
    fake.filled["mail.compose.message"]["body"] = long_body + "<p>Pay to account 000123 instead.</p>"
    with pytest.raises(ConfirmationRequired, match="does not match"):
        await svc.run_action("sale.order", [5], "action_quotation_send", None, preview["confirm_token"])
    assert changes(fake) == []


async def test_a_new_quotation_pdf_does_not_stop_the_approved_e_mail(svc, fake):
    preview = await svc.preview_action("sale.order", [5], "action_quotation_send", None)
    fake.records["ir.attachment"][701] = {"name": "Quotation - S00005.pdf"}  # Odoo makes the PDF again on each opening
    fake.filled["mail.compose.message"]["attachment_ids"] = [701]
    await svc.run_action("sale.order", [5], "action_quotation_send", None, preview["confirm_token"])
    assert fake.calls_to("create")[0].kwargs["vals_list"][0]["attachment_ids"] == [[6, 0, [701]]]


async def test_an_e_mail_whose_answer_was_lost_is_never_sent_twice(svc, fake):
    preview = await svc.preview_action("sale.order", [5], "action_quotation_send", None)
    fake.errors[("mail.compose.message", "action_send_mail")] = OdooError("timed out", kind="timeout")
    with pytest.raises(OdooError) as info:
        await svc.run_action("sale.order", [5], "action_quotation_send", None, preview["confirm_token"])
    assert "may already have" in str(info.value) and "nothing was changed" not in str(info.value).lower()
    del fake.errors[("mail.compose.message", "action_send_mail")]
    with pytest.raises(ConfirmationRequired, match="already used"):
        await svc.run_action("sale.order", [5], "action_quotation_send", None, preview["confirm_token"])


async def test_followers_who_also_get_it_are_named(svc, fake):
    fake.followers = [{"res_id": 5, "partner_id": [1, "Acme Corp"]}, {"res_id": 5, "partner_id": [2, "Jane Buyer"]}]
    preview = await svc.preview_action("sale.order", [5], "action_quotation_send", None)
    assert preview["dialog"]["Also notified: followers of the record (followers)"] == ["Jane Buyer"]


async def test_a_recipient_without_an_e_mail_address_is_refused_before_approval(svc, fake):
    fake.filled["mail.compose.message"]["partner_ids"] = [3]  # Globex has no e-mail address
    with pytest.raises(ValidationFailed, match="Globex .no e-mail address. has no e-mail address"):
        await svc.preview_action("sale.order", [5], "action_quotation_send", None)


async def test_the_e_mail_is_sent_as_odoo_writes_it(svc, fake):
    with pytest.raises(ValidationFailed, match="exactly as Odoo's template writes it"):
        await svc.preview_action("sale.order", [5], "action_quotation_send", None, {"subject": "Hi"})
    with pytest.raises(ValidationFailed, match="one sale.order record at a time"):
        await svc.preview_action("sale.order", [5, 6], "action_quotation_send", None)
    assert fake.calls_to("action_quotation_send") == []


@pytest.mark.parametrize(
    "context",
    [
        {**SENT_BY_ODOO["context"], "default_res_ids": [6]},  # another order
        {**SENT_BY_ODOO["context"], "default_composition_mode": "mass_mail"},
        {key: value for key, value in SENT_BY_ODOO["context"].items() if key != "default_template_id"},
    ],
)
async def test_a_composer_odoo_opened_differently_is_refused(svc, fake, context):
    fake.action_results[("sale.order", "action_quotation_send")] = {**SENT_BY_ODOO, "context": context}
    with pytest.raises(ValidationFailed, match="send it from Odoo"):
        await svc.preview_action("sale.order", [5], "action_quotation_send", None)
    assert fake.calls_to("onchange") == [] and changes(fake) == []


async def test_without_the_e_mail_switch_nothing_is_asked_of_odoo(fake):
    svc = make_service(fake, mcp_allow_outbound_messages=False)
    with pytest.raises(PolicyViolation, match="e-mails"):
        await svc.preview_action("sale.order", [5], "action_quotation_send", None)
    assert fake.calls_to("action_quotation_send") == [] and fake.calls_to("onchange") == []


async def test_the_composer_stays_read_only_otherwise(svc, fake):
    fake.records["mail.compose.message"] = {40: {"subject": "x"}}
    with pytest.raises(PolicyViolation, match="e-mails and messages"):
        await svc.preview_create("mail.compose.message", [{"subject": "Hi", "body": "<p>x</p>"}], None)
    with pytest.raises(PolicyViolation, match="e-mails and messages"):
        await svc.preview_action("mail.compose.message", [40], "action_send_mail", None)
    with pytest.raises(PolicyViolation, match="e-mails and messages"):
        await svc.preview_update("mail.compose.message", [40], {"subject": "Hi"}, None)


async def test_list_actions_shows_send_as_one_step(svc):
    actions = (await svc.list_actions("sale.order"))["actions"]
    send = next(a for a in actions if a.get("method") == "action_quotation_send")
    assert send["opens_dialog"] == "mail.compose.message" and send["ai_can_run"] is True
