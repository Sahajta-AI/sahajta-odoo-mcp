"""What Claude needs to act correctly for Shubhang: one approval per dialog flow, previews computed by Odoo itself,
refusals before approval, results with links, several changes under one approval, plain-language texts.

Odoo is the in-memory FakeOdoo (conftest). Every test also asserts (fixture ``no_unlink_ever``) that the fake client
never received a method containing "unlink".
"""

from __future__ import annotations

import pytest
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from conftest import AUDIT_FIELDS, CHATTER_FIELDS, FakeOdoo, _f
from sahajta_odoo_mcp.errors import ConfirmationRequired, OdooError, PolicyViolation, ValidationFailed
from sahajta_odoo_mcp.schema import REFRESH_MIN_SECONDS
from sahajta_odoo_mcp.tools import INSTRUCTIONS, register_tools
from test_service_offline import LEAD, make_service, make_shared

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

CHANGES = {
    "create", "write", "web_save_multi", "message_post", "action_post", "action_confirm", "action_create_payments",
    "action_send_and_print", "refund_moves", "action_lost_reason_apply",
}
LINES = [201, 202]
OPENED_PAYMENT = {
    "type": "ir.actions.act_window", "res_model": "account.payment.register", "target": "new",
    "context": {"active_model": "account.move.line", "active_ids": LINES},
}


def changes(fake: FakeOdoo) -> list[str]:
    return [f"{c.model}.{c.method}" for c in fake.calls if c.method in CHANGES]


def accounting(fake: FakeOdoo) -> FakeOdoo:
    """Adds an Indian company's posted invoice, its dialogs (Pay, Send, Credit Note) and a Lost button on leads."""
    fake.schema.update({
        "account.move": {
            **AUDIT_FIELDS, **CHATTER_FIELDS,
            "name": _f("char", "Number"),
            "move_type": _f("selection", "Type", readonly=True, selection=[["entry", "Journal Entry"], ["out_invoice", "Customer Invoice"], ["in_invoice", "Vendor Bill"]]),
            "partner_id": _f("many2one", "Partner", relation="res.partner"),
            "state": _f("selection", "Status", readonly=True, required=True, selection=[["draft", "Draft"], ["posted", "Posted"]]),
            "payment_state": _f("selection", "Payment Status", readonly=True, selection=[["not_paid", "Not Paid"], ["partial", "Partially Paid"], ["paid", "Paid"]]),
            "journal_id": _f("many2one", "Journal", relation="account.journal", required=True),
            "currency_id": _f("many2one", "Currency", relation="res.currency", required=True),
            "date": _f("date", "Date", required=True),
            "invoice_date_due": _f("date", "Due Date"),
            "amount_untaxed": _f("monetary", "Untaxed Amount", readonly=True),
            "amount_tax": _f("monetary", "Tax", readonly=True),
            "amount_total": _f("monetary", "Total", readonly=True),
            "amount_residual": _f("monetary", "Amount Due", readonly=True),
            "tax_totals": _f("binary", "Invoice Totals", readonly=True, store=False),
            "is_move_sent": _f("boolean", "Is Move Sent", readonly=True),
            "invoice_line_ids": _f("one2many", "Invoice lines", relation="account.move.line", relation_field="move_id"),
        },
        "account.move.line": {
            "move_id": _f("many2one", "Journal Entry", relation="account.move", required=True),
            "product_id": _f("many2one", "Product", relation="product.product"),
            "quantity": _f("float", "Quantity"),
            "price_unit": _f("float", "Unit Price"),
            "tax_ids": _f("many2many", "Taxes", relation="account.tax"),
            "currency_id": _f("many2one", "Currency", relation="res.currency"),
        },
        "account.journal": {"name": _f("char", "Journal Name")},
        "res.currency": {"name": _f("char", "Currency")},
        "account.payment.method.line": {"name": _f("char", "Name")},
        "mail.template": {"name": _f("char", "Name")},
        "crm.lost.reason": {"name": _f("char", "Name")},
        "account.payment": {
            **AUDIT_FIELDS, "name": _f("char", "Number"), "amount": _f("monetary", "Amount"),
            "currency_id": _f("many2one", "Currency", relation="res.currency"),
            "partner_id": _f("many2one", "Customer/Vendor", relation="res.partner"),
        },
        "account.payment.register": {
            "line_ids": _f("many2many", "Journal items", relation="account.move.line", readonly=True),
            "partner_id": _f("many2one", "Customer/Vendor", relation="res.partner", readonly=True),
            "amount": _f("monetary", "Amount"),
            "currency_id": _f("many2one", "Currency", relation="res.currency"),
            "payment_date": _f("date", "Payment Date", required=True),
            "journal_id": _f("many2one", "Journal", relation="account.journal", required=True),
            "payment_method_line_id": _f("many2one", "Payment Method", relation="account.payment.method.line"),
            "communication": _f("char", "Memo"),
            "payment_difference": _f("monetary", "Payment Difference", readonly=True),
            "payment_difference_handling": _f("selection", "Payment Difference Handling", selection=[["open", "Keep open"], ["reconcile", "Mark as fully paid"]]),
            "payment_token_id": _f("many2one", "Saved payment token", relation="payment.token"),
        },
        "account.move.send.wizard": {
            "move_id": _f("many2one", "Move", relation="account.move", required=True),
            "mail_partner_ids": _f("many2many", "To", relation="res.partner"),
            "subject": _f("char", "Subject"),
            "template_id": _f("many2one", "Mail Template", relation="mail.template"),
            "mail_attachments_widget": _f("json", "Mail Attachments Widget"),
            "sending_method_checkboxes": _f("json", "Sending Method Checkboxes"),
            "alerts": _f("json", "Alerts", readonly=True, store=False),
            "body": _f("html", "Contents"),
        },
        "account.move.reversal": {
            "move_ids": _f("many2many", "Moves", relation="account.move"),
            "reason": _f("char", "Reason displayed on Credit Note"),
            "journal_id": _f("many2one", "Journal", relation="account.journal", required=True),
            "date": _f("date", "Reversal date"),
        },
        "crm.lead.lost": {
            "lead_ids": _f("many2many", "Leads", relation="crm.lead"),
            "lost_reason_id": _f("many2one", "Lost Reason", relation="crm.lost.reason"),
            "lost_feedback": _f("html", "Closing Note"),
        },
    })
    fake.records.update({
        "account.move": {20: {
            "name": "INV/2026/00020", "partner_id": [1, "Acme Corp"], "state": "posted", "payment_state": "not_paid",
            "move_type": "out_invoice", "amount_total": 1180.0, "amount_residual": 1180.0, "currency_id": [2, "INR"],
            "invoice_date_due": "2026-11-25", "write_date": "2026-10-15 10:00:00",
        }},
        "account.journal": {1: {"name": "Sales"}, 6: {"name": "Bank"}},
        "res.currency": {2: {"name": "INR"}},
        "account.payment.method.line": {1: {"name": "Manual Payment (Bank)"}},
        "mail.template": {13: {"name": "Invoice: Sending"}},
        "crm.lost.reason": {1: {"name": "Too expensive"}},
        "account.payment": {7: {"name": "PBNK1/2026/00007", "amount": 1180.0, "currency_id": [2, "INR"], "partner_id": [1, "Acme Corp"]}},
    })
    fake.records["res.partner"][1]["email"] = "accounts@acme.example"
    fake.schema["sale.order"].update(amount_untaxed=_f("monetary", "Untaxed Amount", readonly=True),
                                     amount_tax=_f("monetary", "Taxes", readonly=True))
    fake.views["account.move"] = {"views": {"form": {"arch": """
        <form><header>
          <button name="action_post" string="Confirm" type="object"/>
          <button name="action_register_payment" string="Pay" type="object" class="oe_highlight"/>
          <button name="action_invoice_sent" string="Send" type="object"/>
          <button name="action_reverse" string="Credit Note" type="object"/>
        </header></form>"""}}}
    fake.views["crm.lead"] = {"views": {"form": {"arch": '<form><header><button name="318" string="Lost" type="action"/></header></form>'}}}
    fake.views["account.payment.register"] = {"views": {"form": {"arch": """
        <form><field name="line_ids" invisible="1"/><field name="partner_id"/><field name="amount"/>
          <field name="journal_id"/><field name="payment_date"/><field name="communication"/>
          <footer><button string="Create Payment" name="action_create_payments" type="object" class="oe_highlight"/>
          <button string="Discard" special="cancel"/></footer></form>"""}}}
    fake.views["account.move.send.wizard"] = {"views": {"form": {"arch": """
        <form><field name="mail_partner_ids"/><field name="subject"/>
          <footer><button string="Send" name="action_send_and_print" type="object" class="btn-primary"/></footer></form>"""}}}
    fake.views["account.move.reversal"] = {"views": {"form": {"arch": """
        <form><field name="move_ids" invisible="1"/><field name="reason"/><field name="journal_id"/><field name="date"/>
          <footer><button string="Reverse" name="refund_moves" type="object" class="btn-primary"/></footer></form>"""}}}
    fake.views["crm.lead.lost"] = {"views": {"form": {"arch": """
        <form><field name="lead_ids" invisible="1"/><field name="lost_reason_id"/><field name="lost_feedback"/>
          <footer><button name="action_lost_reason_apply" string="Mark as Lost" type="object" class="btn-primary"/></footer></form>"""}}}
    # what Odoo's own dialogs propose (its onchange), and its defaults
    fake.action_results[("account.move", "action_register_payment")] = OPENED_PAYMENT
    fake.filled["account.payment.register"] = {
        "partner_id": 1, "amount": 1180.0, "currency_id": 2, "payment_date": "2026-10-26", "journal_id": 6,
        "payment_method_line_id": 1, "communication": "INV/2026/00020", "payment_difference": 0.0,
        "payment_difference_handling": "open",
    }
    fake.defaults["account.move.send.wizard"] = {"move_id": 20}
    fake.filled["account.move.send.wizard"] = {
        "mail_partner_ids": [1], "subject": "Sahajta Invoice (Ref INV/2026/00020)", "template_id": 13,
        "mail_attachments_widget": [{"id": "placeholder_INV_2026_00020.pdf", "name": "INV_2026_00020.pdf", "placeholder": True}],
        "sending_method_checkboxes": {"email": {"checked": True, "label": "by Email"}, "snailmail": {"checked": False, "label": "by Post"}},
        "body": "<p>Dear Acme Corp,</p><p>Here is your invoice INV/2026/00020 amounting to ₹ 1,180.00.</p>",
    }
    fake.defaults["account.move.reversal"] = {"move_ids": [[6, 0, [20]]]}
    fake.filled["account.move.reversal"] = {"journal_id": 1, "date": "2026-10-26"}
    return fake


@pytest.fixture
def fake() -> FakeOdoo:
    return accounting(FakeOdoo())


@pytest.fixture
def svc(fake):
    return make_service(fake, mcp_allow_outbound_messages=True, mcp_allow_cancel_actions=True)


# ======================================================================================= 1. dialogs in one approval


async def test_pay_is_one_preview_one_approval_one_commit(svc, fake):
    def paid(model, ids, context, **kwargs):
        fake.touch("account.move", 20, payment_state="paid", amount_residual=0.0)
        return {"type": "ir.actions.act_window", "res_model": "account.payment", "res_id": 7, "view_mode": "form"}

    fake._m_action_create_payments = paid
    preview = await svc.preview_action("account.move", [20], "action_register_payment", None)
    assert changes(fake) == [], "a preview changes nothing"
    dialog = preview["dialog"]
    assert dialog["Amount (amount)"] == "1,180.00 INR"
    assert dialog["Journal (journal_id)"] == "Bank"
    assert dialog["Payment Date (payment_date)"] == "2026-10-26"
    assert dialog["Memo (communication)"] == "INV/2026/00020"
    assert dialog["Payment Method (payment_method_line_id)"] == "Manual Payment (Bank)"
    assert "Payment Difference (payment_difference)" not in dialog  # a full payment: no difference options
    onchange = fake.calls_to("onchange")[-1]
    assert onchange.model == "account.payment.register"
    assert onchange.context["active_model"] == "account.move.line" and onchange.context["active_ids"] == LINES

    result = await svc.run_action("account.move", [20], "action_register_payment", None, preview["confirm_token"])
    assert changes(fake) == ["account.payment.register.create", "account.payment.register.action_create_payments"]
    create = fake.calls_to("create")[0]
    assert create.context["active_ids"] == LINES
    assert create.kwargs["vals_list"][0]["amount"] == 1180.0 and create.kwargs["vals_list"][0]["journal_id"] == 6
    assert "partner_id" not in create.kwargs["vals_list"][0]  # read-only in the dialog: never sent
    assert fake.calls_to("action_create_payments")[0].ids == [1000]
    invoice = result["records_now"][0]
    assert invoice["payment_status"] == "Paid" and invoice["amount_due"] == "0.00 INR"
    assert invoice["link"] == "https://odoo.example.com/odoo/account.move/20"
    assert result["odoo_opened"]["name"] == "PBNK1/2026/00007" and result["odoo_opened"]["total"] == "1,180.00 INR"
    with pytest.raises(ConfirmationRequired):  # one approval, one payment
        await svc.run_action("account.move", [20], "action_register_payment", None, preview["confirm_token"])
    assert len(fake.calls_to("action_create_payments")) == 1


async def test_a_part_payment_shows_what_happens_to_the_rest(svc, fake):
    fake.filled["account.payment.register"]["payment_difference"] = 680.0
    preview = await svc.preview_action("account.move", [20], "action_register_payment", None, {"amount": 500})
    assert preview["dialog"]["Amount (amount)"] == "500.00 INR"
    assert preview["dialog"]["Payment Difference (payment_difference)"] == "680.00 INR"
    assert preview["dialog"]["Payment Difference Handling (payment_difference_handling)"] == "Keep open"
    await svc.run_action("account.move", [20], "action_register_payment", None, preview["confirm_token"], {"amount": 500})
    assert fake.calls_to("create")[0].kwargs["vals_list"][0]["amount"] == 500


async def test_send_shows_recipients_subject_and_attachments_and_never_presses_send_in_the_preview(svc, fake):
    preview = await svc.preview_action("account.move", [20], "action_invoice_sent", None)
    dialog = preview["dialog"]
    assert dialog["To (mail_partner_ids)"] == ["Acme Corp <accounts@acme.example>"]
    assert dialog["Subject (subject)"] == "Sahajta Invoice (Ref INV/2026/00020)"
    assert dialog["E-mail template (template_id)"] == "Invoice: Sending"
    assert dialog["Attachments (mail_attachments_widget)"] == ["INV_2026_00020.pdf"]
    assert dialog["Send (sending_method_checkboxes)"] == ["by Email"]
    assert "INV/2026/00020" in dialog["Message (body)"] and "<p>" not in dialog["Message (body)"]
    assert fake.calls_to("action_invoice_sent") == [], "its button may check the customer with outside services"
    await svc.run_action("account.move", [20], "action_invoice_sent", None, preview["confirm_token"])
    assert changes(fake) == ["account.move.send.wizard.create", "account.move.send.wizard.action_send_and_print"]
    assert fake.calls_to("action_invoice_sent") == []
    assert fake.calls_to("create")[0].context["allow_partners_without_mail"] is True


async def test_send_warns_when_nobody_would_get_the_e_mail(svc, fake):
    fake.filled["account.move.send.wizard"]["mail_partner_ids"] = []
    preview = await svc.preview_action("account.move", [20], "action_invoice_sent", None)
    assert any("Nobody would get this e-mail" in w for w in preview["warnings"])


async def test_send_works_on_one_invoice_at_a_time(svc, fake):
    fake.records["account.move"][21] = dict(fake.records["account.move"][20], name="INV/2026/00021")
    with pytest.raises(ValidationFailed, match="one account.move record at a time"):
        await svc.preview_action("account.move", [20, 21], "action_invoice_sent", None)


async def test_credit_note_in_one_step(svc, fake):
    preview = await svc.preview_action("account.move", [20], "action_reverse", None, {"reason": "Wrong quantity"})
    assert preview["dialog"] == {
        "Reason displayed on Credit Note (reason)": "Wrong quantity", "Journal (journal_id)": "Sales",
        "Reversal date (date)": "2026-10-26",
    }
    await svc.run_action("account.move", [20], "action_reverse", None, preview["confirm_token"], {"reason": "Wrong quantity"})
    # Odoo's form saves the journal it proposed; created with the reason alone, Odoo 19 refuses the dialog
    assert fake.calls_to("create")[0].kwargs["vals_list"] == [{"journal_id": 1, "date": "2026-10-26", "reason": "Wrong quantity"}]
    assert fake.calls_to("create")[0].context["active_ids"] == [20]  # the invoice reaches the dialog as in Odoo
    assert fake.calls_to("refund_moves")[0].ids == [1000]


async def test_mark_lost_in_one_step(svc, fake):
    preview = await svc.preview_action("crm.lead", [100], "dialog:crm.lead.lost", None, {"lost_reason_id": 1})
    assert preview["dialog"] == {"Lost Reason (lost_reason_id)": "Too expensive"}
    assert preview["records"][0]["name"] == "Big deal"
    await svc.run_action("crm.lead", [100], "dialog:crm.lead.lost", None, preview["confirm_token"], {"lost_reason_id": 1})
    create = fake.calls_to("create")[0]
    assert create.model == "crm.lead.lost" and create.context["default_lead_ids"] == [100]
    assert fake.calls_to("action_lost_reason_apply")[0].ids == [1000]


@pytest.mark.parametrize(
    "setting, model, ids, method, needle",
    [
        ("mcp_allow_outbound_messages", "account.move", [20], "action_invoice_sent", "e-mail"),
        ("mcp_allow_cancel_actions", "account.move", [20], "action_reverse", "(?i)revers"),
        ("mcp_allow_cancel_actions", "crm.lead", [100], "dialog:crm.lead.lost", "lost"),
    ],
)
async def test_a_dialog_whose_button_is_switched_off_is_refused_in_the_preview(fake, setting, model, ids, method, needle):
    svc = make_service(fake, **{setting: False})
    with pytest.raises(PolicyViolation, match=needle):
        await svc.preview_action(model, ids, method, None)
    assert fake.calls_to("onchange") == [] and changes(fake) == []


async def test_a_dialog_approval_is_bound_to_what_odoo_showed(svc, fake):
    preview = await svc.preview_action("account.move", [20], "action_register_payment", None)
    fake.filled["account.payment.register"]["amount"] = 900.0  # e.g. a payment was registered meanwhile
    with pytest.raises(ConfirmationRequired, match="does not match"):
        await svc.run_action("account.move", [20], "action_register_payment", None, preview["confirm_token"])
    assert changes(fake) == []


async def test_a_dialog_odoo_could_not_open_changed_nothing_and_the_approval_still_works(svc, fake):
    preview = await svc.preview_action("account.move", [20], "action_register_payment", None)
    fake.errors[("account.payment.register", "create")] = OdooError("Missing required value for Journal", kind="validation")
    with pytest.raises(OdooError) as info:
        await svc.run_action("account.move", [20], "action_register_payment", None, preview["confirm_token"])
    assert str(info.value).endswith("Nothing was changed.")  # Odoo refused the values: no retry hint
    assert fake.calls_to("action_create_payments") == []
    del fake.errors[("account.payment.register", "create")]
    await svc.run_action("account.move", [20], "action_register_payment", None, preview["confirm_token"])
    assert len(fake.calls_to("action_create_payments")) == 1


async def test_a_dialog_whose_answer_was_lost_is_never_done_twice(svc, fake):
    preview = await svc.preview_action("account.move", [20], "action_register_payment", None)
    fake.errors[("account.payment.register", "action_create_payments")] = OdooError("timed out", kind="timeout")
    with pytest.raises(OdooError) as info:
        await svc.run_action("account.move", [20], "action_register_payment", None, preview["confirm_token"])
    assert "may already have" in str(info.value) and "nothing was changed" not in str(info.value).lower()
    del fake.errors[("account.payment.register", "action_create_payments")]
    with pytest.raises(ConfirmationRequired, match="already used"):
        await svc.run_action("account.move", [20], "action_register_payment", None, preview["confirm_token"])
    assert len(fake.calls_to("action_create_payments")) == 1


async def test_a_payment_that_would_charge_a_saved_card_is_refused(svc, fake):
    fake.filled["account.payment.register"]["payment_token_id"] = 3
    with pytest.raises(PolicyViolation, match="saved card"):
        await svc.preview_action("account.move", [20], "action_register_payment", None)


async def test_odoo_refusing_to_open_the_dialog_is_reported_in_the_preview(svc, fake):
    fake.errors[("account.move", "action_register_payment")] = OdooError(
        "You can only register payment for posted journal entries.", kind="user_error"
    )
    with pytest.raises(OdooError, match="only register payment for posted"):
        await svc.preview_action("account.move", [20], "action_register_payment", None)
    assert fake.calls_to("onchange") == [] and changes(fake) == []


async def test_dialog_values_are_checked_like_any_values(svc, fake):
    with pytest.raises(ValidationFailed, match="not a field"):
        await svc.preview_action("account.move", [20], "action_register_payment", None, {"amout": 5})
    with pytest.raises(ValidationFailed, match="dialog_values"):
        await svc.preview_action("account.move", [20], "action_post", None, {"amount": 5})
    with pytest.raises(ValidationFailed, match="context may only"):
        await svc.preview_action("account.move", [20], "action_register_payment", {"active_ids": [21]})


async def test_list_actions_shows_which_buttons_finish_their_dialog_in_one_step(fake):
    svc = make_service(fake, mcp_allow_cancel_actions=False)
    actions = (await svc.list_actions("account.move"))["actions"]
    pay = next(a for a in actions if a.get("method") == "action_register_payment")
    assert pay["opens_dialog"] == "account.payment.register" and pay["ai_can_run"] is True
    lost = (await svc.list_actions("crm.lead"))["actions"]
    assert lost == [{
        "kind": "dialog", "method": "dialog:crm.lead.lost", "label": "Lost", "opens_dialog": "crm.lead.lost",
        "ai_can_run": False, "why_not": lost[0]["why_not"],
    }]


async def test_list_actions_keeps_long_conditions_short(fake):
    fake.views["account.move"]["views"]["form"]["arch"] = fake.views["account.move"]["views"]["form"]["arch"].replace(
        'class="oe_highlight"', 'class="oe_highlight" invisible="(  state != \'posted\'\n   ' + " or x" * 100 + ')"'
    )
    pay = next(a for a in (await make_service(fake).list_actions("account.move"))["actions"] if a.get("method") == "action_register_payment")
    assert len(pay["visible_when_not"]) <= 162 and "\n" not in pay["visible_when_not"] and "  " not in pay["visible_when_not"]


# ======================================================================================= 2. create previews


async def test_invoice_preview_shows_what_odoo_fills_in_and_the_totals_without_false_warnings(svc, fake):
    fake.filled["account.move"] = {
        "journal_id": 1, "currency_id": 2, "date": "2026-10-26", "invoice_date_due": "2026-11-25",
        "amount_untaxed": 0.0, "amount_tax": 0.0, "amount_total": 0.0,
        "tax_totals": {
            "base_amount_currency": 1000.0, "tax_amount_currency": 180.0, "total_amount_currency": 1180.0,
            "subtotals": [{"tax_groups": [{"group_name": "GST 18%", "tax_amount_currency": 180.0}]}],
        },
    }
    record = {"move_type": "out_invoice", "partner_id": 1, "invoice_line_ids": [{"product_id": 10, "quantity": 1, "price_unit": 1000.0, "tax_ids": [1]}]}
    preview = await svc.preview_create("account.move", [record], None)
    assert preview["warnings"] == []  # Odoo fills the journal, currency and date itself
    assert preview["filled_in_by_odoo"] == [{
        "Journal (journal_id)": "Sales", "Currency (currency_id)": "INR", "Date (date)": "2026-10-26",
        "Due Date (invoice_date_due)": "2026-11-25",
    }]
    assert preview["totals"] == [{
        "untaxed": "1,000.00 INR", "taxes": "180.00 INR", "total": "1,180.00 INR", "tax_breakdown": {"GST 18%": "180.00 INR"},
    }]
    # like Odoo's form: the invoice first, then its lines as a change (so the taxes set on a line are kept)
    first, second = fake.calls_to("onchange")
    assert "invoice_line_ids" not in first.kwargs["values"] and first.kwargs["field_names"] == []
    assert second.kwargs["field_names"] == ["invoice_line_ids"]
    assert second.kwargs["values"]["journal_id"] == 1 and second.kwargs["values"]["invoice_line_ids"][0][2]["tax_ids"] == [[6, 0, [1]]]
    assert changes(fake) == []


async def test_order_totals_come_from_odoo(svc, fake):
    fake.filled["sale.order"] = {"amount_untaxed": 200.0, "amount_tax": 36.0, "amount_total": 236.0, "date_order": "2026-10-26 09:00:00"}
    preview = await svc.preview_create("sale.order", [{"partner_id": 1, "name": "S1"}], None)
    assert preview["totals"] == [{"untaxed": "200.00", "taxes": "36.00", "total": "236.00"}]
    assert preview["filled_in_by_odoo"] == [{"Order Date (date_order)": "2026-10-26T14:30:00+05:30"}]


async def test_create_preview_falls_back_to_defaults_when_odoo_cannot_preview(svc, fake):
    fake.errors[("crm.lead", "onchange")] = OdooError("odd onchange", kind="validation")
    preview = await svc.preview_create("crm.lead", [{"partner_id": 1}], None)
    assert any("Opportunity (name)" in w and "Type (type)" in w for w in preview["warnings"])
    assert "filled_in_by_odoo" not in preview


async def test_create_preview_passes_on_odoo_s_own_warning(svc, fake):
    fake._m_onchange = lambda model, ids, context, **kw: {"value": {}, "warning": {"title": "Warning", "message": "Acme is on credit hold."}}
    preview = await svc.preview_create("crm.lead", LEAD, None)
    assert "record 1: Odoo says: Acme is on credit hold." in preview["warnings"]


# ======================================================================================= 3. access refused before approval


async def test_an_edit_odoo_would_refuse_is_refused_in_the_preview(svc, fake):
    fake.access[("crm.lead", "write")] = False
    with pytest.raises(OdooError, match="may not change crm.lead records") as info:
        await svc.preview_update("crm.lead", [100], {"probability": 5}, None)
    assert "Nothing was changed" in str(info.value) and "MCP_" not in str(info.value)
    fake.access[("sale.order", "write")] = False
    with pytest.raises(OdooError, match="may not change sale.order records"):
        await svc.preview_action("sale.order", [5], "action_confirm", None)
    has_access = fake.calls_to("has_access")[0]
    assert has_access.ids == [100] and has_access.kwargs == {"operation": "write"}  # the record's own rules count
    assert changes(fake) == []


async def test_a_create_odoo_would_refuse_is_refused_in_the_preview(svc, fake):
    fake.access[("crm.lead", "create")] = False
    with pytest.raises(OdooError, match="may not create crm.lead records"):
        await svc.preview_create("crm.lead", LEAD, None)
    fake.access[("account.payment.register", "create")] = False
    with pytest.raises(OdooError, match="may not create account.payment.register"):
        await svc.preview_action("account.move", [20], "action_register_payment", None)


async def test_an_odoo_without_has_access_still_previews(svc, fake):
    fake.errors[("crm.lead", "has_access")] = OdooError("no such method", kind="missing")
    assert (await svc.preview_update("crm.lead", [100], {"probability": 5}, None))["confirm_token"]


# ======================================================================================= 4. results with links


async def test_results_name_the_records_with_their_link_total_and_status(svc, fake):
    preview = await svc.preview_create("crm.lead", LEAD, None)
    created = (await svc.create("crm.lead", LEAD, None, preview["confirm_token"]))["created"][0]
    assert created["link"] == f"https://odoo.example.com/odoo/crm.lead/{created['id']}"
    preview = await svc.preview_update("crm.lead", [100], {"probability": 5}, None)
    updated = (await svc.update("crm.lead", [100], {"probability": 5}, None, preview["confirm_token"]))["updated"][0]
    assert updated["link"] == "https://odoo.example.com/odoo/crm.lead/100"
    assert updated["partner"] == "Acme Corp" and updated["stage"] == "New" and updated["probability"] == 5
    preview = await svc.preview_action("account.move", [20], "action_post", None)
    assert "next_step" not in preview["records"][0]  # a preview is no place for the step after it
    done = await svc.run_action("account.move", [20], "action_post", None, preview["confirm_token"])
    invoice = done["records_now"][0]
    assert invoice["status"] == "Posted" and invoice["total"] == "1,180.00 INR" and invoice["due_date"] == "2026-11-25"
    assert invoice["partner"] == "Acme Corp" and "action_invoice_sent" in invoice["next_step"]


# ======================================================================================= 6. several changes, one approval


async def test_different_values_for_several_records_need_one_approval(svc, fake):
    batch = [{"ids": [100], "values": {"probability": 10}}, {"ids": [101], "values": {"probability": 90, "priority": "2"}}]
    preview = await svc.preview_update("crm.lead", None, None, None, batch)
    assert [(c["id"], c["new"]) for c in preview["changes"]] == [
        (100, {"Probability (probability)": 10}),
        (101, {"Probability (probability)": 90, "Priority (priority)": "2 (High)"}),
    ]
    assert changes(fake) == []
    with pytest.raises(ConfirmationRequired):
        await svc.update("crm.lead", None, None, None, preview["confirm_token"], [batch[0], {"ids": [101], "values": {"probability": 99}}])
    result = await svc.update("crm.lead", None, None, None, preview["confirm_token"], batch)
    assert changes(fake) == ["crm.lead.web_save_multi"]  # one call: Odoo applies all of them or none
    call = fake.calls_to("web_save_multi")[0]
    assert call.ids == [100, 101] and call.kwargs["vals_list"] == [{"probability": 10}, {"probability": 90, "priority": "2"}]
    assert [r["probability"] for r in result["updated"]] == [10, 90]


async def test_one_change_in_the_list_is_the_same_as_ids_and_values(svc, fake):
    preview = await svc.preview_update("crm.lead", [100], {"probability": 10}, None)
    await svc.update("crm.lead", None, None, None, preview["confirm_token"], [{"ids": [100], "values": {"probability": 10}}])
    assert changes(fake) == ["crm.lead.write"]


async def test_the_record_cap_counts_every_record_of_every_change(fake):
    svc = make_service(fake, mcp_max_write_records=2)
    fake.records["crm.lead"][102] = {"name": "Third", "type": "lead"}
    with pytest.raises(ValidationFailed, match="limit is 2"):
        await svc.preview_update("crm.lead", None, None, None, [{"ids": [100, 101], "values": {"probability": 1}},
                                                               {"ids": [102], "values": {"probability": 2}}])


@pytest.mark.parametrize(
    "ids, values, batch, needle",
    [
        (None, None, [{"ids": [100], "values": {"probability": 1}}, {"ids": [100], "values": {"color": 2}}], "more than one change"),
        ([100], {"probability": 1}, [{"ids": [101], "values": {"probability": 2}}], "not both"),
        (None, None, [], "non-empty"),
        (None, None, [{"ids": [100]}], "each change"),
    ],
)
async def test_a_list_of_changes_is_checked(svc, fake, ids, values, batch, needle):
    with pytest.raises(ValidationFailed, match=needle):
        await svc.preview_update("crm.lead", ids, values, None, batch)


async def test_several_changes_whose_answer_was_lost_are_never_applied_twice(svc, fake):
    batch = [{"ids": [100], "values": {"probability": 10}}, {"ids": [101], "values": {"probability": 90}}]
    preview = await svc.preview_update("crm.lead", None, None, None, batch)
    fake.errors[("crm.lead", "web_save_multi")] = OdooError("timed out", kind="timeout")
    with pytest.raises(OdooError, match="may already have"):
        await svc.update("crm.lead", None, None, None, preview["confirm_token"], batch)
    del fake.errors[("crm.lead", "web_save_multi")]
    with pytest.raises(ConfirmationRequired, match="already used"):
        await svc.update("crm.lead", None, None, None, preview["confirm_token"], batch)


# ======================================================================================= 7. messages


async def test_a_message_the_customer_would_not_get_says_so(svc, fake):
    fake.followers = [{"partner_id": [2, "Jane Buyer"]}]
    preview = await svc.preview_message("crm.lead", 100, "Dear customer, your quote is ready.")
    assert "Acme Corp, the customer on this record, does not follow it" in preview["warnings"][0]
    fake.followers.append({"partner_id": [1, "Acme Corp"]})
    assert "warnings" not in await svc.preview_message("crm.lead", 100, "Dear customer, your quote is ready.")


# ======================================================================================= 8. fields added since caching


def age(svc) -> None:
    """Makes the cached field lists old enough to be asked again from Odoo (see schema.REFRESH_MIN_SECONDS)."""
    cache = svc.shared.schema._data
    for key, (expires, fields, fetched) in list(cache.items()):
        cache[key] = (expires, fields, fetched - REFRESH_MIN_SECONDS if fetched is not None else None)


async def test_a_field_added_since_caching_is_found(svc, fake):
    await svc.describe_model("crm.lead", None, None)  # caches the fields
    fake.schema["crm.lead"]["x_gst_number"] = _f("char", "GST Number")
    age(svc)
    found = await svc.describe_model("crm.lead", "gst", None)
    assert [f["name"] for f in found["fields"]] == ["x_gst_number"]
    fake.schema["crm.lead"]["x_region"] = _f("char", "Region")
    age(svc)
    await svc.search("crm.lead", None, ["name"], None, None, "x_region desc", False)
    assert fake.calls_to("search_read")[-1].kwargs["order"] == "x_region desc"


# ======================================================================================= 9. plain words, recipes


async def test_switched_off_changes_are_explained_without_setting_names(fake):
    svc = make_service(fake, mcp_access_mode="read_only")
    with pytest.raises(PolicyViolation) as info:
        await svc.create("crm.lead", LEAD, None, "123.abc")
    assert "switched off" in str(info.value) and "MCP_" not in str(info.value)


def test_instructions_carry_the_recipes_in_plain_words():
    for needle in ("action_register_payment", "action_invoice_sent", "action_reverse", "dialog:crm.lead.lost",
                   "purchases@", "cannot attach files", "Accounting > Bank", "account.bank.statement.line", "changes="):
        assert needle in INSTRUCTIONS, needle
    assert "MCP_" not in INSTRUCTIONS


async def test_the_tools_take_changes_and_dialog_values(fake):
    shared = make_shared(mcp_allow_cancel_actions=True)
    service = make_service(fake, shared)
    mcp = MCPServer("ux-test")

    async def get_service():
        return service

    register_tools(mcp, get_service, shared.settings)
    async with Client(mcp) as client:
        batch = [{"ids": [100], "values": {"probability": 10}}, {"ids": [101], "values": {"probability": 90}}]
        result = await client.call_tool("odoo_preview_update", {"model": "crm.lead", "changes": batch})
        assert not result.is_error and "in 2 different ways" in result.content[0].text
        args = {"model": "account.move", "ids": [20], "method": "action_reverse", "dialog_values": {"reason": "Duplicate"}}
        result = await client.call_tool("odoo_preview_action", args)
        assert not result.is_error and "Duplicate" in result.content[0].text
