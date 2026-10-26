"""Shared offline fakes for the unit tests (no network, no Odoo).

Nothing here is autouse, so other test modules (OAuth, live Odoo) are unaffected.
"""

from __future__ import annotations

import copy
import itertools
from dataclasses import dataclass, field
from typing import Any

import pytest

from sahajta_odoo_mcp.config import Settings
from sahajta_odoo_mcp.errors import OdooError
from sahajta_odoo_mcp.odoo_client import OdooCredentials, OdooIdentity

# Every safety-relevant setting is passed explicitly, so stray MCP_* / ODOO_* environment
# variables or a .env file on the developer's machine can never change a test's outcome.
SAFE_DEFAULTS: dict[str, Any] = dict(
    odoo_url="https://odoo.example.com",
    odoo_db="testdb",
    odoo_protocol="json2",
    odoo_login="ai.tester@example.com",
    odoo_api_key="test-api-key",
    mcp_access_mode="read_only",
    mcp_require_preview=True,
    mcp_allow_archive=False,
    mcp_allow_cancel_actions=False,
    mcp_allow_outbound_messages=False,
    mcp_default_read_limit=50,
    mcp_max_read_records=200,
    mcp_max_write_records=20,
    mcp_max_text_chars=4000,
    mcp_max_response_chars=120_000,
    mcp_blocked_models=[],
    mcp_readonly_models=[],
    mcp_writable_models=[],
    mcp_blocked_methods=[],
    mcp_extra_allowed_methods=[],
    mcp_reads_per_minute=1000,
    mcp_writes_per_minute=1000,
    mcp_audit_log_file=None,
    mcp_secret=None,
)


def build_settings(**overrides: Any) -> Settings:
    values = {**SAFE_DEFAULTS, **overrides}
    return Settings(_env_file=None, **values)


@pytest.fixture
def make_settings():
    return build_settings


# --------------------------------------------------------------------------------------------
# Field metadata, shaped like fields_get() output
# --------------------------------------------------------------------------------------------


def _f(ftype: str, string: str | None = None, **extra: Any) -> dict:
    meta = {"type": ftype, "string": string or ftype, "store": True, "readonly": False, "required": False}
    meta.update(extra)
    return meta


AUDIT_FIELDS = {
    "display_name": _f("char", "Display Name", readonly=True, store=False),
    "create_uid": _f("many2one", "Created by", relation="res.users", readonly=True),
    "create_date": _f("datetime", "Created on", readonly=True),
    "write_uid": _f("many2one", "Last Updated by", relation="res.users", readonly=True),
    "write_date": _f("datetime", "Last Updated on", readonly=True),
}

CHATTER_FIELDS = {
    "message_ids": _f("one2many", "Messages", relation="mail.message", relation_field="res_id"),
    "message_follower_ids": _f("one2many", "Followers", relation="mail.followers", relation_field="res_id"),
    "activity_ids": _f("one2many", "Activities", relation="mail.activity", relation_field="res_id"),
    "access_url": _f("char", "Portal Access URL", readonly=True, store=False),
    "access_token": _f("char", "Security Token"),
}

SCHEMA: dict[str, dict[str, dict]] = {
    "crm.lead": {
        **AUDIT_FIELDS,
        **CHATTER_FIELDS,
        "name": _f("char", "Opportunity", required=True),
        "partner_id": _f("many2one", "Customer", relation="res.partner"),
        "user_id": _f("many2one", "Salesperson", relation="res.users"),
        "stage_id": _f("many2one", "Stage", relation="crm.stage"),
        "company_id": _f("many2one", "Company", relation="res.company"),
        "tag_ids": _f("many2many", "Tags", relation="crm.tag"),
        "required_tag_ids": _f("many2many", "Mandatory Tags", relation="crm.tag", required=True),
        "expected_revenue": _f("monetary", "Expected Revenue"),
        "probability": _f("float", "Probability"),
        "color": _f("integer", "Color Index"),
        "priority": _f(
            "selection", "Priority", selection=[["0", "Low"], ["1", "Medium"], ["2", "High"], ["3", "Very High"]]
        ),
        "type": _f("selection", "Type", required=True, selection=[["lead", "Lead"], ["opportunity", "Opportunity"]]),
        "kanban_level": _f("selection", "Level", selection=[[1, "One"], [2, "Two"]]),
        "date_deadline": _f("date", "Expected Closing"),
        "next_call_at": _f("datetime", "Next Call"),
        "date_closed": _f("datetime", "Closed Date", readonly=True),
        "active": _f("boolean", "Active"),
        "is_hot": _f("boolean", "Hot"),
        "description": _f("html", "Notes"),
        "email_from": _f("char", "Email"),
        "lead_properties": _f("properties", "Properties"),
        "x_source_ref": _f("reference", "Source", selection=[["res.partner", "Contact"], ["sale.order", "Order"]]),
        "x_res_id": _f("many2one_reference", "Related Id"),
        "x_attachment": _f("binary", "Attachment"),
        "x_api_key": _f("char", "Integration API key"),
        "x_cron_id": _f("many2one", "Cron", relation="ir.cron"),
        "x_server_action_ids": _f("many2many", "Server actions", relation="ir.actions.server"),
        "x_payslip_id": _f("many2one", "Payslip", relation="hr.payslip"),
        "x_mystery": _f("weird_type", "Mystery"),
    },
    "sale.order": {
        **AUDIT_FIELDS,
        **CHATTER_FIELDS,
        "name": _f("char", "Order Reference", required=True),
        "partner_id": _f("many2one", "Customer", relation="res.partner", required=True),
        "user_id": _f("many2one", "Salesperson", relation="res.users"),
        "state": _f(
            "selection", "Status", selection=[["draft", "Quotation"], ["sent", "Sent"], ["sale", "Sales Order"], ["cancel", "Cancelled"]]
        ),
        "order_line": _f("one2many", "Order Lines", relation="sale.order.line", relation_field="order_id"),
        "tag_ids": _f("many2many", "Tags", relation="crm.tag"),
        "date_order": _f("datetime", "Order Date", required=True),
        "validity_date": _f("date", "Expiration"),
        "amount_total": _f("monetary", "Total", readonly=True),
        "note": _f("html", "Terms and conditions"),
        "company_id": _f("many2one", "Company", relation="res.company"),
        "invoice_status": _f("selection", "Invoice Status", selection=[["no", "Nothing to Invoice"]]),
    },
    "sale.order.line": {
        **AUDIT_FIELDS,
        "order_id": _f("many2one", "Order Reference", relation="sale.order", required=True),
        "product_id": _f("many2one", "Product", relation="product.product"),
        "product_uom_qty": _f("float", "Quantity"),
        "price_unit": _f("float", "Unit Price"),
        "name": _f("text", "Description"),
        "sequence": _f("integer", "Sequence"),
        "tax_ids": _f("many2many", "Taxes", relation="account.tax"),
        "x_config_ids": _f("one2many", "Settings", relation="ir.config_parameter", relation_field="x_line_id"),
        "x_cron_line_ids": _f("one2many", "Crons", relation="ir.cron", relation_field="x_line_id"),
        "x_note_ids": _f("one2many", "Notes", relation="mail.message", relation_field="x_line_id"),
        "x_sub_ids": _f("one2many", "Sub lines", relation="sale.order.subline", relation_field="line_id"),
    },
    "sale.order.subline": {
        "line_id": _f("many2one", "Line", relation="sale.order.line", required=True),
        "name": _f("char", "Name"),
        "x_deep_ids": _f("one2many", "Deeper", relation="sale.order.deep", relation_field="subline_id"),
    },
    "sale.order.deep": {
        "subline_id": _f("many2one", "Sub line", relation="sale.order.subline", required=True),
        "name": _f("char", "Name"),
        "x_deeper_ids": _f("one2many", "Deepest", relation="sale.order.deepest", relation_field="deep_id"),
    },
    "sale.order.deepest": {
        "deep_id": _f("many2one", "Deep", relation="sale.order.deep", required=True),
        "name": _f("char", "Name"),
    },
    "res.partner": {
        **AUDIT_FIELDS,
        **CHATTER_FIELDS,
        "name": _f("char", "Name"),
        "email": _f("char", "Email"),
        "is_company": _f("boolean", "Is a Company"),
        "parent_id": _f("many2one", "Related Company", relation="res.partner"),
        "child_ids": _f("one2many", "Contacts", relation="res.partner", relation_field="parent_id"),
        "category_id": _f("many2many", "Tags", relation="res.partner.category"),
        "country_id": _f("many2one", "Country", relation="res.country"),
        "bank_ids": _f("one2many", "Banks", relation="res.partner.bank", relation_field="partner_id"),
        "user_ids": _f("one2many", "Users", relation="res.users", relation_field="partner_id"),
        "signup_token": _f("char", "Signup Token"),
        "image_1920": _f("image", "Image"),
        "comment": _f("html", "Notes"),
        "active": _f("boolean", "Active"),
    },
    "res.users": {
        **AUDIT_FIELDS,
        "name": _f("char", "Name"),
        "login": _f("char", "Login", required=True),
        "password": _f("char", "Password"),
        "partner_id": _f("many2one", "Related Partner", relation="res.partner", required=True),
        "api_key_ids": _f("one2many", "API Keys", relation="res.users.apikeys", relation_field="user_id"),
        "log_ids": _f("one2many", "User log entries", relation="res.users.log", relation_field="create_uid"),
        "groups_id": _f("many2many", "Groups", relation="res.groups"),
        "company_id": _f("many2one", "Company", relation="res.company"),
        "share": _f("boolean", "Share User"),
    },
    "res.users.log": {**AUDIT_FIELDS},
    "crm.tag": {"name": _f("char", "Tag Name", required=True), "color": _f("integer", "Color")},
    "crm.stage": {"name": _f("char", "Stage Name", required=True)},
    "res.country": {"name": _f("char", "Country Name"), "code": _f("char", "Country Code")},
    "res.company": {"name": _f("char", "Company Name")},
    "res.partner.category": {"name": _f("char", "Tag Name")},
    "product.product": {"name": _f("char", "Name"), "list_price": _f("float", "Sales Price")},
    "account.tax": {"name": _f("char", "Tax Name")},
    "mail.message": {"body": _f("html", "Contents")},
    "ir.config_parameter": {"key": _f("char", "Key"), "value": _f("text", "Value")},
    "ir.cron": {"name": _f("char", "Name")},
}

# Records the fake Odoo "has". write_date values are deliberately coarse (one-second resolution).
RECORDS: dict[str, dict[int, dict]] = {
    "res.partner": {
        1: {"name": "Acme Corp", "email": "info@acme.example", "is_company": True},
        2: {"name": "Jane Buyer", "email": "jane@acme.example", "parent_id": [1, "Acme Corp"]},
        3: {"name": "Globex", "is_company": True},
    },
    "res.users": {7: {"name": "AI Tester", "login": "ai.tester@example.com"}, 8: {"name": "Sam Sales", "login": "sam"}},
    "crm.tag": {1: {"name": "Hot"}, 2: {"name": "Export"}, 3: {"name": "Training"}},
    "crm.stage": {1: {"name": "New"}, 2: {"name": "Qualified"}},
    "res.country": {104: {"name": "India", "code": "IN"}},
    "res.company": {1: {"name": "Sahajta"}},
    "product.product": {10: {"name": "Licence"}, 11: {"name": "Training day"}},
    "account.tax": {1: {"name": "GST 18%"}},
    "crm.lead": {
        100: {"name": "Big deal", "partner_id": [1, "Acme Corp"], "type": "opportunity", "expected_revenue": 1000.0,
              "tag_ids": [1], "required_tag_ids": [2], "active": True, "stage_id": [1, "New"]},
        101: {"name": "Small deal", "type": "lead", "expected_revenue": 10.0, "tag_ids": [], "active": True},
    },
    "sale.order": {
        5: {"name": "S00005", "partner_id": [1, "Acme Corp"], "state": "draft", "order_line": [50, 51],
            "date_order": "2026-10-01 09:00:00"},
        6: {"name": "S00006", "partner_id": [3, "Globex"], "state": "draft", "order_line": [60],
            "date_order": "2026-10-02 09:00:00"},
    },
    "sale.order.line": {
        50: {"order_id": [5, "S00005"], "product_id": [10, "Licence"], "product_uom_qty": 1.0, "price_unit": 100.0},
        51: {"order_id": [5, "S00005"], "product_id": [11, "Training day"], "product_uom_qty": 2.0, "price_unit": 50.0},
        60: {"order_id": [6, "S00006"], "product_id": [10, "Licence"], "product_uom_qty": 5.0, "price_unit": 100.0},
    },
}


# Setup areas (settings, e-mail templates, automation rules, accounting setup, analytic distribution), shaped like
# Odoo 19's fields_get. Added on top of SCHEMA/RECORDS by the ``setup_fake`` fixture only, so other tests are unaffected.
_TRIGGERS = [
    "on_stage_set", "on_user_set", "on_tag_set", "on_state_set", "on_priority_set", "on_archive", "on_unarchive",
    "on_create", "on_create_or_write", "on_write", "on_unlink", "on_change", "on_time", "on_time_created",
    "on_time_updated", "on_message_received", "on_message_sent", "on_webhook",
]
_ACTION_TYPES = [
    "object_write", "object_create", "object_copy", "next_activity", "mail_post", "sms", "followers",
    "remove_followers", "code", "webhook", "multi",
]
SETUP_SCHEMA: dict[str, dict[str, dict]] = {
    "ir.model": {"model": _f("char", "Model"), "name": _f("char", "Model Description")},
    "ir.model.fields": {"name": _f("char", "Field Name"), "model": _f("char", "Model")},
    "ir.ui.menu": {
        "name": _f("char", "Menu", required=True),
        "complete_name": _f("char", "Full Path", readonly=True, store=False, searchable=False),
        "parent_id": _f("many2one", "Parent Menu", relation="ir.ui.menu"),
    },
    "res.config.settings": {
        **AUDIT_FIELDS,
        "company_id": _f("many2one", "Company", relation="res.company", required=True),
        "group_analytic_accounting": _f("boolean", "Analytic Accounting"),
        "group_uom": _f("boolean", "Units of Measure"),
        "module_crm": _f("boolean", "CRM"),
        "quotation_validity_days": _f("integer", "Default Quotation Validity"),
        "l10n_in_gstin": _f("char", "GST Number"),
        "l10n_in_pan": _f("char", "PAN"),
        "auth_signup_uninvited": _f("selection", "Customer Account", selection=[["b2b", "On invitation"], ["b2c", "Free"]]),
        "account_fiscal_country_id": _f("many2one", "Fiscal Country", relation="res.country"),
    },
    "mail.template": {
        **AUDIT_FIELDS,
        "name": _f("char", "Name"),
        "model_id": _f("many2one", "Applies to", relation="ir.model"),
        "subject": _f("char", "Subject"),
        "body_html": _f("html", "Body"),
        "email_from": _f("char", "From"),
        "email_to": _f("char", "To (Emails)"),
        "email_cc": _f("char", "Cc"),
        "partner_to": _f("char", "To (Partners)"),
        "use_default_to": _f("boolean", "Default Recipients"),
        "reply_to": _f("char", "Reply To"),
        "attachment_ids": _f("many2many", "Attachments", relation="ir.attachment"),
        "mail_server_id": _f("many2one", "Outgoing Mail Server", relation="ir.mail_server"),
    },
    "base.automation": {
        **AUDIT_FIELDS,
        **CHATTER_FIELDS,
        "name": _f("char", "Automation Rule Name", required=True),
        "model_id": _f("many2one", "Model", relation="ir.model", required=True),
        "model_name": _f("char", "Model Name", readonly=True, store=False),
        "trigger": _f("selection", "Trigger", required=True, selection=[[t, t] for t in _TRIGGERS]),
        "trigger_field_ids": _f("many2many", "Trigger Fields", relation="ir.model.fields"),
        "trg_date_range": _f("integer", "Delay"),
        "filter_pre_domain": _f("char", "Before Update Domain"),
        "filter_domain": _f("char", "Apply on"),
        "action_server_ids": _f("one2many", "Actions", relation="ir.actions.server", relation_field="base_automation_id"),
        "record_getter": _f("char", "Record Getter"),
        "log_webhook_calls": _f("boolean", "Log Calls"),
        "on_change_field_ids": _f("many2many", "On Change Fields Trigger", relation="ir.model.fields"),
        "url": _f("char", "Url", readonly=True, store=False),
        "webhook_uuid": _f("char", "Webhook UUID", readonly=True),
        "active": _f("boolean", "Active"),
    },
    "ir.actions.server": {
        **AUDIT_FIELDS,
        "name": _f("char", "Action Name", required=True),
        "state": _f("selection", "Type", required=True, selection=[[t, t] for t in _ACTION_TYPES]),
        "model_id": _f("many2one", "Model", relation="ir.model", required=True),
        "base_automation_id": _f("many2one", "Automation Rule", relation="base.automation"),
        "sequence": _f("integer", "Sequence"),
        "update_path": _f("char", "Field to Update Path"),
        "evaluation_type": _f("selection", "Value Type", selection=[["value", "Update"], ["sequence", "Sequence"], ["equation", "Compute"]]),
        "value": _f("text", "Value"),
        "html_value": _f("html", "Html Value"),
        "resource_ref": _f("reference", "Record", selection=[["res.users", "User"], ["crm.stage", "Stage"], ["crm.tag", "Tag"]]),
        "update_boolean_value": _f("selection", "Boolean Value", selection=[["true", "true"], ["false", "false"]]),
        "update_m2m_operation": _f("selection", "Many2many Operations", selection=[["add", "Adding"], ["remove", "Removing"], ["set", "Setting it to"], ["clear", "Clearing it"]]),
        "partner_ids": _f("many2many", "Followers", relation="res.partner"),
        "template_id": _f("many2one", "Email Template", relation="mail.template"),
        "mail_post_method": _f("selection", "Send Email As", selection=[["email", "Email"], ["comment", "Message"], ["note", "Note"]]),
        "activity_type_id": _f("many2one", "Activity Type", relation="mail.activity.type"),
        "activity_summary": _f("char", "Title"),
        "activity_user_id": _f("many2one", "Responsible", relation="res.users"),
        "code": _f("text", "Python Code"),
        "webhook_url": _f("char", "Webhook URL"),
        "webhook_sample_payload": _f("text", "Sample Payload", readonly=True, store=False),
        "child_ids": _f("one2many", "Child Actions", relation="ir.actions.server", relation_field="parent_id"),
        "group_ids": _f("many2many", "Allowed Groups", relation="res.groups"),
        "usage": _f("selection", "Usage", selection=[["ir_actions_server", "Server Action"], ["base_automation", "Automation Rule"]]),
    },
    "mail.activity.type": {"name": _f("char", "Name")},
    "account.tax": {
        **AUDIT_FIELDS,
        "name": _f("char", "Tax Name", required=True),
        "amount": _f("float", "Amount"),
        "type_tax_use": _f("selection", "Tax Type", selection=[["sale", "Sales"], ["purchase", "Purchases"], ["none", "None"]]),
        "invoice_repartition_line_ids": _f("one2many", "Distribution for Invoices", relation="account.tax.repartition.line", relation_field="tax_id"),
        "refund_repartition_line_ids": _f("one2many", "Distribution for Refunds", relation="account.tax.repartition.line", relation_field="tax_id"),
        "tax_group_id": _f("many2one", "Tax Group", relation="account.tax.group"),
        "active": _f("boolean", "Active"),
    },
    "account.tax.repartition.line": {
        "tax_id": _f("many2one", "Tax", relation="account.tax"),
        "factor_percent": _f("float", "%", required=True),
        "repartition_type": _f("selection", "Based On", required=True, selection=[["base", "Base"], ["tax", "of tax"]]),
        "document_type": _f("selection", "Document Type", required=True, selection=[["invoice", "Invoice"], ["refund", "Refund"]]),
        "account_id": _f("many2one", "Account", relation="account.account"),
    },
    "account.tax.group": {"name": _f("char", "Name")},
    "account.account": {
        **AUDIT_FIELDS,
        "name": _f("char", "Account Name", required=True),
        "code": _f("char", "Code"),
        "account_type": _f("selection", "Type", selection=[["income", "Income"], ["expense", "Expenses"]]),
    },
    "account.journal": {
        **AUDIT_FIELDS,
        "name": _f("char", "Journal Name", required=True),
        "code": _f("char", "Short Code", required=True),
        "type": _f("selection", "Type", required=True, selection=[["sale", "Sales"], ["bank", "Bank"], ["general", "Misc"]]),
        "bank_account_id": _f("many2one", "Bank Account", relation="res.partner.bank"),
        "bank_acc_number": _f("char", "Account Number", store=False),
        "bank_id": _f("many2one", "Bank", relation="res.bank", store=False),
    },
    "account.move": {
        **AUDIT_FIELDS,
        "ref": _f("char", "Reference"),
        "partner_id": _f("many2one", "Partner", relation="res.partner"),
        "partner_bank_id": _f("many2one", "Recipient Bank", relation="res.partner.bank"),
    },
    "account.move.line": {
        **AUDIT_FIELDS,
        "name": _f("char", "Label"),
        "analytic_distribution": _f("json", "Analytic Distribution"),
        "x_other_json": _f("json", "Other JSON"),
    },
    "account.analytic.account": {"name": _f("char", "Analytic Account", required=True)},
}
SETUP_RECORDS: dict[str, dict[int, dict]] = {
    "ir.model": {
        90: {"model": "res.partner", "name": "Contact"},
        91: {"model": "crm.lead", "name": "Lead/Opportunity"},
        92: {"model": "res.users", "name": "User"},
        93: {"model": "mail.template", "name": "Email Templates"},
        94: {"model": "sale.order", "name": "Sales Order"},
    },
    "ir.ui.menu": {1: {"name": "Sales"}},
    "base.automation": {
        300: {"name": "Plan a call on new leads", "model_id": [91, "Lead/Opportunity"], "model_name": "crm.lead",
              "trigger": "on_create_or_write", "action_server_ids": [400], "active": True},
        301: {"name": "Old rule with code", "model_id": [91, "Lead/Opportunity"], "model_name": "crm.lead",
              "trigger": "on_create_or_write", "action_server_ids": [401], "active": True},
    },
    "ir.actions.server": {
        400: {"name": "Plan a call", "state": "next_activity", "model_id": [91, "Lead/Opportunity"]},
        401: {"name": "Python thing", "state": "code", "model_id": [91, "Lead/Opportunity"], "code": "record.write({})"},
    },
    "mail.template": {20: {"name": "Sales: Send Quotation", "subject": "Your quotation"}},
    "mail.activity.type": {4: {"name": "Call"}},
    "account.analytic.account": {7: {"name": "Project Alpha"}, 8: {"name": "Project Beta"}, 31: {"name": "Marketing"}},
    "account.account": {50: {"name": "Sales"}},
    "account.journal": {60: {"name": "Customer Invoices", "code": "INV", "type": "sale"}},
    "account.move": {70: {"ref": "INV/2026/0001"}},
    "account.move.line": {700: {"name": "Licence"}},
}


def add_setup_models(fake: FakeOdoo) -> FakeOdoo:
    for model, fields in SETUP_SCHEMA.items():
        fake.schema.setdefault(model, {}).update(copy.deepcopy(fields))
    for model, rows in SETUP_RECORDS.items():
        for rid, row in copy.deepcopy(rows).items():
            row.setdefault("write_date", "2026-10-15 10:00:00")
            fake.records.setdefault(model, {})[rid] = row
    return fake


SALE_ORDER_FORM = """
<form string="Sales Order">
  <header>
    <button name="action_quotation_send" string="Send by Email" type="object" invisible="state != 'draft'"/>
    <button name="action_confirm" string="Confirm" type="object" class="btn-primary" invisible="state not in ('draft', 'sent')"/>
    <button name="action_confirm" string="Confirm" type="object" invisible="state != 'sent'"/>
    <button name="action_cancel" string="Cancel" type="object" invisible="state == 'cancel'"
            confirm="Are you sure you want to cancel this order?"/>
    <button name="payment_action_capture" string="Capture Transaction" type="object"/>
    <button name="action_draft" string="Set to Quotation" type="object"/>
    <button name="42" string="Create Invoice" type="action" invisible="invoice_status != 'to invoice'"/>
    <button name="%(sale.some_unresolved_xmlid)d" string="Broken" type="action"/>
    <button name="unlink" string="Delete" type="object"/>
    <button name="_action_private" string="Private" type="object"/>
    <button name="Action_Upper" string="Upper" type="object"/>
    <button string="No name" type="object"/>
    <button name="action_preview_sale_order" string="Preview" type="object"/>
  </header>
  <sheet>
    <field name="partner_id"/>
    <field name="order_line">
      <list>
        <field name="product_id"/>
        <button name="action_line_explode" string="Explode line" type="object"/>
      </list>
    </field>
  </sheet>
</form>
"""

SALE_ORDER_LIST = """
<list>
  <field name="name"/>
  <header><button name="action_mass_confirm" string="Confirm selected" type="object"/></header>
</list>
"""


@dataclass
class Call:
    model: str
    method: str
    ids: list[int] | None
    context: dict | None
    kwargs: dict


@dataclass
class FakeOdoo:
    """In-memory stand-in for OdooClient with the same ``call()`` signature.

    Every call is recorded. A method containing ``unlink`` makes the test fail immediately,
    and test modules additionally assert after each test that none was ever attempted.
    """

    schema: dict[str, dict[str, dict]] = field(default_factory=lambda: copy.deepcopy(SCHEMA))
    records: dict[str, dict[int, dict]] = field(default_factory=lambda: copy.deepcopy(RECORDS))
    uid: int = 7
    login: str = "ai.tester@example.com"
    tz: str = "Asia/Kolkata"
    views: dict[str, dict] = field(default_factory=dict)
    defaults: dict[str, dict] = field(default_factory=dict)
    errors: dict[tuple[str, str], Exception] = field(default_factory=dict)
    action_results: dict[tuple[str, str], Any] = field(default_factory=dict)
    followers: list[dict] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    # what Odoo's onchange fills in on a new record of a model (computed values such as totals or a journal)
    filled: dict[str, dict] = field(default_factory=dict)
    # has_access answers, (model, operation) -> bool; anything not listed is allowed
    access: dict[tuple[str, str], bool] = field(default_factory=dict)

    instances = []  # class-level registry (not a dataclass field: no annotation)

    def __post_init__(self) -> None:
        self.creds = OdooCredentials("https://odoo.example.com", "testdb", self.login, "secret-api-key-123")
        self.identity_obj = OdooIdentity(
            uid=self.uid, login=self.login, name="AI Tester", tz=self.tz, lang="en_US", company_id=1,
            company_name="Sahajta", is_internal_user=True, server_version="19.0", protocol="json2",
        )
        self._ids = itertools.count(1000)
        self._clock = itertools.count(1)
        self.views.setdefault(
            "sale.order",
            {"views": {"form": {"arch": SALE_ORDER_FORM}, "list": {"arch": SALE_ORDER_LIST}}},
        )
        self.records.setdefault("ir.actions.act_window", {42: {"res_model": "sale.advance.payment.inv", "name": "Create invoices"}})
        for model_records in self.records.values():
            for row in model_records.values():
                row.setdefault("write_date", "2026-10-15 10:00:00")
        FakeOdoo.instances.append(self)

    # ----------------------------------------------------------------- helpers for tests

    def methods(self) -> list[str]:
        return [c.method for c in self.calls]

    def calls_to(self, method: str) -> list[Call]:
        return [c for c in self.calls if c.method == method]

    def touch(self, model: str, rid: int, **values: Any) -> None:
        """Simulate another person editing a record in Odoo."""
        self.records[model][rid].update(values)
        self.records[model][rid]["write_date"] = f"2026-10-15 11:00:{next(self._clock):02d}"

    # ----------------------------------------------------------------- OdooClient surface

    async def identity(self) -> OdooIdentity:
        return self.identity_obj

    async def call(self, model: str, method: str, *, ids: list[int] | None = None, context: dict | None = None, **kwargs: Any) -> Any:
        self.calls.append(Call(model, method, list(ids) if ids else None, copy.deepcopy(context), copy.deepcopy(kwargs)))
        assert "unlink" not in method.lower(), f"FakeOdoo received a forbidden method: {model}.{method}"
        if (model, method) in self.errors:
            raise self.errors[(model, method)]
        handler = getattr(self, f"_m_{method}", None)
        if handler is not None:
            return handler(model, ids, context, **kwargs)
        if (model, method) in self.action_results:
            return self.action_results[(model, method)]
        return True  # any other (button) method

    # ----------------------------------------------------------------- method emulation

    def _store(self, model: str) -> dict[int, dict]:
        return self.records.setdefault(model, {})

    def _m_fields_get(self, model, ids, context, attributes=None):
        if model not in self.schema:
            raise OdooError(f"Object {model} doesn't exist", kind="missing", status=404)
        return copy.deepcopy(self.schema[model])

    def _m_search(self, model, ids, context, domain=None, **kw):
        store = self._store(model)
        for term in domain or []:
            if isinstance(term, list) and term[:2] == ["id", "in"]:
                return [i for i in term[2] if i in store]
        return sorted(store)

    def _row(self, model: str, rid: int, fields: list[str]) -> dict:
        rec = self._store(model)[rid]
        meta = self.schema.get(model, {})
        row = {"id": rid}
        for name in fields:
            if name == "id":
                continue
            if name == "display_name":
                row[name] = rec.get("name") or f"{model},{rid}"
                continue
            default = [] if meta.get(name, {}).get("type") in ("one2many", "many2many") else False
            row[name] = copy.deepcopy(rec.get(name, default))
        return row

    def _m_read(self, model, ids, context, fields=None, **kw):
        store = self._store(model)
        return [self._row(model, i, fields or list(self.schema.get(model, {}))) for i in ids or [] if i in store]

    def _m_search_read(self, model, ids, context, domain=None, fields=None, offset=0, limit=None, order=None, **kw):
        store = self._store(model)
        if model == "mail.followers":
            return copy.deepcopy(self.followers)
        selected = sorted(store)[offset or 0:]
        if limit:
            selected = selected[:limit]
        return [self._row(model, i, fields or []) for i in selected]

    def _m_search_count(self, model, ids, context, domain=None, **kw):
        return len(self._store(model))

    def _m_get_views(self, model, ids, context, views=None, options=None):
        return copy.deepcopy(self.views.get(model, {"views": {}}))

    def _m_default_get(self, model, ids, context, fields=None):
        from_context = {k[len("default_"):]: v for k, v in (context or {}).items() if k.startswith("default_")}
        return copy.deepcopy({**self.defaults.get(model, {}), **from_context})

    def _m_has_access(self, model, ids, context, operation=None):
        return self.access.get((model, operation), True)

    def _m_onchange(self, model, ids, context, values=None, field_names=None, fields_spec=None):
        """A new record as Odoo's form would show it: values, then defaults, then what Odoo computes."""
        merged = {**self._m_default_get(model, ids, context), **copy.deepcopy(self.filled.get(model, {})), **(values or {})}
        meta = self.schema.get(model, {})
        out = {}
        for name, spec in (fields_spec or {}).items():
            value = merged.get(name, False)
            ftype = meta.get(name, {}).get("type")
            relation = meta.get(name, {}).get("relation")
            if ftype == "many2one" and isinstance(value, int) and not isinstance(value, bool) and spec.get("fields"):
                value = {"id": value, "display_name": self._store(relation).get(value, {}).get("name")}
            elif ftype in ("many2many", "one2many") and isinstance(value, list) and spec.get("fields"):
                ids = [i for cmd in value for i in (cmd[2] if isinstance(cmd, list) and cmd[0] == 6 else [cmd] if isinstance(cmd, int) else [])]
                rows = [{"id": i, **{f: self._store(relation).get(i, {}).get("name" if f == "display_name" else f, False)
                                      for f in spec["fields"]}} for i in ids]
                value = [[4, row["id"], row] for row in rows] or [cmd for cmd in value if isinstance(cmd, list) and cmd[0] == 0]
            out[name] = value
        return {"value": out}

    def _m_web_save_multi(self, model, ids, context, vals_list=None, specification=None):
        for rid, vals in zip(ids or [], vals_list or [], strict=True):
            self.touch(model, rid, **{k: v for k, v in vals.items() if not isinstance(v, list)})
        return [{"id": rid} for rid in ids or []]

    def _m_create(self, model, ids, context, vals_list=None, **kw):
        new_ids = []
        for vals in vals_list or []:
            rid = next(self._ids)
            row = {k: v for k, v in vals.items() if not isinstance(v, list)}
            row.setdefault("name", f"New {model} {rid}")
            row["write_date"] = "2026-10-15 12:00:00"
            self._store(model)[rid] = row
            new_ids.append(rid)
        return new_ids

    def _m_write(self, model, ids, context, vals=None, **kw):
        for rid in ids or []:
            self.touch(model, rid, **{k: v for k, v in (vals or {}).items() if not isinstance(v, list)})
        return True

    def _m_message_post(self, model, ids, context, **kw):
        return next(self._ids)

    def _m_name_search(self, model, ids, context, name="", operator="ilike", limit=50, **kw):
        store = self._store(model)
        return [[i, r.get("name")] for i, r in sorted(store.items()) if name.lower() in str(r.get("name", "")).lower()][:limit]


@pytest.fixture
def fake_odoo() -> FakeOdoo:
    return FakeOdoo()


@pytest.fixture
def setup_fake() -> FakeOdoo:
    """A FakeOdoo that also has the setup-area models (settings, templates, automation rules, accounting setup)."""
    return add_setup_models(FakeOdoo())


@pytest.fixture
def no_unlink_ever():
    """Use with ``pytestmark = pytest.mark.usefixtures("no_unlink_ever")``: after each test, no FakeOdoo
    created during it may have received any method containing 'unlink'."""
    start = len(FakeOdoo.instances)
    yield
    created = FakeOdoo.instances[start:]
    del FakeOdoo.instances[start:]
    for fake in created:
        bad = [f"{c.model}.{c.method}" for c in fake.calls if "unlink" in c.method.lower()]
        assert not bad, f"unlink-like methods reached the Odoo client: {bad}"
