"""The safety policy: which models, fields, methods and context keys the AI may touch.

Two layers:
  * HARD rules are constants in this file. No environment variable can loosen them.
    They cover deletion, credentials, code execution, security configuration and
    module management.
  * SOFT rules come from Settings and default to "off" (read-only, no archiving,
    no cancelling, no outbound e-mail/SMS).

A few setup areas are open within limits (see "Setup areas" below): app settings, e-mail
templates (their texts, and new ones), automation rules without code, new accounting setup and a few edits
to existing setup, bank matching rules, and copying or moving files already in Odoo onto business records.
Every change there still goes through preview and approval.

Deleting has one narrow path (see DELETABLE): drafts that never had a number, cancelled quotations
and archived leads, through the delete tools only. Removing lines is open only on documents that are
still drafts (see LINE_REMOVAL).

Odoo's own access rights still apply on top of all of this: the server can never
do more than the signed-in Odoo user is allowed to do in the Odoo UI.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .config import Settings
from .errors import PolicyViolation

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

# Never readable and never writable: credentials, secrets, code execution,
# security rules, module management, server internals.
HARD_BLOCKED_MODELS: frozenset[str] = frozenset(
    {
        # credentials / authentication
        "res.users.apikeys",
        "res.users.apikeys.description",
        "res.users.apikeys.show",
        "res.users.identitycheck",
        "res.users.deletion",
        "res.users.log",
        "res.device",
        "res.device.log",
        "res.session",  # Odoo 20: session identifiers, IPs, user agents
        "auth_totp.device",
        "auth_totp.wizard",
        "auth.totp.wizard",
        "auth.oauth.provider",
        "auth.passkey.key",
        "change.password.wizard",
        "change.password.user",
        "change.password.own",
        "portal.wizard",
        "portal.wizard.user",
        # secrets & integrations
        "ir.config_parameter",
        "ir.mail_server",
        "fetchmail.server",
        "iap.account",
        "payment.provider",
        "payment.token",
        "payment.data",  # raw payment-provider webhook payloads
        "sms.account.phone",
        "sms.account.code",
        "sms.account.sender",
        # (res.config.settings is a limited setup area, see below)
        "res.config",
        "res.config.installer",
        # code execution / automation (automation rules and their server actions are a limited setup area, see below)
        "ir.cron",
        "ir.cron.trigger",
        "ir.cron.progress",
        "ir.actions.client",
        # security configuration
        "ir.model.access",
        "ir.rule",
        "ir.access",  # Odoo 20 merged access rights and record rules into this model
        # module management
        "ir.module.module",
        "ir.module.module.dependency",
        "ir.module.module.exclusion",
        "base.module.update",
        "base.module.upgrade",
        "base.module.uninstall",
        "base.module.install.request",
        "base.module.install.review",
        # server internals
        "ir.logging",
        "ir.profile",
        "ir.profile.query",  # raw SQL with parameters
        "ir.autovacuum",
        "ir.demo",
        "ir.demo_failure",
        "ir.demo_failure.wizard",
        "ir.http",
        "ir.qweb",
        "ir.binary",
        "ir.websocket",
        "bus.bus",
        "bus.presence",
        "base_import.import",
        "base_import.mapping",
        "base.partner.merge.automatic.wizard",  # merging partners deletes the duplicates
        "data_merge.record",
        "data_merge.group",
        "data_merge.model",
        "data_cleaning.record",
        "data_cleaning.model",
    }
)

# Readable (where Odoo allows it) but never writable, by area: each area has its own short reason, which the AI
# and the person see. Prefix matches end with "."; the others also cover longer names (account.tax.group, ...).
PROTECTED_AREAS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        # changing bank details is the classic payment-fraud vector
        "holds bank details, and a wrong bank account sends money to the wrong place",
        ("res.partner.bank", "account.online."),  # account.online.: bank-sync connections
    ),
    ("sets the accounting lock dates", ("account.change.lock.date", "account.lock_exception")),
    (
        "is accounting setup: a wrong change silently affects every future entry and report",
        (
            "account.account", "account.tax", "account.fiscal.position", "account.journal", "account.report",
            "account.reconcile.model", "account.payment.method", "account.cash.rounding", "account.code.mapping",
            "account.root", "account.group", "account.return.type", "account.return.check.template",
            "decimal.precision",
        ),
    ),
    (
        # mail.message: use the note tool instead; mail.followers: adding a follower makes Odoo e-mail that person
        "sends or stores e-mails and messages (to log an internal note, use odoo_add_note)",
        (
            "mail.template", "mail.mail", "mail.message", "mail.compose.message", "mail.followers", "mail.alias",
            "mail.server", "mail.ice.server", "mail.gateway.allowed", "mail.guest", "mailing.", "sms.", "whatsapp.",
            "snailmail.", "digest.",
        ),
    ),
    ("handles payments or paid Odoo credits", ("payment.", "iap.", "iap", "crm.iap")),
    # the website model holds custom <script> code; pages hold raw HTML
    ("holds website pages and their code", ("website", "web_editor.")),
    # an AI must not rewrite another AI's instructions
    ("holds Odoo's own AI agents and their instructions", ("ai.",)),
    (
        "shares data outside the company or keeps a document's edit history",
        ("spreadsheet.dashboard.share", "documents.share", "knowledge.invite", "spreadsheet.revision"),
    ),
    (
        # ir.: all technical models (views, menus, sequences, attachments, fields, server actions, ...);
        # res.users: also res.users.settings etc.; creating users also costs subscription seats
        "is system or security setup (users, access rights, companies, technical settings)",
        (
            "ir.", "base.", "base_import.", "res.users", "res.groups", "res.company", "res.currency", "res.lang",
            "res.country", "auth", "bus.",
        ),
    ),
)
HARD_READONLY_PREFIXES: tuple[str, ...] = tuple(prefix for _, prefixes in PROTECTED_AREAS for prefix in prefixes)


def protected_area(model: str) -> str | None:
    """The reason a model is write-protected, or None when it is not in a protected area."""
    for reason, prefixes in PROTECTED_AREAS:
        for prefix in prefixes:
            if model == prefix.rstrip(".") or model.startswith(prefix):
                return reason
    return None

# Writable only with MCP_ALLOW_OUTBOUND_MESSAGES: creating these e-mails or shares with outside people.
OUTBOUND_GATED_PREFIXES: tuple[str, ...] = (
    "sign.request",  # creating a signature request e-mails the signers
    "sign.send.request",
    "survey.invite",
    "project.collaborator",  # shares the project with portal users
    "portal.share",
    "appointment.invite",
)

# Note: communication models (mail.compose.message, mailing.*, sms.*, whatsapp.*, snailmail.*) are in the
# list above and stay read-only even with MCP_ALLOW_OUTBOUND_MESSAGES; that flag only enables the dedicated,
# previewed odoo_send_message tool, message-sending buttons, and e-mail/follower actions in automation rules.

# ---------------------------------------------------------------------------
# Setup areas: open within limits, always through preview and approval
# ---------------------------------------------------------------------------

SETTINGS_MODEL = "res.config.settings"  # create a settings record, then press its Save button (execute)
TEMPLATE_MODEL = "mail.template"  # subject, body and recipients; a new one also gets a name and a business model
AUTOMATION_MODEL = "base.automation"  # rules without code; their actions only nested inside them
SERVER_ACTION_MODEL = "ir.actions.server"

# Accounting setup: new records may be created (with the usual field rules). Records already in Odoo get only the
# edits in SETUP_EDIT_FIELDS: entries already use them, so a rate, an account type or a journal's code would change
# past reports and GST returns. What may be set on creation is not limited by that list.
ACCOUNTING_SETUP_MODELS: frozenset[str] = frozenset(
    {"account.account", "account.tax", "account.fiscal.position", "account.journal"}
)
SETUP_EDIT_FIELDS: dict[str, frozenset[str]] = {
    # name; tags place the account in the cash flow report; archiving only an account without journal items (the
    # service asks Odoo first)
    "account.account": frozenset({"name", "tag_ids", "active"}),
    # on/off and its texts. fiscal_position_ids / original_tax_ids are the fiscal position tax mapping, which Odoo 19
    # keeps on the replacement tax ("Fiscal Positions" and "Replaces" on its form)
    "account.tax": frozenset(
        {"active", "name", "description", "invoice_label", "fiscal_position_ids", "original_tax_ids"}
    ),
    # name, when it applies on its own, and its mappings: tax_ids (Odoo 19: its replacement taxes; Odoo 18: mapping
    # lines) and account_ids (account mapping lines)
    "account.fiscal.position": frozenset(
        {"name", "auto_apply", "country_id", "country_group_id", "state_ids", "zip_from", "zip_to", "vat_required",
         "tax_ids", "account_ids"}
    ),
    # how it is shown: name, dashboard, colour and display order
    "account.journal": frozenset({"name", "show_on_dashboard", "color", "sequence"}),
}
# Bank matching rules may also be edited and archived: they only decide how future bank lines are matched,
# never past entries. Their buttons stay closed.
RECONCILE_MODEL = "account.reconcile.model"
# Files already in Odoo (e.g. a bill's PDF, a contract signed in Odoo Sign) can be moved or copied onto business
# records: only which record they are on changes, or Odoo duplicates the file itself. Their content never passes
# through Claude, and nothing is uploaded or deleted. Where they come from is checked against Odoo by the service.
ATTACHMENT_MODEL = "ir.attachment"
# A file may be moved onto an accounting entry or a CRM lead ...
ATTACHMENT_TARGETS: frozenset[str] = frozenset({"account.move", "crm.lead"})
# ... from no record, a draft entry (the service checks the state) or a CRM lead (e.g. one Odoo's CRM inbox made).
ATTACHMENT_SOURCES: frozenset[str] = frozenset({"account.move", "crm.lead"})
# A copy may go onto a lead, a bill/invoice/entry, a quotation/order or a contact, from any file the person may read.
ATTACHMENT_COPY_TARGETS: frozenset[str] = frozenset({"crm.lead", "account.move", "sale.order", "res.partner"})
_SETUP_NAMES: dict[str, str] = {
    "account.account": "Accounts",
    "account.tax": "Taxes",
    "account.fiscal.position": "Fiscal positions",
    "account.reconcile.model": "Reconciliation models",
    "account.journal": "Journals",
}

# Models these rules open, although their prefix is protected or they were blocked before.
LIMITED_MODELS: frozenset[str] = ACCOUNTING_SETUP_MODELS | {
    SETTINGS_MODEL, TEMPLATE_MODEL, AUTOMATION_MODEL, RECONCILE_MODEL, ATTACHMENT_MODEL,
}

# Lines that may be written only inside their parent record, through these fields (never on their own).
NESTED_LINES: dict[tuple[str, str], str] = {
    ("account.tax", "invoice_repartition_line_ids"): "account.tax.repartition.line",
    ("account.tax", "refund_repartition_line_ids"): "account.tax.repartition.line",
    ("account.tax", "repartition_line_ids"): "account.tax.repartition.line",
    ("account.fiscal.position", "account_ids"): "account.fiscal.position.account",
    ("account.fiscal.position", "tax_ids"): "account.fiscal.position.tax",  # Odoo 18 and older (19 links taxes)
    ("account.reconcile.model", "line_ids"): "account.reconcile.model.line",
    (AUTOMATION_MODEL, "action_server_ids"): SERVER_ACTION_MODEL,
}
_LINE_PARENTS: dict[str, tuple[str, str]] = {line: parent for parent, line in NESTED_LINES.items()}

# On these models only the listed fields may be written; all others stay read-only.
FIELD_ALLOWLISTS: dict[str, frozenset[str]] = {
    ATTACHMENT_MODEL: frozenset({"res_model", "res_id"}),
    # name and model_id only when a template is created (CREATE_ONLY_FIELDS); never a sender, attachments or reports
    TEMPLATE_MODEL: frozenset(
        {"subject", "body_html", "email_to", "email_cc", "partner_to", "use_default_to", "reply_to", "name", "model_id"}
    ),
    AUTOMATION_MODEL: frozenset(
        {
            "name", "description", "model_id", "trigger", "trigger_field_ids", "trg_selection_field_id",
            "trg_field_ref", "trg_date_id", "trg_date_range", "trg_date_range_mode", "trg_date_range_type",
            "trg_date_calendar_id", "filter_pre_domain", "filter_domain", "action_server_ids", "active",
        }
    ),
    SERVER_ACTION_MODEL: frozenset(
        {
            "name", "sequence", "state", "model_id",
            # update a field with a fixed value
            "update_path", "evaluation_type", "value", "html_value", "resource_ref", "update_boolean_value",
            "update_m2m_operation",
            # add followers
            "followers_type", "followers_partner_field_name", "partner_ids",
            # post a message or send an e-mail from a template
            "template_id", "mail_post_method", "mail_post_autofollow",
            # create an activity
            "activity_type_id", "activity_summary", "activity_note", "activity_date_deadline_range",
            "activity_date_deadline_range_type", "activity_user_type", "activity_user_id", "activity_user_field_name",
        }
    ),
}

# Never read, searched, grouped or written: a webhook's secret address, and Python code (which may hold keys).
HIDDEN_FIELDS: dict[str, frozenset[str]] = {
    AUTOMATION_MODEL: frozenset({"url", "webhook_uuid"}),
    SERVER_ACTION_MODEL: frozenset({"code", "webhook_url", "webhook_sample_payload"}),
}

# The only buttons Claude may press on these models.
LIMITED_BUTTONS: dict[str, frozenset[str]] = {
    SETTINGS_MODEL: frozenset({"execute"}),  # the settings screen's Save (drawn by Odoo's web client, not the view)
    TEMPLATE_MODEL: frozenset(),
    AUTOMATION_MODEL: frozenset(),
    **{model: frozenset() for model in ACCOUNTING_SETUP_MODELS | {RECONCILE_MODEL, ATTACHMENT_MODEL}},
}
_BUTTONS_REFUSED: dict[str, str] = {
    ATTACHMENT_MODEL: "Buttons on files cannot be pressed through Claude. Claude can only move a file onto a bill, "
    "invoice, journal entry or lead, or copy it onto a lead, bill, quotation or contact.",
    SETTINGS_MODEL: "Only the settings screen's Save button (execute) can be pressed through Claude; the other "
    "settings buttons open or install things. Use them in Odoo.",
    TEMPLATE_MODEL: "Buttons on e-mail templates cannot be pressed through Claude. Claude can only change a "
    "template's subject, body and recipients, or create a new template.",
    AUTOMATION_MODEL: "Buttons on automation rules cannot be pressed through Claude. To stop a rule, archive it "
    "(set active to false).",
}

# Lines that may be removed (Odoo's command 2 deletes the line): only from these fields, and only while the document
# is in one of these states. The service asks Odoo for the state before the approval and again at the change.
# Every other one2many field keeps the general rule: lines are added or edited, never removed.
LINE_REMOVAL: dict[tuple[str, str], frozenset[str]] = {
    ("sale.order", "order_line"): frozenset({"draft", "sent"}),  # quotations
    ("purchase.order", "order_line"): frozenset({"draft", "sent"}),  # requests for quotation
    ("account.move", "invoice_line_ids"): frozenset({"draft"}),  # draft invoices, bills and entries
}
_LINE_REMOVAL_REFUSED: dict[str, str] = {
    "sale.order": "is a confirmed or cancelled order, not a quotation, so removing lines is not possible (Odoo keeps "
    "them to track what is delivered and invoiced). Set the line's quantity to 0 instead",
    "purchase.order": "is a confirmed or cancelled purchase order, not a request for quotation, so removing lines is "
    "not possible. Set the line's quantity to 0 instead",
    "account.move": "is not a draft (it is posted or cancelled), so removing lines is not possible. Reset it to draft "
    "first and then remove the line, or set the line's quantity to 0 on a draft",
}

# The only records Claude may delete, through odoo_preview_delete / odoo_delete and nothing else. The service checks
# each record with Odoo before the approval and again right before deleting (OdooService._deletable).
DELETABLE: dict[str, str] = {
    "account.move": "a draft invoice, bill or journal entry that never had a number",
    "sale.order": "a cancelled quotation or sales order",
    "crm.lead": "an archived lead or opportunity",
}
DELETABLE_TEXT = (
    "draft invoices, bills or entries that never had a number, cancelled quotations or sales orders, and archived "
    "leads"
)

# Settings fields that are refused (module_* is checked separately).
_IDENTITY_FIELD_RE = re.compile(
    r"^(company_name|company_registry|company_details|vat|logo|email|phone|mobile|website|street2?|city|zip|"
    r"state_id|partner_id)$|(^|_)(vat|gstin|pan|tan|registry|logo|country)(_|$)|bank"
)
_SECURITY_SETTING_RE = re.compile(r"^auth_|totp|signup|password|username|audit_trail|lock_date")

# Automation rules
AUTOMATION_TRIGGERS: frozenset[str] = frozenset(
    {
        "on_create", "on_write", "on_create_or_write", "on_stage_set", "on_user_set", "on_tag_set", "on_state_set",
        "on_priority_set", "on_archive", "on_unarchive", "on_time", "on_time_created", "on_time_updated",
        "on_message_received", "on_message_sent",
    }
)
_REFUSED_TRIGGERS: dict[str, str] = {
    "on_change": "runs Python code while someone is editing a record",
    "on_webhook": "lets an outside system start the rule through a web address",
    "on_unlink": "runs when records are deleted",
}
_MESSAGE_TRIGGERS = frozenset({"on_message_received", "on_message_sent"})
AUTOMATION_ACTION_TYPES: frozenset[str] = frozenset({"object_write", "followers", "next_activity", "mail_post"})
_REFUSED_ACTIONS: dict[str, str] = {
    "code": "runs Python code",
    "webhook": "sends record data to an outside web address",
    "sms": "sends text messages",
    "whatsapp": "sends WhatsApp messages",
    "multi": "runs other server actions",
    "object_create": "creates new records",
    "object_copy": "duplicates records",
    "remove_followers": "removes followers",
}
_ALLOWED_ACTIONS_TEXT = (
    "Allowed: update a field with a fixed value, add followers, create an activity, post a message or send an "
    "e-mail from a template."
)

# ---------------------------------------------------------------------------
# Fields
# ---------------------------------------------------------------------------

# Field names that look like secrets are never returned, never searched on, never written.
_SENSITIVE_FIELD_RE = re.compile(
    r"(^|_)(password|passwd|pwd|secret|secrets|token|tokens|apikey|apikeys|api_key|api_keys|"
    r"private_key|totp|otp|credential|credentials|passkey|passkeys|hmac|signup|pin|pass|passphrase|vault)(_|$)"
    r"|(^|_)key$|^key_|^new_password$|_hash$|session_identifier"
)

# Never writable regardless of model.
MAGIC_FIELDS: frozenset[str] = frozenset(
    {"id", "create_uid", "create_date", "write_uid", "write_date", "display_name", "__last_update"}
)

# Workflow fields: changing them directly skips Odoo's business logic (e.g. an invoice
# marked "posted" without journal entries). Use the model's buttons instead.
WORKFLOW_FIELDS: frozenset[str] = frozenset({"state", "move_type", "payment_state", "invoice_status"})

# (model, field) pairs that pick what a new record is (customer invoice, vendor bill, credit note, ...).
# Odoo marks them read-only because its own screens set them on create (the record always starts in
# draft); they may be set on create here too, but never changed afterwards. An automation rule's model is
# fixed too: changing it would detach its actions. So are an e-mail template's model and name, which other
# records and rules rely on.
CREATE_ONLY_FIELDS: frozenset[tuple[str, str]] = frozenset(
    {
        ("account.move", "move_type"), (AUTOMATION_MODEL, "model_id"), (SERVER_ACTION_MODEL, "model_id"),
        (TEMPLATE_MODEL, "model_id"), (TEMPLATE_MODEL, "name"),
    }
)

# Field types the AI can never write: files, and free-form JSON whose changes a preview can't show clearly.
UNWRITABLE_TYPES: frozenset[str] = frozenset({"binary", "image", "properties", "properties_definition", "json"})
# The one JSON field that is written, with its own checks: {"analytic account id(s)": percentage}.
ANALYTIC_FIELD = "analytic_distribution"

# ---------------------------------------------------------------------------
# Methods
# ---------------------------------------------------------------------------

# Substrings that make a method uncallable, always.
HARD_BLOCKED_METHOD_SUBSTRINGS: tuple[str, ...] = (
    "unlink",
    "delete",
    "purge",
    "install",  # also matches uninstall
    "password",
    "apikey",
    "api_key",
    "totp",
    "passkey",
    "impersonate",
    "signup",
    "sudo",
    "with_user",
    "with_context",
    "with_env",
    "invalidate",
    "truncate",
    # payment-provider operations move real money (capture/void/refund card transactions)
    "capture",
    "void",
    "payout",
    "payment_action",
    "transaction",
    # irreversible or costly side effects
    "hash",  # inalterability hash / lock of posted entries
    "iap",  # paid Odoo IAP credits (lead enrichment, lead generation, ...)
    "create_user",  # new Odoo users = new access and new paid seats
    "trust",  # trusting a bank account enables payments to it (fraud vector)
    "generate_leads",
)
# Whole name parts (split on "_") that make a method uncallable, always.
HARD_BLOCKED_METHOD_TOKENS: frozenset[str] = frozenset(
    {"drop", "erase", "destroy", "wipe", "merge", "module", "modules", "upgrade", "load", "import", "remove"}
)

# Exact method names that are never callable through the action tool (they have
# dedicated, validated tools, or they bypass validation).
HARD_BLOCKED_METHODS: frozenset[str] = frozenset(
    {
        "create",
        "write",
        "copy",
        "copy_data",
        "copy_multi",
        "browse",
        "search",
        "read",
        "name_create",
        "message_post",
        "message_subscribe",
        "message_unsubscribe",
        "message_notify",
        "message_update",
        "message_post_with_source",
        "toggle_active",
        "action_archive",
        "action_unarchive",
        "execute",
        "set_values",
        "run",
        "unlink",
        "export_data",
        "load",
        "web_save",
        "web_save_multi",
        "onchange",
        "flush_model",
        "flush_recordset",
    }
)

ARCHIVE_METHODS: frozenset[str] = frozenset({"toggle_active", "action_archive", "action_unarchive"})

CANCEL_METHOD_PARTS: tuple[str, ...] = (
    "cancel",
    "close",  # e.g. closing (churning) a subscription
    "reverse",
    "reversal",
    "refund",
    "draft",
    "reset",
    "unpost",
    "unreconcile",
    "unlock",
    "revert",
    "refuse",
    "reject",
    "lost",
)

OUTBOUND_METHOD_PARTS: tuple[str, ...] = (
    "send",
    "sent",
    "mail",
    "email",
    "sms",
    "whatsapp",
    "snailmail",
    "fax",
    "invite",
    "notify",
    "share",
    "portal",
)

# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

_ALLOWED_CONTEXT_KEYS: frozenset[str] = frozenset(
    # no active_domain: it would let a wizard act on every matching record, bypassing the per-change cap
    {"active_id", "active_ids", "active_model", "lang", "tz", "allowed_company_ids"}
)
# Context keys that would hide changes from Odoo's audit trail or skip safety checks.
_FORBIDDEN_CONTEXT_PARTS: tuple[str, ...] = (
    "tracking_disable",
    "notrack",
    "nolog",
    "check_move_validity",
    "skip",
    "bypass",
    "force",
    "install",
    "module",
    "no_reset_password",
    "import_file",
)


# Whole families blocked like the models above, so variants added in future Odoo versions are covered too.
HARD_BLOCKED_PREFIXES: tuple[str, ...] = (
    "res.users.apikeys",
    "res.device",
    "res.session",
    "auth_totp",
    "auth.totp",
    "auth.passkey",
    "ir.profile",
    "ir.cron",
    "ir.actions.server.",  # e.g. ir.actions.server.history (old versions of Python code); the model itself is limited
    "ir.module",
    "base.module",
    "base.automation.",  # the rules themselves are a limited setup area
    "payment.provider",
    "payment.token",
    "payment.data",
    "iap.account",
    "fetchmail",
    "ir.mail_server",
    "certificate.",  # e-invoicing certificates and their private keys
)


def is_sensitive_field(name: str) -> bool:
    return bool(_SENSITIVE_FIELD_RE.search(name.lower()))


@dataclass(frozen=True)
class MethodDecision:
    allowed: bool
    reason: str = ""


class SafetyPolicy:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._extra_blocked = {m.strip() for m in settings.mcp_blocked_models}
        self._extra_readonly = {m.strip() for m in settings.mcp_readonly_models}
        self._writable_allowlist = {m.strip() for m in settings.mcp_writable_models}
        self._extra_blocked_methods = tuple(m.strip().lower() for m in settings.mcp_blocked_methods)
        self._extra_allowed_methods = {m.strip() for m in settings.mcp_extra_allowed_methods}
        # What to do when something is switched off for Claude (never an operator setting's name).
        self._elsewhere = f"Do it in Odoo, or ask {settings.mcp_admin_contact.strip() or 'your Odoo admin'}."

    # -- models ---------------------------------------------------------------------

    def model_read_block_reason(self, model: str) -> str | None:
        if not isinstance(model, str) or not re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+)*", model):
            return f"'{model}' is not a valid Odoo model name"
        if model in HARD_BLOCKED_MODELS or model.startswith(HARD_BLOCKED_PREFIXES):
            return f"'{model}' holds credentials, code or system configuration and is blocked for safety"
        if model in self._extra_blocked or _matches_any(model, self._extra_blocked):
            return f"'{model}' is blocked by this server's configuration"
        return None

    def check_read(self, model: str) -> None:
        reason = self.model_read_block_reason(model)
        if reason:
            raise PolicyViolation(reason)

    def model_write_block_reason(self, model: str) -> str | None:
        """Why no change at all may be made on model. Creating versus changing is checked by change_block_reason."""
        reason = self.model_read_block_reason(model)
        if reason:
            return reason
        if not self.settings.read_write:
            return f"Changes are switched off for Claude: this connection is in read-only mode. {self._elsewhere}"
        if model.startswith(OUTBOUND_GATED_PREFIXES) and not self.settings.mcp_allow_outbound_messages:
            return (
                f"'{model}' e-mails or shares with people outside the company, which is switched off for Claude. "
                f"{self._elsewhere}"
            )
        area = None if model in LIMITED_MODELS else protected_area(model)
        if area:
            return f"'{model}' {area}, so Claude cannot change it. A person can change it in Odoo."
        reason = self._configured_readonly_reason(model)
        if reason:
            return reason
        if self._writable_allowlist and not (
            model in self._writable_allowlist or _matches_any(model, self._writable_allowlist)
        ):
            return f"'{model}' is not on the list of records Claude may change on this connection. {self._elsewhere}"
        return None

    def _configured_readonly_reason(self, model: str) -> str | None:
        if model in self._extra_readonly or _matches_any(model, self._extra_readonly):
            return f"'{model}' is read-only by this server's configuration"
        return None

    def check_write(self, model: str) -> None:
        reason = self.model_write_block_reason(model)
        if reason:
            raise PolicyViolation(reason)

    def change_block_reason(self, model: str, mode: str) -> str | None:
        """Why creating (mode 'create') or changing existing records (any other mode) is refused on a model
        that model_write_block_reason lets through: the limited setup areas."""
        if mode == "create":
            if model == ATTACHMENT_MODEL:
                return (
                    "Files cannot be uploaded through Claude. Upload them in Odoo, or forward a bill's PDF to the bill "
                    "inbox (it becomes a draft bill); Claude can then move a file onto the right bill or entry. A file "
                    'already in Odoo can be copied: records [{"copy_from": <file id>, "res_model": ..., "res_id": ...}].'
                )
            return None
        # existing accounting setup: only the fields in SETUP_EDIT_FIELDS, checked per field
        if model == SETTINGS_MODEL:
            return (
                "Settings are changed by creating a new settings record with only the values to change "
                f"(odoo_preview_create on {SETTINGS_MODEL}), then pressing its Save button (method 'execute'). "
                "An existing settings record cannot be edited."
            )
        return None

    def check_change(self, model: str, mode: str) -> None:
        reason = self.change_block_reason(model, mode)
        if reason:
            raise PolicyViolation(reason)

    def nested_write_block_reason(self, parent: str, field: str, comodel: str, *, creating: bool) -> str | None:
        """Why a comodel record may not be created (creating=True) or edited inside parent.field."""
        if NESTED_LINES.get((parent, field)) == comodel:
            # part of the parent record, which the caller already checked; only blocks configured here still count
            return self.model_read_block_reason(comodel) or self._configured_readonly_reason(comodel)
        if comodel in _LINE_PARENTS:
            owner, owner_field = _LINE_PARENTS[comodel]
            return f"{comodel} records can be written only inside their {owner} record (field {owner_field})"
        if creating and comodel == TEMPLATE_MODEL:  # its model is checked only for a template created on its own
            return (
                "New e-mail templates cannot be created inside another record; create one on its own "
                f"(odoo_preview_create on {TEMPLATE_MODEL})"
            )
        if comodel in ACCOUNTING_SETUP_MODELS and not creating:
            return (
                f"{_SETUP_NAMES[comodel]} already in Odoo cannot be changed through another record; change them on "
                f"their own (odoo_preview_update on {comodel}), where only some fields can change"
            )
        return self.model_write_block_reason(comodel) or self.change_block_reason(
            comodel, "create" if creating else "write"
        )

    def check_nested_write(self, parent: str, field: str, comodel: str, *, creating: bool) -> None:
        reason = self.nested_write_block_reason(parent, field, comodel, creating=creating)
        if reason:
            raise PolicyViolation(reason)

    # -- fields -----------------------------------------------------------------------

    def field_write_block_reason(
        self, name: str, meta: dict, *, model: str | None = None, creating: bool = False
    ) -> str | None:
        if is_sensitive_field(name):
            return "looks like a credential or secret"
        if name in MAGIC_FIELDS:
            return "is maintained automatically by Odoo"
        if name in HIDDEN_FIELDS.get(model or "", ()):
            return "is hidden for safety (secret addresses and Python code are never read or written)"
        allowlist = FIELD_ALLOWLISTS.get(model or "")
        if allowlist is not None and name not in allowlist:
            return f"cannot be changed through Claude; on {model} only these fields can: {', '.join(sorted(allowlist))}"
        create_only = (model, name) in CREATE_ONLY_FIELDS
        if create_only:
            if not creating:
                return "can be set only when the record is created, never changed afterwards"
        elif name in WORKFLOW_FIELDS and allowlist is None:  # (a server action's 'state' is its type, not a status)
            return "is a workflow status; use odoo_list_actions and run the matching button instead"
        ftype = meta.get("type")
        if ftype in UNWRITABLE_TYPES and not (ftype == "json" and name == ANALYTIC_FIELD):
            return f"is a {ftype} field, which this server never writes (a person can edit it in Odoo)"
        if meta.get("readonly") and not create_only:
            return "is read-only in Odoo"
        relation = meta.get("relation")
        if ftype in ("one2many", "many2many", "many2one", "reference") and relation:
            if self.model_read_block_reason(relation):
                return f"points to a blocked model ({relation})"
            if relation == "res.partner.bank":
                return _BANK_FIELD
            if relation == SERVER_ACTION_MODEL and NESTED_LINES.get((model, name)) != relation:
                return f"points to a blocked model ({relation}): server actions can be added only inside an automation rule"
        if model == "account.journal" and "bank" in name:
            return _BANK_FIELD
        setup_edits = SETUP_EDIT_FIELDS.get(model or "")
        if setup_edits is not None and not creating and name not in setup_edits:
            kind = _SETUP_NAMES[model].lower()
            return (
                f"cannot be changed through Claude on {kind} already in Odoo: entries already use them, so the change "
                f"would alter past reports and GST returns. A person can do it in Odoo. On existing {kind} Claude can "
                f"change only: {', '.join(sorted(setup_edits))}"
            )
        if model == SETTINGS_MODEL:
            reason = _settings_field_block_reason(name)
            if reason:
                return reason
        if name == "active" and not self.settings.mcp_allow_archive:
            return f"would archive or unarchive the record, and archiving is switched off for Claude. {self._elsewhere}"
        return None

    # -- methods ------------------------------------------------------------------------

    def method_decision(self, model: str, method: str, *, is_ui_button: bool, label: str = "") -> MethodDecision:
        low = method.lower()
        label_low = (label or "").lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", low):
            return MethodDecision(False, "private or invalid method name")
        if model in LIMITED_BUTTONS:
            if method not in LIMITED_BUTTONS[model]:
                if any(part in low for part in _DELETE_PARTS):
                    return MethodDecision(False, self._delete_reason())
                return MethodDecision(False, _BUTTONS_REFUSED.get(model, _SETUP_BUTTONS_REFUSED))
            for part in self._extra_blocked_methods:
                if part and (part in low or fnmatch.fnmatch(f"{model}:{method}", part)):
                    return MethodDecision(False, f"blocked by this server's configuration ({part})")
            return MethodDecision(True)
        if low in HARD_BLOCKED_METHODS:
            if low in ARCHIVE_METHODS and self.settings.mcp_allow_archive:
                pass
            elif low in ARCHIVE_METHODS:
                return MethodDecision(False, self._archive_reason())
            elif low == "unlink":
                return MethodDecision(False, self._delete_reason())
            else:
                return MethodDecision(
                    False, f"'{method}' cannot be run as a button (use odoo_create / odoo_update / odoo_add_note instead)"
                )
        tokens = set(low.split("_"))
        for part in HARD_BLOCKED_METHOD_SUBSTRINGS:
            if part in low:
                if part in _DELETE_PARTS:
                    return MethodDecision(False, self._delete_reason())
                return MethodDecision(False, f"methods containing '{part}' are permanently blocked")
        for part in HARD_BLOCKED_METHOD_TOKENS & tokens:
            if part in _DELETE_TOKENS:
                return MethodDecision(False, self._delete_reason())
            return MethodDecision(False, f"methods that '{part}' data are permanently blocked")
        for part in self._extra_blocked_methods:
            if part and (part in low or fnmatch.fnmatch(f"{model}:{method}", part)):
                return MethodDecision(False, f"blocked by this server's configuration ({part})")
        if low in ARCHIVE_METHODS or "archive" in low or "restore" in tokens:
            if not self.settings.mcp_allow_archive:
                return MethodDecision(False, self._archive_reason())
        if not self.settings.mcp_allow_cancel_actions:
            for part in CANCEL_METHOD_PARTS:
                if part in tokens or any(token.startswith(part) for token in tokens):
                    phrase = _cancel_phrase(model, part)
                    return MethodDecision(False, f"{phrase} is switched off for Claude. {self._elsewhere}")
        if not self.settings.mcp_allow_outbound_messages:
            for part in OUTBOUND_METHOD_PARTS:
                if (
                    part in tokens
                    or (part in _OUTBOUND_SUBSTRINGS and part in low)
                    or any(token.startswith(part) for token in tokens if part in ("send", "sent", "invite", "notify"))
                ):
                    return MethodDecision(
                        False,
                        f"Sending e-mails or messages to people ('{part}') is switched off for Claude. {self._elsewhere}",
                    )
        if not self.settings.mcp_allow_cancel_actions and _CANCEL_LABEL_RE.search(label_low):
            return MethodDecision(
                False,
                f"The '{label}' button cancels, resets or reverses, which is switched off for Claude. {self._elsewhere}",
            )
        if not self.settings.mcp_allow_outbound_messages and _OUTBOUND_LABEL_RE.search(label_low):
            return MethodDecision(
                False,
                f"The '{label}' button may e-mail or message people, which is switched off for Claude. {self._elsewhere}",
            )
        if not is_ui_button and f"{model}:{method}" not in self._extra_allowed_methods:
            return MethodDecision(
                False,
                f"'{method}' is not a button on {model}'s screens in Odoo; only UI buttons can be run "
                "(call odoo_list_actions to see them)",
            )
        return MethodDecision(True)

    def _archive_reason(self) -> str:
        return f"Archiving is switched off for Claude. {self._elsewhere}"

    def _delete_reason(self) -> str:
        only = f"Claude can delete only {DELETABLE_TEXT}, with odoo_preview_delete."
        if self.settings.mcp_allow_archive:
            return (
                f"Deleting is not possible through Claude's buttons. {only} Archive the record instead (set active to "
                "false with odoo_preview_update), or delete it in Odoo."
            )
        return f"Deleting is not possible through Claude's buttons. {only} Delete anything else in Odoo."

    # -- deleting and removing lines ------------------------------------------------------

    def delete_block_reason(self, model: str) -> str | None:
        """Why records of model may never be deleted (before any record is looked at), or None."""
        reason = self.model_write_block_reason(model)
        if reason:
            return reason
        if model not in DELETABLE:
            return (
                f"Deleting {model} records is not possible through Claude. Claude can delete only {DELETABLE_TEXT}. "
                "Archive or cancel instead where that is allowed, or delete it in Odoo."
            )
        return None

    def check_delete(self, model: str) -> None:
        reason = self.delete_block_reason(model)
        if reason:
            raise PolicyViolation(reason)

    @staticmethod
    def line_removal_states(model: str, field: str) -> frozenset[str] | None:
        """The document states in which lines may be removed from model.field; None when they never may."""
        return LINE_REMOVAL.get((model, field))

    @staticmethod
    def line_removal_refusal(model: str, name: str) -> str:
        """Why no line can be removed from this document (shown as name) in its current state."""
        return f"'{name}' {_LINE_REMOVAL_REFUSED.get(model, 'is not a draft, so removing lines is not possible')}"

    # -- e-mail templates ---------------------------------------------------------------

    def template_model_block_reason(self, model: object) -> str | None:
        """Why a new e-mail template may not be made for records of model: only business records Claude may
        change, never setup, security or e-mail models."""
        if not isinstance(model, str) or not model:
            return "a new e-mail template must say which kind of record it is for (model_id: the id of its ir.model)"
        reason = self.model_write_block_reason(model)
        if reason is None and (model in LIMITED_MODELS or protected_area(model) or model.startswith("mail.")):
            reason = f"'{model}' is setup, security or e-mail configuration, not business records"
        if reason:
            return f"a new e-mail template can be made only for business records Claude may change: {reason}"
        return None

    # -- automation rules ---------------------------------------------------------------

    def automation_trigger_block_reason(self, trigger: object) -> str | None:
        if trigger in AUTOMATION_TRIGGERS:
            return None
        why = _REFUSED_TRIGGERS.get(trigger) if isinstance(trigger, str) else None
        return (
            f"the trigger {trigger!r} is not allowed for automation rules made through Claude"
            f"{f' (it {why})' if why else ''}. Allowed triggers: {', '.join(sorted(AUTOMATION_TRIGGERS))}"
        )

    def automation_action_block_reason(self, action: Mapping, *, trigger: object = None) -> str | None:
        """Why an automation rule's action (its values as they will be after the change) is refused, or None."""
        state = action.get("state")
        name = action.get("name") or "an action"
        if state not in AUTOMATION_ACTION_TYPES:
            why = _REFUSED_ACTIONS.get(state) if isinstance(state, str) else None
            what = why or f"has the type {state!r}"
            return f"action '{name}' {what}, which automation rules made through Claude may not do. {_ALLOWED_ACTIONS_TEXT}"
        if state == "object_write":
            if (action.get("evaluation_type") or "value") != "value":
                return (
                    f"action '{name}' must set a fixed value (evaluation_type 'value'), never a Python expression "
                    "or a sequence"
                )
            path = action.get("update_path")
            if not isinstance(path, str) or not path.strip():
                return f"action '{name}' must name the field to update in update_path, e.g. 'user_id'"
            if "." in path:
                return (
                    f"action '{name}' may update only a field of the rule's own record, not one reached through "
                    f"another record ('{path}')"
                )
        outbound = self.settings.mcp_allow_outbound_messages
        if state == "mail_post" and (action.get("mail_post_method") or "email") != "note":
            if not outbound:
                return f"action '{name}' e-mails or messages people, which is switched off for Claude. {self._elsewhere}"
            if trigger in _MESSAGE_TRIGGERS:
                return (
                    f"action '{name}' would answer messages with messages, which can start an endless e-mail loop "
                    "with an auto-reply. Use an activity or an internal note instead."
                )
        if state == "followers" and not outbound:
            return (
                f"action '{name}' adds followers, and Odoo e-mails followers; that is switched off for Claude. "
                f"{self._elsewhere}"
            )
        return None

    # -- previews -----------------------------------------------------------------------

    def change_warnings(
        self, model: str, mode: str, field_names: Iterable[str], values: Iterable[dict] | None = None
    ) -> list[str]:
        """Plain-language warnings for a preview of a change to the limited setup areas. Pure: no Odoo calls.

        mode is 'create' or 'write' (also 'update'); field_names are the fields the change sets; values, when
        given, are the new values (one dict per record or per group of records).
        """
        names = sorted({str(name) for name in field_names or ()})
        if model == ATTACHMENT_MODEL:
            if mode == "create":
                return ["Odoo makes a copy of each file on the new record; the original stays where it is."]
            return ["Each file leaves the record it is on now. It can be moved back the same way; nothing is deleted."]
        if model == RECONCILE_MODEL:
            warnings = [
                "Changes how Odoo matches bank lines from now on (past entries stay as they are). If this rule is "
                "Automated, Odoo applies it to matching bank lines on its own, with nobody reviewing them."
            ]
            if any(isinstance(v, dict) and v.get("trigger") == "auto_reconcile" for v in values or ()):
                warnings.insert(0, (
                    "Sets this rule to Automated: from now on Odoo books every bank line that matches it on its own, "
                    "without anyone checking. Make sure the conditions are narrow."
                ))
            return warnings
        if model == SETTINGS_MODEL:
            groups = [name for name in names if name.startswith("group_")]
            if groups:
                return [f"Switches a feature on or off for every user in the company, not just you: {', '.join(groups)}."]
            return []
        if model == TEMPLATE_MODEL:
            if mode == "create":
                return [
                    "A new template sends nothing by itself. From now on, people (and automation rules) can choose it "
                    "when they send e-mails about these records."
                ]
            return ["Changes every e-mail Odoo sends with this template from now on, to every recipient."]
        if model == AUTOMATION_MODEL:
            if mode != "create" and names == ["active"]:
                return [
                    "Archiving stops the rule. Unarchiving starts it again: it then runs automatically on every "
                    "matching record, without asking anyone."
                ]
            return ["This rule runs automatically from now on, on every matching record, without asking anyone first."]
        if model in ACCOUNTING_SETUP_MODELS and mode == "create":
            return [
                "New accounting setup affects every future entry; afterwards Claude can change only a few things on it "
                "(such as its name). Check the tax setup with your CA before approving."
            ]
        if model in ACCOUNTING_SETUP_MODELS:
            return _setup_edit_warnings(model, names, values)
        return []

    # -- context ------------------------------------------------------------------------------

    def sanitize_context(self, context: dict | None) -> dict:
        if not context:
            return {}
        if not isinstance(context, dict):
            raise PolicyViolation("context must be an object")
        clean: dict = {}
        for key, value in context.items():
            low = str(key).lower()
            if any(part in low for part in _FORBIDDEN_CONTEXT_PARTS):
                raise PolicyViolation(f"context key '{key}' is not allowed (it would skip Odoo checks or hide changes)")
            if key in _ALLOWED_CONTEXT_KEYS:
                if key == "active_model":
                    # wizards change the records they are opened on, so those must be changeable
                    self.check_write(str(value))
                    self.check_change(str(value), "write")
                    if value in ACCOUNTING_SETUP_MODELS:
                        raise PolicyViolation(
                            f"dialogs cannot act on {_SETUP_NAMES[value].lower()} already in Odoo: a dialog could "
                            "change setup that entries already use, which changes past reports and GST returns. "
                            "Do it in Odoo"
                        )
                elif key in ("lang", "tz") and not (isinstance(value, str) and len(value) <= 64):
                    raise PolicyViolation(f"context {key} must be a short text value")
                elif key in ("active_id",) and not _is_int(value):
                    raise PolicyViolation("context active_id must be an integer record id")
                elif key in ("active_ids", "allowed_company_ids") and not (
                    isinstance(value, list) and all(_is_int(v) for v in value)
                ):
                    raise PolicyViolation(f"context {key} must be a list of integer ids")
                if key == "active_ids" and len(value) > self.settings.mcp_max_action_records:
                    # a dialog acts on the records it is opened on, like a button
                    raise PolicyViolation(
                        f"context active_ids lists {len(value)} records; the limit per change is "
                        f"{self.settings.mcp_max_action_records}"
                    )
                clean[key] = value
            elif low.startswith("default_"):
                field = key[len("default_") :]
                if is_sensitive_field(field) or field in MAGIC_FIELDS:
                    raise PolicyViolation(f"context key '{key}' is not allowed")
                clean[key] = value
            else:
                raise PolicyViolation(
                    f"context key '{key}' is not allowed; permitted: active_id, active_ids, active_model, "
                    "lang, tz, allowed_company_ids, default_<field>"
                )
        return clean


_OUTBOUND_SUBSTRINGS = ("mail", "email", "sms", "whatsapp", "send")

# Method names that ask to delete: the refusal then says what to do instead.
_DELETE_PARTS = ("unlink", "delete", "purge")
_DELETE_TOKENS = frozenset({"drop", "erase", "destroy", "wipe", "remove"})

_SETUP_BUTTONS_REFUSED = (
    "Buttons on accounting setup cannot be pressed through Claude: they change setup that entries already use. "
    "Do it in Odoo."
)


# Odoo 19 keeps the tax mapping on the taxes: a tax linked to fiscal positions is a replacement tax, offered on new
# documents only under those fiscal positions (account.tax._compute_is_domestic and its search domain).
_TAX_OFFERED = (
    "A tax linked to a fiscal position is offered on new documents only under that fiscal position; a tax linked to "
    "none is offered on all new documents. Check that the usual taxes stay available."
)


def _setup_edit_warnings(model: str, names: list[str], values: Iterable[dict] | None) -> list[str]:
    """What an edit to accounting setup already in Odoo affects, in plain words."""
    actives = {v.get("active") for v in values or () if isinstance(v, dict) and "active" in v}
    changed = set(names)
    warnings: list[str] = []
    if model == "account.account":
        if "name" in changed:
            warnings.append("The new name shows wherever the account appears, also in reports for past periods. "
                            "Amounts and entries do not change.")
        if "tag_ids" in changed:
            warnings.append("Tags decide where the account's amounts appear in reports that use tags, such as the cash "
                            "flow statement, also for past periods. Entries do not change.")
        if False in actives:
            warnings.append("Archiving hides the account from new entries. Odoo shows no journal items on it (checked "
                            "just now); it can be unarchived later.")
        if True in actives:
            warnings.append("Unarchiving lets people choose the account on new entries again.")
    elif model == "account.tax":
        if False in actives:
            warnings.append("Switching the tax off hides it on new invoices, bills and orders: products and fiscal "
                            "positions that have it stop adding it to new lines. Documents already made keep it, and "
                            "past reports and GST returns do not change. It can be switched on again.")
        if True in actives:
            warnings.append("Switching the tax on lets new invoices, bills and orders use it again, also through the "
                            "products and fiscal positions that have it.")
        if changed & {"fiscal_position_ids", "original_tax_ids"}:
            warnings.append("Changes which tax replaces which under a fiscal position. This applies only to new "
                            "documents and new lines; documents already made keep their taxes.")
        if "fiscal_position_ids" in changed:
            warnings.append(_TAX_OFFERED)
        if changed & {"name", "description", "invoice_label"}:
            warnings.append("The new text shows on documents from now on, and wherever Odoo shows the tax. The rate and "
                            "amounts do not change.")
    elif model == "account.fiscal.position":
        warnings.append("Fiscal position changes apply only to new documents, or when a person chooses the fiscal "
                        "position again on a draft. Invoices, bills and orders already made keep their taxes and "
                        "accounts, and past reports do not change.")
        if "tax_ids" in changed:
            warnings.append(_TAX_OFFERED)
    elif model == "account.journal":
        warnings.append("Changes only how the journal is shown (name, dashboard, colour, order). Its entries and their "
                        "numbers do not change.")
    return warnings


_BANK_FIELD = (
    "holds bank details, which Claude never sets: a wrong bank account sends money to the wrong place. "
    "A person sets it in Odoo"
)

_CANCEL_PHRASES: dict[str, str] = {
    "cancel": "Cancelling",
    "close": "Closing",
    "reverse": "Reversing",
    "reversal": "Reversing",
    "refund": "Refunds and credit notes",
    "draft": "Resetting to draft",
    "reset": "Resetting",
    "unpost": "Un-posting",
    "unreconcile": "Un-reconciling",
    "unlock": "Unlocking",
    "revert": "Reverting",
    "refuse": "Refusing",
    "reject": "Rejecting",
    "lost": "Marking as lost",
}


def _cancel_phrase(model: str, part: str) -> str:
    if part == "lost" and model == "crm.lead":
        return "Marking leads lost"
    return _CANCEL_PHRASES.get(part, f"'{part}' actions")


def _settings_field_block_reason(name: str) -> str | None:
    if name.startswith("module_"):
        return (
            "installs or removes an Odoo app, which can raise the Odoo bill and is hard to undo. A person installs "
            "apps in Odoo"
        )
    if _IDENTITY_FIELD_RE.search(name):
        return (
            "is part of the company's identity (name, address, GSTIN/VAT, PAN, bank, logo, e-mail, phone). A person "
            "changes it in Odoo, on the company"
        )
    if _SECURITY_SETTING_RE.search(name):
        return "is a security, sign-in or audit setting. A person changes it in Odoo"
    return None


# Button captions are checked too, as phrases: "Create Draft" is fine, "Reset to Draft" is not.
_CANCEL_LABEL_RE = re.compile(
    r"\b(cancel\w*|close\b|reset\b|set to draft|reset to draft|revert\w*|unlock\w*|refuse\w*|reject\w*|mark as lost|"
    r"lost\b|reverse\w*|reversal|refund\w*|credit note|restore\w*|archive\w*|unarchive\w*)"
)
_OUTBOUND_LABEL_RE = re.compile(
    r"\b(send\w*|e-?mail\w*|mail\b|sms|whatsapp|invite\w*|share\b|notify\w*|message\b|post a message)"
)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _matches_any(model: str, patterns: set[str]) -> bool:
    return any(fnmatch.fnmatch(model, pattern) for pattern in patterns if any(c in pattern for c in "*?["))
