"""The safety policy: which models, fields, methods and context keys the AI may touch.

Two layers:
  * HARD rules are constants in this file. No environment variable can loosen them.
    They cover deletion, credentials, code execution, security configuration and
    module management.
  * SOFT rules come from Settings and default to "off" (read-only, no archiving,
    no cancelling, no outbound e-mail/SMS).

Odoo's own access rights still apply on top of all of this: the server can never
do more than the signed-in Odoo user is allowed to do in the Odoo UI.
"""

from __future__ import annotations

import fnmatch
import re
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
        "res.config.settings",
        "res.config",
        "res.config.installer",
        # code execution / automation
        "ir.actions.server",
        "ir.cron",
        "ir.cron.trigger",
        "ir.cron.progress",
        "base.automation",
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

# Readable (where Odoo allows it) but never writable. Prefix matches end with ".".
HARD_READONLY_PREFIXES: tuple[str, ...] = (
    "ir.",  # all technical models (views, menus, sequences, attachments, fields, ...)
    "base.",
    "base_import.",
    "res.users",  # also res.users.settings etc.; creating users also costs subscription seats
    "res.groups",
    "res.company",
    "res.currency",
    "res.lang",
    "auth",
    "iap.",
    "payment.",
    "bus.",
    "web_editor.",
    "website",  # the website model holds custom <script> code; pages hold raw HTML
    "mail.template",
    "mail.mail",
    "mail.message",  # use the dedicated note tool instead
    "mail.compose.message",
    "mail.followers",  # adding a follower makes Odoo e-mail that person
    "mail.alias",
    "mail.server",
    "mailing.",  # mass mailing campaigns
    "sms.",
    "whatsapp.",
    "snailmail.",  # costs money (postal mail)
    "account.change.lock.date",
    "res.partner.bank",  # changing bank details is the classic payment-fraud vector
    "crm.iap",
    "iap",
    "account.lock_exception",
    "spreadsheet.revision",
    "documents.share",
    "knowledge.invite",
    # accounting configuration: a wrong edit silently corrupts every future entry and report
    "account.account",
    "account.tax",
    "account.fiscal.position",
    "account.journal",
    "account.report",
    "account.reconcile.model",
    "account.payment.method",
    "account.cash.rounding",
    "account.code.mapping",
    "account.root",
    "account.group",
    "account.return.type",
    "account.return.check.template",
    "account.online.",  # bank-sync connections
    "decimal.precision",
    # Odoo's own AI agents and prompts (an AI must not rewrite another AI's instructions)
    "ai.",
    # e-mail infrastructure, outside guests, digests
    "digest.",
    "mail.ice.server",
    "mail.gateway.allowed",
    "mail.guest",
    "res.country",
    "spreadsheet.dashboard.share",  # creates a public link to a dashboard
)

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
# previewed odoo_send_message tool and message-sending buttons.

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
# draft); they may be set on create here too, but never changed afterwards.
CREATE_ONLY_FIELDS: frozenset[tuple[str, str]] = frozenset({("account.move", "move_type")})

# Field types the AI can never write: files, and free-form JSON whose changes a preview can't show clearly.
UNWRITABLE_TYPES: frozenset[str] = frozenset({"binary", "image", "properties", "properties_definition", "json"})

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
    "ir.actions.server",
    "ir.module",
    "base.module",
    "base.automation",
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
        reason = self.model_read_block_reason(model)
        if reason:
            return reason
        if not self.settings.read_write:
            return "this server is in read-only mode (MCP_ACCESS_MODE=read_only)"
        if model.startswith(OUTBOUND_GATED_PREFIXES) and not self.settings.mcp_allow_outbound_messages:
            return (
                f"'{model}' e-mails or shares with people outside the company, which is disabled "
                "(MCP_ALLOW_OUTBOUND_MESSAGES=false)"
            )
        for prefix in HARD_READONLY_PREFIXES:
            if model == prefix.rstrip(".") or model.startswith(prefix):
                return (
                    f"'{model}' is protected (system/security settings, communications, or financially sensitive "
                    "data such as bank details) and can only be changed by a person in Odoo"
                )
        if model in self._extra_readonly or _matches_any(model, self._extra_readonly):
            return f"'{model}' is read-only by this server's configuration"
        if self._writable_allowlist and not (
            model in self._writable_allowlist or _matches_any(model, self._writable_allowlist)
        ):
            return f"'{model}' is not in this server's list of writable models (MCP_WRITABLE_MODELS)"
        return None

    def check_write(self, model: str) -> None:
        reason = self.model_write_block_reason(model)
        if reason:
            raise PolicyViolation(f"Changes to {reason}." if reason.startswith("this server") else reason)

    # -- fields -----------------------------------------------------------------------

    def field_write_block_reason(
        self, name: str, meta: dict, *, model: str | None = None, creating: bool = False
    ) -> str | None:
        if is_sensitive_field(name):
            return "looks like a credential or secret"
        if name in MAGIC_FIELDS:
            return "is maintained automatically by Odoo"
        create_only = (model, name) in CREATE_ONLY_FIELDS
        if create_only:
            if not creating:
                return "can be set only when the record is created (e.g. move_type='out_invoice'), never changed afterwards"
        elif name in WORKFLOW_FIELDS:
            return "is a workflow status; use odoo_list_actions and run the matching button instead"
        ftype = meta.get("type")
        if ftype in UNWRITABLE_TYPES:
            return f"is a {ftype} field, which this server never writes (a person can edit it in Odoo)"
        if meta.get("readonly") and not create_only:
            return "is read-only in Odoo"
        if ftype in ("one2many", "many2many", "many2one", "reference") and meta.get("relation"):
            reason = self.model_read_block_reason(meta["relation"])
            if reason:
                return f"points to a blocked model ({meta['relation']})"
        if name == "active" and not self.settings.mcp_allow_archive:
            return "would archive/unarchive the record, which is disabled (MCP_ALLOW_ARCHIVE=false)"
        return None

    # -- methods ------------------------------------------------------------------------

    def method_decision(self, model: str, method: str, *, is_ui_button: bool, label: str = "") -> MethodDecision:
        low = method.lower()
        label_low = (label or "").lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", low):
            return MethodDecision(False, "private or invalid method name")
        if low in HARD_BLOCKED_METHODS:
            if low in ARCHIVE_METHODS and self.settings.mcp_allow_archive:
                pass
            elif low in ARCHIVE_METHODS:
                return MethodDecision(False, "archiving is disabled (MCP_ALLOW_ARCHIVE=false)")
            else:
                return MethodDecision(
                    False, f"'{method}' cannot be run as a button (use odoo_create / odoo_update / odoo_add_note instead)"
                )
        tokens = set(low.split("_"))
        for part in HARD_BLOCKED_METHOD_SUBSTRINGS:
            if part in low:
                return MethodDecision(False, f"methods containing '{part}' are permanently blocked")
        for part in HARD_BLOCKED_METHOD_TOKENS & tokens:
            return MethodDecision(False, f"methods that '{part}' data are permanently blocked")
        for part in self._extra_blocked_methods:
            if part and (part in low or fnmatch.fnmatch(f"{model}:{method}", part)):
                return MethodDecision(False, f"blocked by this server's configuration ({part})")
        if low in ARCHIVE_METHODS or "archive" in low or "restore" in tokens:
            if not self.settings.mcp_allow_archive:
                return MethodDecision(False, "archiving is disabled (MCP_ALLOW_ARCHIVE=false)")
        if not self.settings.mcp_allow_cancel_actions:
            for part in CANCEL_METHOD_PARTS:
                if part in tokens or any(token.startswith(part) for token in tokens):
                    return MethodDecision(
                        False, f"cancel/reset-type actions ('{part}') are disabled (MCP_ALLOW_CANCEL_ACTIONS=false)"
                    )
        if not self.settings.mcp_allow_outbound_messages:
            for part in OUTBOUND_METHOD_PARTS:
                if (
                    part in tokens
                    or (part in _OUTBOUND_SUBSTRINGS and part in low)
                    or any(token.startswith(part) for token in tokens if part in ("send", "sent", "invite", "notify"))
                ):
                    return MethodDecision(
                        False,
                        f"actions that may e-mail/message people ('{part}') are disabled (MCP_ALLOW_OUTBOUND_MESSAGES=false)",
                    )
        if not self.settings.mcp_allow_cancel_actions and _CANCEL_LABEL_RE.search(label_low):
            return MethodDecision(
                False, f"the '{label}' button cancels/resets/reverses; disabled (MCP_ALLOW_CANCEL_ACTIONS=false)"
            )
        if not self.settings.mcp_allow_outbound_messages and _OUTBOUND_LABEL_RE.search(label_low):
            return MethodDecision(
                False, f"the '{label}' button may e-mail/message people; disabled (MCP_ALLOW_OUTBOUND_MESSAGES=false)"
            )
        if not is_ui_button and f"{model}:{method}" not in self._extra_allowed_methods:
            return MethodDecision(
                False,
                f"'{method}' is not a button on {model}'s screens in Odoo; only UI buttons can be run "
                "(call odoo_list_actions to see them)",
            )
        return MethodDecision(True)

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
                elif key in ("lang", "tz") and not (isinstance(value, str) and len(value) <= 64):
                    raise PolicyViolation(f"context {key} must be a short text value")
                elif key in ("active_id",) and not _is_int(value):
                    raise PolicyViolation("context active_id must be an integer record id")
                elif key in ("active_ids", "allowed_company_ids") and not (
                    isinstance(value, list) and all(_is_int(v) for v in value)
                ):
                    raise PolicyViolation(f"context {key} must be a list of integer ids")
                if key == "active_ids" and len(value) > self.settings.mcp_max_write_records:
                    raise PolicyViolation(
                        f"context active_ids lists {len(value)} records; the limit per change is "
                        f"{self.settings.mcp_max_write_records}"
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
