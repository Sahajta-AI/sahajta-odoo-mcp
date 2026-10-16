"""SafetyPolicy: models, fields, methods and context. These are the hard rules that guard production data."""

from __future__ import annotations

import pytest

from conftest import build_settings
from sahajta_odoo_mcp.errors import PolicyViolation
from sahajta_odoo_mcp.policy import (
    HARD_BLOCKED_MODELS,
    MAGIC_FIELDS,
    WORKFLOW_FIELDS,
    SafetyPolicy,
    is_sensitive_field,
)

ALL_FLAGS_ON = dict(
    mcp_access_mode="read_write",
    mcp_allow_archive=True,
    mcp_allow_cancel_actions=True,
    mcp_allow_outbound_messages=True,
)


def policy(**overrides) -> SafetyPolicy:
    return SafetyPolicy(build_settings(**overrides))


@pytest.fixture
def ro() -> SafetyPolicy:
    return policy()


@pytest.fixture
def rw() -> SafetyPolicy:
    return policy(mcp_access_mode="read_write")


@pytest.fixture
def everything_on() -> SafetyPolicy:
    return policy(**ALL_FLAGS_ON)


# =============================================================================== models: read


@pytest.mark.parametrize(
    "model",
    [
        "ir.config_parameter",
        "res.users.apikeys",
        "res.users.apikeys.description",
        "ir.actions.server",
        "ir.cron",
        "base.automation",
        "ir.module.module",
        "base.module.uninstall",
        "payment.provider",
        "payment.token",
        "ir.mail_server",
        "fetchmail.server",
        "res.config.settings",
        "ir.model.access",
        "ir.rule",
        "auth_totp.device",
        "res.users.log",
        "base.partner.merge.automatic.wizard",
        "base_import.import",
        "change.password.wizard",
    ],
)
def test_hard_blocked_models_cannot_be_read_or_written_even_with_every_flag(model, everything_on):
    assert model in HARD_BLOCKED_MODELS
    with pytest.raises(PolicyViolation, match="blocked"):
        everything_on.check_read(model)
    with pytest.raises(PolicyViolation):
        everything_on.check_write(model)


def test_hard_blocked_models_cannot_be_unblocked_by_writable_allowlist():
    p = policy(mcp_access_mode="read_write", mcp_writable_models=["ir.config_parameter", "ir.*", "*"])
    with pytest.raises(PolicyViolation):
        p.check_read("ir.config_parameter")
    with pytest.raises(PolicyViolation):
        p.check_write("ir.config_parameter")


@pytest.mark.parametrize("model", ["res.partner", "crm.lead", "sale.order", "res.users", "ir.ui.view", "mail.message"])
def test_ordinary_and_readonly_models_are_readable(model, ro):
    ro.check_read(model)  # no exception
    assert ro.model_read_block_reason(model) is None


@pytest.mark.parametrize(
    "model",
    [
        "",
        "Res.Partner",
        "IR.CONFIG_PARAMETER",  # case games must not dodge the blocklist
        "ir.config_parameter ",
        " ir.config_parameter",
        "ir.config_parameter\n",
        "res..partner",
        ".res.partner",
        "res.partner.",
        "res partner",
        "res.partner;drop",
        "../ir.config_parameter",
        "res.partner/../../ir.config_parameter",
        "res.partner/search_read",
        "rés.partner",
        "res-partner",
        None,
        123,
        ["res.partner"],
    ],
)
def test_invalid_model_names_are_refused(model, everything_on):
    reason = everything_on.model_read_block_reason(model)
    assert reason and "not a valid Odoo model name" in reason
    with pytest.raises(PolicyViolation):
        everything_on.check_read(model)
    with pytest.raises(PolicyViolation):
        everything_on.check_write(model)


# =============================================================================== models: write


@pytest.mark.parametrize(
    "model",
    [
        "ir.ui.view",
        "ir.attachment",
        "ir.sequence",
        "ir.model.fields",
        "res.users",
        "res.users.settings",
        "res.groups",
        "res.company",
        "res.currency.rate",
        "res.partner.bank",
        "mail.template",
        "mail.mail",
        "mail.message",
        "mail.followers",
        "mail.compose.message",
        "mailing.mailing",
        "mailing.contact",
        "sms.sms",
        "website",
        "website.page",
        "website.menu",
        "payment.transaction",
        "account.change.lock.date",
        "crm.iap.lead.mining.request",
        "iap.service",
    ],
)
def test_write_blocked_prefixes_hold_in_read_write_mode_with_every_flag(model, everything_on):
    assert everything_on.model_read_block_reason(model) is None, "should still be readable"
    with pytest.raises(PolicyViolation):
        everything_on.check_write(model)


@pytest.mark.parametrize("model", ["ir.ui.view", "res.users", "mail.template", "website.page"])
def test_write_blocked_prefixes_cannot_be_opened_by_the_writable_allowlist(model):
    p = policy(**ALL_FLAGS_ON, mcp_writable_models=[model, "*"])
    with pytest.raises(PolicyViolation):
        p.check_write(model)


@pytest.mark.parametrize("model", ["crm.lead", "res.partner", "sale.order", "project.task"])
def test_read_only_mode_blocks_every_write(model, ro):
    reason = ro.model_write_block_reason(model)
    assert reason and "read-only mode" in reason
    with pytest.raises(PolicyViolation, match="read-only mode"):
        ro.check_write(model)


@pytest.mark.parametrize("model", ["crm.lead", "res.partner", "sale.order", "sale.order.line", "project.task"])
def test_business_models_are_writable_in_read_write_mode(model, rw):
    assert rw.model_write_block_reason(model) is None
    rw.check_write(model)


def test_writable_allowlist_exact_and_glob():
    p = policy(mcp_access_mode="read_write", mcp_writable_models="crm.lead, project.*")
    assert p.model_write_block_reason("crm.lead") is None
    assert p.model_write_block_reason("project.task") is None
    assert p.model_write_block_reason("project.project") is None
    for model in ("sale.order", "res.partner", "crm.lead.tag", "crm.leadx"):
        reason = p.model_write_block_reason(model)
        assert reason and "MCP_WRITABLE_MODELS" in reason, model
    # the allowlist never widens what can be read, and never opens hard blocks
    assert p.model_read_block_reason("sale.order") is None


def test_blocked_models_setting_blocks_reads_with_globs_and_csv_whitespace():
    p = policy(mcp_access_mode="read_write", mcp_blocked_models="hr.payslip*,  hr.contract ,hr.employee.private")
    for model in ("hr.payslip", "hr.payslip.line", "hr.payslip.run", "hr.contract", "hr.employee.private"):
        with pytest.raises(PolicyViolation, match="configuration"):
            p.check_read(model)
        with pytest.raises(PolicyViolation):
            p.check_write(model)
    p.check_read("hr.employee")
    p.check_read("hr.contract.type")  # exact entries are not prefixes


def test_readonly_models_setting_allows_reads_but_not_writes():
    p = policy(mcp_access_mode="read_write", mcp_readonly_models=["account.*", "res.partner"])
    p.check_read("account.move")
    p.check_read("res.partner")
    for model in ("account.move", "account.move.line", "res.partner"):
        with pytest.raises(PolicyViolation, match="read-only by this server's configuration"):
            p.check_write(model)
    p.check_write("crm.lead")


def test_outbound_models_stay_readonly_even_with_outbound_flag(everything_on):
    # OUTBOUND_MODELS_PREFIXES suggests these become writable with MCP_ALLOW_OUTBOUND_MESSAGES, but every one of
    # them is also a HARD_READONLY prefix, so they never are. Safe, but the outbound branch is dead code.
    for model in ("mail.compose.message", "mailing.mailing", "sms.composer", "whatsapp.composer", "snailmail.letter"):
        with pytest.raises(PolicyViolation):
            everything_on.check_write(model)


# =============================================================================== sensitive fields


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "new_password",
        "old_passwd",
        "pwd",
        "api_key",
        "api_key_ids",
        "apikey",
        "apiKey",
        "totp_secret",
        "totp_enabled",
        "signup_token",
        "signup_url",
        "access_token",
        "oauth_access_token",
        "refresh_token",
        "client_secret",
        "webhook_secret",
        "private_key",
        "private_key_id",
        "key",
        "license_key",
        "password_hash",
        "credential_ids",
        "passkey_ids",
        "hmac_secret",
        "x_studio_password",
        "PASSWORD",
    ],
)
def test_sensitive_field_true_positives(name):
    assert is_sensitive_field(name)


@pytest.mark.parametrize(
    "name",
    [
        "name",
        "partner_id",
        "journal_id",
        "monkey",  # ends in "key" but not "_key"
        "turnkey_solution",
        "keyword",
        "session_id",
        "secretary_id",
        "tokenization_enabled",
        "passport_id",  # PII, but not a credential: left to Odoo access rights / MCP_BLOCKED_MODELS
        "email",
        "access_url",
        "is_key_account",
        "hash",
        "display_name",
    ],
)
def test_sensitive_field_must_not_flag_ordinary_business_fields(name):
    assert not is_sensitive_field(name)


@pytest.mark.parametrize(
    "name",
    [
        # Documented surprises: over-blocking (the safe direction). These fields are hidden and unwritable.
        "sort_key",  # (^|_)key$
        "key_account_manager_id",  # ^key_  -- yet "is_key_account" above is NOT flagged
        "token_count",
        "file_hash",  # _hash$ (checksums are not secrets)
        "otp_enabled",
    ],
)
def test_sensitive_field_known_false_positives(name):
    assert is_sensitive_field(name)


# Regression test (was a bug, now fixed): BUG: credential-like field names not caught by _SENSITIVE_FIELD_RE (policy.py)
@pytest.mark.parametrize(
    "name",
    [
        "pin",  # hr.employee.pin: kiosk / POS login PIN
        "smtp_pass",  # ir.mail_server's field naming; 'pass' alone is not in the regex
        "passphrase",
    ],
)
def test_sensitive_field_false_negatives(name):
    assert is_sensitive_field(name)


# =============================================================================== field write rules


@pytest.mark.parametrize("name", sorted(WORKFLOW_FIELDS))
def test_workflow_fields_are_never_writable(name, everything_on):
    assert "workflow" in everything_on.field_write_block_reason(name, {"type": "selection"})


@pytest.mark.parametrize("name", sorted(MAGIC_FIELDS))
def test_magic_fields_are_never_writable(name, everything_on):
    assert everything_on.field_write_block_reason(name, {"type": "integer"})


@pytest.mark.parametrize("ftype", ["binary", "image", "properties", "properties_definition", "json"])
def test_file_and_free_form_json_fields_are_never_writable(ftype, everything_on):
    reason = everything_on.field_write_block_reason("x_document", {"type": ftype})
    assert reason and ftype in reason and "never writes" in reason


def test_readonly_fields_are_not_writable(everything_on):
    assert "read-only" in everything_on.field_write_block_reason("amount_total", {"type": "monetary", "readonly": True})


def test_sensitive_fields_are_not_writable_whatever_their_type(everything_on):
    for name in ("password", "x_api_key", "signup_token", "totp_secret"):
        assert "secret" in everything_on.field_write_block_reason(name, {"type": "char"})


def test_active_needs_the_archive_flag(rw):
    assert "MCP_ALLOW_ARCHIVE" in rw.field_write_block_reason("active", {"type": "boolean"})
    assert policy(mcp_access_mode="read_write", mcp_allow_archive=True).field_write_block_reason(
        "active", {"type": "boolean"}
    ) is None


@pytest.mark.parametrize(
    "ftype, relation",
    [
        ("many2one", "ir.cron"),
        ("many2many", "ir.actions.server"),
        ("one2many", "res.users.apikeys"),
        ("many2one", "payment.token"),
        ("reference", "ir.config_parameter"),
    ],
)
def test_relations_to_hard_blocked_models_are_not_writable(ftype, relation, everything_on):
    reason = everything_on.field_write_block_reason("x_link", {"type": ftype, "relation": relation})
    assert reason and "blocked model" in reason


def test_relations_to_configured_blocked_models_are_not_writable():
    p = policy(mcp_access_mode="read_write", mcp_blocked_models=["hr.payslip*"])
    assert "blocked model" in p.field_write_block_reason("x_payslip_id", {"type": "many2one", "relation": "hr.payslip"})


def test_relations_to_readonly_models_are_writable_links(rw):
    # Assigning a salesperson links to res.users, it does not write res.users itself.
    assert rw.field_write_block_reason("user_id", {"type": "many2one", "relation": "res.users"}) is None
    assert rw.field_write_block_reason("partner_id", {"type": "many2one", "relation": "res.partner"}) is None


def test_ordinary_fields_are_writable(rw):
    assert rw.field_write_block_reason("name", {"type": "char"}) is None
    assert rw.field_write_block_reason("expected_revenue", {"type": "monetary"}) is None


# =============================================================================== methods


def decide(p: SafetyPolicy, method: str, *, model: str = "sale.order", ui: bool = True, label: str = ""):
    return p.method_decision(model, method, is_ui_button=ui, label=label)


ALWAYS_BLOCKED = [
    "unlink",
    "UNLINK",
    "Unlink",
    "action_unlink_lines",
    "unlink_all",
    "button_delete",
    "action_delete",
    "purge_old_records",
    "button_immediate_install",
    "button_install",
    "button_immediate_uninstall",
    "module_uninstall",
    "button_upgrade",
    "sudo",
    "action_sudo",
    "with_user",
    "with_context",
    "_private",
    "_action_confirm",
    "__init__",
    "write",
    "create",
    "copy",
    "copy_data",
    "name_create",
    "message_post",
    "message_subscribe",
    "message_notify",
    "load",
    "load_records",
    "action_import",
    "action_merge",
    "merge_records",
    "action_remove_lines",
    "payment_action_capture",
    "payment_action_void",
    "action_capture",
    "action_void",
    "action_reset_password",
    "action_impersonate_user",
    "read",
    "search",
    "browse",
    "execute",
    "run",
    "web_save",
    "onchange",
    "export_data",
    "invalidate_recordset",
    "action_drop_table",
    "action_wipe",
    "action_payout",
    "action_view_transaction",
    "button_hash_integrity",
    "action_iap_enrich",
    "action_create_user",
    "action_trust_bank",
    "action_generate_leads",
    "action unlink",  # spaces
    "action-confirm",
    "action.confirm",
    "",
]


@pytest.mark.parametrize("method", ALWAYS_BLOCKED)
def test_always_blocked_methods_even_with_every_flag_and_ui_button(method, everything_on):
    decision = decide(everything_on, method, ui=True)
    assert decision.allowed is False, method
    assert decision.reason


@pytest.mark.parametrize("method", ["unlink", "write", "create", "_private", "sudo", "button_immediate_uninstall"])
def test_extra_allowed_methods_cannot_unblock_hard_blocked_methods(method):
    p = policy(**ALL_FLAGS_ON, mcp_extra_allowed_methods=[f"sale.order:{method}"])
    assert decide(p, method, ui=False).allowed is False
    assert decide(p, method, ui=True).allowed is False


@pytest.mark.parametrize("method", ["action_archive", "action_unarchive", "toggle_active", "action_archive_all", "action_restore"])
def test_archive_methods_need_the_archive_flag(method, rw):
    decision = decide(rw, method)
    # (for the three exact archive methods the refusal text is the generic "use the dedicated tool, or it is
    # unsafe", although no archive tool exists; cosmetic)
    assert decision.allowed is False and decision.reason
    assert decide(policy(mcp_access_mode="read_write", mcp_allow_archive=True), method).allowed is True
    # still only as a real UI button
    assert decide(policy(mcp_access_mode="read_write", mcp_allow_archive=True), method, ui=False).allowed is False


@pytest.mark.parametrize(
    "method",
    ["action_cancel", "button_cancel", "action_draft", "button_draft", "action_set_lost", "action_unlock",
     "action_refuse", "action_reject", "action_reverse", "action_revert_to_quotation", "refund_moves",
     "action_reversal_wizard", "action_cancelled_x"],
)
def test_cancel_type_methods_need_the_cancel_flag(method, rw):
    decision = decide(rw, method)
    assert decision.allowed is False and "MCP_ALLOW_CANCEL_ACTIONS" in decision.reason
    assert decide(policy(mcp_access_mode="read_write", mcp_allow_cancel_actions=True), method).allowed is True


@pytest.mark.parametrize(
    "method",
    ["action_quotation_send", "action_send_mail", "action_rfq_send", "action_invoice_sent", "action_resend",
     "action_sms", "action_send_whatsapp", "action_invite", "action_share", "action_notify_customer",
     "action_portal_access", "action_sendmail"],
)
def test_outbound_methods_need_the_outbound_flag(method, rw):
    decision = decide(rw, method)
    assert decision.allowed is False and "MCP_ALLOW_OUTBOUND_MESSAGES" in decision.reason
    assert decide(policy(mcp_access_mode="read_write", mcp_allow_outbound_messages=True), method).allowed is True


@pytest.mark.parametrize(
    "label, flag",
    [("Send by Email", "MCP_ALLOW_OUTBOUND_MESSAGES"), ("Share", "MCP_ALLOW_OUTBOUND_MESSAGES"),
     ("Send & Print", "MCP_ALLOW_OUTBOUND_MESSAGES"), ("E-mail customer", "MCP_ALLOW_OUTBOUND_MESSAGES"),
     ("Cancel", "MCP_ALLOW_CANCEL_ACTIONS"), ("Reset to Draft", "MCP_ALLOW_CANCEL_ACTIONS"),
     ("Set to Draft", "MCP_ALLOW_CANCEL_ACTIONS"), ("Mark as Lost", "MCP_ALLOW_CANCEL_ACTIONS"),
     ("Add Credit Note", "MCP_ALLOW_CANCEL_ACTIONS"), ("Reverse Entry", "MCP_ALLOW_CANCEL_ACTIONS")],
)
def test_button_labels_are_checked_too(label, flag, rw):
    decision = decide(rw, "action_custom_thing", label=label)
    assert decision.allowed is False and flag in decision.reason


@pytest.mark.parametrize("label", ["Create Draft Invoice", "Confirm", "Mark as Won", "Print"])
def test_harmless_button_labels_are_not_refused(label, rw):
    assert decide(rw, "action_custom_thing", label=label).allowed is True


def test_button_labels_do_not_block_when_the_flag_is_on():
    p = policy(**ALL_FLAGS_ON)
    for label in ("Send by Email", "Cancel", "Reset to Draft"):
        assert decide(p, "action_custom_thing", label=label).allowed is True


def test_non_ui_methods_are_refused_unless_explicitly_listed(rw):
    decision = decide(rw, "action_compute_score", ui=False)
    assert decision.allowed is False and "not a button" in decision.reason

    p = policy(mcp_access_mode="read_write", mcp_extra_allowed_methods="crm.lead:action_compute_score")
    assert decide(p, "action_compute_score", model="crm.lead", ui=False).allowed is True
    # the allowance is per model
    assert decide(p, "action_compute_score", model="sale.order", ui=False).allowed is False


def test_a_normal_ui_button_is_allowed(rw):
    assert decide(rw, "action_confirm").allowed is True
    assert decide(rw, "action_confirm", label="Confirm").allowed is True


def test_blocked_methods_setting_by_name_and_by_model_pattern():
    p = policy(mcp_access_mode="read_write", mcp_blocked_methods=["action_confirm", "crm.lead:action_set_won*"])
    assert decide(p, "action_confirm").allowed is False
    assert decide(p, "action_confirm", model="crm.lead").allowed is False
    assert decide(p, "action_set_won_rainbowman", model="crm.lead").allowed is False
    assert decide(p, "action_set_won_rainbowman", model="sale.order").allowed is True


def test_method_decision_does_not_check_model_writability():
    """method_decision is only about the method; the service must call check_write too (tested in service tests)."""
    assert decide(policy(), "action_confirm").allowed is True


# =============================================================================== context


def test_empty_context_is_empty(rw):
    assert rw.sanitize_context(None) == {}
    assert rw.sanitize_context({}) == {}


def test_non_dict_context_is_refused(rw):
    with pytest.raises(PolicyViolation):
        rw.sanitize_context([("lang", "en_US")])
    with pytest.raises(PolicyViolation):
        rw.sanitize_context("{'tracking_disable': True}")


def test_allowed_context_keys_pass_through(rw):
    ctx = {
        "lang": "en_US",
        "tz": "Asia/Kolkata",
        "active_id": 5,
        "active_ids": [5, 6],
        "active_model": "sale.order",
        "allowed_company_ids": [1],
        "default_name": "Hello",
        "default_partner_id": 3,
    }
    assert rw.sanitize_context(ctx) == ctx


@pytest.mark.parametrize(
    "key",
    [
        "tracking_disable",
        "TRACKING_DISABLE",
        "mail_notrack",
        "mail_create_nolog",
        "check_move_validity",
        "force_company",
        "force_delete",
        "skip_invoice_sync",
        "bypass_access",
        "install_mode",
        "module",
        "no_reset_password",
        "import_file",
        "default_tracking_disable",
    ],
)
def test_forbidden_context_keys(key, everything_on):
    with pytest.raises(PolicyViolation, match="not allowed"):
        everything_on.sanitize_context({key: True})


@pytest.mark.parametrize(
    "key",
    ["active_test", "uid", "su", "mail_create_nosubscribe", "mail_auto_subscribe_no_notify", "Lang", "lang ",
     "allowed_company_ids ", "params", "search_default_x", "__debug__"],
)
def test_unknown_context_keys_are_refused(key, rw):
    with pytest.raises(PolicyViolation, match="not allowed"):
        rw.sanitize_context({key: 1})


@pytest.mark.parametrize("key", ["default_password", "default_api_key", "default_create_uid", "default_id",
                                 "default_write_date", "default_signup_token"])
def test_default_keys_for_secrets_and_magic_fields_are_refused(key, rw):
    with pytest.raises(PolicyViolation):
        rw.sanitize_context({key: "x"})


@pytest.mark.parametrize(
    "model", ["ir.config_parameter", "res.users.apikeys", "payment.provider", "bad model", "x;y", "res.users", "ir.ui.view"]
)
def test_active_model_must_be_a_changeable_model(model, rw):
    # wizards act on the records named by active_model/active_ids, so those must be writable, not just readable
    with pytest.raises(PolicyViolation):
        rw.sanitize_context({"active_model": model})


def test_active_model_is_refused_in_read_only_mode(ro):
    with pytest.raises(PolicyViolation, match="read-only"):
        ro.sanitize_context({"active_model": "sale.order"})


def test_active_model_respects_configured_blocks_and_allowlist():
    p = policy(mcp_access_mode="read_write", mcp_blocked_models=["hr.*"], mcp_writable_models=["crm.lead", "hr.*"])
    with pytest.raises(PolicyViolation):
        p.sanitize_context({"active_model": "hr.employee"})
    with pytest.raises(PolicyViolation, match="MCP_WRITABLE_MODELS"):
        p.sanitize_context({"active_model": "sale.order"})
    assert p.sanitize_context({"active_model": "crm.lead"}) == {"active_model": "crm.lead"}


@pytest.mark.parametrize(
    "key, value",
    [
        ("active_id", "5"),
        ("active_id", True),
        ("active_id", 5.0),
        ("active_id", [5]),
        ("active_ids", "1,2"),
        ("active_ids", 5),
        ("active_ids", [1, "2"]),
        ("active_ids", [True]),
        ("active_ids", [1.0]),
        ("allowed_company_ids", [1, "2"]),
        ("allowed_company_ids", 1),
    ],
)
def test_context_id_type_checks(key, value, rw):
    with pytest.raises(PolicyViolation, match="integer"):
        rw.sanitize_context({key: value})


@pytest.mark.parametrize("domain", [[["password", "!=", False]], [], "[(1, '=', 1)]", [["id", ">", 0]]])
def test_active_domain_is_refused(domain, everything_on):
    # active_domain would let a wizard act on every matching record, bypassing the per-change cap and the
    # domain validation (sensitive fields, blocked paths) that normal searches get.
    with pytest.raises(PolicyViolation, match="not allowed"):
        everything_on.sanitize_context({"active_domain": domain})


def test_active_ids_are_capped_at_the_write_limit():
    p = policy(mcp_access_mode="read_write", mcp_max_write_records=20)
    assert p.sanitize_context({"active_ids": list(range(1, 21))})["active_ids"] == list(range(1, 21))
    with pytest.raises(PolicyViolation, match="limit"):
        p.sanitize_context({"active_model": "sale.order", "active_ids": list(range(1, 22))})
    with pytest.raises(PolicyViolation, match="limit"):
        p.sanitize_context({"active_model": "sale.order", "active_ids": list(range(1, 5001))})


# =============================================================================== settings that feed the policy


def test_hard_caps_cannot_be_raised_by_environment():
    s = build_settings(mcp_max_write_records=10_000, mcp_max_read_records=1_000_000, mcp_default_read_limit=5_000)
    assert s.mcp_max_write_records == 100
    assert s.mcp_max_read_records == 1000
    assert s.mcp_default_read_limit == 1000


def test_safe_defaults_without_any_configuration():
    from sahajta_odoo_mcp.config import Settings

    s = Settings(_env_file=None, odoo_url="https://odoo.example.com/")
    assert s.odoo_url == "https://odoo.example.com"
    assert s.read_write is False
    assert s.mcp_require_preview is True
    assert not (s.mcp_allow_archive or s.mcp_allow_cancel_actions or s.mcp_allow_outbound_messages)
    assert s.mcp_max_write_records == 20


def test_odoo_url_must_be_http(monkeypatch):
    with pytest.raises(ValueError):
        build_settings(odoo_url="ftp://odoo.example.com")
    with pytest.raises(ValueError):
        build_settings(odoo_url="odoo.example.com")
