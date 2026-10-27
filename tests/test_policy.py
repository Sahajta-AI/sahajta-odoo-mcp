"""SafetyPolicy: models, fields, methods and context. These are the hard rules that guard production data."""

from __future__ import annotations

import pytest

from conftest import build_settings
from sahajta_odoo_mcp.errors import PolicyViolation
from sahajta_odoo_mcp.policy import (
    CREATE_ONLY_FIELDS,
    HARD_BLOCKED_MODELS,
    HARD_BLOCKED_PREFIXES,
    HARD_READONLY_PREFIXES,
    LIMITED_MODELS,
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
        "ir.actions.server.history",
        "ir.cron",
        "base.automation.lead.test",
        "ir.module.module",
        "base.module.uninstall",
        "payment.provider",
        "payment.token",
        "ir.mail_server",
        "fetchmail.server",
        "res.config",
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
    assert model in HARD_BLOCKED_MODELS or model.startswith(HARD_BLOCKED_PREFIXES)
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
        "ir.sequence",
        "ir.model.fields",
        "res.users",
        "res.users.settings",
        "res.groups",
        "res.company",
        "res.currency.rate",
        "res.partner.bank",
        "mail.template.reset",
        "mail.alias",
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


@pytest.mark.parametrize("model", ["ir.ui.view", "res.users", "mail.alias", "website.page", "ir.actions.server"])
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
        assert reason and "list of records Claude may change" in reason, model
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
    assert "workflow" in everything_on.field_write_block_reason(name, {"type": "selection"}, creating=True)
    # move_type is create-only on invoices, nowhere else (e.g. the related copy on invoice lines)
    assert "workflow" in everything_on.field_write_block_reason(
        name, {"type": "selection"}, model="account.move.line", creating=True
    )


def test_invoice_type_is_set_on_create_only(everything_on):
    meta = {"type": "selection", "readonly": True}  # Odoo marks it read-only: its screens set it on create
    assert ("account.move", "move_type") in CREATE_ONLY_FIELDS
    assert everything_on.field_write_block_reason("move_type", meta, model="account.move", creating=True) is None
    assert "only when the record is created" in everything_on.field_write_block_reason(
        "move_type", meta, model="account.move"
    )
    # other models' read-only fields stay read-only on create
    assert "read-only" in everything_on.field_write_block_reason("amount_total", meta, model="account.move", creating=True)


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
    assert "archiving is switched off for Claude" in rw.field_write_block_reason("active", {"type": "boolean"})
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
    assert decision.allowed is False and "is switched off for Claude. Do it in Odoo, or ask your administrator." in decision.reason
    assert decide(policy(mcp_access_mode="read_write", mcp_allow_cancel_actions=True), method).allowed is True


@pytest.mark.parametrize(
    "method",
    ["action_quotation_send", "action_send_mail", "action_rfq_send", "action_invoice_sent", "action_resend",
     "action_sms", "action_send_whatsapp", "action_invite", "action_share", "action_notify_customer",
     "action_portal_access", "action_sendmail"],
)
def test_outbound_methods_need_the_outbound_flag(method, rw):
    decision = decide(rw, method)
    assert decision.allowed is False and "Sending e-mails or messages to people" in decision.reason
    assert decide(policy(mcp_access_mode="read_write", mcp_allow_outbound_messages=True), method).allowed is True


@pytest.mark.parametrize(
    "label, flag",
    [("Send by Email", "may e-mail or message"), ("Share", "may e-mail or message"),
     ("Send & Print", "may e-mail or message"), ("E-mail customer", "may e-mail or message"),
     ("Cancel", "cancels, resets or reverses"), ("Reset to Draft", "cancels, resets or reverses"),
     ("Set to Draft", "cancels, resets or reverses"), ("Mark as Lost", "cancels, resets or reverses"),
     ("Add Credit Note", "cancels, resets or reverses"), ("Reverse Entry", "cancels, resets or reverses")],
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
    with pytest.raises(PolicyViolation, match="list of records Claude may change"):
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


# =============================================================================== setup areas: app settings


def test_settings_are_readable_and_changed_only_by_a_new_record_then_save(rw):
    assert rw.model_read_block_reason("res.config.settings") is None
    rw.check_write("res.config.settings")
    assert rw.change_block_reason("res.config.settings", "create") is None
    reason = rw.change_block_reason("res.config.settings", "write")
    assert reason and "new settings record" in reason and "execute" in reason
    # the rest of the family stays blocked
    for model in ("res.config", "res.config.installer"):
        with pytest.raises(PolicyViolation, match="blocked"):
            rw.check_read(model)


@pytest.mark.parametrize(
    "name, needle",
    [
        ("module_crm", "installs or removes an Odoo app"),
        ("module_l10n_in_reports", "Odoo bill"),
        ("l10n_in_gstin", "identity"),
        ("l10n_in_pan", "identity"),
        ("l10n_in_tan", "identity"),
        ("company_name", "identity"),
        ("vat", "identity"),
        ("logo", "identity"),
        ("email", "identity"),
        ("phone", "identity"),
        ("account_fiscal_country_id", "identity"),
        ("l10n_xx_bank_account", "identity"),
        ("auth_signup_uninvited", "credential"),  # already refused by the secret-name rule
        ("auth_totp_policy", "credential"),
        ("auth_password_policy_x", "credential"),
        ("auth_ldap_enabled", "security"),
        ("restrictive_audit_trail", "audit"),
        ("l10n_in_edi_username", "sign-in"),
    ],
)
def test_settings_that_install_apps_or_touch_identity_or_security_are_refused(name, needle, everything_on):
    reason = everything_on.field_write_block_reason(name, {"type": "char"}, model="res.config.settings", creating=True)
    assert reason and needle in reason


@pytest.mark.parametrize(
    "name", ["group_analytic_accounting", "group_uom", "quotation_validity_days", "l10n_in_gsp", "email_primary_color"]
)
def test_ordinary_settings_and_feature_switches_are_allowed(name, rw):
    assert rw.field_write_block_reason(name, {"type": "boolean"}, model="res.config.settings", creating=True) is None
    # the settings rules apply to the settings model only
    assert rw.field_write_block_reason("module_crm", {"type": "boolean"}, model="crm.lead") is None


def test_the_settings_save_button_is_the_only_one_and_needs_no_view_button(rw):
    # Odoo 19's settings screen draws Save in its web client: 'execute' is not a button in the view
    assert decide(rw, "execute", model="res.config.settings", ui=False).allowed is True
    for method in ("set_values", "action_open_template_user", "Execute", "button_immediate_install", "unlink"):
        decision = decide(rw, method, model="res.config.settings", ui=True)
        assert decision.allowed is False, method
    assert "Save button" in decide(rw, "action_open_template_user", model="res.config.settings").reason
    # execute stays blocked everywhere else
    assert decide(rw, "execute", model="sale.order").allowed is False
    # and the operator's own block list still applies
    p = policy(mcp_access_mode="read_write", mcp_blocked_methods=["res.config.settings:execute"])
    assert decide(p, "execute", model="res.config.settings", ui=False).allowed is False


# =============================================================================== setup areas: e-mail templates


def test_templates_can_be_edited_in_listed_fields_but_never_created(rw):
    rw.check_write("mail.template")
    assert rw.change_block_reason("mail.template", "write") is None
    assert "cannot be created" in rw.change_block_reason("mail.template", "create")
    for name in ("subject", "body_html", "email_to", "email_cc", "partner_to", "use_default_to", "reply_to"):
        assert rw.field_write_block_reason(name, {"type": "char"}, model="mail.template") is None, name
    for name in ("email_from", "model_id", "attachment_ids", "report_template_ids", "lang", "auto_delete", "name"):
        reason = rw.field_write_block_reason(name, {"type": "char"}, model="mail.template")
        assert reason and "only these fields" in reason, name


@pytest.mark.parametrize("model", ["mail.alias", "mail.alias.domain", "mail.template.reset", "mail.template.preview"])
def test_aliases_and_template_wizards_stay_read_only(model, everything_on):
    with pytest.raises(PolicyViolation, match="e-mails and messages"):
        everything_on.check_write(model)


def test_template_buttons_are_refused(rw):
    for method in ("create_action", "reset_template", "action_open_preview"):
        decision = decide(rw, method, model="mail.template")
        assert decision.allowed is False and "templates" in decision.reason


# =============================================================================== setup areas: automation rules


def test_automation_rules_are_open_but_their_actions_only_inside_them(rw):
    rw.check_read("base.automation")
    rw.check_write("base.automation")
    rw.check_read("ir.actions.server")
    with pytest.raises(PolicyViolation, match="system or security setup"):
        rw.check_write("ir.actions.server")
    for model in ("ir.actions.server.history", "base.automation.lead.test", "ir.cron", "ir.cron.trigger"):
        with pytest.raises(PolicyViolation, match="blocked"):
            rw.check_read(model)
    assert rw.nested_write_block_reason("base.automation", "action_server_ids", "ir.actions.server", creating=True) is None
    assert rw.nested_write_block_reason("base.automation", "action_server_ids", "ir.actions.server", creating=False) is None
    reason = rw.nested_write_block_reason("crm.lead", "x_server_action_ids", "ir.actions.server", creating=True)
    assert reason and "only inside their base.automation" in reason
    # a field pointing at server actions anywhere else stays closed
    assert "blocked model" in rw.field_write_block_reason(
        "x_server_action_ids", {"type": "many2many", "relation": "ir.actions.server"}, model="crm.lead"
    )
    assert rw.field_write_block_reason(
        "action_server_ids", {"type": "one2many", "relation": "ir.actions.server"}, model="base.automation"
    ) is None


def test_automation_rule_and_action_fields_are_limited(rw):
    for name in ("name", "trigger", "filter_domain", "filter_pre_domain", "action_server_ids", "trg_date_range"):
        assert rw.field_write_block_reason(name, {"type": "char"}, model="base.automation", creating=True) is None
    for name in ("record_getter", "log_webhook_calls", "on_change_field_ids"):
        assert "only these fields" in rw.field_write_block_reason(name, {"type": "char"}, model="base.automation")
    for name in ("url", "webhook_uuid"):
        assert "hidden" in rw.field_write_block_reason(name, {"type": "char"}, model="base.automation")
    # a server action's 'state' is its type, not a workflow status
    assert rw.field_write_block_reason("state", {"type": "selection"}, model="ir.actions.server", creating=True) is None
    assert "workflow" in rw.field_write_block_reason("state", {"type": "selection"}, model="sale.order")
    for name in ("code", "webhook_url"):
        assert "hidden" in rw.field_write_block_reason(name, {"type": "text"}, model="ir.actions.server", creating=True)
    for name in ("child_ids", "group_ids", "binding_model_id", "crud_model_id", "sms_template_id", "usage"):
        assert "only these fields" in rw.field_write_block_reason(name, {"type": "char"}, model="ir.actions.server")
    # a rule's model is fixed once created
    meta = {"type": "many2one", "relation": "ir.model"}
    assert rw.field_write_block_reason("model_id", meta, model="base.automation", creating=True) is None
    assert "only when the record is created" in rw.field_write_block_reason("model_id", meta, model="base.automation")


@pytest.mark.parametrize("trigger", ["on_create_or_write", "on_stage_set", "on_time", "on_message_received", "on_archive"])
def test_safe_triggers_are_allowed(trigger, rw):
    assert rw.automation_trigger_block_reason(trigger) is None


@pytest.mark.parametrize(
    "trigger, needle",
    [("on_change", "Python code"), ("on_webhook", "outside system"), ("on_unlink", "deleted"), ("on_nuke", "not allowed"),
     (None, "not allowed")],
)
def test_triggers_that_run_code_delete_or_open_a_web_door_are_refused(trigger, needle, everything_on):
    reason = everything_on.automation_trigger_block_reason(trigger)
    assert reason and needle in reason


@pytest.mark.parametrize(
    "state, needle",
    [("code", "Python code"), ("webhook", "outside web address"), ("sms", "text messages"),
     ("whatsapp", "WhatsApp"), ("multi", "other server actions"), ("object_create", "creates new records"),
     ("object_copy", "duplicates"), ("remove_followers", "removes followers"), ("ai", "has the type 'ai'"), (None, "type")],
)
def test_action_types_outside_the_four_are_refused(state, needle, everything_on):
    reason = everything_on.automation_action_block_reason({"name": "X", "state": state})
    assert reason and needle in reason and "Allowed: update a field" in reason


def test_update_actions_use_a_fixed_value_on_the_rules_own_record(rw):
    ok = {"name": "Set stage", "state": "object_write", "update_path": "stage_id", "value": "2"}
    assert rw.automation_action_block_reason(ok) is None
    assert rw.automation_action_block_reason({**ok, "evaluation_type": "value"}) is None
    for evaluation in ("equation", "sequence"):
        assert "fixed value" in rw.automation_action_block_reason({**ok, "evaluation_type": evaluation})
    assert "update_path" in rw.automation_action_block_reason({**ok, "update_path": ""})
    assert "own record" in rw.automation_action_block_reason({**ok, "update_path": "partner_id.email"})
    assert rw.automation_action_block_reason({"name": "Call", "state": "next_activity"}) is None


def test_email_and_follower_actions_need_the_outbound_switch(rw):
    for action in (
        {"name": "Mail", "state": "mail_post", "mail_post_method": "email"},
        {"name": "Msg", "state": "mail_post", "mail_post_method": "comment"},
        {"name": "Mail", "state": "mail_post"},  # Odoo's default is an e-mail
        {"name": "Follow", "state": "followers"},
    ):
        reason = rw.automation_action_block_reason(action)
        assert reason and "switched off for Claude" in reason and "MCP_" not in reason
    assert rw.automation_action_block_reason({"name": "Note", "state": "mail_post", "mail_post_method": "note"}) is None
    p = policy(mcp_access_mode="read_write", mcp_allow_outbound_messages=True)
    assert p.automation_action_block_reason({"name": "Mail", "state": "mail_post"}) is None
    assert p.automation_action_block_reason({"name": "Follow", "state": "followers"}) is None


def test_replying_to_messages_with_messages_is_refused_to_avoid_mail_loops():
    p = policy(mcp_access_mode="read_write", mcp_allow_outbound_messages=True)
    for trigger in ("on_message_received", "on_message_sent"):
        reason = p.automation_action_block_reason({"name": "Reply", "state": "mail_post"}, trigger=trigger)
        assert reason and "loop" in reason
        assert p.automation_action_block_reason(
            {"name": "Note", "state": "mail_post", "mail_post_method": "note"}, trigger=trigger
        ) is None
    assert p.automation_action_block_reason({"name": "Reply", "state": "mail_post"}, trigger="on_create") is None


# =============================================================================== setup areas: accounting setup


@pytest.mark.parametrize(
    "model, name",
    [("account.account", "Accounts"), ("account.tax", "Taxes"), ("account.fiscal.position", "Fiscal positions"),
     ("account.journal", "Journals")],
)
def test_accounting_setup_is_create_only(model, name, everything_on):
    everything_on.check_write(model)
    assert everything_on.change_block_reason(model, "create") is None
    reason = everything_on.change_block_reason(model, "write")
    assert reason.startswith(f"{name} already in Odoo cannot be changed or archived")
    assert "past reports and GST returns" in reason and "Do it in Odoo" in reason
    # no wizard may act on existing setup either, and no button may be pressed on it
    with pytest.raises(PolicyViolation, match="past reports"):
        everything_on.sanitize_context({"active_model": model})
    decision = decide(everything_on, "action_archive", model=model)
    assert decision.allowed is False and "accounting setup" in decision.reason


@pytest.mark.parametrize(
    "model",
    ["account.tax.group", "account.tax.repartition.line", "account.account.tag", "account.journal.group",
     "account.fiscal.position.account", "account.reconcile.model.line", "account.payment.method.line", "account.report"],
)
def test_the_rest_of_accounting_setup_stays_read_only(model, everything_on):
    with pytest.raises(PolicyViolation, match="accounting setup"):
        everything_on.check_write(model)


def test_setup_lines_are_written_only_inside_their_parent(rw):
    for parent, field, line in [
        ("account.tax", "invoice_repartition_line_ids", "account.tax.repartition.line"),
        ("account.tax", "refund_repartition_line_ids", "account.tax.repartition.line"),
        ("account.fiscal.position", "account_ids", "account.fiscal.position.account"),
        ("account.reconcile.model", "line_ids", "account.reconcile.model.line"),
    ]:
        assert rw.nested_write_block_reason(parent, field, line, creating=True) is None
        reason = rw.nested_write_block_reason("sale.order", "x_lines", line, creating=True)
        assert reason and f"only inside their {parent}" in reason
    # configured blocks still count inside a parent
    p = policy(mcp_access_mode="read_write", mcp_readonly_models=["account.tax.repartition.line"])
    assert p.nested_write_block_reason("account.tax", "invoice_repartition_line_ids", "account.tax.repartition.line", creating=True)
    # setup created inside another record is still create-only
    assert rw.nested_write_block_reason("product.template", "taxes_id", "account.tax", creating=True) is None
    assert "cannot be changed" in rw.nested_write_block_reason("product.template", "taxes_id", "account.tax", creating=False)
    assert "cannot be created" in rw.nested_write_block_reason("res.partner", "x_template_ids", "mail.template", creating=True)


# =============================================================================== bank details


@pytest.mark.parametrize(
    "model, name",
    [("account.move", "partner_bank_id"), ("account.bank.statement.line", "partner_bank_id"),
     ("account.payment", "partner_bank_id"), ("account.payment.register", "partner_bank_id"),
     ("account.journal", "bank_account_id"), ("hr.employee", "bank_account_id"), ("res.partner", "bank_ids")],
)
def test_fields_pointing_at_bank_accounts_are_never_writable(model, name, everything_on):
    reason = everything_on.field_write_block_reason(
        name, {"type": "many2one", "relation": "res.partner.bank"}, model=model, creating=True
    )
    assert reason and "bank details" in reason


@pytest.mark.parametrize("name", ["bank_acc_number", "bank_id", "bank_statements_source"])
def test_journal_bank_fields_are_never_writable(name, everything_on):
    reason = everything_on.field_write_block_reason(name, {"type": "char"}, model="account.journal", creating=True)
    assert reason and "bank details" in reason
    assert everything_on.field_write_block_reason("code", {"type": "char"}, model="account.journal", creating=True) is None


# =============================================================================== analytic distribution


def test_only_analytic_distribution_is_a_writable_json_field(rw):
    assert rw.field_write_block_reason("analytic_distribution", {"type": "json"}, model="account.move.line") is None
    assert "json" in rw.field_write_block_reason("x_other_json", {"type": "json"}, model="account.move.line")
    assert "read-only" in rw.field_write_block_reason("analytic_distribution", {"type": "json", "readonly": True})


# =============================================================================== preview warnings


def test_change_warnings_for_settings_name_the_feature_switches(rw):
    names = ["quotation_validity_days", "group_uom", "group_analytic_accounting"]
    assert rw.change_warnings("res.config.settings", "create", names) == [
        "Switches a feature on or off for every user in the company, not just you: group_analytic_accounting, group_uom."
    ]
    assert rw.change_warnings("res.config.settings", "create", ["quotation_validity_days"]) == []


def test_change_warnings_for_templates_rules_and_accounting_setup(rw):
    assert "every e-mail Odoo sends with this template" in rw.change_warnings("mail.template", "write", ["subject"])[0]
    assert rw.change_warnings("mail.template", "update", ["body_html"]) == rw.change_warnings("mail.template", "write", ["x"])
    for mode in ("create", "write"):
        (warning,) = rw.change_warnings("base.automation", mode, ["name", "filter_domain"])
        assert "runs automatically from now on, on every matching record, without asking" in warning
    assert "Archiving stops the rule" in rw.change_warnings("base.automation", "write", ["active"])[0]
    for model in ("account.account", "account.tax", "account.fiscal.position", "account.journal"):
        (warning,) = rw.change_warnings(model, "create", ["name"])
        assert "every future entry" in warning and "CA" in warning


def test_change_warnings_are_empty_for_ordinary_changes_and_take_any_iterable(rw):
    assert rw.change_warnings("crm.lead", "write", ["name"]) == []
    assert rw.change_warnings("sale.order", "create", []) == []
    assert rw.change_warnings("account.tax", "write", ["name"]) == []  # refused anyway
    assert rw.change_warnings("res.config.settings", "create", iter(["group_uom"]))
    assert rw.change_warnings("base.automation", "create", None)


# =============================================================================== plain-language refusals


def test_refusals_never_name_operator_settings():
    ro_p, rw_p = policy(), policy(mcp_access_mode="read_write", mcp_writable_models=["crm.*"])
    texts = [
        ro_p.model_write_block_reason("crm.lead"),
        rw_p.model_write_block_reason("sale.order"),
        rw_p.model_write_block_reason("sign.request"),
        rw_p.field_write_block_reason("active", {"type": "boolean"}),
        *(decide(rw_p, m, model="crm.lead").reason for m in ("action_archive", "action_set_lost", "action_cancel",
                                                            "action_send_mail", "unlink", "action_delete_all")),
        decide(rw_p, "action_x", label="Cancel").reason,
        decide(rw_p, "action_x", label="Send by Email").reason,
        rw_p.automation_action_block_reason({"name": "Mail", "state": "mail_post"}),
    ]
    for text in texts:
        assert text and "MCP_" not in text and "=false" not in text and "=read_only" not in text, text


def test_marking_leads_lost_names_what_is_off_and_what_to_do(rw):
    assert decide(rw, "action_set_lost", model="crm.lead").reason == (
        "Marking leads lost is switched off for Claude. Do it in Odoo, or ask your administrator."
    )
    assert decide(rw, "action_set_lost", model="sale.order").reason.startswith("Marking as lost is switched off")
    assert policy(mcp_access_mode="read_write", mcp_admin_contact="Shubhang").method_decision(
        "crm.lead", "action_set_lost", is_ui_button=True
    ).reason.endswith("ask Shubhang.")


def test_read_only_mode_says_what_is_off_and_what_to_do(ro):
    with pytest.raises(PolicyViolation) as info:
        ro.check_write("crm.lead")
    assert str(info.value) == (
        "Blocked by safety policy: Changes are switched off for Claude: this connection is in read-only mode. "
        "Do it in Odoo, or ask your administrator."
    )


@pytest.mark.parametrize(
    "method", ["unlink", "action_unlink_lines", "button_delete", "purge_old_records", "action_wipe", "action_remove_lines"]
)
def test_asking_to_delete_says_it_is_not_possible_and_what_to_do_instead(method):
    off = decide(policy(mcp_access_mode="read_write"), method)
    assert off.reason == "Deleting is not possible through Claude. Delete it in Odoo."
    on = decide(policy(mcp_access_mode="read_write", mcp_allow_archive=True), method)
    assert on.allowed is False and "Archive the record instead" in on.reason and "delete it in Odoo" in on.reason
    assert "odoo_create" not in on.reason


@pytest.mark.parametrize(
    "model, needle",
    [
        ("account.tax.group", "accounting setup"),
        ("account.report", "accounting setup"),
        ("res.partner.bank", "bank details"),
        ("account.online.link", "bank details"),
        ("account.change.lock.date", "lock dates"),
        ("mail.mail", "e-mails and messages"),
        ("res.users", "system or security setup"),
        ("ir.ui.view", "system or security setup"),
        ("website.page", "website pages"),
        ("payment.transaction", "payments"),
        ("ai.agent", "AI agents"),
        ("documents.share", "shares data"),
    ],
)
def test_each_protected_area_has_its_own_reason(model, needle, everything_on):
    reason = everything_on.model_write_block_reason(model)
    assert needle in reason and "A person can change it in Odoo" in reason
    if needle != "bank details":
        assert "bank" not in reason


# The protected list before the setup areas were opened: every entry must still be protected, except the exact
# models opened within limits.
_OLD_PROTECTED = [
    "account.account", "account.cash.rounding", "account.change.lock.date", "account.code.mapping",
    "account.fiscal.position", "account.group", "account.journal", "account.lock_exception", "account.online.",
    "account.payment.method", "account.reconcile.model", "account.report", "account.return.check.template",
    "account.return.type", "account.root", "account.tax", "ai.", "auth", "base.", "base_import.", "bus.", "crm.iap",
    "decimal.precision", "digest.", "documents.share", "iap", "iap.", "ir.", "knowledge.invite", "mail.alias",
    "mail.compose.message", "mail.followers", "mail.gateway.allowed", "mail.guest", "mail.ice.server", "mail.mail",
    "mail.message", "mail.server", "mail.template", "mailing.", "payment.", "res.company", "res.country",
    "res.currency", "res.groups", "res.lang", "res.partner.bank", "res.users", "sms.", "snailmail.",
    "spreadsheet.dashboard.share", "spreadsheet.revision", "web_editor.", "website", "whatsapp.",
]


@pytest.mark.parametrize("prefix", _OLD_PROTECTED)
def test_every_previously_protected_area_is_still_protected(prefix, everything_on):
    assert prefix in HARD_READONLY_PREFIXES
    with pytest.raises(PolicyViolation):
        everything_on.check_write(prefix + "x" if prefix.endswith(".") else prefix + ".x")
    exact = prefix.rstrip(".")
    if exact not in LIMITED_MODELS and everything_on.model_read_block_reason(exact) is None:
        with pytest.raises(PolicyViolation):
            everything_on.check_write(exact)


def test_bank_matching_rules_can_be_created_edited_and_archived_but_not_buttoned(everything_on):
    model = "account.reconcile.model"
    everything_on.check_write(model)
    assert everything_on.change_block_reason(model, "create") is None
    assert everything_on.change_block_reason(model, "write") is None
    assert everything_on.field_write_block_reason("active", {"type": "boolean"}, model=model) is None
    assert everything_on.nested_write_block_reason(model, "line_ids", "account.reconcile.model.line", creating=False) is None
    assert decide(everything_on, "action_archive", model=model).allowed is False  # buttons stay closed


def test_bank_matching_rules_archive_only_with_the_archive_switch(rw):
    reason = rw.field_write_block_reason("active", {"type": "boolean"}, model="account.reconcile.model")
    assert reason and "archiving is switched off" in reason


def test_bank_matching_rule_previews_warn_and_flag_automated(rw):
    (general,) = rw.change_warnings("account.reconcile.model", "write", ["name"], [{"name": "Bank fees"}])
    assert "from now on" in general and "past entries stay as they are" in general and "Automated" in general
    automated, _ = rw.change_warnings("account.reconcile.model", "write", ["trigger"], [{"trigger": "auto_reconcile"}])
    assert automated.startswith("Sets this rule to Automated") and "without anyone checking" in automated
    assert len(rw.change_warnings("account.reconcile.model", "create", ["trigger"], [{"trigger": "manual"}])) == 1


def test_files_can_only_be_moved_never_uploaded_edited_or_buttoned(everything_on):
    model = "ir.attachment"
    everything_on.check_write(model)  # moving a file = changing which record it is on
    assert "cannot be uploaded" in everything_on.change_block_reason(model, "create")
    assert everything_on.change_block_reason(model, "write") is None
    for name in ("res_model", "res_id"):
        assert everything_on.field_write_block_reason(name, {"type": "char"}, model=model) is None
    for name, ftype in (("datas", "binary"), ("name", "char"), ("public", "boolean"), ("res_field", "char"), ("type", "selection")):
        assert "only these fields" in everything_on.field_write_block_reason(name, {"type": ftype}, model=model)
    decision = decide(everything_on, "action_open", model=model)
    assert decision.allowed is False and "move a file" in decision.reason
    (warning,) = everything_on.change_warnings(model, "write", ["res_id", "res_model"])
    assert "nothing is deleted" in warning
