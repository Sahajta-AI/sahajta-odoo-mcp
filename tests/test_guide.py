"""The guide (odoo_help): in every area Claude can tell the person what it can do, what it cannot and why, how
they do the rest in Odoo, and what it needs from them. The text follows this connection's switches and the
person's own Odoo (bill inbox, menus), falls back to fixed wording when Odoo does not tell, and every refusal
points to its area's guide without touching the "what changed" wording.

Odoo is the in-memory FakeOdoo (conftest). Every test also asserts (fixture ``no_unlink_ever``) that the fake client
never received a method containing "unlink".
"""

from __future__ import annotations

import json
import re

import pytest
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from conftest import FakeOdoo, build_settings
from sahajta_odoo_mcp import guide
from sahajta_odoo_mcp import policy as policy_module
from sahajta_odoo_mcp.errors import OdooError, PolicyViolation, RateLimited, ValidationFailed
from sahajta_odoo_mcp.policy import SafetyPolicy
from sahajta_odoo_mcp.tools import INSTRUCTIONS, register_tools
from test_service_offline import make_service, make_shared

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

READ_ONLY = dict(mcp_access_mode="read_only")
SWITCHES_OFF = dict(mcp_access_mode="read_write")
ALL_ON = dict(
    mcp_access_mode="read_write", mcp_allow_archive=True, mcp_allow_cancel_actions=True, mcp_allow_outbound_messages=True,
)
MODES = {"read_only": READ_ONLY, "switches_off": SWITCHES_OFF, "all_on": ALL_ON}
REQUIRED_TOPICS = (
    "overview", "contacts", "crm", "sales", "invoices", "vendor_bills", "payments", "bank", "files", "email",
    "automation", "settings", "accounting_setup", "users_access", "delete", "reports", "bulk_import", "connection",
    "limits",
)
# Words only operators know: never shown to the person.
SETTING_WORDS = re.compile(
    r"mcp_|MCP_|ODOO_|access_mode|allow_archive|allow_cancel|outbound_messages|admin_contact|read_write|require_preview"
)
LEFT_OVER = re.compile(r"\{(menu:)?[a-z_][a-z0-9_.]*\}")
HINT = re.compile(r' To guide the person: odoo_help\(topic="([a-z_]+)"\)$')


@pytest.fixture
def fake() -> FakeOdoo:
    return FakeOdoo()


def lines_of(rendered: dict) -> list[str]:
    out: list[str] = []
    for value in rendered.values():
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, list):
            out.extend(value)
        elif isinstance(value, dict):
            for item in value.values():
                out.extend(item if isinstance(item, list) else [item])
    return out


def mentions(lines: list[str], text: str) -> bool:
    return any(text.lower() in line.lower() for line in lines)


def with_facts(fake: FakeOdoo) -> FakeOdoo:
    """An Odoo whose purchases and sales journals have inbox addresses, and whose menus say Invoicing (Community)."""
    fake.records["account.journal"] = {
        1: {"name": "Vendor Bills", "type": "purchase", "alias_email": "bills@sahajta.odoo.com", "alias_name": "bills"},
        2: {"name": "Customer Invoices", "type": "sale", "alias_email": "invoices@sahajta.odoo.com",
            "alias_name": "invoices"},
        3: {"name": "Bank", "type": "bank", "alias_email": False, "alias_name": False},
    }
    fake.menus = {
        "account.menu_action_move_in_invoice_type": "Invoicing → Vendors → Bills",
        "account.menu_action_move_out_invoice_type": "Invoicing → Customers → Invoices",
        "account.menu_board_journal_1": "Invoicing → Dashboard",
        "contacts.menu_contacts": "Contacts",
    }
    return fake


# ======================================================================================= 1. every topic, every mode


def test_all_areas_have_a_topic():
    assert set(REQUIRED_TOPICS) <= set(guide.TOPIC_NAMES)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("topic", guide.TOPIC_NAMES)
def test_every_topic_says_what_claude_can_and_cannot_do_and_how_to_do_the_rest(topic, mode):
    rendered = guide.render(topic, build_settings(**MODES[mode]))
    for part in ("can", "cannot", "yourself", "needs"):
        assert rendered[part] and all(isinstance(line, str) and line.strip() for line in rendered[part]), part
    assert all("Why: " in line for line in rendered["cannot"])  # every "cannot" says why, in one line
    for line in lines_of(rendered):
        assert not SETTING_WORDS.search(line), line
        assert not LEFT_OVER.search(line), line
    for call in rendered["related"]:
        assert re.fullmatch(r'odoo_help\(topic="([a-z_]+)"\)', call) and call[17:-2] in guide.TOPICS, call


def test_the_overview_lists_every_other_topic():
    overview = guide.render(None, build_settings())
    assert overview["topic"] == "overview" and set(overview["topics"]) == set(guide.TOPIC_NAMES) - {"overview"}
    assert guide.topic_name("Vendor Bills") == "vendor_bills" and guide.topic_name("bills") == "vendor_bills"
    assert guide.topic_name("payroll") is None


def test_a_pdf_shared_in_the_chat_gets_both_ways():
    bills = guide.render("vendor_bills", build_settings(**SWITCHES_OFF))
    [steps] = bills["cases"].values()
    assert mentions(steps, "(a) Claude creates the draft bill") and mentions(steps, "(b) To keep the PDF")
    assert mentions(steps, "moves it onto the bill from (a)")
    assert mentions(bills["cannot"], "Take a PDF shared in this chat into Odoo. Why: Claude cannot pass files")


# ======================================================================================= 2. the switches


def test_read_only_moves_every_change_to_cannot():
    bills = guide.render("vendor_bills", build_settings(**READ_ONLY))
    assert not mentions(bills["can"], "Type a bill in")
    assert mentions(bills["cannot"], "Type a bill in") and mentions(bills["cannot"], "(read-only)")
    assert mentions(guide.render("vendor_bills", build_settings(**SWITCHES_OFF))["can"], "Type a bill in")


@pytest.mark.parametrize(
    "topic, ability, switch, own_step",
    [
        ("invoices", "Make a credit note", "mcp_allow_cancel_actions", "click Credit Note"),
        ("contacts", "Archive or bring back a contact", "mcp_allow_archive", "→ Archive"),
        ("email", "Send a message on a record", "mcp_allow_outbound_messages", "click Send message"),
        ("crm", "Mark a lead lost", "mcp_allow_cancel_actions", "click Mark as Lost"),
    ],
)
def test_a_switch_moves_its_abilities_and_the_persons_own_steps(topic, ability, switch, own_step):
    off = guide.render(topic, build_settings(**SWITCHES_OFF, mcp_admin_contact="Pranamya"))
    on = guide.render(topic, build_settings(**SWITCHES_OFF, **{switch: True}))
    assert mentions(on["can"], ability) and not mentions(on["cannot"], ability)
    blocked = next(line for line in off["cannot"] if ability in line)
    assert "switched off for Claude" in blocked and "Ask Pranamya to switch it on" in blocked
    assert not mentions(off["can"], ability)
    # the person's own steps for it are shown only while Claude may not do it
    assert mentions(off["yourself"], own_step) and not mentions(on["yourself"], own_step)


def test_a_step_needing_two_switches_shows_until_both_are_on():
    restore, step = "Bring back a lost lead", "click Restore"
    half = guide.render("crm", build_settings(**SWITCHES_OFF, mcp_allow_archive=True))
    assert mentions(half["cannot"], restore) and mentions(half["yourself"], step)
    full = guide.render("crm", build_settings(**SWITCHES_OFF, mcp_allow_archive=True, mcp_allow_cancel_actions=True))
    assert mentions(full["can"], restore) and not mentions(full["yourself"], step)


def test_the_admin_contact_is_named_and_previews_follow_their_setting():
    text = str(guide.render("vendor_bills", build_settings(mcp_admin_contact="Shubhang")))
    assert "ask Shubhang" in text  # the bill inbox fallback says whom to ask
    assert mentions(guide.render("limits", build_settings(**SWITCHES_OFF))["can"], "only after your yes")
    loose = guide.render("limits", build_settings(**SWITCHES_OFF, mcp_require_preview=False))
    assert mentions(loose["can"], "Previews are optional") and not mentions(loose["can"], "only after your yes")


# ======================================================================================= 3. facts from the person's Odoo


async def test_the_guide_uses_the_persons_own_odoo(fake):
    svc = make_service(with_facts(fake))
    bills = await svc.guide("vendor_bills")
    text = json.dumps(bills, ensure_ascii=False)
    assert "forward each vendor PDF as its own e-mail to bills@sahajta.odoo.com" in text
    assert "Invoicing → Vendors → Bills, click Upload" in text and "Accounting → Vendors → Bills" not in text
    assert "Menu names are Odoo's usual ones" not in text
    assert mentions((await svc.guide("invoices"))["yourself"], "e-mail each one to invoices@sahajta.odoo.com")
    setup = await svc.guide("accounting_setup")  # menus this person does not have: Odoo's usual path, flagged
    assert mentions(setup["yourself"], "Journals: Accounting → Configuration → Accounting → Journals.")
    assert mentions(setup["yourself"], "Not in your Odoo menus: Accounting → Configuration → Accounting → Chart of Accounts")
    who = await svc.whoami()
    assert who["bill_inbox"] == ["bills@sahajta.odoo.com"] and "odoo_help" in who["help"]
    # read once per person and hour, not on every call
    await svc.guide("bank")
    assert len(fake.calls_to("load_menus")) == 1
    assert len([c for c in fake.calls if c.model == "account.journal"]) == 1


async def test_the_guide_falls_back_to_fixed_wording_when_odoo_does_not_tell(fake):
    fake.errors[("account.journal", "search_read")] = OdooError("not allowed to access Journal", kind="access", status=403)
    svc = make_service(fake)  # fake.menus is None: this Odoo has no load_menus
    bills = await svc.guide("vendor_bills")
    text = json.dumps(bills, ensure_ascii=False)
    assert "Accounting → Vendors → Bills, click Upload" in text
    assert "open the purchases journal, Advanced Settings tab, Email Alias" in text
    assert mentions(bills["yourself"], "Menu names are Odoo's usual ones")
    assert not mentions(bills["yourself"], "Not in your Odoo menus")
    who = await svc.whoami()
    assert who["bill_inbox"].startswith("Not found") and "odoo_help" in who["help"]
    assert len(fake.calls_to("search_read")) == 1  # a failed read is not repeated on every call


async def test_a_bill_inbox_without_an_email_domain_is_explained(fake):
    fake.records["account.journal"] = {1: {"name": "Purchases", "type": "purchase", "alias_email": False,
                                           "alias_name": "purchases"}}
    text = json.dumps(await make_service(fake).guide("vendor_bills"), ensure_ascii=False)
    assert "inbox name 'purchases' but no e-mail domain" in text and "Configure Alias Domain" in text


async def test_odoo_rejecting_the_key_while_the_guide_reads_is_passed_on(fake):
    fake.errors[("account.journal", "search_read")] = OdooError("Invalid API key", kind="auth", status=401)
    with pytest.raises(OdooError) as info:
        await make_service(fake).whoami()
    assert info.value.key_rejected


async def test_an_unknown_topic_names_the_real_ones_without_asking_odoo(fake):
    svc = make_service(fake)
    with pytest.raises(ValidationFailed, match="vendor_bills"):
        await svc.guide("payroll")
    assert fake.calls == []
    assert (await svc.guide("Bills"))["topic"] == "vendor_bills"


def test_facts_from_odoo_cannot_inject_placeholders_or_odd_addresses():
    inboxes = guide.inboxes_from([
        {"name": "Bills {admin}", "type": "purchase", "alias_email": "not an address", "alias_name": "x{menu:y}"},
        {"name": "Misc", "type": "general", "alias_email": "misc@x.com"},
    ])
    assert inboxes == (guide.Inbox("Bills admin", "purchase", "", "xmenu:y"),)
    paths = guide.menu_paths_from({
        "root": {"children": [1]}, "1": {"name": "Sales", "xmlid": "sale.root", "children": [2]},
        "2": {"name": "Quotations", "xmlid": "sale.q", "children": []},
    })
    assert paths == {"sale.root": "Sales", "sale.q": "Sales → Quotations"}
    with pytest.raises(ValueError):
        guide.menu_paths_from(True)


# ======================================================================================= 4. refusals point to their guide

P = SafetyPolicy(build_settings(**SWITCHES_OFF))
READ_ONLY_POLICY = SafetyPolicy(build_settings(**READ_ONLY))


def button(model: str, method: str, label: str = "") -> PolicyViolation:
    return PolicyViolation(P.method_decision(model, method, is_ui_button=True, label=label).reason)


def blocked(model: str, policy: SafetyPolicy = P) -> PolicyViolation:
    return PolicyViolation(policy.model_write_block_reason(model))


def field(model: str, name: str, meta: dict) -> ValidationFailed:
    return ValidationFailed([f"{model}.{name} {P.field_write_block_reason(name, meta, model=model)}"])


# (refusal, the model the tool call was about, the guide topic it must point to)
REFUSALS = [
    pytest.param(button("sale.order", "unlink"), "sale.order", "delete", id="delete-button"),
    pytest.param(ValidationFailed("sale.order.order_line: command 2 would delete or detach existing lines; removing "
                                  "lines is not allowed through this server (a person can do it in Odoo)"),
                 "sale.order", "delete", id="remove-lines"),
    pytest.param(button("crm.lead", "action_archive"), "crm.lead", "crm", id="archive-off"),
    pytest.param(button("sale.order", "action_cancel", "Cancel"), "sale.order", "sales", id="cancel-off"),
    pytest.param(button("account.move", "action_reverse", "Credit Note"), "account.move", "invoices", id="credit-note-off"),
    pytest.param(button("crm.lead.lost", "action_lost_reason_apply"), "crm.lead", "crm", id="lost-off"),
    pytest.param(button("account.move", "action_invoice_sent", "Send"), "account.move", "email", id="send-off"),
    pytest.param(button("crm.lead", "iap_enrich", "Enrich"), "crm.lead", "crm", id="paid-credits"),
    pytest.param(button("sale.order", "payment_action_capture"), "sale.order", "payments", id="capture"),
    pytest.param(button("account.move", "button_hash", "Lock"), "account.move", "invoices", id="lock"),
    pytest.param(button("res.users", "action_reset_password"), "res.users", "users_access", id="password"),
    pytest.param(button("ir.module.module", "button_immediate_install"), "ir.module.module", "settings", id="install"),
    pytest.param(button("res.partner", "action_import"), "res.partner", "bulk_import", id="import"),
    pytest.param(button("res.partner", "action_merge"), "res.partner", "contacts", id="merge"),
    pytest.param(button("res.config.settings", "action_open_template"), "res.config.settings", "settings",
                 id="settings-button"),
    pytest.param(button("ir.attachment", "action_rename"), "ir.attachment", "files", id="file-button"),
    pytest.param(button("mail.template", "send_mail"), "mail.template", "email", id="template-button"),
    pytest.param(button("base.automation", "action_run"), "base.automation", "automation", id="automation-button"),
    pytest.param(button("account.tax", "action_open"), "account.tax", "accounting_setup", id="setup-button"),
    pytest.param(button("account.reconcile.model", "action_open"), "account.reconcile.model", "bank",
                 id="matching-rule-button"),
    pytest.param(blocked("account.move", READ_ONLY_POLICY), "account.move", "invoices", id="read-only"),
    pytest.param(blocked("res.partner.bank"), "res.partner.bank", "payments", id="bank-accounts"),
    pytest.param(blocked("account.online.link"), "account.online.link", "bank", id="bank-sync"),
    pytest.param(blocked("account.change.lock.date"), "account.change.lock.date", "accounting_setup", id="lock-dates"),
    pytest.param(PolicyViolation(P.change_block_reason("account.tax", "write")), "account.tax", "accounting_setup",
                 id="existing-setup"),
    pytest.param(blocked("mail.alias"), "mail.alias", "email", id="aliases"),
    pytest.param(blocked("mailing.mailing"), "mailing.mailing", "email", id="mass-mailing"),
    pytest.param(blocked("res.users"), "res.users", "users_access", id="users"),
    pytest.param(blocked("res.users.apikeys"), "res.users.apikeys", "users_access", id="api-keys"),
    pytest.param(blocked("res.company"), "res.company", "settings", id="company"),
    pytest.param(blocked("ir.cron"), "ir.cron", "automation", id="scheduled-actions"),
    pytest.param(blocked("payment.provider"), "payment.provider", "payments", id="payment-providers"),
    pytest.param(blocked("sign.request"), "sign.request", "email", id="sign-request"),
    pytest.param(PolicyViolation(P.change_block_reason("ir.attachment", "create")), "ir.attachment", "files",
                 id="upload"),
    pytest.param(PolicyViolation(P.change_block_reason("mail.template", "create")), "mail.template", "email",
                 id="new-template"),
    pytest.param(PolicyViolation(P.change_block_reason("res.config.settings", "write")), "res.config.settings",
                 "settings", id="edit-settings"),
    pytest.param(field("account.journal", "bank_account_id", {"type": "many2one", "relation": "res.partner.bank"}),
                 "account.journal", "bank", id="journal-bank-field"),
    pytest.param(field("res.partner", "bank_ids", {"type": "one2many", "relation": "res.partner.bank"}),
                 "res.partner", "payments", id="contact-bank-field"),
    pytest.param(field("crm.lead", "active", {"type": "boolean"}), "crm.lead", "crm", id="archive-field"),
    pytest.param(field("crm.lead", "x_attachment", {"type": "binary"}), "crm.lead", "files", id="binary-field"),
    pytest.param(field("res.config.settings", "module_crm", {"type": "boolean"}), "res.config.settings", "settings",
                 id="app-install-field"),
    pytest.param(field("res.config.settings", "l10n_in_gstin", {"type": "char"}), "res.config.settings", "settings",
                 id="company-identity-field"),
    pytest.param(field("ir.actions.server", "code", {"type": "text"}), "base.automation", "automation",
                 id="python-code"),
    pytest.param(ValidationFailed([P.automation_trigger_block_reason("on_webhook")]), "base.automation", "automation",
                 id="webhook-trigger"),
    pytest.param(ValidationFailed([P.automation_action_block_reason({"state": "mail_post", "name": "Mail"})]),
                 "base.automation", "automation", id="automation-email-off"),
    pytest.param(PolicyViolation("sending e-mails and messages to people is switched off for Claude on this server; "
                                 "ask your administrator if it is needed"), "crm.lead", "email", id="message-off"),
    pytest.param(PolicyViolation("this payment would charge the customer's saved card or account through a payment "
                                 "provider, which Claude never does"), "account.move", "payments", id="saved-card"),
    pytest.param(OdooError("your Odoo user may not create crm.lead records (Odoo's access rights for this user)",
                           kind="access"), "crm.lead", "users_access", id="odoo-access"),
    pytest.param(OdooError("Invalid API key", kind="auth", status=401), "crm.lead", "connection", id="key-rejected"),
    pytest.param(ValidationFailed("too many records at once (25); the limit is 20"), "crm.lead", "bulk_import",
                 id="too-many"),
    pytest.param(RateLimited("Too many requests; wait a minute"), None, "limits", id="rate-limit"),
    pytest.param(ValidationFailed(["'bill.pdf' is on INV/1, which is not a draft; files on posted or cancelled "
                                   "entries stay where they are"]), "ir.attachment", "files", id="file-on-posted"),
    pytest.param(PolicyViolation("context key 'force_company' is not allowed (it would skip Odoo checks or hide "
                                 "changes)"), "project.task", "overview", id="anything-else"),
]


@pytest.mark.parametrize("refusal, model, topic", REFUSALS)
def test_each_refusal_points_to_its_guide(refusal, model, topic):
    assert guide.refusal_topic(refusal, model) == topic, str(refusal)


@pytest.mark.parametrize(
    "error",
    [
        ValidationFailed("'nme' is not a field of crm.lead. Did you mean 'name'?"),
        OdooError("Record is being edited by someone else", kind="busy", status=409),
        OdooError("You cannot post an invoice without lines", kind="user_error"),
        OdooError("timed out", kind="timeout"),
    ],
)
def test_mistakes_and_bad_weather_are_not_refusals(error):
    assert guide.refusal_topic(error, "crm.lead") is None


# Areas with no guide of their own: the overview covers them.
GENERAL_AREAS = frozenset({
    "website", "web_editor.", "ai.", "spreadsheet.dashboard.share", "documents.share", "knowledge.invite",
    "spreadsheet.revision", "bus.",
})
TECHNICAL_METHOD_PARTS = frozenset({"sudo", "with_user", "with_context", "with_env", "invalidate", "truncate"})


def _a_model(prefix: str) -> str:
    return f"{prefix}x" if prefix.endswith(".") else prefix


def test_every_protected_area_has_a_guide():
    """Fails when a new protected area is added to policy.py without a guide topic for it."""
    for _, prefixes in policy_module.PROTECTED_AREAS:
        for prefix in prefixes:
            model = _a_model(prefix)
            # the setup areas open within limits refuse only some changes: their refusal for editing
            reason = P.model_write_block_reason(model) or P.change_block_reason(model, "write") or ""
            topic = guide.topic_for_refusal(reason, model)
            assert (topic == "overview") == (prefix in GENERAL_AREAS), (prefix, topic)


def test_every_blocked_model_has_a_guide():
    """Fails when a new always-blocked model or family is added to policy.py without a guide topic for it."""
    models = sorted(policy_module.HARD_BLOCKED_MODELS) + [_a_model(p) for p in policy_module.HARD_BLOCKED_PREFIXES]
    for model in models:
        topic = guide.topic_for_refusal(P.model_read_block_reason(model), model)
        assert topic != "overview" or model.startswith("bus."), (model, topic)


def test_every_always_blocked_button_has_a_guide_whatever_the_record():
    """Fails when a new blocked method part is added to policy.py without a text rule that names its guide."""
    parts = [*policy_module.HARD_BLOCKED_METHOD_SUBSTRINGS, *policy_module.HARD_BLOCKED_METHOD_TOKENS]
    for part in parts:
        if part in TECHNICAL_METHOD_PARTS:
            continue
        reason = P.method_decision("crm.lead", f"action_{part}", is_ui_button=True).reason
        assert reason, part
        topics = {guide.topic_for_refusal(reason, model) for model in ("crm.lead", "project.task", None)}
        assert len(topics) == 1 and topics != {"overview"}, (part, reason, topics)


def test_switched_off_buttons_point_to_the_records_own_area_or_to_email():
    for part in policy_module.CANCEL_METHOD_PARTS:
        reason = P.method_decision("sale.order", f"action_{part}", is_ui_button=True).reason
        assert guide.topic_for_refusal(reason, "sale.order") == "sales", (part, reason)
    for part in policy_module.OUTBOUND_METHOD_PARTS:
        reason = P.method_decision("sale.order", f"action_{part}", is_ui_button=True).reason
        assert guide.topic_for_refusal(reason, "sale.order") == "email", (part, reason)


def test_every_setup_area_refusal_points_to_that_area():
    for model in policy_module.LIMITED_BUTTONS:
        reason = P.method_decision(model, "action_open_something", is_ui_button=True).reason
        assert guide.topic_for_refusal(reason, model) == guide.topic_for_model(model) != "overview", model
    for model in policy_module.FIELD_ALLOWLISTS:
        error = ValidationFailed([f"{model}.x_other {P.field_write_block_reason('x_other', {'type': 'char'}, model=model)}"])
        assert guide.refusal_topic(error, model) == guide.topic_for_model(model) != "overview", model
    for trigger in policy_module._REFUSED_TRIGGERS:
        error = ValidationFailed([P.automation_trigger_block_reason(trigger)])
        assert guide.refusal_topic(error, "base.automation") == "automation", trigger
    for state in policy_module._REFUSED_ACTIONS:
        error = ValidationFailed([P.automation_action_block_reason({"state": state, "name": "x"})])
        assert guide.refusal_topic(error, "base.automation") == "automation", state


# ======================================================================================= 5. through the MCP tools


async def tool_client(fake: FakeOdoo, **settings):
    shared = make_shared(**settings)
    service = make_service(fake, shared)
    mcp = MCPServer("guide-test")

    async def get_service():
        return service

    register_tools(mcp, get_service, shared.settings)
    return Client(mcp)


async def test_refused_changes_end_with_their_guide_after_what_changed(fake):
    async with await tool_client(fake, **SWITCHES_OFF) as client:
        preview = await client.call_tool("odoo_preview_action", {"model": "sale.order", "ids": [5], "method": "action_confirm"})
        token = json.loads(preview.content[0].text)["confirm_token"]
        cancel = await client.call_tool(
            "odoo_run_action", {"model": "sale.order", "ids": [5], "method": "action_cancel", "confirm_token": token}
        )
        archive = await client.call_tool(
            "odoo_update", {"model": "crm.lead", "ids": [100], "values": {"active": False}, "confirm_token": token}
        )
        delete = await client.call_tool("odoo_preview_action", {"model": "crm.lead", "ids": [100], "method": "unlink"})
        capture = await client.call_tool(
            "odoo_preview_action", {"model": "sale.order", "ids": [5], "method": "payment_action_capture"}
        )
        typo = await client.call_tool("odoo_search", {"model": "crm.lead", "fields": ["nme"]})
    assert capture.content[0].text.endswith('permanently blocked. To guide the person: odoo_help(topic="payments")')
    for result, topic in ((cancel, "sales"), (archive, "crm"), (delete, "delete")):
        text = result.content[0].text
        assert result.is_error and HINT.search(text) and HINT.search(text).group(1) == topic, text
    for result in (cancel, archive):  # the change tools still say exactly what changed, before the hint
        text = result.content[0].text.lower()
        assert "nothing was changed" in text and "may already have" not in text
        assert text.index("nothing was changed") < text.index("to guide the person")
    assert typo.is_error and "To guide the person" not in typo.content[0].text  # a typo is not a refusal
    assert [c for c in fake.calls if c.method in ("action_cancel", "write")] == []


async def test_odoo_help_and_whoami_work_in_read_only_mode(fake):
    async with await tool_client(with_facts(fake), **READ_ONLY) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert "odoo_help" in tools and "odoo_create" not in tools
        description = " ".join(tools["odoo_help"].description.split())
        assert "after any refusal" in description and "shared in the chat" in description
        overview = json.loads((await client.call_tool("odoo_help", {})).content[0].text)
        bills = json.loads((await client.call_tool("odoo_help", {"topic": "vendor_bills"})).content[0].text)
        who = json.loads((await client.call_tool("odoo_whoami", {})).content[0].text)
        unknown = await client.call_tool("odoo_help", {"topic": "payroll"})
    assert overview["topic"] == "overview" and "vendor_bills" in overview["topics"]
    assert mentions(bills["cannot"], "Type a bill in") and mentions(bills["yourself"], "bills@sahajta.odoo.com")
    assert who["bill_inbox"] == ["bills@sahajta.odoo.com"] and "odoo_help" in who["help"]
    assert unknown.is_error and "vendor_bills" in unknown.content[0].text


def test_the_instructions_say_never_just_no_and_stay_short():
    assert "Never just say something is not possible" in INSTRUCTIONS and "one item at a time" in INSTRUCTIONS
    assert "odoo_help" in INSTRUCTIONS and "Accounting > Bank" not in INSTRUCTIONS
    assert len(INSTRUCTIONS) < 5000
