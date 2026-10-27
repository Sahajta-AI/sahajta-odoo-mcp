"""The guide: in each area of Odoo, what Claude can do, what it cannot (and why), how the person does the rest
themselves, and what Claude must ask them for.

The single source of that guide. odoo_help shows a topic, every refusal points to one (refusal_topic), and
odoo_whoami names the bill inbox. The text follows this connection's switches (read-only, archiving,
cancelling, e-mail) and facts read from the person's own Odoo (bill inbox addresses, their menu paths); when
those reads fail, fixed wording is used. Written for a non-technical person: plain words, never the name of
an operator setting. The "How" parts are for Claude.

Facts checked on Odoo 19 (Community in Docker, menu ids on Enterprise): button and dialog captions (Confirm,
Send, Print, Pay, Credit Note, Reverse, Reset to Draft, Lost, Mark as Lost, Restore, Enrich, Won), the
journal's Advanced Settings tab with its Email Alias, the Bills list's Upload button, a list's gear menu with
Import records, the contact's Merge and Grant portal access actions, and Settings' Activate the developer mode.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .config import Settings
from .confirm import DEFAULT_TTL_SECONDS
from .errors import OdooError, PolicyViolation, RateLimited, ValidationFailed

# ---------------------------------------------------------------------------
# Facts read from the person's Odoo
# ---------------------------------------------------------------------------

# Menu XML ids, checked on Odoo 19 Enterprise, with the path shown when the person's own menus could not be
# read or do not have it. True: a technical menu, visible only in developer mode.
MENUS: dict[str, tuple[str, bool]] = {
    "account.menu_action_move_in_invoice_type": ("Accounting → Vendors → Bills", False),
    "account.menu_action_move_out_invoice_type": ("Accounting → Customers → Invoices", False),
    "account.menu_action_account_payments_receivable": ("Accounting → Customers → Payments", False),
    "account.menu_action_account_payments_payable": ("Accounting → Vendors → Payments", False),
    "account.menu_board_journal_1": ("Accounting → Dashboard", False),
    "account.menu_finance_reports": ("Accounting → Reporting", False),
    "account.menu_account_config": ("Accounting → Configuration → Settings", False),
    "account.menu_action_tax_form": ("Accounting → Configuration → Accounting → Taxes", False),
    "account.menu_action_account_form": ("Accounting → Configuration → Accounting → Chart of Accounts", False),
    "account.menu_action_account_journal_form": ("Accounting → Configuration → Accounting → Journals", False),
    "account.menu_action_account_fiscal_position_form": (
        "Accounting → Configuration → Accounting → Fiscal Positions", False,
    ),
    "account_accountant.menu_action_change_lock_date": ("Accounting → Accounting → Closing → Lock Dates", False),
    "base.menu_action_res_users": ("Settings → Users & Companies → Users", False),
    "base.menu_action_res_company_form": ("Settings → Users & Companies → Companies", False),
    "base.menu_administration": ("Settings", False),
    "base.menu_management": ("Apps", False),
    "base.menu_ir_cron_act": ("Settings → Technical → Automation → Scheduled Actions", True),
    "base_automation.menu_base_automation_form": ("Settings → Technical → Automation → Automation Rules", True),
    "mail.menu_email_templates": ("Settings → Technical → Email → Email Templates", True),
    "contacts.menu_contacts": ("Contacts", False),
    "crm.menu_crm_opportunities": ("CRM → Sales → My Pipeline", False),
    "sale.menu_sale_quotations": ("Sales → Orders → Quotations", False),
}
DEVELOPER_MODE = "To see menus marked (developer mode): open Settings, scroll to the bottom, click Activate the developer mode."

FACTS_TTL_SECONDS = 3600  # facts read from Odoo are kept this long per person and server process
FACTS_RETRY_SECONDS = 300  # after a failed read, fixed wording is used this long before Odoo is asked again


@dataclass(frozen=True)
class Inbox:
    """A journal's e-mail inbox: Odoo makes a draft bill (purchase) or invoice (sale) from each e-mail."""

    journal: str
    kind: str  # "purchase" or "sale"
    email: str  # empty when the journal has an inbox name but no e-mail domain is set up
    name: str = ""


@dataclass(frozen=True)
class Facts:
    """What the guide knows about this person's Odoo. None: could not be read (fixed wording is used)."""

    odoo_url: str = ""
    inboxes: tuple[Inbox, ...] | None = None
    menus: Mapping[str, str] | None = None  # menu XML id -> "App → Menu → Item", as this person sees it

    def bill_inboxes(self) -> list[str]:
        return [box.email for box in self.inboxes or () if box.kind == "purchase" and box.email]


def inboxes_from(rows: Any) -> tuple[Inbox, ...]:
    """Inboxes from account.journal search_read rows (name, type, alias_email, alias_name)."""
    found = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or row.get("type") not in ("purchase", "sale"):
            continue
        email = _text(row.get("alias_email"), 255)
        email = email if re.fullmatch(r"[^\s@<>\"']{1,64}@[^\s@<>\"']{1,190}", email) else ""
        found.append(Inbox(_text(row.get("name"), 80), row["type"], email, _text(row.get("alias_name"), 64)))
    return tuple(found)


def _text(value: Any, limit: int) -> str:
    """A short text from Odoo, without the braces the guide uses for its own placeholders."""
    return re.sub(r"[{}]", "", value).strip()[:limit] if isinstance(value, str) else ""


def menu_paths_from(menus: Any) -> dict[str, str]:
    """{xml id: "App → Menu → Item"} from ir.ui.menu load_menus (the menus this person sees, in their language)."""
    if not isinstance(menus, dict) or not isinstance(menus.get("root"), dict):
        raise ValueError("not a menu tree")
    by_id = {str(key): value for key, value in menus.items() if isinstance(value, dict)}
    paths: dict[str, str] = {}

    def walk(menu: dict, trail: tuple[str, ...], depth: int) -> None:
        for child_id in menu.get("children") or []:
            child = by_id.get(str(child_id))
            if not child or depth > 8:
                continue
            here = (*trail, str(child.get("name") or "").strip().rstrip("…").rstrip(".").strip()[:60])
            if isinstance(child.get("xmlid"), str) and child["xmlid"]:
                paths.setdefault(child["xmlid"], " → ".join(here))
            walk(child, here, depth + 1)

    walk(by_id["root"], (), 0)
    return paths


# ---------------------------------------------------------------------------
# Topics
# ---------------------------------------------------------------------------

# Switches: "write" = changes allowed at all; the others also need "write".
SWITCHES = ("write", "archive", "cancel", "outbound")
_OFF = {
    "write": "changes are switched off for Claude on this connection (read-only)",
    "archive": "archiving is switched off for Claude on this connection",
    "cancel": "cancelling, resetting, reversing and marking lost are switched off for Claude on this connection",
    "outbound": "sending e-mails and messages to people is switched off for Claude on this connection",
}


@dataclass(frozen=True)
class Can:
    """Something Claude can do: what, and how (the tool flow). needs: switches it takes."""

    text: str
    how: str = ""
    needs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Step:
    """A step the person does in Odoo. unless: switches ("archive", or "archive,cancel"); the step is shown only while
    one of them is off (otherwise Claude can do it)."""

    text: str
    unless: str = ""


@dataclass(frozen=True)
class Topic:
    title: str
    summary: str
    can: tuple[Can, ...]
    cannot: tuple[tuple[str, str], ...]  # (what, why)
    yourself: tuple[Step, ...]
    needs: tuple[str, ...]  # what Claude asks the person for, in this order, one at a time
    related: tuple[str, ...] = ()
    cases: tuple[tuple[str, tuple[str, ...]], ...] = field(default=())


def _steps(*items: str | Step) -> tuple[Step, ...]:
    return tuple(item if isinstance(item, Step) else Step(item) for item in items)


_FILES_WHY = "Claude cannot pass files between this chat and Odoo"
_BANK_WHY = "a wrong bank account sends money to the wrong place"
_DELETE_STEP = "Delete in Odoo: open the record, click the gear icon (Actions), Delete, and confirm. See odoo_help topic delete."

TOPICS: dict[str, Topic] = {
    "overview": Topic(
        title="What Claude can do in your Odoo",
        summary="What Claude can do in Odoo, and how this works",
        can=(
            Can("Find and read anything your Odoo user can see: contacts, leads, quotations, invoices, bills, "
                "payments, bank lines, products.", "odoo_find, odoo_search, odoo_read; totals with odoo_aggregate"),
            Can("Create and change records, and press workflow buttons (Confirm, Pay, Send). Claude first shows "
                "exactly what will change and does it only after you say yes.",
                "an odoo_preview_* tool, then the matching change tool with its confirm_token", ("write",)),
            Can("Log internal notes on a record (nobody is e-mailed).", "odoo_add_note", ("write",)),
            Can("Archive records you no longer need (they can be brought back).",
                "odoo_preview_update with values {\"active\": false}", ("archive",)),
            Can("Cancel, reset to draft, reverse or mark lost.", "the record's own button (odoo_list_actions)",
                ("cancel",)),
            Can("E-mail or message customers from a record, after you approve the recipients.",
                "odoo_preview_message, then odoo_send_message", ("outbound",)),
            Can("Give you a link to each record, to open it in Odoo."),
        ),
        cannot=(
            ("Delete anything", "deleting cannot be undone, so only a person does it, in Odoo"),
            ("Upload, download, rename or delete files, or take a file shared in this chat into Odoo", _FILES_WHY),
            ("Install apps, or change users, access rights, passwords or API keys",
             "these decide who can do what, and can raise your Odoo bill"),
            ("Set bank account details, or charge cards through payment providers", _BANK_WHY),
            ("Change anything you have not approved", "every change waits for your yes on a preview"),
        ),
        yourself=_steps(
            "Open Odoo at {odoo_url} and sign in as usual.",
            "Each answer from Claude has a link to the record: open it to see it or to finish a step in Odoo.",
            DEVELOPER_MODE,
        ),
        needs=(
            "What you want done, in your own words.",
            "Which record: its name or number (for example the customer's name or the invoice number).",
            "For a change: the new values.",
            "Your yes on the preview.",
        ),
        related=("invoices", "vendor_bills", "payments", "files", "delete", "limits"),
    ),
    "contacts": Topic(
        title="Contacts: customers and vendors",
        summary="Customers, vendors and their details",
        can=(
            Can("Find contacts and companies by name, e-mail, phone or GSTIN.",
                "odoo_find model res.partner, or odoo_search on email, phone or vat"),
            Can("Create a contact or company: name, e-mail, phone, address, GSTIN, tags.",
                "odoo_preview_create model res.partner, then odoo_create", ("write",)),
            Can("Update a contact's details.", "odoo_preview_update model res.partner", ("write",)),
            Can("Archive or bring back a contact.", "odoo_preview_update with values {\"active\": false or true}",
                ("archive",)),
            Can("Log an internal note on a contact.", "odoo_add_note", ("write",)),
        ),
        cannot=(
            ("Add or change a contact's bank account", _BANK_WHY),
            ("Merge duplicate contacts", "merging deletes the duplicates, and that cannot be undone"),
            ("Delete contacts", "deleting cannot be undone"),
            ("Change a contact's photo or logo", "Claude never writes files or images"),
            ("Give a contact access to your Odoo portal", "that invites an outside person into your Odoo"),
        ),
        yourself=_steps(
            "Contacts are under {menu:contacts.menu_contacts}.",
            "Bank account of a contact: open the contact, Accounting (or Invoicing) tab, Bank Accounts. All bank "
            "accounts: Contacts → Configuration → Bank Accounts → Bank Accounts.",
            "Merge duplicates: in the Contacts list, tick the duplicates, then gear icon (Actions) → Merge.",
            "Portal access: open the contact, gear icon (Actions) → Grant portal access.",
            Step("Archive: open the contact, gear icon (Actions) → Archive.", unless="archive"),
            _DELETE_STEP,
        ),
        needs=(
            "Name, and whether it is a company or a person.",
            "E-mail address.",
            "Phone number.",
            "GSTIN, for a registered business.",
            "Address, with the state (it decides the GST type).",
        ),
        related=("crm", "payments", "delete"),
    ),
    "crm": Topic(
        title="CRM: leads and opportunities",
        summary="Leads, opportunities and the pipeline",
        can=(
            Can("Find leads and opportunities; show the pipeline by stage with expected revenue.",
                "odoo_search model crm.lead; odoo_aggregate group_by stage_id, measures expected_revenue:sum"),
            Can("Create a lead or opportunity.",
                "odoo_preview_create model crm.lead with name, type (\"lead\" or \"opportunity\"), partner_id or "
                "contact_name and email_from, expected_revenue, user_id", ("write",)),
            Can("Move it to another stage; set the salesperson, expected revenue, tags or closing date.",
                "odoo_preview_update model crm.lead (stage ids from crm.stage); several leads with different "
                "values in one preview with changes", ("write",)),
            Can("Turn a lead into an opportunity.", "odoo_preview_update values {\"type\": \"opportunity\"}",
                ("write",)),
            Can("Mark an opportunity won.", "odoo_preview_action model crm.lead, method action_set_won_rainbowman",
                ("write",)),
            Can("Mark a lead lost, with a reason.",
                "odoo_preview_action model crm.lead, method \"dialog:crm.lead.lost\", dialog_values "
                "{\"lost_reason_id\": <id from crm.lost.reason>} (and \"lost_feedback\" for a note)", ("cancel",)),
            Can("Bring back a lost lead.", "odoo_preview_action model crm.lead, method action_restore",
                ("archive", "cancel")),
        ),
        cannot=(
            ("Enrich leads with company data (the Enrich button) or generate new leads",
             "they spend paid Odoo credits"),
            ("Delete leads", "deleting cannot be undone"),
        ),
        yourself=_steps(
            "Your pipeline: {menu:crm.menu_crm_opportunities}.",
            Step("Mark lost: open the lead, click Lost, pick a reason, click Mark as Lost.", unless="cancel"),
            Step("Bring back a lost lead: in the pipeline search, use the Lost filter, open the lead, click Restore.",
                 unless="archive,cancel"),
            "Enrich a lead: open it and click Enrich (it uses paid credits; check with {admin} first).",
            _DELETE_STEP,
        ),
        needs=(
            "Which lead: its title or the customer's name.",
            "For a new lead: a title, then the customer or contact name, then their e-mail or phone.",
            "Expected revenue.",
            "Salesperson, if not you.",
            "For a lost lead: the reason.",
        ),
        related=("contacts", "sales", "email"),
    ),
    "sales": Topic(
        title="Sales: quotations and orders",
        summary="Quotations and sales orders",
        can=(
            Can("Find quotations and orders; totals by customer or by month.",
                "odoo_search model sale.order; odoo_aggregate group_by partner_id or date_order:month"),
            Can("Create a quotation with lines.",
                "odoo_preview_create model sale.order with partner_id and order_line [{\"product_id\", "
                "\"product_uom_qty\", \"price_unit\"}]", ("write",)),
            Can("Add lines to a quotation, or change quantities and prices.",
                "odoo_preview_update with order_line: new lines as objects, [1, line_id, {...}] to edit one",
                ("write",)),
            Can("Confirm a quotation into a sales order.", "odoo_preview_action model sale.order, method action_confirm",
                ("write",)),
            Can("Create the invoice of a confirmed order (a draft invoice).",
                "odoo_preview_action model sale.order, method \"dialog:sale.advance.payment.inv\"", ("write",)),
            Can("Cancel an order, or set it back to quotation.",
                "odoo_preview_action model sale.order, method action_cancel or action_draft; if Odoo opens a "
                "window, follow the next_step it returns", ("cancel",)),
        ),
        cannot=(
            ("E-mail the quotation to the customer (the Send button)",
             "Odoo's e-mail window for quotations cannot be filled in through Claude"),
            ("Remove lines from an order", "removing a line deletes it"),
            ("Capture or void online card payments", "payment providers move real money"),
            ("Delete quotations", "deleting cannot be undone"),
        ),
        yourself=_steps(
            "Quotations: {menu:sale.menu_sale_quotations}.",
            "Send the quotation: open it, click Send, check the e-mail, click Send.",
            "Download the PDF: open it and click Print.",
            "Remove a line: open the quotation, click the bin icon on the line, save.",
            Step("Cancel: open the order and click Cancel. Back to quotation: click Set to Quotation.", unless="cancel"),
        ),
        needs=(
            "The customer.",
            "Each product and its quantity.",
            "The price, if not the usual price.",
            "The expiry date, if it matters.",
            "To invoice an order: the whole amount or a down payment.",
        ),
        related=("invoices", "crm", "contacts", "email"),
    ),
    "invoices": Topic(
        title="Customer invoices and credit notes",
        summary="Customer invoices, credit notes and GST on lines",
        can=(
            Can("Find invoices: unpaid, overdue, by customer; totals due.",
                "odoo_search model account.move, move_type out_invoice, payment_state; odoo_aggregate on "
                "amount_residual"),
            Can("Create a draft invoice with GST on each line. The preview shows Odoo's own tax breakdown and total.",
                "odoo_preview_create model account.move with move_type \"out_invoice\", partner_id, invoice_date, "
                "invoice_line_ids [{\"product_id\" or \"name\", \"quantity\", \"price_unit\", \"tax_ids\": [GST "
                "tax ids from account.tax]}]", ("write",)),
            Can("Set the place of supply on a draft invoice.",
                "find the field with odoo_describe_model model account.move, query \"supply\"; its value is a "
                "state id", ("write",)),
            Can("Split a line across projects or departments (analytic distribution).",
                "line value \"analytic_distribution\": {\"<analytic account id>\": percent}", ("write",)),
            Can("Confirm (post) a draft invoice.", "odoo_preview_action model account.move, method action_post",
                ("write",)),
            Can("E-mail the invoice with its PDF to the customer. The preview shows recipients, subject and "
                "attachments.", "odoo_preview_action model account.move (one invoice), method action_invoice_sent",
                ("outbound",)),
            Can("Make a credit note for a posted invoice (a draft, to post afterwards).",
                "odoo_preview_action model account.move, method action_reverse, dialog_values {\"reason\": "
                "\"...\"}; then action_post on the credit note", ("cancel",)),
            Can("Reset a posted invoice to draft, or cancel a draft.",
                "odoo_preview_action model account.move, method button_draft or button_cancel", ("cancel",)),
        ),
        cannot=(
            ("Give you the invoice PDF in this chat", _FILES_WHY),
            ("Lock posted entries (the Lock button)", "locking cannot be undone"),
            ("Delete invoices", "deleting cannot be undone; Odoo itself never deletes posted invoices"),
        ),
        yourself=_steps(
            "Invoices: {menu:account.menu_action_move_out_invoice_type}.",
            "Download the PDF: open the invoice (Claude gives the link) and click Print.",
            Step("Credit note: open the invoice, click Credit Note, give the reason, click Reverse.", unless="cancel"),
            Step("Reset to draft: open the invoice and click Reset to Draft. Cancel a draft: click Cancel.",
                 unless="cancel"),
            Step("Send by e-mail: open the invoice and click Send.", unless="outbound"),
            "{sales_inbox_step}",
            "Payment reminders (follow-up levels): Accounting → Configuration → Invoicing → Follow-up Levels.",
        ),
        needs=(
            "The customer.",
            "The invoice date.",
            "Each line: product or description, quantity, unit price.",
            "The GST rate for each line.",
            "Place of supply, if the customer is in another state.",
            "Payment terms, if not the usual ones.",
        ),
        related=("payments", "sales", "email", "files", "reports"),
    ),
    "vendor_bills": Topic(
        title="Vendor bills",
        summary="Vendor bills, the bill inbox, and bill PDFs",
        can=(
            Can("Find bills: unpaid, due soon, by vendor.",
                "odoo_search model account.move, move_type in_invoice, payment_state, invoice_date_due"),
            Can("Type a bill in, from what you tell Claude or what Claude reads in a PDF shared here. It is made "
                "as a draft for you to check.",
                "odoo_preview_create model account.move with move_type \"in_invoice\", partner_id, invoice_date, "
                "ref (the vendor's bill number), invoice_line_ids [{\"product_id\" or \"name\", \"quantity\", "
                "\"price_unit\", \"tax_ids\"}]", ("write",)),
            Can("Fill in or correct a draft bill (for example one the bill inbox made).",
                "odoo_preview_update model account.move", ("write",)),
            Can("Move a PDF that is already in Odoo onto the right bill: from a draft bill (such as one the bill "
                "inbox made) or from no record.",
                "find the file (odoo_search ir.attachment: name, res_model, res_id); odoo_preview_update model "
                "ir.attachment, values {\"res_model\": \"account.move\", \"res_id\": <bill id>}; several files to "
                "different bills in one preview with changes. Then name the emptied draft bills for the person "
                "to delete in Odoo", ("write",)),
            Can("Confirm (post) a bill.", "odoo_preview_action model account.move, method action_post", ("write",)),
        ),
        cannot=(
            ("Take a PDF shared in this chat into Odoo", _FILES_WHY),
            ("Upload a bill PDF in Odoo", _FILES_WHY),
            ("Move files off a posted bill, or move PDFs Odoo made itself", "posted entries keep their documents"),
            ("Delete draft bills", "deleting cannot be undone"),
        ),
        yourself=_steps(
            "Bill inbox: forward each vendor PDF as its own e-mail to {bill_inbox}. Odoo makes one draft bill per "
            "e-mail, with the PDF attached.",
            "Or upload it: {menu:account.menu_action_move_in_invoice_type}, click Upload, pick the PDF. Odoo makes a "
            "draft bill.",
            "Put a PDF on a bill you already have: open the bill and drag the PDF onto it, or click the paperclip "
            "beside the messages and pick the file.",
            _DELETE_STEP,
        ),
        needs=(
            "The vendor (name or GSTIN).",
            "The vendor's bill number.",
            "The bill date.",
            "Each line: description or product, quantity, unit price.",
            "The GST rate for each line.",
            "The due date, if not the vendor's usual terms.",
        ),
        related=("files", "payments", "bank", "delete"),
        cases=((
            "A bill PDF shared in this chat",
            (
                "Claude can read the PDF here, but cannot pass the file itself to Odoo. Offer both ways and ask "
                "which one the person wants.",
                "(a) Claude creates the draft bill from what it reads: vendor, bill number, date, lines, GST. "
                "The person checks the preview and approves; the bill stays a draft until they confirm it.",
                "(b) To keep the PDF with the bill: the person forwards it, one PDF per e-mail, to "
                "{bill_inbox_short}, or opens the bill in Odoo and drags the PDF onto it.",
                "After (a) and a forward in (b): Odoo makes a second draft bill with the PDF. Claude finds that "
                "file, moves it onto the bill from (a) in one approval, and names the empty draft bill for the "
                "person to delete in Odoo.",
                "With (b) alone: Odoo makes the draft bill from the PDF; Claude can then check it against the PDF "
                "and fill in what is missing.",
            ),
        ),),
    ),
    "payments": Topic(
        title="Payments",
        summary="Recording payments received and made",
        can=(
            Can("See what is due and what was paid.",
                "odoo_search model account.move on payment_state and amount_residual; model account.payment"),
            Can("Record a payment on a posted invoice or bill, in one approval. Without other values Odoo records "
                "the full amount due, today, in its default bank journal.",
                "odoo_preview_action model account.move, method action_register_payment", ("write",)),
            Can("Record part of the amount, another date or another bank or cash journal. The invoice then shows "
                "as partly paid.",
                "the same, with dialog_values {\"amount\": 5000, \"payment_date\": \"YYYY-MM-DD\", "
                "\"journal_id\": <id>}", ("write",)),
            Can("Reset or cancel a recorded payment.", "the payment's buttons: odoo_list_actions model account.payment",
                ("cancel",)),
        ),
        cannot=(
            ("Move money", "Claude only records payments in Odoo; the money moves in your bank"),
            ("Charge a customer's saved card or account, or capture, void or refund online payments",
             "payment providers move real money"),
            ("Add or change bank account numbers, yours or a vendor's", _BANK_WHY),
        ),
        yourself=_steps(
            "Payments received: {menu:account.menu_action_account_payments_receivable}. Payments made: "
            "{menu:account.menu_action_account_payments_payable}.",
            "Bank accounts of contacts: Contacts → Configuration → Bank Accounts → Bank Accounts.",
            Step("Reset or cancel a payment: open it and click Reset to Draft or Cancel.", unless="cancel"),
        ),
        needs=(
            "Which invoice or bill.",
            "The amount: all of it or part.",
            "The payment date.",
            "The bank or cash account it went through.",
        ),
        related=("invoices", "vendor_bills", "bank"),
    ),
    "bank": Topic(
        title="Bank lines and matching",
        summary="Bank lines, matching, and matching rules",
        can=(
            Can("Find bank lines not yet matched.",
                "odoo_search model account.bank.statement.line with is_reconciled = false"),
            Can("Find the open bill or invoice for each line: same amount, and the same partner or reference.",
                "odoo_search model account.move, state posted, payment_state not_paid or partial"),
            Can("Prepare the matching: set the partner on bank lines so Odoo's bank screen suggests the right bill "
                "or invoice. Then tell you which pairs to confirm there.",
                "one odoo_preview_update model account.bank.statement.line with changes [{\"ids\": [line], "
                "\"values\": {\"partner_id\": id}}, ...]", ("write",)),
            Can("Create or edit bank matching rules (for example, book bank charges to an expense account). A rule "
                "set to Automated books matching lines with nobody checking: keep its conditions narrow.",
                "odoo_preview_create or odoo_preview_update model account.reconcile.model (line_ids for what it "
                "books); say plainly when trigger is \"auto_reconcile\" (Automated)", ("write",)),
            Can("Archive a matching rule.", "odoo_preview_update model account.reconcile.model, values "
                "{\"active\": false}", ("archive",)),
        ),
        cannot=(
            ("Match a bank line with a bill or invoice, or undo a match",
             "matching happens in Odoo's bank screen, where you see both sides before you confirm"),
            ("Connect or change bank feeds (bank sync)", "they hold your bank connection"),
            ("Change bank account details on a journal", _BANK_WHY),
        ),
        yourself=_steps(
            "Matching and undoing a match happen in Odoo's bank screen: {menu:account.menu_board_journal_1}, open "
            "the Bank card.",
            "Bank matching rules are managed from that bank matching screen.",
            "Bank feeds and bank account details are set in Odoo by your Odoo administrator.",
        ),
        needs=(
            "Which bank account.",
            "Which dates, or which lines.",
            "For a line Claude cannot place: who paid (or was paid), and for which invoice or bill.",
        ),
        related=("payments", "vendor_bills", "invoices"),
    ),
    "files": Topic(
        title="Files and PDFs",
        summary="PDFs and other attachments",
        can=(
            Can("See which files are on a record, or on no record.",
                "odoo_search model ir.attachment with res_model and res_id"),
            Can("Move files onto a bill, invoice or journal entry: only from a draft entry or from no record. The "
                "entry then shows the file as its main document.",
                "odoo_preview_update model ir.attachment, values {\"res_model\": \"account.move\", \"res_id\": "
                "<entry id>}; several files to different entries in one preview with changes", ("write",)),
        ),
        cannot=(
            ("Upload a file, including one shared in this chat", _FILES_WHY),
            ("Download, open, rename or delete files", _FILES_WHY),
            ("Move files off posted entries or other kinds of records, or move PDFs Odoo made itself",
             "posted entries keep their documents"),
            ("Change images such as logos or product photos", "Claude never writes files or images"),
        ),
        yourself=_steps(
            "Download: open the record (Claude gives the link) and click the file beside the messages. For an "
            "invoice or quotation PDF, click Print.",
            "Attach a file: open the record and drag the file onto it, or click the paperclip beside the messages.",
            "Bill PDFs: forward each one as its own e-mail to {bill_inbox}.",
            "Delete a file: open the record and remove it from its attachments.",
        ),
        needs=(
            "Which record the file is on now.",
            "The file's name.",
            "Which bill, invoice or entry it should go to.",
        ),
        related=("vendor_bills", "invoices", "delete"),
        cases=((
            "A file shared in this chat",
            (
                "Claude can read it here, but cannot pass the file to Odoo.",
                "For a vendor bill, follow the vendor_bills guide: Claude creates the draft bill from what it reads, "
                "and the person forwards the PDF to {bill_inbox_short} or attaches it in Odoo.",
                "For any other record: the person opens the record in Odoo (Claude gives the link) and drags the "
                "file onto it.",
            ),
        ),),
    ),
    "email": Topic(
        title="E-mail, messages and templates",
        summary="Notes, messages, sending documents, e-mail templates",
        can=(
            Can("Read the messages, notes and e-mails on a record.",
                "odoo_search model mail.message with model and res_id of the record"),
            Can("Show the e-mail templates and what they say.", "odoo_search model mail.template"),
            Can("Log an internal note on a record (nobody is e-mailed).", "odoo_add_note", ("write",)),
            Can("Send a message on a record to its followers (customers too), after you approve the recipients.",
                "odoo_preview_message, then odoo_send_message", ("outbound",)),
            Can("E-mail an invoice with its PDF to the customer.",
                "odoo_preview_action model account.move, method action_invoice_sent", ("outbound",)),
            Can("Change an e-mail template's subject, text, recipients, Cc and Reply-to. It changes every e-mail "
                "sent with that template from now on.",
                "odoo_preview_update model mail.template with subject, body_html, email_to, partner_to, "
                "use_default_to, email_cc or reply_to", ("write",)),
        ),
        cannot=(
            ("Create new e-mail templates, or change a template's sender or attachments",
             "Claude can change only a template's text and recipients"),
            ("Add or remove followers on a record", "Odoo e-mails followers"),
            ("Send a quotation by e-mail", "Odoo's e-mail window for quotations cannot be filled in through Claude"),
            ("Change e-mail inbox addresses (aliases), mass mailing, SMS, WhatsApp or postal mail",
             "they send to many people or change where e-mail goes"),
            ("See or change mail servers", "they hold passwords"),
        ),
        yourself=_steps(
            "E-mail templates: {menu:mail.menu_email_templates}, then New.",
            "Followers: open the record and use the followers button beside the messages.",
            "Send a quotation: open it, click Send.",
            Step("Send an invoice: open it, click Send.", unless="outbound"),
            Step("Message a customer: open the record, click Send message beside the messages.", unless="outbound"),
            "Inbox addresses, mass mailing, SMS and WhatsApp are set up in Odoo by your Odoo administrator.",
        ),
        needs=(
            "Which record or template.",
            "Who should get it.",
            "The text.",
        ),
        related=("invoices", "sales", "automation"),
    ),
    "automation": Topic(
        title="Automation rules",
        summary="Automation rules (no code)",
        can=(
            Can("See the automation rules and what they do.", "odoo_search model base.automation with action_server_ids"),
            Can("Create a rule without code: when a record is created or changed, a stage or user is set, or a date "
                "is reached, then update a field with a fixed value, create an activity, or log a note.",
                "odoo_preview_create model base.automation with name, model_id (ir.model id), trigger, filter_domain "
                "(a plain list of conditions), action_server_ids [{\"name\", \"state\": \"object_write\", "
                "\"next_activity\" or \"mail_post\" with mail_post_method \"note\", ...}]", ("write",)),
            Can("Rules that e-mail people: post a message, send an e-mail template, or add followers.",
                "the same, with state \"mail_post\" or \"followers\"", ("outbound",)),
            Can("Change a rule, one at a time.", "odoo_preview_update model base.automation", ("write",)),
            Can("Switch a rule off or on.", "odoo_preview_update model base.automation, values {\"active\": false}",
                ("archive",)),
        ),
        cannot=(
            ("Run Python code, call web addresses (webhooks), send SMS or WhatsApp, or create or copy records",
             "these can do anything in Odoo or send data outside, with nobody checking"),
            ("Use the triggers on change, on webhook or on delete", "they run code or are started from outside"),
            ("Scheduled actions", "they run code on a timer"),
            ("Change a rule that already contains code", "the code could do anything"),
            ("Rules on setup records, or on records Claude may not change", "a rule may do only what Claude may do"),
        ),
        yourself=_steps(
            "Automation rules: {menu:base_automation.menu_base_automation_form}.",
            "Scheduled actions: {menu:base.menu_ir_cron_act}. They and rules with code are for someone who knows "
            "the code: ask {admin}.",
            DEVELOPER_MODE,
        ),
        needs=(
            "Which records (for example leads or invoices).",
            "When it should run.",
            "What it should do.",
            "Any conditions (for example only above ₹1,00,000).",
        ),
        related=("email", "settings"),
    ),
    "settings": Topic(
        title="Settings, apps and company details",
        summary="App settings, apps and company details",
        can=(
            Can("List the app options and whether Claude may change each one.",
                "odoo_describe_model model res.config.settings, query a word such as \"analytic\""),
            Can("Switch app options on or off, or set their values (for example analytic accounting, units of "
                "measure, quotation validity days). Options that switch a feature apply to everyone.",
                "odoo_preview_create model res.config.settings with only the values to change, odoo_create, then "
                "odoo_preview_action method execute (Save) on the new record", ("write",)),
        ),
        cannot=(
            ("Install or remove apps", "it can raise your Odoo bill and is hard to undo"),
            ("Change company details: name, address, GSTIN, PAN, bank, logo, e-mail, phone",
             "they print on every invoice and GST return"),
            ("Change security, sign-in or audit settings", "they decide who can get in"),
            ("Press other buttons on the settings screen", "they open or install things"),
            ("System parameters, mail servers, e-invoicing certificates", "they hold keys and passwords"),
        ),
        yourself=_steps(
            "Accounting settings: {menu:account.menu_account_config}. All settings: {menu:base.menu_administration}.",
            "Apps: {menu:base.menu_management}.",
            "Company details: {menu:base.menu_action_res_company_form}.",
            DEVELOPER_MODE,
        ),
        needs=(
            "Which option.",
            "On or off, or the new value.",
        ),
        related=("accounting_setup", "users_access", "automation"),
    ),
    "accounting_setup": Topic(
        title="Accounting setup",
        summary="Accounts, taxes, fiscal positions, journals, lock dates",
        can=(
            Can("Show the chart of accounts, taxes, fiscal positions and journals.",
                "odoo_search model account.account, account.tax, account.fiscal.position or account.journal"),
            Can("Create a new account, tax (with its lines), fiscal position or journal. Check with your CA first: "
                "every future entry uses it.",
                "odoo_preview_create model account.account, account.tax, account.fiscal.position or account.journal",
                ("write",)),
            Can("Split invoice and bill lines across analytic accounts.",
                "line value \"analytic_distribution\": {\"<analytic account id>\": percent} (above 0, up to 100)",
                ("write",)),
        ),
        cannot=(
            ("Change or archive existing accounts, taxes, fiscal positions or journals",
             "entries already use them, so a change alters past reports and GST returns"),
            ("Bank details on journals", _BANK_WHY),
            ("Lock dates", "they close a period for everyone"),
            ("Report layouts, payment methods, rounding", "they change every report"),
        ),
        yourself=_steps(
            "Chart of accounts: {menu:account.menu_action_account_form}.",
            "Taxes: {menu:account.menu_action_tax_form}.",
            "Fiscal positions: {menu:account.menu_action_account_fiscal_position_form}.",
            "Journals: {menu:account.menu_action_account_journal_form}.",
            "Lock dates: {menu:account_accountant.menu_action_change_lock_date}.",
            "Check every change to existing setup with your CA first.",
        ),
        needs=(
            "What to create: account, tax, fiscal position or journal.",
            "For an account: name, code, type. For a tax: name, rate, sales or purchases. For a journal: name, "
            "short code, type.",
            "Your CA's go-ahead.",
        ),
        related=("settings", "invoices", "bank"),
    ),
    "users_access": Topic(
        title="Users, access and sign-in",
        summary="Users, access rights, passwords and API keys",
        can=(
            Can("Show who you are signed in as, and what Claude may do here.", "odoo_whoami"),
            Can("Find users by name, for example to set a salesperson.", "odoo_find model res.users"),
        ),
        cannot=(
            ("Create users, or change access rights or groups",
             "they decide who can see and do what, and each user can cost a paid seat"),
            ("Passwords, API keys, two-factor sign-in", "Claude never handles sign-in secrets"),
            ("Do what your own Odoo user may not do", "Claude works with your Odoo access, never more"),
        ),
        yourself=_steps(
            "Users and access rights: {menu:base.menu_action_res_users} (your Odoo administrator does this).",
            "Your API key: click your profile picture (top right) → My Preferences → Security tab → Create API Key "
            "(Account Security and New API Key in older versions).",
            "If Odoo refused because of your access: ask your Odoo administrator to give your user that access, or ask a colleague "
            "who has it to do the step.",
        ),
        needs=(
            "Whose access.",
            "Which app or record.",
            "What they need to do there.",
        ),
        related=("connection", "settings"),
    ),
    "delete": Topic(
        title="Deleting",
        summary="Deleting records",
        can=(
            Can("Find the records to delete and give you their links."),
            Can("Archive instead: the record is hidden and can be brought back.",
                "odoo_preview_update values {\"active\": false}", ("archive",)),
            Can("Cancel a document instead (quotation, invoice, bill).", "its Cancel button (odoo_list_actions)",
                ("cancel",)),
        ),
        cannot=(
            ("Delete anything: records, lines, files, messages",
             "deleting cannot be undone, so only a person does it, in Odoo"),
        ),
        yourself=_steps(
            "One record: open it, click the gear icon (Actions), Delete, confirm.",
            "Several: in the list, tick them, then gear icon (Actions) → Delete.",
            "Odoo does not delete posted invoices or bills: cancel them, or ask your accountant.",
            Step("Archive: open the record, gear icon (Actions) → Archive.", unless="archive"),
        ),
        needs=(
            "Which records: names or numbers.",
            "Whether archiving or cancelling would do instead.",
        ),
        related=("files", "invoices", "contacts"),
    ),
    "reports": Topic(
        title="Reports and totals",
        summary="Totals, lists and official reports",
        can=(
            Can("Totals and breakdowns worked out by Odoo: sales by month, unpaid invoices by customer, spend by "
                "vendor.", "odoo_aggregate (Odoo adds up), odoo_count"),
            Can("Lists: overdue invoices, bills due this week, top customers.", "odoo_search with order and limit"),
        ),
        cannot=(
            ("Make official reports (Profit and Loss, Balance Sheet, GST returns, ledgers)",
             "they are built in Odoo's reporting screens"),
            ("Make files (PDF or Excel)", _FILES_WHY),
        ),
        yourself=_steps(
            "Official reports: {menu:account.menu_finance_reports}, pick the report and the dates; download it "
            "from the report's own buttons.",
        ),
        needs=(
            "Which period.",
            "Which customers, vendors or products.",
            "How to group it: by month, customer, product.",
        ),
        related=("invoices", "vendor_bills", "limits"),
    ),
    "bulk_import": Topic(
        title="Many records at once",
        summary="Many records at once, imports",
        can=(
            Can("Check a list against Odoo before you import it: which records already exist, which names do not "
                "match.", "odoo_find or odoo_search for each name or number"),
            Can("Create or change up to {max_write} records per approval, for example a list you paste here. For "
                "more, Claude works in batches, each with its own approval.",
                "odoo_preview_create with several records; odoo_preview_update with changes", ("write",)),
        ),
        cannot=(
            ("Import a spreadsheet file (CSV or Excel)", _FILES_WHY),
            ("Change more than {max_write} records in one approval", "it limits the harm one mistake can do"),
        ),
        yourself=_steps(
            "Big imports: open the list (for example {menu:contacts.menu_contacts}), click the gear icon next to "
            "the title → Import records, upload the file, match the columns, click Test, then Import.",
        ),
        needs=(
            "Which kind of record.",
            "The data: paste it, or describe it.",
            "For changes: how to find each record (name or number).",
        ),
        related=("limits", "contacts"),
    ),
    "connection": Topic(
        title="Connection and sign-in",
        summary="Signing in, API keys, reconnecting",
        can=(
            Can("Check the connection and who you are signed in as.", "odoo_whoami"),
        ),
        cannot=(
            ("Fix sign-in from inside the chat, or see your API key", "Claude never sees or handles keys"),
        ),
        yourself=_steps(
            "If Claude says Odoo no longer accepts your key: make a new API key (profile picture → My Preferences → "
            "Security tab → Create API Key), then reconnect the Odoo connector in Claude and paste the new key.",
            "Keys of ordinary users last up to 3 months; then make a new one the same way.",
            "If Odoo is busy or down: check that {odoo_url} opens in your browser, wait a minute, try again.",
        ),
        needs=(
            "Does Odoo open in your browser?",
            "The exact message Claude showed.",
        ),
        related=("users_access", "limits"),
    ),
    "limits": Topic(
        title="Limits and approvals",
        summary="How much Claude can do per step, and approvals",
        can=(
            Can("Read up to {max_read} records in one search ({default_read} unless asked for more), and tell you "
                "when there are more."),
            Can("Change up to {max_write} records in one approval.", "", ("write",)),
            Can("{approval_rule}", "", ("write",)),
        ),
        cannot=(
            ("Change more than {max_write} records in one approval", "it limits the harm one mistake can do"),
            ("Use an approval twice, or after {approval_minutes} minutes", "each approval is for one change, now"),
            ("Go faster than {reads_per_minute} reads and {writes_per_minute} changes a minute per person",
             "{pace_reason}"),
            ("Do more than your own Odoo user may do", "Odoo's own access rights always apply"),
        ),
        yourself=_steps(
            "Bigger jobs: split them into batches, or import a file in Odoo (odoo_help topic bulk_import).",
        ),
        needs=(
            "How many records the job covers, so Claude can plan the batches.",
        ),
        related=("bulk_import", "overview"),
    ),
}
TOPIC_NAMES: tuple[str, ...] = tuple(TOPICS)
_ALIASES = {
    "help": "overview", "general": "overview", "contact": "contacts", "customers": "contacts", "vendors": "contacts",
    "leads": "crm", "lead": "crm", "pipeline": "crm", "sale": "sales", "quotations": "sales", "orders": "sales",
    "invoice": "invoices", "credit_notes": "invoices", "bills": "vendor_bills", "bill": "vendor_bills",
    "purchases": "vendor_bills", "payment": "payments", "reconciliation": "bank", "file": "files",
    "attachments": "files", "pdf": "files", "mail": "email", "messages": "email", "templates": "email",
    "automations": "automation", "setup": "accounting_setup", "taxes": "accounting_setup", "users": "users_access",
    "access": "users_access", "deleting": "delete", "report": "reports", "import": "bulk_import",
    "sign_in": "connection", "api_key": "connection",
}

HOW_TO_GUIDE = (
    "Tell the person what Claude can do here (and offer it), what it cannot do and why in one line, and the steps "
    "under 'yourself' for the rest. Ask for the 'needs' one at a time, in order, skipping what you already know. "
    "Give the record links."
)


def topic_name(topic: str | None) -> str | None:
    """The topic a name means (case, spaces and a few synonyms forgiven), or None when there is no such topic."""
    if topic is None or not str(topic).strip():
        return "overview"
    key = re.sub(r"[\s\-]+", "_", str(topic).strip().lower())
    return key if key in TOPICS else _ALIASES.get(key)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_PLACEHOLDER = re.compile(r"\{(menu:)?([a-z_][a-z0-9_.]*)\}")


class _Writer:
    def __init__(self, settings: Settings, facts: Facts):
        self.settings = settings
        self.facts = facts
        self.admin = settings.mcp_admin_contact.strip() or "your Odoo admin"
        self.not_in_menus: list[str] = []
        self.used_menus = False

    def on(self, switch: str) -> bool:
        s = self.settings
        if not s.read_write:
            return False
        return {
            "write": True, "archive": s.mcp_allow_archive, "cancel": s.mcp_allow_cancel_actions,
            "outbound": s.mcp_allow_outbound_messages,
        }[switch]

    def text(self, template: str) -> str:
        return _PLACEHOLDER.sub(self._fill, template)

    def _fill(self, match: re.Match) -> str:
        if match.group(1):
            return self.menu(match.group(2))
        return self.text(self.value(match.group(2)))

    def menu(self, xmlid: str) -> str:
        fallback, technical = MENUS[xmlid]
        self.used_menus = True
        menus = self.facts.menus
        path = (menus or {}).get(xmlid)
        if not path:
            path = fallback
            # technical menus are only listed in developer mode, so their absence says nothing about access
            if menus is not None and not technical and fallback not in self.not_in_menus:
                self.not_in_menus.append(fallback)
        return f"{path} (developer mode)" if technical else path

    def value(self, key: str) -> str:
        s = self.settings
        values = {
            "admin": self.admin,
            "odoo_url": self.facts.odoo_url or s.odoo_url,
            "max_read": str(s.mcp_max_read_records),
            "default_read": str(s.mcp_default_read_limit),
            "max_write": str(s.mcp_max_write_records),
            "reads_per_minute": str(s.mcp_reads_per_minute),
            "writes_per_minute": str(s.mcp_writes_per_minute),
            "approval_minutes": str(DEFAULT_TTL_SECONDS // 60),
            "pace_reason": (
                "it keeps runaway loops in check, and Odoo is asked one thing at a time (Odoo Online's fair-use rule)"
                if s.odoo_max_parallel_requests == 1 else "it keeps runaway loops in check"
            ),
            "approval_rule": (
                "Show every change as a preview first and make it only after your yes. One approval makes one "
                "change, within {approval_minutes} minutes."
                if s.mcp_require_preview else
                "Ask before each change. Previews are optional on this connection, but Claude shows one when it "
                "helps; e-mails always need your approved preview."
            ),
        }
        if key == "bill_inbox":
            return self.bill_inbox()
        if key == "bill_inbox_short":
            return " or ".join(self.facts.bill_inboxes()) or "the bill inbox (see 'yourself' for where it is set)"
        if key == "sales_inbox_step":
            return self.sales_inbox_step()
        return values[key]  # a KeyError here is a typo in the guide (the tests render every topic)

    def bill_inbox(self) -> str:
        addresses = self.facts.bill_inboxes()
        if addresses:
            return " or ".join(addresses)
        named = [box.name for box in self.facts.inboxes or () if box.kind == "purchase" and box.name]
        where = (
            "{menu:account.menu_action_account_journal_form}, open the purchases journal, Advanced Settings tab, "
            "Email Alias"
        )
        if named:
            return (
                f"the bill inbox of your purchases journal (Odoo has the inbox name '{named[0]}' but no e-mail "
                f"domain, so e-mails cannot reach it yet; your Odoo administrator can set it up: {where}, Configure Alias Domain)"
            )
        return f"the bill inbox address of your purchases journal ({where}; if it is empty, ask your Odoo administrator)"

    def sales_inbox_step(self) -> str:
        addresses = [box.email for box in self.facts.inboxes or () if box.kind == "sale" and box.email]
        if not addresses:
            return ""
        return (
            f"Invoices made outside Odoo: e-mail each one to {' or '.join(addresses)}; Odoo makes a draft customer "
            "invoice from it."
        )


def render(topic: str | None, settings: Settings, facts: Facts | None = None) -> dict:
    """One topic of the guide, as odoo_help shows it, with this connection's switches and the facts filled in."""
    name = topic_name(topic)
    if name is None:
        raise ValidationFailed(f"there is no help topic '{topic}'. Topics: {', '.join(TOPIC_NAMES)}")
    writer = _Writer(settings, facts or Facts())
    entry = TOPICS[name]
    can: list[str] = []
    switched_off: dict[str, list[str]] = {}
    for item in entry.can:
        off = next((switch for switch in ("write", *item.needs) if item.needs and not writer.on(switch)), None)
        if off is None:
            can.append(writer.text(f"{item.text} How: {item.how}." if item.how else item.text))
        else:
            what = writer.text(item.text).split(". ")[0].rstrip(".")
            if off in switched_off:  # joined into one sentence: "Make a credit note; reset ..."
                what = what[:1].lower() + what[1:]
            switched_off.setdefault(off, []).append(what)
    cannot = [
        writer.text(
            f"{'; '.join(items)}. Why: {_OFF[off]}. Ask {{admin}} to switch it on, or do it in Odoo (see 'yourself')."
        )
        for off, items in switched_off.items()
    ]
    cannot.extend(writer.text(f"{what}. Why: {why}.") for what, why in entry.cannot)
    yourself = [
        writer.text(step.text) for step in entry.yourself
        if not step.unless or not all(writer.on(switch) for switch in step.unless.split(","))
    ]
    yourself = [line for line in yourself if line]
    result: dict[str, Any] = {
        "topic": name,
        "title": entry.title,
        "can": can,
        "cannot": cannot,
        "yourself": yourself,
        "needs": [writer.text(line) for line in entry.needs],
    }
    if entry.cases:
        result["cases"] = {title: [writer.text(line) for line in lines] for title, lines in entry.cases}
    if writer.not_in_menus:
        result["yourself"].append(writer.text(
            f"Not in your Odoo menus: {'; '.join(writer.not_in_menus)}. Your user may not have access, or the app "
            "is not installed: ask your Odoo administrator."
        ))
    if writer.used_menus and (facts is None or facts.menus is None):
        result["yourself"].append("Menu names are Odoo's usual ones; yours may differ slightly.")
    result["related"] = [hint_call(other) for other in entry.related]
    if name == "overview":
        result["topics"] = {key: value.summary for key, value in TOPICS.items() if key != "overview"}
    result["how_to_guide"] = HOW_TO_GUIDE
    return result


# ---------------------------------------------------------------------------
# Refusals → topics
# ---------------------------------------------------------------------------

def hint_call(topic: str) -> str:
    return f'odoo_help(topic="{topic}")'


def hint(topic: str) -> str:
    """What every refusal ends with: the guide that tells the person how to do it themselves."""
    return f"To guide the person: {hint_call(topic)}"


# Which area a model belongs to; the longest matching prefix wins. Models of no listed area: overview.
MODEL_TOPICS: dict[str, str] = {
    "res.partner": "contacts", "base.partner.merge": "contacts", "data_merge.": "contacts", "data_cleaning.": "contacts",
    "res.partner.bank": "payments",
    "crm.": "crm", "crm.lead": "crm", "iap": "crm", "iap.": "crm",
    "sale.": "sales", "sale.order": "sales",
    "account.move": "invoices",
    "account.payment": "payments", "payment.": "payments",
    "account.bank.statement": "bank", "account.online.": "bank", "account.reconcile.model": "bank",
    "account.": "accounting_setup", "account.change.lock.date": "accounting_setup",
    "account.lock_exception": "accounting_setup", "decimal.precision": "accounting_setup",
    "res.currency": "accounting_setup",
    "ir.attachment": "files",
    "mail.": "email", "mailing.": "email", "sms.": "email", "whatsapp.": "email", "snailmail.": "email",
    "digest.": "email", "fetchmail": "email", "ir.mail_server": "email", "sign.": "email", "survey.invite": "email",
    "portal.share": "email", "appointment.invite": "email", "project.collaborator": "email",
    "base.automation": "automation", "ir.actions.server": "automation", "ir.cron": "automation",
    "res.config": "settings", "ir.config_parameter": "settings", "ir.module": "settings", "base.module": "settings",
    "res.company": "settings", "certificate.": "settings", "ir.": "settings", "base.": "settings",
    "res.lang": "settings", "res.country": "settings",
    "res.users": "users_access", "res.groups": "users_access", "auth": "users_access",
    "change.password": "users_access", "portal.wizard": "users_access", "res.device": "users_access",
    "res.session": "users_access", "ir.model.access": "users_access", "ir.rule": "users_access",
    "ir.access": "users_access",
    "base_import.": "bulk_import",
}
_BY_LENGTH = sorted(MODEL_TOPICS, key=len, reverse=True)


def topic_for_model(model: str | None) -> str:
    if isinstance(model, str):
        for prefix in _BY_LENGTH:
            if model == prefix.rstrip(".") or model.startswith(prefix):
                return MODEL_TOPICS[prefix]
    return "overview"


def _bank_or_payments(model: str | None) -> str:
    return "bank" if topic_for_model(model) in ("bank", "accounting_setup") else "payments"


def _credits(model: str | None) -> str:
    return "payments" if topic_for_model(model) == "payments" else "crm"


def _setup(model: str | None) -> str:
    return "bank" if topic_for_model(model) == "bank" else "accounting_setup"  # bank matching rules


def _email(model: str | None) -> str:
    return "automation" if topic_for_model(model) == "automation" else "email"  # an automation rule that e-mails


# What a refusal is about, from its text (lower-cased); the first match wins. Refusals that only say something
# is switched off or protected fall through to the area of the model they were about.
TEXT_RULES: tuple[tuple[str, Any], ...] = (
    (r"too many records at once|the limit per change is", "bulk_import"),
    (r"automation rule|server actions can be added", "automation"),  # before delete: "runs when records are deleted"
    (r"\bdelet|removing lines", "delete"),
    (r"company's identity|security, sign-in or audit|install or remove an app|installs or removes an odoo app|"
     r"methods containing 'install'|that '(module|modules|upgrade)' data|settings are changed by|settings screen",
     "settings"),
    (r"saved card|methods containing '(capture|void|payout|payment_action|transaction|trust)'", "payments"),
    (r"bank details", _bank_or_payments),
    (r"lock date", "accounting_setup"),
    (r"methods containing '(password|apikey|api_key|totp|passkey|impersonate|signup|create_user)'", "users_access"),
    (r"methods containing 'hash'", "invoices"),
    (r"methods containing '(iap|generate_leads)'|paid odoo credits", _credits),
    (r"that '(load|import)' data", "bulk_import"),
    (r"that 'merge' data", "contacts"),
    (r"files cannot be uploaded|buttons on files|file can only be moved|is a (binary|image) field|it cannot be moved|"
     r"files on posted|only files on draft", "files"),
    (r"e-mail template", "email"),
    (r"e-mails|e-mail or message|messages to people|adds followers", _email),
    (r"accounting setup|past reports and gst returns", _setup),
    (r"odoo's access rights", "users_access"),
)
# A ValidationFailed is a refusal (not a typo in a field name, say) when one of its problems says one of these.
_REFUSAL_MARKERS = re.compile(
    r"switched off|through claude|claude never|never writes|for safety|blocked|credential or secret|bank details|"
    r"odoo app|company's identity|sign-in or audit|is not allowed|not allowed through|may not do|can be written only|"
    r"can be set only when|workflow status|too many records at once|can only be moved|cannot be moved|files on posted|"
    r"only files on draft|fixed value|may update only"
)


def topic_for_refusal(text: str, model: str | None = None) -> str:
    """The guide topic for a refusal's text, about records of model (None when not about a model)."""
    low = text.lower()
    for pattern, topic in TEXT_RULES:
        if re.search(pattern, low):
            return topic(model) if callable(topic) else topic
    return topic_for_model(model)


def refusal_topic(exc: BaseException, model: str | None = None) -> str | None:
    """The guide topic for an error a tool returns, or None when it is not a refusal (a typo, Odoo busy, ...)."""
    if isinstance(exc, OdooError):
        if exc.kind == "auth":
            return "connection"
        return "users_access" if exc.kind == "access" else None
    if isinstance(exc, RateLimited):
        return "limits"
    if isinstance(exc, PolicyViolation):
        return topic_for_refusal(exc.describe(), model)
    if isinstance(exc, ValidationFailed):
        text = exc.describe()
        return topic_for_refusal(text, model) if _REFUSAL_MARKERS.search(text.lower()) else None
    return None
