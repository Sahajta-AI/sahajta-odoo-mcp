"""Edits to accounting setup already in Odoo, and removing lines from draft documents.

Odoo is the in-memory FakeOdoo with Odoo 19 shapes: the fiscal position tax mapping lives on the replacement tax
(fiscal_position_ids / original_tax_ids, the fiscal position's tax_ids), account mappings are
account.fiscal.position.account lines.
"""

from __future__ import annotations

import pytest

from conftest import AUDIT_FIELDS, FakeOdoo, _f, add_setup_models
from sahajta_odoo_mcp.errors import ConfirmationRequired, PolicyViolation, ValidationFailed
from test_service_offline import changes, make_service

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

STATES = [["draft", "Draft"], ["posted", "Posted"], ["cancel", "Cancelled"]]


def odoo19(fake: FakeOdoo) -> FakeOdoo:
    add_setup_models(fake)
    s, r = fake.schema, fake.records
    s["account.account"].update({
        "tag_ids": _f("many2many", "Tags", relation="account.account.tag"),
        "active": _f("boolean", "Active"),
        "used": _f("boolean", "Used", readonly=True, store=False),
        "reconcile": _f("boolean", "Allow Reconciliation"),
        "currency_id": _f("many2one", "Account Currency", relation="res.currency"),
    })
    s["account.account.tag"] = {"name": _f("char", "Tag Name"), "applicability": _f(
        "selection", "Applicability", selection=[["accounts", "Accounts"], ["taxes", "Taxes"], ["products", "Products"]])}
    s["account.tax"].update({
        "description": _f("html", "Description"),
        "invoice_label": _f("char", "Label on Invoices"),
        "amount_type": _f("selection", "Tax Computation", selection=[["percent", "Percentage"], ["fixed", "Fixed"]]),
        "fiscal_position_ids": _f("many2many", "Fiscal Positions", relation="account.fiscal.position"),
        "original_tax_ids": _f("many2many", "Replaces", relation="account.tax"),
    })
    s["account.fiscal.position"] = {
        **AUDIT_FIELDS,
        "name": _f("char", "Fiscal Position", required=True),
        "active": _f("boolean", "Active"),
        "auto_apply": _f("boolean", "Detect Automatically"),
        "vat_required": _f("boolean", "VAT required"),
        "country_id": _f("many2one", "Country", relation="res.country"),
        "foreign_vat": _f("char", "Foreign Tax ID"),
        "note": _f("html", "Notes"),
        "tax_ids": _f("many2many", "Taxes", relation="account.tax"),
        "account_ids": _f("one2many", "Account Mapping", relation="account.fiscal.position.account",
                          relation_field="position_id"),
    }
    s["account.fiscal.position.account"] = {
        **AUDIT_FIELDS,
        "position_id": _f("many2one", "Fiscal Position", relation="account.fiscal.position", required=True),
        "account_src_id": _f("many2one", "Account on Product", relation="account.account", required=True),
        "account_dest_id": _f("many2one", "Account to Use Instead", relation="account.account", required=True),
    }
    s["account.journal"].update({
        "show_on_dashboard": _f("boolean", "Show journal on dashboard"),
        "color": _f("integer", "Color Index"),
        "sequence": _f("integer", "Sequence"),
        "default_account_id": _f("many2one", "Default Account", relation="account.account"),
        "active": _f("boolean", "Active"),
    })
    s["account.move"].update({
        "name": _f("char", "Number"),
        "state": _f("selection", "Status", selection=STATES, readonly=True),
        "posted_before": _f("boolean", "Posted Before", readonly=True),
        "amount_total": _f("monetary", "Total", readonly=True),
        "invoice_line_ids": _f("one2many", "Invoice lines", relation="account.move.line", relation_field="move_id"),
    })
    s["account.move.line"].update({
        "move_id": _f("many2one", "Journal Entry", relation="account.move", required=True),
        "product_id": _f("many2one", "Product", relation="product.product"),
        "quantity": _f("float", "Quantity"),
        "price_unit": _f("float", "Unit Price"),
        "price_subtotal": _f("monetary", "Subtotal", readonly=True),
    })
    s["sale.order.line"]["price_subtotal"] = _f("monetary", "Subtotal", readonly=True)
    s["purchase.order"] = {
        **AUDIT_FIELDS,
        "name": _f("char", "Order Reference", required=True),
        "state": _f("selection", "Status", readonly=True, selection=[
            ["draft", "RFQ"], ["sent", "RFQ Sent"], ["to approve", "To Approve"], ["purchase", "Purchase Order"],
            ["cancel", "Cancelled"]]),
        "order_line": _f("one2many", "Order Lines", relation="purchase.order.line", relation_field="order_id"),
    }
    s["purchase.order.line"] = {
        **AUDIT_FIELDS,
        "order_id": _f("many2one", "Order Reference", relation="purchase.order", required=True),
        "name": _f("text", "Description"),
        "product_qty": _f("float", "Quantity"),
        "price_subtotal": _f("monetary", "Subtotal", readonly=True),
    }
    s["res.currency"] = {"name": _f("char", "Currency")}
    s["res.partner"]["child_ids"] = _f("one2many", "Contacts", relation="res.partner", relation_field="parent_id")
    for model, rows in {
        "account.account": {50: {"name": "Sales", "code": "400000", "active": True},
                            51: {"name": "Export Sales", "code": "400100", "active": True},
                            52: {"name": "Old spare", "code": "999900", "active": True}},
        "account.account.tag": {1: {"name": "Operating Activities", "applicability": "accounts"},
                                9: {"name": "+GST 18% base", "applicability": "taxes"}},
        "account.tax": {1: {"name": "GST 18%", "amount": 18.0, "active": True, "fiscal_position_ids": [1]},
                        2: {"name": "IGST 18%", "amount": 18.0, "active": True, "fiscal_position_ids": [2],
                            "original_tax_ids": [1]}},
        "account.fiscal.position": {1: {"name": "Intra State", "tax_ids": [1], "account_ids": []},
                                    2: {"name": "Inter State", "tax_ids": [2], "account_ids": [80]}},
        "account.fiscal.position.account": {80: {"position_id": [2, "Inter State"], "account_src_id": [50, "Sales"],
                                                 "account_dest_id": [51, "Export Sales"]}},
        "account.journal": {60: {"name": "Customer Invoices", "code": "INV", "type": "sale", "sequence": 5}},
        "account.move": {
            70: {"name": False, "state": "draft", "posted_before": False, "invoice_line_ids": [701, 702]},
            71: {"name": "BILL/2026/10/0007", "state": "posted", "posted_before": True, "invoice_line_ids": [711]},
        },
        "account.move.line": {
            701: {"name": "Paper", "move_id": [70, "Draft Bill"], "quantity": 3.0, "price_unit": 100.0, "price_subtotal": 300.0},
            702: {"name": "Toner", "move_id": [70, "Draft Bill"], "quantity": 1.0, "price_unit": 250.0, "price_subtotal": 250.0},
            711: {"name": "Rent", "move_id": [71, "BILL/2026/10/0007"], "quantity": 1.0, "price_unit": 900.0},
        },
        "purchase.order": {30: {"name": "P00030", "state": "draft", "order_line": [301]},
                           31: {"name": "P00031", "state": "purchase", "order_line": [311]}},
        "purchase.order.line": {301: {"name": "Chairs", "order_id": [30, "P00030"], "product_qty": 4.0, "price_subtotal": 400.0},
                                311: {"name": "Desks", "order_id": [31, "P00031"], "product_qty": 2.0}},
    }.items():
        for rid, row in rows.items():
            row.setdefault("write_date", "2026-10-15 10:00:00")
            r.setdefault(model, {})[rid] = row
    r["sale.order.line"][50]["price_subtotal"] = 100.0
    r["sale.order.line"][50]["name"] = "Licence, 1 year"
    return fake


def journal_items_on(fake: FakeOdoo, *account_ids: int) -> set[int]:
    """Accounts that have journal items, as Odoo's 'used' search reports them (add to the set returned later)."""
    used = set(account_ids)
    plain = fake._m_search

    def search(model, ids, context, domain=None, **kw):
        found = plain(model, ids, context, domain=domain, **kw)
        if model == "account.account" and any(isinstance(t, list) and t[0] == "used" for t in domain or []):
            return [i for i in found if i in used]
        return found

    fake._m_search = search
    return used


@pytest.fixture
def fake() -> FakeOdoo:
    return odoo19(FakeOdoo())


@pytest.fixture
def svc(fake):
    return make_service(fake, mcp_allow_archive=True)


async def apply(svc, model, ids, values):
    preview = await svc.preview_update(model, ids, values, None)
    await svc.update(model, ids, values, None, preview["confirm_token"])
    return preview


# ====================================================================================== 1. accounts


async def test_an_account_is_renamed_and_tagged_for_the_cash_flow_report(svc, fake):
    values = {"name": "Sales India", "tag_ids": [[4, 1]]}
    preview = await apply(svc, "account.account", [50], values)
    assert "also in reports for past periods" in str(preview["warnings"]) and "cash flow" in str(preview["warnings"])
    [write] = fake.calls_to("write")
    assert write.model == "account.account" and write.kwargs["vals"] == {"name": "Sales India", "tag_ids": [[4, 1, 0]]}


async def test_an_account_takes_only_account_tags(svc, fake):
    with pytest.raises(ValidationFailed, match="not an account tag"):
        await svc.preview_update("account.account", [50], {"tag_ids": [[4, 9]]}, None)
    assert changes(fake) == []


@pytest.mark.parametrize("values", [{"code": "400001"}, {"account_type": "expense"}, {"currency_id": 1},
                                    {"reconcile": True}])
async def test_an_accounts_code_type_currency_and_reconcile_stay(svc, fake, values):
    with pytest.raises(ValidationFailed, match="past reports and GST returns"):
        await svc.preview_update("account.account", [50], values, None)


async def test_an_account_with_journal_items_is_never_archived(svc, fake):
    journal_items_on(fake, 50)
    with pytest.raises(PolicyViolation, match="Sales already has journal items"):
        await svc.preview_update("account.account", [50, 52], {"active": False}, None)
    assert changes(fake) == []


async def test_an_account_without_journal_items_is_archived(svc, fake):
    journal_items_on(fake, 50)
    preview = await apply(svc, "account.account", [52], {"active": False})
    assert "no journal items" in str(preview["warnings"])
    assert fake.records["account.account"][52]["active"] is False


async def test_journal_items_booked_after_the_preview_stop_the_archiving(svc, fake):
    used = journal_items_on(fake)
    preview = await svc.preview_update("account.account", [52], {"active": False}, None)
    used.add(52)  # someone books on it in Odoo before the person approves
    with pytest.raises(PolicyViolation, match="already has journal items") as info:
        await svc.update("account.account", [52], {"active": False}, None, preview["confirm_token"])
    assert "Nothing was changed" in str(info.value) and changes(fake) == []


async def test_archiving_setup_still_needs_the_archive_switch(fake):
    svc = make_service(fake, mcp_allow_archive=False)
    for model, rid in (("account.account", 52), ("account.tax", 1)):
        with pytest.raises(ValidationFailed, match="archiving is switched off"):
            await svc.preview_update(model, [rid], {"active": False}, None)


# ====================================================================================== 2. taxes and fiscal positions


async def test_a_tax_is_switched_off_and_on_and_the_preview_says_what_it_affects(svc, fake):
    off = await apply(svc, "account.tax", [1], {"active": False})
    assert "stop adding it to new lines" in str(off["warnings"]) and "GST returns do not change" in str(off["warnings"])
    on = await apply(svc, "account.tax", [1], {"active": True})
    assert "use it again" in str(on["warnings"])
    assert [c.kwargs["vals"] for c in fake.calls_to("write")] == [{"active": False}, {"active": True}]


async def test_a_taxs_texts_change(svc, fake):
    await apply(svc, "account.tax", [1], {"name": "GST 18% (goods)", "invoice_label": "GST 18%", "description": "<p>x</p>"})
    assert fake.records["account.tax"][1]["invoice_label"] == "GST 18%"


@pytest.mark.parametrize(
    "values",
    [{"amount": 12.0}, {"amount_type": "fixed"}, {"type_tax_use": "purchase"}, {"tax_group_id": 1},
     {"invoice_repartition_line_ids": [{"repartition_type": "base", "document_type": "invoice", "factor_percent": 100}]}],
)
async def test_a_taxs_rate_computation_accounts_and_group_stay(svc, fake, values):
    with pytest.raises(ValidationFailed, match="past reports and GST returns"):
        await svc.preview_update("account.tax", [1], values, None)
    assert changes(fake) == []


async def test_the_fiscal_position_tax_mapping_is_edited_on_either_side(svc, fake):
    # Odoo 19: IGST replaces GST under "Inter State" = IGST is in the position's taxes and IGST "Replaces" GST
    preview = await apply(svc, "account.fiscal.position", [2], {"tax_ids": [[3, 2], [4, 1]]})
    assert "only to new documents" in str(preview["warnings"])
    # in Odoo 19 linking a tax to a fiscal position also decides where the tax is offered
    assert "offered on new documents only under that fiscal position" in str(preview["warnings"])
    preview = await apply(svc, "account.tax", [2], {"original_tax_ids": [[6, 0, [1]]], "fiscal_position_ids": [[4, 2]]})
    assert "which tax replaces which" in str(preview["warnings"])
    assert "offered on new documents only under that fiscal position" in str(preview["warnings"])
    renamed = await apply(svc, "account.fiscal.position", [2], {"name": "Inter State"})
    assert "offered on new documents" not in str(renamed["warnings"])


async def test_fiscal_position_rules_and_account_mappings_are_edited(svc, fake):
    values = {"name": "Inter State (IGST)", "auto_apply": True, "country_id": 104, "vat_required": True,
              "account_ids": [[0, 0, {"account_src_id": 51, "account_dest_id": 50}], [1, 80, {"account_dest_id": 52}]]}
    preview = await apply(svc, "account.fiscal.position", [2], values)
    assert "keep their taxes and accounts" in str(preview["warnings"])
    sent = fake.calls_to("write")[0].kwargs["vals"]["account_ids"]
    assert sent == [[0, 0, {"account_src_id": 51, "account_dest_id": 50}], [1, 80, {"account_dest_id": 52}]]


async def test_an_account_mapping_line_is_not_removed_and_other_fields_stay(svc, fake):
    with pytest.raises(ValidationFailed, match="delete or detach"):
        await svc.preview_update("account.fiscal.position", [2], {"account_ids": [[2, 80, 0]]}, None)
    for values in ({"foreign_vat": "29ABCDE1234F1Z5"}, {"note": "x"}, {"active": False}):
        with pytest.raises(ValidationFailed, match="past reports and GST returns"):
            await svc.preview_update("account.fiscal.position", [2], values, None)
    assert changes(fake) == []


# ====================================================================================== 3. journals


async def test_a_journal_is_renamed_and_reordered(svc, fake):
    preview = await apply(svc, "account.journal", [60], {"name": "Sales India", "sequence": 1, "color": 3,
                                                           "show_on_dashboard": False})
    assert "numbers do not change" in str(preview["warnings"])


@pytest.mark.parametrize("values", [{"code": "SAL"}, {"type": "general"}, {"default_account_id": 51}, {"active": False}])
async def test_a_journals_code_type_and_accounts_stay(svc, fake, values):
    with pytest.raises(ValidationFailed, match="past reports and GST returns"):
        await svc.preview_update("account.journal", [60], values, None)


async def test_creating_setup_is_not_limited_by_the_edit_list(svc, fake):
    preview = await svc.preview_create("account.journal", [{"name": "HDFC", "code": "HDFC", "type": "bank"}], None)
    assert "Check the tax setup with your CA" in str(preview["warnings"])


async def test_no_dialog_acts_on_existing_setup(svc, fake):
    with pytest.raises(PolicyViolation, match="dialogs cannot act on taxes"):
        await svc.preview_create("crm.lead", [{"name": "x", "type": "lead"}], {"active_model": "account.tax", "active_ids": [1]})


# ====================================================================================== 4. removing lines


async def test_a_line_is_removed_from_a_quotation_and_the_preview_names_it(svc, fake):
    values = {"order_line": [[2, 50, 0]]}
    preview = await svc.preview_update("sale.order", [5], values, None)
    [removed] = preview["changes"][0]["new"]["Order Lines (order_line)"]
    assert removed == {"remove line (deleted)": {"id": 50, "line": "Licence, 1 year", "product": "Licence",
                                                 "quantity": 1.0, "unit_price": "100.00", "amount": "100.00"}}
    await svc.update("sale.order", [5], values, None, preview["confirm_token"])
    assert fake.calls_to("write")[0].kwargs["vals"] == {"order_line": [[2, 50, 0]]}


async def test_a_sent_quotation_and_a_draft_rfq_lose_lines_too(svc, fake):
    fake.records["sale.order"][5]["state"] = "sent"
    await apply(svc, "sale.order", [5], {"order_line": [[2, 51, 0]]})
    await apply(svc, "purchase.order", [30], {"order_line": [[2, 301, 0]]})
    assert [c.kwargs["vals"] for c in fake.calls_to("write")] == [{"order_line": [[2, 51, 0]]}, {"order_line": [[2, 301, 0]]}]


@pytest.mark.parametrize("state", ["sale", "cancel"])
async def test_no_line_is_removed_from_a_confirmed_or_cancelled_order(svc, fake, state):
    fake.records["sale.order"][5]["state"] = state
    with pytest.raises(PolicyViolation, match="Set the line's quantity to 0 instead"):
        await svc.preview_update("sale.order", [5], {"order_line": [[2, 50, 0]]}, None)
    with pytest.raises(PolicyViolation, match="quantity to 0"):
        await svc.preview_update("purchase.order", [31], {"order_line": [[2, 311, 0]]}, None)
    assert changes(fake) == []


async def test_an_order_confirmed_after_the_preview_keeps_its_lines(svc, fake):
    preview = await svc.preview_update("sale.order", [5], {"order_line": [[2, 50, 0]]}, None)
    fake.touch("sale.order", 5, state="sale")
    with pytest.raises(PolicyViolation, match="not a quotation") as info:
        await svc.update("sale.order", [5], {"order_line": [[2, 50, 0]]}, None, preview["confirm_token"])
    assert "Nothing was changed" in str(info.value) and changes(fake) == []


async def test_a_line_changed_after_the_preview_voids_the_approval(svc, fake):
    preview = await svc.preview_update("sale.order", [5], {"order_line": [[2, 50, 0]]}, None)
    fake.touch("sale.order.line", 50, product_uom_qty=7.0)  # the person approved removing 1 licence, not 7
    with pytest.raises(ConfirmationRequired, match="modified in Odoo since the preview"):
        await svc.update("sale.order", [5], {"order_line": [[2, 50, 0]]}, None, preview["confirm_token"])
    assert changes(fake) == []


async def test_a_line_is_removed_from_a_draft_bill_but_never_from_a_posted_one(svc, fake):
    preview = await apply(svc, "account.move", [70], {"invoice_line_ids": [[2, 702, 0]]})
    [removed] = preview["changes"][0]["new"]["Invoice lines (invoice_line_ids)"]
    assert removed["remove line (deleted)"]["line"] == "Toner" and removed["remove line (deleted)"]["amount"] == "250.00"
    with pytest.raises(PolicyViolation, match="Reset it to draft first"):
        await svc.preview_update("account.move", [71], {"invoice_line_ids": [[2, 711, 0]]}, None)
    assert [c.kwargs["vals"] for c in fake.calls_to("write")] == [{"invoice_line_ids": [[2, 702, 0]]}]


async def test_removing_lines_stays_narrow(svc, fake):
    for model, rid, values, needle in [
        ("sale.order", 5, {"order_line": [[2, 60, 0]]}, "does not belong"),  # a line of another order
        ("sale.order", 5, {"order_line": [[2, 50, 0], [1, 50, {"price_unit": 1.0}]]}, "listed twice"),
        ("sale.order", 5, {"order_line": [[5, 0, 0]]}, "detach or replace"),
        ("res.partner", 1, {"child_ids": [[2, 2, 0]]}, "delete or detach"),  # any other one2many: today's rule
        ("account.move", 70, {"line_ids": [[2, 701, 0]]}, "is not a field"),  # only invoice_line_ids
    ]:
        with pytest.raises(ValidationFailed, match=needle):
            await svc.preview_update(model, [rid], values, None)
    with pytest.raises(ValidationFailed, match="only be removed from an existing record"):
        await svc.preview_create("sale.order", [{"partner_id": 1, "order_line": [[2, 50, 0]]}], None)
    assert changes(fake) == []
