"""Bank matching, undoing a match, the tax lock date and correcting a posted bill (accounting.py).

The FakeOdoo below acts like Odoo 19's bank screen methods as they behaved on a copy of the real database: matching
replaces the bank line's suspense item with one matched item per open item, an edit writes the bank line's items
anew, and changing a matched bill's total makes Odoo drop the bank match.
"""

from __future__ import annotations

import copy

import pytest
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from conftest import AUDIT_FIELDS, FakeOdoo, _f
from sahajta_odoo_mcp import accounting
from sahajta_odoo_mcp import service as service_module
from sahajta_odoo_mcp.errors import OdooError, OdooMCPError, PolicyViolation, ValidationFailed
from sahajta_odoo_mcp.odoo_client import OdooClient, OdooCredentials
from sahajta_odoo_mcp.tools import register_tools
from test_service_offline import make_service, make_shared

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

BANK, MOVE, LINE, WIZARD = "account.bank.statement.line", "account.move", "account.move.line", "account.change.lock.date"
NOTHING, MAYBE = "nothing was changed", "may already have applied"
BANK_METHODS = {"set_line_bank_statement_line", "edit_reconcile_line", "set_account_bank_statement_line",
                "undo_bank_match", "button_draft", "action_post", "change_lock_date"}

SCHEMA = {
    BANK: {**AUDIT_FIELDS, **{n: _f(t, n, relation=r) if r else _f(t, n) for n, t, r in (
        ("date", "date", None), ("payment_ref", "char", None), ("amount", "monetary", None),
        ("partner_id", "many2one", "res.partner"), ("journal_id", "many2one", "account.journal"),
        ("company_id", "many2one", "res.company"), ("move_id", "many2one", MOVE), ("is_reconciled", "boolean", None),
        ("payment_ids", "many2many", "account.payment"), ("line_ids", "one2many", LINE),
        ("currency_id", "many2one", "res.currency"), ("foreign_currency_id", "many2one", "res.currency"),
    )}},
    MOVE: {
        **AUDIT_FIELDS,
        "name": _f("char", "Number"), "ref": _f("char", "Reference"),
        "state": _f("selection", "Status", selection=[["draft", "Draft"], ["posted", "Posted"], ["cancel", "Cancelled"]]),
        "move_type": _f("selection", "Type", selection=[["entry", "Journal Entry"], ["in_invoice", "Vendor Bill"],
                                                       ["out_invoice", "Customer Invoice"]]),
        "partner_id": _f("many2one", "Partner", relation="res.partner"),
        "date": _f("date", "Date"), "invoice_date_due": _f("date", "Due Date"),
        "amount_total": _f("monetary", "Total", readonly=True), "amount_residual": _f("monetary", "Amount Due", readonly=True),
        "payment_state": _f("selection", "Payment Status", readonly=True, selection=[
            ["not_paid", "Not Paid"], ["partial", "Partially Paid"], ["paid", "Paid"]]),
        "is_move_sent": _f("boolean", "Is Move Sent", readonly=True),
        "journal_id": _f("many2one", "Journal", relation="account.journal"),
        "company_id": _f("many2one", "Company", relation="res.company"),
        "currency_id": _f("many2one", "Currency", relation="res.currency"),
        "line_ids": _f("one2many", "Journal Items", relation=LINE, relation_field="move_id"),
        "invoice_line_ids": _f("one2many", "Invoice lines", relation=LINE, relation_field="move_id"),
    },
    LINE: {
        **AUDIT_FIELDS,
        "move_id": _f("many2one", "Journal Entry", relation=MOVE), "name": _f("char", "Label"),
        "partner_id": _f("many2one", "Partner", relation="res.partner"),
        "account_id": _f("many2one", "Account", relation="account.account"),
        "balance": _f("monetary", "Balance"), "amount_currency": _f("monetary", "Amount in Currency"),
        "amount_residual": _f("monetary", "Residual", readonly=True), "reconciled": _f("boolean", "Reconciled", readonly=True),
        "reconciled_lines_ids": _f("many2many", "Matched", relation=LINE, readonly=True, store=False),
        "parent_state": _f("char", "Status", readonly=True), "company_id": _f("many2one", "Company", relation="res.company"),
        "display_type": _f("char", "Display Type"), "payment_id": _f("many2one", "Payment", relation="account.payment"),
        "statement_line_id": _f("many2one", "Bank line", relation=BANK),
        "currency_id": _f("many2one", "Currency", relation="res.currency"),
        "date": _f("date", "Date"), "date_maturity": _f("date", "Due Date"),
        "quantity": _f("float", "Quantity"), "price_unit": _f("float", "Unit Price"),
        "price_subtotal": _f("monetary", "Subtotal", readonly=True),
        "tax_ids": _f("many2many", "Taxes", relation="account.tax"), "tax_line_id": _f("many2one", "Tax", relation="account.tax"),
    },
    "account.journal": {**AUDIT_FIELDS, "name": _f("char", "Name"), "type": _f("char", "Type"),
                        "suspense_account_id": _f("many2one", "Suspense", relation="account.account"),
                        "default_account_id": _f("many2one", "Default", relation="account.account")},
    "account.account": {**AUDIT_FIELDS, "name": _f("char", "Name"), "code": _f("char", "Code"),
                        "account_type": _f("char", "Type"), "reconcile": _f("boolean", "Reconcile")},
    "res.company": {**AUDIT_FIELDS, "name": _f("char", "Name"),
                    **{f: _f("date", f) for f in accounting.LOCK_FIELDS},
                    **{f"user_{f}": _f("date", f, store=False) for f in accounting.LOCK_FIELDS}},
    WIZARD: {**AUDIT_FIELDS, **{f: _f("date", f) for f in accounting.LOCK_FIELDS},
             "exception_needed_fields": _f("char", "Exception needed", readonly=True)},
    "account.payment": {**AUDIT_FIELDS, "name": _f("char", "Name")},
    "account.tax": {"name": _f("char", "Tax")},
    "res.currency": {"name": _f("char", "Currency")},
}


def records() -> dict:
    line = lambda **v: {"parent_state": "posted", "company_id": [1, "Sahajta"], "currency_id": [20, "INR"],  # noqa: E731
                        "reconciled": False, "reconciled_lines_ids": [], "display_type": "product", **v}
    return {
        "res.company": {1: {"name": "Sahajta", **{f: False for f in accounting.LOCK_FIELDS},
                            **{f"user_{f}": "1-01-01" for f in accounting.LOCK_FIELDS}}},
        "res.partner": {417: {"name": "Test Vendor"}, 500: {"name": "Other Vendor"}},
        "res.currency": {20: {"name": "INR"}},
        "account.tax": {61: {"name": "18% GST P"}},
        "account.journal": {6: {"name": "Bank", "type": "bank", "suspense_account_id": [104, "100202 Bank Suspense"],
                                "default_account_id": [103, "100201 Bank"]}},
        "account.account": {
            103: {"name": "100201 Bank", "account_type": "asset_cash", "reconcile": False},
            104: {"name": "100202 Bank Suspense", "account_type": "asset_current", "reconcile": False},
            24: {"name": "112110 Creditors", "account_type": "liability_payable", "reconcile": True},
            61: {"name": "211300 Bank Charges", "account_type": "expense", "reconcile": False},
        },
        MOVE: {
            367: {"name": "BILL/26-27/10/0015", "move_type": "in_invoice", "state": "posted", "partner_id": [417, "Test Vendor"],
                  "date": "2026-10-20", "amount_total": 1180.0, "amount_residual": 1180.0, "payment_state": "not_paid",
                  "journal_id": [2, "Purchases"], "company_id": [1, "Sahajta"], "currency_id": [20, "INR"],
                  "line_ids": [894, 897], "invoice_line_ids": [894]},
            371: {"name": "BILL/26-27/10/0016", "move_type": "in_invoice", "state": "posted", "partner_id": [417, "Test Vendor"],
                  "date": "2026-10-21", "amount_total": 236.0, "amount_residual": 236.0, "payment_state": "not_paid",
                  "company_id": [1, "Sahajta"], "currency_id": [20, "INR"], "line_ids": [925], "invoice_line_ids": []},
            368: {"name": "BNK1/26-27/0118", "move_type": "entry", "state": "posted", "line_ids": [898, 899]},
            380: {"name": "BILL/OTHER", "move_type": "in_invoice", "state": "posted", "partner_id": [500, "Other Vendor"],
                  "amount_total": 300.0, "amount_residual": 300.0, "payment_state": "not_paid", "line_ids": [950]},
        },
        LINE: {
            894: line(move_id=[367, "BILL/26-27/10/0015"], name="Service", account_id=[111, "Software"], balance=1000.0,
                      amount_residual=0.0, quantity=1.0, price_unit=1000.0, price_subtotal=1000.0, tax_ids=[61]),
            897: line(move_id=[367, "BILL/26-27/10/0015"], name="ZZB2-BILL-1", account_id=[24, "112110 Creditors"],
                      balance=-1180.0, amount_residual=-1180.0, display_type="payment_term", partner_id=[417, "Test Vendor"]),
            925: line(move_id=[371, "BILL/26-27/10/0016"], name="ZZB2-BILL-2", account_id=[24, "112110 Creditors"],
                      balance=-236.0, amount_residual=-236.0, display_type="payment_term", partner_id=[417, "Test Vendor"]),
            950: line(move_id=[380, "BILL/OTHER"], name="Other", account_id=[24, "112110 Creditors"],
                      balance=-300.0, amount_residual=-300.0, display_type="payment_term", partner_id=[500, "Other Vendor"]),
            898: line(move_id=[368, "BNK1"], name="Outgoing 1180", account_id=[103, "100201 Bank"], balance=-1180.0,
                      statement_line_id=[158, "BNK1"]),
            899: line(move_id=[368, "BNK1"], name="Outgoing 1180", account_id=[104, "100202 Bank Suspense"], balance=1180.0,
                      statement_line_id=[158, "BNK1"]),
        },
        BANK: {158: {"date": "2026-10-25", "payment_ref": "Outgoing 1180", "amount": -1180.0, "partner_id": False,
                     "journal_id": [6, "Bank"], "company_id": [1, "Sahajta"], "move_id": [368, "BNK1"],
                     "is_reconciled": False, "payment_ids": [], "line_ids": [898, 899], "currency_id": [20, "INR"],
                     "foreign_currency_id": False}},
        "account.payment": {77: {"name": "PBNK1/0013"}},
    }


class BankOdoo(FakeOdoo):
    """FakeOdoo plus Odoo 19's bank screen, bill reset/post and lock date dialog, as observed on the test copy."""

    def __post_init__(self) -> None:
        super().__post_init__()
        self.schema.update(copy.deepcopy(SCHEMA))
        for model, rows in records().items():
            self.records[model] = rows
            for row in rows.values():
                row.setdefault("write_date", "2026-10-15 10:00:00")
        self.unmatch_on_line_write = False  # Odoo drops the bank match when a bill's total changes

    # -- helpers
    def bank_lines(self, stl: int) -> list[dict]:
        return [self.records[LINE][i] | {"id": i} for i in self.records[BANK][stl]["line_ids"]]

    def _new_line(self, stl: int, **values) -> int:
        rid = next(self._ids)
        base = {"parent_state": "posted", "company_id": [1, "Sahajta"], "currency_id": [20, "INR"], "reconciled": False,
                "reconciled_lines_ids": [], "statement_line_id": [stl, "BNK1"], "write_date": "2026-10-15 12:00:00"}
        self.records[LINE][rid] = {**base, **values}
        return rid

    def _settle(self, item: int, amount: float) -> None:
        """amount > 0 settles that much of the item; < 0 opens it again."""
        row = self.records[LINE][item]
        sign = -1 if row["balance"] < 0 else 1
        row["amount_residual"] = round(row["amount_residual"] - sign * amount, 2)
        row["reconciled"] = abs(row["amount_residual"]) < 0.005
        move = self.records[MOVE][row["move_id"][0]]
        move["amount_residual"] = round(move["amount_residual"] - amount, 2)
        move["payment_state"] = "paid" if move["amount_residual"] < 0.005 else (
            "partial" if move["amount_residual"] < move["amount_total"] - 0.005 else "not_paid")

    def _rebuild(self, stl: int, matched: list[tuple[int, float, int | None, str | None]]) -> None:
        """Writes the bank line's items anew: bank, (item, amount, account, name)..., suspense for the rest."""
        st = self.records[BANK][stl]
        for old in st["line_ids"]:  # the items forget the bank line's old matched lines
            for item in self.records[LINE][old].get("reconciled_lines_ids") or []:
                links = self.records[LINE][item]["reconciled_lines_ids"]
                self.records[LINE][item]["reconciled_lines_ids"] = [i for i in links if i != old]
        bank = [i for i in st["line_ids"] if self.records[LINE][i]["account_id"][0] == 103]
        ids = list(bank)
        total = abs(st["amount"])
        for item, amount, account, name in matched:
            if item:
                acc = self.records[LINE][item]["account_id"]
                ids.append(self._new_line(stl, account_id=acc, balance=amount, reconciled_lines_ids=[item],
                                          name=self.records[LINE][item]["name"], move_id=[368, "BNK1"]))
                self.records[LINE][item]["reconciled_lines_ids"] = [*self.records[LINE][item]["reconciled_lines_ids"], ids[-1]]
            else:
                ids.append(self._new_line(stl, account_id=[account, self.records["account.account"][account]["name"]],
                                          balance=amount, name=name or st["payment_ref"], move_id=[368, "BNK1"]))
        left = round(total - sum(a for _, a, _, _ in matched), 2)
        if left > 0.005:
            ids.append(self._new_line(stl, account_id=[104, "100202 Bank Suspense"], balance=left, move_id=[368, "BNK1"]))
        st["line_ids"] = ids
        st["is_reconciled"] = left <= 0.005
        st["write_date"] = f"2026-10-15 12:{next(self._clock):02d}:00"

    def _matched(self, stl: int) -> list[tuple[int, float, int | None, str | None]]:
        out = []
        for row in self.bank_lines(stl):
            if row["account_id"][0] in (103, 104):
                continue
            item = (row.get("reconciled_lines_ids") or [None])[0]
            out.append((item, row["balance"], row["account_id"][0], row.get("name")))
        return out

    # -- Odoo methods
    def _m_set_line_bank_statement_line(self, model, ids, context, move_lines_ids=None, **kw):
        assert not kw, f"unexpected arguments {kw}"
        stl = ids[0]
        remaining = abs(self.records[BANK][stl]["amount"])
        matched = self._matched(stl)
        for item in move_lines_ids:
            take = min(abs(self.records[LINE][item]["amount_residual"]), remaining)
            self._settle(item, take)
            remaining -= take
            matched.append((item, take, None, None))
        self._rebuild(stl, matched)
        if not self.records[BANK][stl]["partner_id"]:
            self.records[BANK][stl]["partner_id"] = self.records[LINE][move_lines_ids[0]].get("partner_id") or False

    def _m_edit_reconcile_line(self, model, ids, context, move_line_id=None, record_data=None, **kw):
        assert not kw, f"unexpected arguments {kw}"
        stl, data = ids[0], record_data or {}
        if "balance" in data:
            assert data.get("amount_currency") == data["balance"], "Odoo needs both balance and amount_currency"
        matched = []
        for row in self.bank_lines(stl):
            if row["account_id"][0] in (103, 104):
                continue
            item = (row.get("reconciled_lines_ids") or [None])[0]
            amount, name = row["balance"], row.get("name")
            if row["id"] == move_line_id:
                if "balance" in data:
                    self._settle(item, abs(data["balance"]) - abs(amount))
                    amount = data["balance"]
                name = data.get("name", name)
            matched.append((item, amount, row["account_id"][0], name))
        self._rebuild(stl, matched)

    def _m_set_account_bank_statement_line(self, model, ids, context, aml_id=None, account_id=None, **kw):
        assert not kw, f"unexpected arguments {kw}"
        assert self.records[LINE][aml_id]["account_id"][0] == 104, "Odoo books the suspense item"
        self.records[LINE][aml_id]["account_id"] = [account_id, self.records["account.account"][account_id]["name"]]
        self.records[BANK][ids[0]]["is_reconciled"] = True
        return [ids[0]]

    def _undo_bank_match(self, stl: int) -> None:
        for item, amount, _, _ in self._matched(stl):
            if item:
                self._settle(item, -abs(amount))
        self._rebuild(stl, [])

    def _m_button_draft(self, model, ids, context, **kw):
        self.touch(MOVE, ids[0], state="draft")
        return True

    def _m_action_post(self, model, ids, context, **kw):
        self.touch(MOVE, ids[0], state="posted")
        return False

    def _m_write(self, model, ids, context, vals=None, **kw):
        if model == MOVE and "invoice_line_ids" in (vals or {}) and self.unmatch_on_line_write:
            for stl in self.records[BANK]:
                if any(item for item, *_ in self._matched(stl)):
                    self._undo_bank_match(stl)
            move = self.records[MOVE][ids[0]]
            move["amount_total"] = move["amount_residual"] = 1298.0
            self.records[LINE][897].update(balance=-1298.0, amount_residual=-1298.0, reconciled=False)
            move["payment_state"] = "not_paid"
        return super()._m_write(model, ids, context, vals=vals, **kw)

    def _m_create(self, model, ids, context, vals_list=None, **kw):
        if model == WIZARD:  # Odoo fills the other lock dates from the company
            company = self.records["res.company"][1]
            vals_list = [{**{f: company[f] for f in accounting.LOCK_FIELDS}, "exception_needed_fields": "", **v}
                         for v in vals_list]
        return super()._m_create(model, ids, context, vals_list=vals_list, **kw)

    def _m_change_lock_date(self, model, ids, context, **kw):
        wizard = self.records[WIZARD][ids[0]]
        company = self.records["res.company"][1]
        for f in accounting.LOCK_FIELDS:
            company[f] = wizard.get(f, False)
            company[f"user_{f}"] = wizard.get(f) or "1-01-01"
        return {"type": "ir.actions.act_window_close"}


@pytest.fixture
def fake() -> BankOdoo:
    return BankOdoo()


def svc_for(fake, **overrides):
    return make_service(fake, **{"mcp_allow_cancel_actions": True, **overrides})


def sent(fake) -> list[str]:
    return [c.method for c in fake.calls if c.method in BANK_METHODS or (c.method in ("write", "create") and c.model != "res.users")]


def lock(fake, name: str, day: str) -> None:
    fake.records["res.company"][1][name] = day
    fake.records["res.company"][1][f"user_{name}"] = day


def match_line(fake, stl: int = 158) -> None:
    """Someone matched the whole bank line with bill 367 in Odoo (not a call from the connector)."""
    fake._m_set_line_bank_statement_line(BANK, [stl], None, move_lines_ids=[897])


ITEMS = [{"move_id": 367, "amount": 700}, {"move_id": 371}]


# ================================================================================ matching


async def test_match_preview_shows_each_item_what_stays_open_and_changes_nothing(fake):
    svc = svc_for(fake)
    shown = await svc.preview_bank_match(158, ITEMS, None, None)
    items = {i["document"]: i for i in shown["items"]}
    assert items["BILL/26-27/10/0015"]["amount_matched"] == "700.00 INR"
    assert items["BILL/26-27/10/0015"]["status_after"] == "partly paid (480.00 INR still open)"
    assert items["BILL/26-27/10/0016"]["status_after"] == "paid" and items["BILL/26-27/10/0016"]["partner"] == "Test Vendor"
    assert shown["left_unmatched_on_bank_line"].startswith("244.00 INR")
    assert shown["bank_line"]["date"] == "2026-10-25" and shown["bank_line"]["label"] == "Outgoing 1180"
    assert shown["confirm_token"] and sent(fake) == []


async def test_match_uses_the_bank_screen_methods_and_ends_as_previewed(fake):
    svc = svc_for(fake)
    token = (await svc.preview_bank_match(158, ITEMS, None, None))["confirm_token"]
    done = await svc.bank_match(158, ITEMS, None, None, token)
    [match] = fake.calls_to("set_line_bank_statement_line")
    assert match.ids == [158] and match.kwargs == {"move_lines_ids": [897, 925]}
    edits = [c.kwargs["record_data"] for c in fake.calls_to("edit_reconcile_line")]
    assert {"balance": 700.0, "amount_currency": 700.0} in edits  # Odoo took all 1,180 for the first bill
    assert "differs_from_preview" not in done and done["bank_line_now"]["left_unmatched"] == "244.00 INR"
    assert fake.records[MOVE][367]["amount_residual"] == 480.0 and fake.records[MOVE][371]["payment_state"] == "paid"


async def test_one_approval_matches_once(fake):
    svc = svc_for(fake)
    token = (await svc.preview_bank_match(158, [{"move_id": 367}], None, None))["confirm_token"]
    await svc.bank_match(158, [{"move_id": 367}], None, None, token)
    with pytest.raises(OdooMCPError):
        await svc.bank_match(158, [{"move_id": 367}], None, None, token)
    assert len(fake.calls_to("set_line_bank_statement_line")) == 1


async def test_a_line_already_matched_is_refused_before_and_at_the_approval(fake):
    svc = svc_for(fake)
    token = (await svc.preview_bank_match(158, [{"move_id": 371}], None, None))["confirm_token"]
    match_line(fake)  # someone matched it in Odoo in the meantime
    with pytest.raises(PolicyViolation, match="already matched"):
        await svc.preview_bank_match(158, [{"move_id": 371}], None, None)
    with pytest.raises(PolicyViolation, match="already matched") as caught:
        await svc.bank_match(158, [{"move_id": 371}], None, None, token)
    assert NOTHING in str(caught.value).lower() and fake.calls_to("set_line_bank_statement_line") == []


@pytest.mark.parametrize("name", ["fiscalyear_lock_date", "hard_lock_date"])
async def test_a_bank_line_in_a_locked_period_is_refused(fake, name):
    lock(fake, name, "2026-10-31")
    with pytest.raises(PolicyViolation, match="locked period"):
        await svc_for(fake).preview_bank_match(158, [{"move_id": 367}], None, None)


async def test_an_item_of_another_partner_carries_a_clear_warning(fake):
    fake.records[BANK][158]["partner_id"] = [417, "Test Vendor"]
    shown = await svc_for(fake).preview_bank_match(158, [{"move_line_id": 950}], None, None)
    assert shown["warnings"][0].startswith("OTHER PARTNER") and "Other Vendor" in shown["warnings"][0]


@pytest.mark.parametrize(("items", "says"), [
    ([{"move_id": 371, "amount": 300}], "more than its open amount"),
    ([{"move_id": 367}, {"move_id": 371}], "nothing of the bank line is left"),
    ([{"move_id": 367, "amount": 1000}, {"move_id": 371, "amount": 200}], "more than what is left"),
    ([{"move_id": 367, "amount": -5}], "positive number"),
    ([{"move_id": 367, "move_line_id": 897}], "one of the two"),
    ([{"move_line_id": 897}, {"move_line_id": 897}], "more than once"),
])
async def test_amounts_and_items_are_checked(fake, items, says):
    with pytest.raises(ValidationFailed, match=says):
        await svc_for(fake).preview_bank_match(158, items, None, None)


async def test_an_item_that_would_add_to_the_bank_line_is_refused(fake):
    fake.records[LINE][925].update(balance=236.0, amount_residual=236.0)  # a credit note against a payment out
    with pytest.raises(PolicyViolation, match="instead of settling"):
        await svc_for(fake).preview_bank_match(158, [{"move_line_id": 925}], None, None)


async def test_items_are_capped_per_approval(fake):
    with pytest.raises(ValidationFailed, match="limit is 2"):
        await svc_for(fake, mcp_max_action_records=2).preview_bank_match(
            158, [{"move_line_id": 897}, {"move_line_id": 925}, {"move_line_id": 950}], None, None)


async def test_booking_to_an_account_with_a_label(fake):
    svc = svc_for(fake)
    shown = await svc.preview_bank_match(158, None, 61, "Bank charges")
    assert shown["booking"] == {"account": "211300 Bank Charges", "amount": "1,180.00 INR", "label": "Bank charges"}
    await svc.bank_match(158, None, 61, "Bank charges", shown["confirm_token"])
    [book] = fake.calls_to("set_account_bank_statement_line")
    assert book.kwargs == {"aml_id": 899, "account_id": 61}
    [label] = fake.calls_to("edit_reconcile_line")
    assert label.kwargs["record_data"] == {"name": "Bank charges"}


@pytest.mark.parametrize(("account", "error", "says"), [
    (24, PolicyViolation, "customer or vendor account"), (104, ValidationFailed, "bank journal's own account"),
])
async def test_booking_refuses_the_wrong_accounts(fake, account, error, says):
    with pytest.raises(error, match=says):
        await svc_for(fake).preview_bank_match(158, None, account, None)


async def test_items_or_an_account_one_of_the_two(fake):
    with pytest.raises(ValidationFailed, match="one of the two"):
        await svc_for(fake).preview_bank_match(158, [{"move_id": 367}], 61, None)


async def test_a_failure_after_the_first_step_says_where_it_stopped_and_keeps_the_approval_used(fake):
    svc = svc_for(fake)
    token = (await svc.preview_bank_match(158, ITEMS, None, None))["confirm_token"]
    fake.errors[(BANK, "edit_reconcile_line")] = OdooError("The entry is not balanced.", kind="user_error")
    with pytest.raises(OdooMCPError) as caught:
        await svc.bank_match(158, ITEMS, None, None, token)
    text = str(caught.value)
    assert "stopped at step 2 of 2" in text and MAYBE in text.lower() and NOTHING not in text.lower()
    assert "The bank line in Odoo now" in text
    with pytest.raises(OdooMCPError):  # the line is partly matched now, and the approval stays used
        await svc.bank_match(158, ITEMS, None, None, token)
    assert not svc.shared.signer._state.claim_once(f"confirm:{token}", int(token.split(".")[0]))  # still used
    assert len(fake.calls_to("set_line_bank_statement_line")) == 1


async def test_odoo_refusing_the_first_step_changes_nothing_and_hands_back_nothing_to_retry(fake):
    svc = svc_for(fake)
    token = (await svc.preview_bank_match(158, [{"move_id": 367}], None, None))["confirm_token"]
    fake.errors[(BANK, "set_line_bank_statement_line")] = OdooError("bad", kind="validation")
    with pytest.raises(OdooMCPError) as caught:
        await svc.bank_match(158, [{"move_id": 367}], None, None, token)
    assert NOTHING in str(caught.value).lower() and MAYBE not in str(caught.value).lower()
    assert fake.calls_to("edit_reconcile_line") == []


async def test_candidates_are_a_read_that_works_in_read_only_mode(fake):
    shown = await make_service(fake, mcp_access_mode="read_only").bank_match_candidates(158, None)
    assert any(i["move_line_id"] == 897 and i["document"] == "BILL/26-27/10/0015" for i in shown["same_amount"])
    [search] = [c for c in fake.calls_to("search_read") if c.model == LINE][:1]
    assert ["statement_line_id", "!=", 158] in search.kwargs["domain"] and sent(fake) == []


# ================================================================================ undoing a match


async def test_unmatch_shows_what_goes_back_to_unpaid_and_uses_its_own_path(fake):
    match_line(fake)
    svc = svc_for(fake)
    shown = await svc.preview_bank_unmatch(158)
    assert shown["goes_back"][0]["document"] == "BILL/26-27/10/0015" and shown["goes_back"][0]["status_after"] == "not paid"
    done = await svc.bank_unmatch(158, shown["confirm_token"])
    assert [c.ids for c in fake.calls_to("undo_bank_match")] == [[158]]
    assert done["documents_now"][0]["payment_status"] == "Not Paid"


async def test_unmatch_is_refused_when_payments_are_linked_even_after_the_preview(fake):
    match_line(fake)
    svc = svc_for(fake)
    fake.records[BANK][158]["payment_ids"] = [77]
    with pytest.raises(PolicyViolation, match="PBNK1/0013"):
        await svc.preview_bank_unmatch(158)
    fake.records[BANK][158]["payment_ids"] = []
    token = (await svc.preview_bank_unmatch(158))["confirm_token"]
    fake.records[BANK][158]["payment_ids"] = [77]  # a payment was linked in Odoo after the preview
    with pytest.raises(PolicyViolation, match="remove those payments") as caught:
        await svc.bank_unmatch(158, token)
    assert NOTHING in str(caught.value).lower() and fake.calls_to("undo_bank_match") == []


async def test_unmatch_needs_the_cancel_switch_and_a_match(fake):
    with pytest.raises(PolicyViolation, match="switched off"):
        await svc_for(fake, mcp_allow_cancel_actions=False).preview_bank_unmatch(158)
    with pytest.raises(PolicyViolation, match="not matched"):
        await svc_for(fake).preview_bank_unmatch(158)


@pytest.mark.parametrize(("model", "method", "tool"), [
    (BANK, "action_undo_reconciliation", "odoo_preview_bank_unmatch"),
    (BANK, "action_unreconcile_entry", "odoo_preview_bank_unmatch"),
    (BANK, "set_line_bank_statement_line", "odoo_preview_bank_match"),
    (BANK, "edit_reconcile_line", "odoo_preview_bank_match"),
    (WIZARD, "change_lock_date", "odoo_preview_lock_date"),
])
def test_the_bank_screen_methods_are_never_plain_buttons(fake, model, method, tool):
    decision = svc_for(fake, mcp_extra_allowed_methods=[f"{model}:{method}"]).policy.method_decision(
        model, method, is_ui_button=True)
    assert not decision.allowed and tool in decision.reason


async def test_the_client_sends_undo_only_through_its_own_path():
    client = OdooClient(OdooCredentials("https://odoo.example.com", None, "x", "k"), http=None, protocol="json2")
    with pytest.raises(OdooError, match="refusing to send"):
        await client.call(BANK, "action_undo_reconciliation", ids=[158])
    for bad in (0, True, "158", [158]):
        with pytest.raises(OdooError, match="one bank line"):
            await client.undo_bank_match(bad)


# ================================================================================ the tax lock date


async def test_lock_preview_shows_all_five_dates_counts_and_what_it_means(fake):
    lock(fake, "hard_lock_date", "2026-03-31")
    shown = await svc_for(fake).preview_lock_date("2026-09-30")
    assert len(shown["lock_dates_now"]) == 5 and shown["lock_dates_now"]["Hard lock date (can never be moved back)"] == "2026-03-31"
    assert "nobody can post, change or delete entries with taxes" in shown["what_locking_means"]
    counts = [c for c in fake.calls_to("search_count") if c.model == MOVE]
    assert len(counts) == 2 and {d[2] for c in counts for d in c.kwargs["domain"] if d[:2] == ["state", "="]} == {"posted", "draft"}
    assert sent(fake) == []


async def test_lock_date_moves_only_the_tax_lock_date_forward(fake):
    lock(fake, "tax_lock_date", "2026-06-30")
    svc = svc_for(fake)
    token = (await svc.preview_lock_date("2026-09-30"))["confirm_token"]
    done = await svc.lock_date("2026-09-30", token)
    [create] = [c for c in fake.calls_to("create") if c.model == WIZARD]
    assert create.kwargs["vals_list"] == [{"tax_lock_date": "2026-09-30"}]
    assert len(fake.calls_to("change_lock_date")) == 1
    assert done["lock_dates_now"]["Tax return lock date (entries with taxes)"] == "2026-09-30"


@pytest.mark.parametrize(("day", "error", "says"), [
    ("2026-06-30", PolicyViolation, "never back"), ("2026-05-31", PolicyViolation, "never back"),
    ("2099-01-01", ValidationFailed, "in the future"), ("30/09/2026", ValidationFailed, "written like"),
])
async def test_lock_date_never_moves_back_or_into_the_future(fake, day, error, says):
    lock(fake, "tax_lock_date", "2026-06-30")
    with pytest.raises(error, match=says):
        await svc_for(fake).preview_lock_date(day)


async def test_a_lock_dialog_that_would_change_more_is_not_confirmed(fake):
    svc = svc_for(fake)
    token = (await svc.preview_lock_date("2026-09-30"))["confirm_token"]
    lock(fake, "hard_lock_date", "2026-09-30")  # the company changed after the preview: the dialog shows it
    with pytest.raises(OdooMCPError) as caught:
        await svc.lock_date("2026-09-30", token)
    assert NOTHING in str(caught.value).lower() and fake.calls_to("change_lock_date") == []


async def test_whoami_shows_the_five_lock_dates(fake):
    lock(fake, "tax_lock_date", "2026-06-30")
    who = await make_service(fake, mcp_access_mode="read_only").whoami()
    assert who["lock_dates"]["Tax return lock date (entries with taxes)"] == "2026-06-30" and len(who["lock_dates"]) == 5


# ================================================================================ correcting a posted bill

FIX = [[1, 894, {"price_unit": 1100}]]


async def test_bill_fix_preview_lists_every_step_and_changes_nothing(fake):
    match_line(fake)
    shown = await svc_for(fake).preview_fix_posted_bill(367, FIX, 158, True)
    assert len(shown["steps"]) == 4 and "keeps its number BILL/26-27/10/0015" in shown["steps"][0]
    assert "edit line 894" in str(shown["steps"][1]) and shown["lines_now"][0]["unit_price"] == "1,000.00 INR"
    assert sent(fake) == []


async def test_bill_fix_runs_each_step_once_and_matches_the_bank_line_again(fake):
    match_line(fake)
    fake.unmatch_on_line_write = True
    svc = svc_for(fake)
    token = (await svc.preview_fix_posted_bill(367, FIX, 158, True))["confirm_token"]
    done = await svc.fix_posted_bill(367, FIX, 158, True, token)
    assert sent(fake)[-4:] == [
        "button_draft", "write", "action_post", "set_line_bank_statement_line"]
    assert fake.calls_to("set_line_bank_statement_line")[-1].kwargs == {"move_lines_ids": [897]}
    assert done["bank_line_now"]["matched_with"] and fake.records[MOVE][367]["state"] == "posted"


async def test_bill_fix_leaves_a_kept_match_alone(fake):
    match_line(fake)
    svc = svc_for(fake)
    token = (await svc.preview_fix_posted_bill(367, [[1, 894, {"name": "Service (Oct)"}]], 158, True))["confirm_token"]
    await svc.fix_posted_bill(367, [[1, 894, {"name": "Service (Oct)"}]], 158, True, token)
    assert fake.calls_to("set_line_bank_statement_line") == []  # Odoo kept the match: nothing to redo


async def test_only_the_bills_own_bank_match_is_restored(fake):
    with pytest.raises(PolicyViolation, match="not matched with BILL/26-27/10/0015"):
        await svc_for(fake).preview_fix_posted_bill(367, FIX, 158, True)
    fake._m_set_line_bank_statement_line(BANK, [158], None, move_lines_ids=[897])
    fake.records[MOVE][367].update(amount_residual=0.0, payment_state="paid")
    fake.records[BANK][158]["line_ids"].append(fake._new_line(158, account_id=[61, "211300 Bank Charges"], balance=5.0))
    with pytest.raises(PolicyViolation, match="also matched with other documents or accounts"):
        await svc_for(fake).preview_fix_posted_bill(367, FIX, 158, True)


async def test_a_paid_bill_needs_the_person_to_know(fake):
    match_line(fake)
    with pytest.raises(PolicyViolation, match="already paid"):
        await svc_for(fake).preview_fix_posted_bill(367, FIX, 158, False)
    shown = await svc_for(fake).preview_fix_posted_bill(367, FIX, None, True)
    assert any("rematch_statement_line_id" in w for w in shown["warnings"])


async def test_a_bill_in_a_tax_locked_period_gets_a_credit_note_instead(fake):
    lock(fake, "tax_lock_date", "2026-10-31")
    with pytest.raises(PolicyViolation, match="credit note"):
        await svc_for(fake).preview_fix_posted_bill(367, FIX, None, False)


async def test_a_step_that_fails_stops_the_plan_and_says_where_the_bill_is(fake):
    match_line(fake)
    fake.unmatch_on_line_write = True
    svc = svc_for(fake)
    token = (await svc.preview_fix_posted_bill(367, FIX, 158, True))["confirm_token"]
    fake.errors[(MOVE, "action_post")] = OdooError("The entry is not balanced.", kind="user_error")
    with pytest.raises(OdooMCPError) as caught:
        await svc.fix_posted_bill(367, FIX, 158, True, token)
    text = str(caught.value)
    assert "stopped at step 3 of 4 (post again)" in text and "step 1 (reset to draft); step 2 (change the lines)" in text
    assert MAYBE in text.lower() and NOTHING not in text.lower()
    assert "is now draft" in text and "post it again" in text and "Bank line 158 is not matched" in text
    assert fake.calls_to("set_line_bank_statement_line") == []  # the match step never ran


async def test_a_bill_fix_refused_by_odoo_at_the_first_step_changes_nothing(fake):
    svc = svc_for(fake)
    token = (await svc.preview_fix_posted_bill(367, FIX, None, False))["confirm_token"]
    fake.errors[(MOVE, "button_draft")] = OdooError("You cannot reset to draft a locked journal entry.", kind="user_error")
    with pytest.raises(OdooMCPError) as caught:
        await svc.fix_posted_bill(367, FIX, None, False, token)
    assert NOTHING in str(caught.value).lower() and fake.calls_to("write") == []


@pytest.mark.parametrize(("changes", "says"), [
    ([[2, 894, 0]], "can only edit lines"), ([], "must list the line changes"), ([[5]], "can only edit lines"),
])
async def test_bill_fix_only_edits_or_adds_lines(fake, changes, says):
    with pytest.raises(ValidationFailed, match=says):
        await svc_for(fake).preview_fix_posted_bill(367, changes, None, False)


async def test_bill_fix_needs_the_cancel_switch_and_a_posted_vendor_bill(fake):
    with pytest.raises(PolicyViolation, match="switched off"):
        await svc_for(fake, mcp_allow_cancel_actions=False).preview_fix_posted_bill(367, FIX, None, False)
    fake.records[MOVE][367]["state"] = "draft"
    with pytest.raises(ValidationFailed, match="not posted"):
        await svc_for(fake).preview_fix_posted_bill(367, FIX, None, False)


def test_partly_done_answers_use_the_services_words():
    assert accounting._MAYBE_APPLIED == service_module._MAYBE_APPLIED
    assert accounting._READ_BACK_FAILED == service_module._READ_BACK_FAILED


# ================================================================================ the tools


@pytest.mark.parametrize("access", ["read_only", "read_write"])
async def test_the_tools_exist_by_mode_and_refusals_point_to_the_guide(fake, access):
    shared = make_shared(mcp_access_mode=access, mcp_allow_cancel_actions=True)
    service = make_service(fake, shared)
    mcp = MCPServer("bank-test")

    async def get_service():
        return service

    register_tools(mcp, get_service, shared.settings)
    changes = {"odoo_preview_bank_match", "odoo_bank_match", "odoo_preview_bank_unmatch", "odoo_bank_unmatch",
               "odoo_preview_lock_date", "odoo_lock_date", "odoo_preview_fix_posted_bill", "odoo_fix_posted_bill"}
    async with Client(mcp) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert "odoo_bank_match_candidates" in tools and (changes <= set(tools)) is (access == "read_write")
        if access == "read_write":
            assert all(tools[name].annotations.destructive_hint for name in changes if "preview" not in name)
            result = await client.call_tool("odoo_preview_bank_unmatch", {"statement_line_id": 158})
            text = result.content[0].text
            assert result.is_error and "not matched" in text and 'odoo_help(topic="bank")' in text
