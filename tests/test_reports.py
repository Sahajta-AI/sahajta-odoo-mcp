"""odoo_report: Odoo's official accounting reports read as compact lines, against the in-memory fake Odoo."""

from __future__ import annotations

import json

import pytest
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from conftest import FakeOdoo, _line, add_reports
from sahajta_odoo_mcp import guide
from sahajta_odoo_mcp.errors import ValidationFailed
from sahajta_odoo_mcp.tools import INSTRUCTIONS, register_tools
from test_service_offline import make_service, make_shared

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

READ_METHODS = {"search_read", "read", "get_options", "get_report_information", "get_expanded_lines"}


@pytest.fixture
def fake() -> FakeOdoo:
    return add_reports(FakeOdoo())


@pytest.fixture
def svc(fake):
    return make_service(fake, mcp_access_mode="read_only")  # reports work in read-only mode


def asked_options(fake: FakeOdoo) -> dict:
    return fake.calls_to("get_options")[-1].kwargs["previous_options"]


async def test_profit_and_loss_is_trimmed_to_names_levels_and_values(svc, fake):
    result = await svc.report("P&L", "2026-04-01", "2026-10-31")
    assert result["report"] == "Profit and Loss"
    assert result["period"] == {"from": "2026-04-01", "to": "2026-10-31"}
    assert result["currency"] == "INR"
    assert result["columns"] == ["Balance"]
    assert result["lines"][0] == {"name": "Revenue", "level": 1, "values": {"Balance": 450397.45}, "can_open": True}
    by_name = {line["name"]: line for line in result["lines"]}
    assert by_name["Less Operating Expenses"]["values"] == {"Balance": 73286.32}  # Odoo's float noise rounded
    assert "Plus Other Income" not in by_name  # all-zero lines are left out
    assert by_name["Net Profit"]["level"] == 0
    assert result["drafts_in_period"] is True
    assert "draft entries in this period that are not counted" in " ".join(result["notes"])
    assert result["open_in_odoo"] == "https://odoo.example.com/odoo/profit-and-loss"
    assert asked_options(fake)["date"] == {"date_from": "2026-04-01", "date_to": "2026-10-31", "filter": "custom", "mode": "range"}
    assert set(fake.methods()) <= READ_METHODS  # nothing but reads, in read-only mode
    assert all(len(line) <= 4 for line in result["lines"]) and "id" not in result["lines"][0]
    assert len(json.dumps(result)) < 3000


async def test_unfold_opens_one_line_in_place(svc, fake):
    result = await svc.report("profit and loss", "2026-04-01", "2026-10-31", unfold="operating expenses")
    names = [line["name"] for line in result["lines"]]
    at = names.index("Less Operating Expenses")
    assert names[at + 1:at + 3] == ["210200 Office Rent", "210300 Software"]
    assert result["opened"] == "Less Operating Expenses"
    sent = fake.calls_to("get_expanded_lines")[0].kwargs
    assert sent["line_dict_id"].endswith("~48") and sent["expand_function_name"] and sent["offset"] == 0


async def test_trial_balance_names_its_two_balance_columns(svc):
    result = await svc.report("trial balance", "2026-04-01", "2026-10-31")
    assert result["columns"] == ["Initial Balance: Balance", "Debit", "Credit", "End Balance: Balance"]
    assert result["lines"][0]["values"]["End Balance: Balance"] == 418207.38


async def test_balance_sheet_is_as_of_one_day(svc, fake):
    result = await svc.report("balance sheet", "2026-04-01", "2026-10-31")
    assert asked_options(fake)["date"] == {"date_to": "2026-10-31", "filter": "custom", "mode": "single"}
    assert result["period"] == {"as_of": "2026-10-31"}
    assert any("date_from is not used" in note for note in result["notes"])
    assert result["drafts_in_period"] is False
    assert result["open_in_odoo"] == "Accounting → Reporting → Balance Sheet"  # no action found: the menu path


@pytest.mark.parametrize("name", ["general ledger", "partner ledger"])
async def test_ledgers_need_one_account_or_partner(svc, fake, name):
    with pytest.raises(ValidationFailed, match="account_or_partner"):
        await svc.report(name, "2026-10-01", "2026-10-31")
    assert fake.calls == []  # refused before asking Odoo


async def test_general_ledger_opens_only_that_account(svc, fake):
    result = await svc.report("general ledger", "2026-10-01", "2026-10-31", account_or_partner="Bank")
    assert [line["name"] for line in result["lines"]] == ["100201 Bank", "Initial Balance", "BNK1/26-27/0079 Twitterapi.Io"]
    entry = result["lines"][2]["values"]
    assert entry == {"Date": "2026-10-02", "Partner": "twitterapi.io", "Debit": 0.0, "Credit": 1001.46, "Balance": 289305.26}
    assert any("only its first entries" in note for note in result["notes"])  # Odoo's "Load more..." line
    assert result["open_in_odoo"] == "https://odoo.example.com/odoo/action-693"
    by_code = await svc.report("gl", "2026-10-01", "2026-10-31", account_or_partner="100400")
    assert by_code["opened"] == "100400 Debtors"


async def test_ledger_line_that_is_not_clear_or_missing_is_refused_with_the_choices(svc):
    with pytest.raises(ValidationFailed, match="several accounts match '1002'.*100201 Bank.*100202"):
        await svc.report("general ledger", "2026-10-01", "2026-10-31", account_or_partner="1002")
    with pytest.raises(ValidationFailed, match="no account named 'Petty cash'.*100400 Debtors"):
        await svc.report("general ledger", "2026-10-01", "2026-10-31", account_or_partner="Petty cash")


async def test_partner_ledger_opens_the_partner(svc):
    result = await svc.report("partner ledger", "2026-04-01", "2026-10-31", account_or_partner="vercel")
    assert [line["name"] for line in result["lines"]] == ["Vercel", "BNK1/26-27/0109 Vercel Inc"]


@pytest.mark.parametrize("name", ["cash flow", "payroll", "", None])
async def test_unknown_report_names_are_refused_with_the_list(svc, fake, name):
    with pytest.raises(ValidationFailed, match="profit and loss, balance sheet, trial balance, general ledger"):
        await svc.report(name, "2026-04-01", "2026-10-31")
    assert fake.calls == []


async def test_gst_return_reads_the_tax_report_and_says_there_is_no_gstr(svc, fake):
    result = await svc.report("GSTR-3B", "2026-10-01", "2026-10-31")
    assert asked_options(fake)["selected_variant_id"] == 1  # not Odoo's default TDS/TCS variant
    assert result["report"] == "Generic Tax report"
    assert result["notes"][0].startswith("This Odoo has no GSTR-1 or GSTR-3B report")
    assert result["lines"][1] == {"name": "18% IGST P (18.0%)", "level": 2, "values": {"Net": 1000.0, "Tax": 180.0}}
    plain = await svc.report("tax report", "2026-10-01", "2026-10-31")
    assert "GSTR" not in " ".join(plain["notes"])


@pytest.mark.parametrize(("date_from", "date_to", "problem"), [
    ("01/04/2026", "2026-10-31", "YYYY-MM-DD"),
    ("2026-02-30", "2026-10-31", "not a real date"),
    ("2026-11-01", "2026-10-31", "after date_to"),
    (None, "2026-10-31", "date_from is needed"),
    ("2026-04-01", None, "date_to is needed"),
])
async def test_dates_are_checked(svc, date_from, date_to, problem):
    with pytest.raises(ValidationFailed, match=problem):
        await svc.report("profit and loss", date_from, date_to)


async def test_a_huge_report_is_cut_to_a_compact_answer(svc, fake):
    fake.reports[7]["lines"] = [
        _line(f"~account.report~7|~account.account~{i}", f"{400000 + i} An account with a fairly long name", 2, 1000.0 + i)
        for i in range(3000)
    ]
    result = await svc.report("profit and loss", "2026-04-01", "2026-10-31")
    size = len(json.dumps(result, ensure_ascii=False))
    assert result["truncated_for_size"] is True and size <= 60_000
    assert 0 < len(result["lines"]) <= 400
    assert "lines fit in one answer" in result["notes"][-1]


async def test_a_report_with_only_zeros_says_so(svc, fake):
    fake.reports[7]["lines"] = [_line("~account.report~7|~account.report.line~45", "Revenue", 1, 0)]
    result = await svc.report("profit and loss", "2026-04-01", "2026-10-31")
    assert result["lines"] == [] and "Every amount in this report is zero" in result["notes"][-1]


async def test_odoo_access_rights_still_apply(svc, fake):
    fake.records["account.report"] = {}  # a user who may not see the accounting reports
    with pytest.raises(ValidationFailed, match="no profit and loss report that your user can see"):
        await svc.report("profit and loss", "2026-04-01", "2026-10-31")


async def test_the_tool_is_offered_in_read_only_mode_and_the_guide_names_it(fake):
    shared = make_shared(mcp_access_mode="read_only")
    service = make_service(fake, shared)
    mcp = MCPServer("report-test")

    async def get_service():
        return service

    register_tools(mcp, get_service, shared.settings)
    async with Client(mcp) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert tools["odoo_report"].annotations.read_only_hint is True
        answer = await client.call_tool(
            "odoo_report", {"report": "profit and loss", "date_from": "2026-04-01", "date_to": "2026-10-31"}
        )
        refused = await client.call_tool("odoo_report", {"report": "general ledger", "date_to": "2026-10-31"})
    assert json.loads(answer.content[0].text)["report"] == "Profit and Loss"
    assert refused.is_error and "account_or_partner" in refused.content[0].text
    topic = guide.TOPICS["reports"]
    assert any("odoo_report" in can.how for can in topic.can)
    assert any("GSTR" in what for what, _ in topic.cannot)
    assert "odoo_report" in INSTRUCTIONS

