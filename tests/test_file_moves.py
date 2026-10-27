"""Moving a file (e.g. a bill's PDF) onto the right accounting entry: what may move, from where, to where."""

from __future__ import annotations

import pytest

from conftest import AUDIT_FIELDS, FakeOdoo, _f
from sahajta_odoo_mcp.errors import PolicyViolation, ValidationFailed
from test_service_offline import changes, make_service


@pytest.fixture
def fake() -> FakeOdoo:
    fake = FakeOdoo()
    fake.schema["ir.attachment"] = {
        **AUDIT_FIELDS,
        "name": _f("char", "Name", required=True),
        "res_model": _f("char", "Resource Model"),
        "res_id": _f("many2one_reference", "Resource ID", model_field="res_model"),
        "res_field": _f("char", "Resource Field", readonly=True),
        "datas": _f("binary", "File Content"),
    }
    fake.schema["account.move"] = {
        **AUDIT_FIELDS,
        "name": _f("char", "Number"),
        "state": _f("selection", "Status", selection=[["draft", "Draft"], ["posted", "Posted"], ["cancel", "Cancelled"]]),
        "message_main_attachment_id": _f("many2one", "Main Attachment", relation="ir.attachment"),
    }
    fake.records["account.move"] = {
        10: {"name": "Draft bill from the inbox", "state": "draft", "message_main_attachment_id": [501, "anthropic.pdf"]},
        11: {"name": "BILL/2026/10/0003", "state": "posted", "message_main_attachment_id": False},
        12: {"name": "BILL/2026/10/0004", "state": "posted", "message_main_attachment_id": [599, "other.pdf"]},
    }
    fake.records["ir.attachment"] = {
        501: {"name": "anthropic.pdf", "res_model": "account.move", "res_id": 10, "res_field": False},
        502: {"name": "myhq.pdf", "res_model": False, "res_id": 0, "res_field": False},
        503: {"name": "INV_2026_0001.pdf", "res_model": "account.move", "res_id": 11, "res_field": "invoice_pdf_report_file"},
        504: {"name": "receipt.pdf", "res_model": "account.move", "res_id": 12, "res_field": False},
        505: {"name": "quote.pdf", "res_model": "sale.order", "res_id": 5, "res_field": False},
    }
    return fake


@pytest.fixture
def svc(fake):
    return make_service(fake, mcp_access_mode="read_write")


MOVE_TO_11 = {"res_model": "account.move", "res_id": 11}


async def test_a_pdf_moves_from_a_draft_bill_onto_a_posted_bill_in_one_approval(svc, fake):
    preview = await svc.preview_update("ir.attachment", [501], MOVE_TO_11, None)
    [move] = preview["moves"]
    assert move["file"] == "anthropic.pdf" and move["from"] == "Draft bill from the inbox" and move["to"] == "BILL/2026/10/0003"
    assert move["to_link"].endswith("/odoo/account.move/11") and "nothing is deleted" in str(preview["warnings"])
    await svc.update("ir.attachment", [501], MOVE_TO_11, None, preview["confirm_token"])
    assert fake.records["ir.attachment"][501]["res_id"] == 11
    assert fake.records["account.move"][11]["message_main_attachment_id"] in (501, [501, "anthropic.pdf"])  # shown next to the bill
    assert not fake.records["account.move"][10]["message_main_attachment_id"]  # the draft no longer points at it


async def test_a_file_on_no_record_can_be_moved_and_several_go_in_one_approval(svc, fake):
    moves = [{"ids": [501], "values": MOVE_TO_11}, {"ids": [502], "values": {"res_model": "account.move", "res_id": 12}}]
    preview = await svc.preview_update("ir.attachment", None, None, None, moves)
    assert [m["from"] for m in preview["moves"]] == ["Draft bill from the inbox", "not attached to any record"]
    await svc.update("ir.attachment", None, None, None, preview["confirm_token"], moves)
    assert fake.records["ir.attachment"][502]["res_id"] == 12
    assert fake.records["account.move"][12]["message_main_attachment_id"] == [599, "other.pdf"]  # its own document stays


@pytest.mark.parametrize(
    "file_id, needle",
    [
        (503, "Odoo keeps itself"),            # the invoice PDF Odoo generated
        (504, "not a draft"),                  # evidence on a posted bill stays there
        (505, "sale.order record"),            # other kinds of records (customers may see them)
    ],
)
async def test_files_that_must_stay_where_they_are_are_refused_before_approval(svc, fake, file_id, needle):
    with pytest.raises(ValidationFailed, match=needle):
        await svc.preview_update("ir.attachment", [file_id], {"res_model": "account.move", "res_id": 10}, None)
    assert changes(fake) == []


@pytest.mark.parametrize(
    "values",
    [
        {"res_model": "sale.order", "res_id": 5},          # only accounting entries
        {"res_model": "account.move", "res_id": 999},      # an entry that does not exist
        {"res_model": "account.move"},                     # both are needed
    ],
)
async def test_files_go_only_onto_existing_accounting_entries(svc, fake, values):
    with pytest.raises(ValidationFailed):
        await svc.preview_update("ir.attachment", [502], values, None)
    assert changes(fake) == []


async def test_a_file_cannot_be_uploaded_renamed_or_rewritten(svc, fake):
    with pytest.raises(PolicyViolation, match="cannot be uploaded"):
        await svc.preview_create("ir.attachment", [{"name": "x.pdf", "res_model": "account.move", "res_id": 11}], None)
    with pytest.raises(ValidationFailed, match="only these fields"):
        await svc.preview_update("ir.attachment", [502], {"name": "renamed.pdf"}, None)


async def test_a_file_moved_meanwhile_is_not_moved_again(svc, fake):
    preview = await svc.preview_update("ir.attachment", [501], MOVE_TO_11, None)
    fake.records["ir.attachment"][501]["res_id"] = 12  # someone moved it in Odoo after the preview
    fake.records["ir.attachment"][501]["res_model"] = "account.move"
    with pytest.raises(Exception):
        await svc.update("ir.attachment", [501], MOVE_TO_11, None, preview["confirm_token"])
    assert changes(fake) == []
