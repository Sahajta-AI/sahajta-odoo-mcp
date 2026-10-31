"""Files already in Odoo: copying them onto leads, bills, quotations and contacts (Odoo duplicates the content
itself), moving them onto and off CRM leads, and reading a PDF's text or an image with odoo_read_file.

Odoo is the in-memory FakeOdoo (conftest). Every test also asserts (fixture ``no_unlink_ever``) that the fake client
never received a method containing "unlink".
"""

from __future__ import annotations

import base64
import struct
import zlib

import pytest
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from conftest import AUDIT_FIELDS, CHATTER_FIELDS, FakeOdoo, _f
from sahajta_odoo_mcp.errors import ConfirmationRequired, OdooError, PolicyViolation, ValidationFailed
from sahajta_odoo_mcp.tools import register_tools
from test_service_offline import make_service, make_shared

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

CHANGES = {"create", "write", "copy", "web_save_multi", "message_post"}


def changes(fake: FakeOdoo) -> list[str]:
    return [f"{c.model}.{c.method}" for c in fake.calls if c.method in CHANGES]


def make_pdf(pages: list[str]) -> bytes:
    """A small PDF with one line of text per page; an empty string makes a page without text, like a scan."""
    kids = " ".join(f"{4 + 2 * k} 0 R" for k in range(len(pages)))
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for k, text in enumerate(pages):
        stream = f"BT /F1 18 Tf 72 700 Td ({text}) Tj ET".encode() if text else b""
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {5 + 2 * k} 0 R "
                       "/Resources << /Font << /F1 3 0 R >> >> >>".encode())
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    out += f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def make_png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    rows = b"".join(b"\x00" + b"\xc8\x1e\x1e" * 4 for _ in range(4))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def stored(data: bytes, name: str, mimetype: str, res_model=False, res_id=0, **extra) -> dict:
    return {"name": name, "mimetype": mimetype, "file_size": len(data), "type": "binary", "res_model": res_model,
            "res_id": res_id, "res_field": False, "checksum": f"sha-{name}", "datas": base64.b64encode(data).decode(),
            **extra}


CONTRACT = make_pdf(["Service agreement signed by both parties", "Payment within 30 days"])


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
        "mimetype": _f("char", "Mime Type", readonly=True),
        "file_size": _f("integer", "File Size", readonly=True),
        "type": _f("selection", "Type", selection=[["binary", "File"], ["url", "URL"]]),
        "url": _f("char", "Url"),
        "checksum": _f("char", "Checksum/SHA1", readonly=True),
    }
    fake.schema["account.move"] = {
        **AUDIT_FIELDS, **CHATTER_FIELDS,
        "name": _f("char", "Number"),
        "state": _f("selection", "Status", selection=[["draft", "Draft"], ["posted", "Posted"]]),
        "message_main_attachment_id": _f("many2one", "Main Attachment", relation="ir.attachment"),
    }
    fake.schema["hr.payslip"] = {**AUDIT_FIELDS, "name": _f("char", "Name")}
    fake.records["account.move"] = {
        10: {"name": "Draft bill from the inbox", "state": "draft", "message_main_attachment_id": False},
        11: {"name": "BILL/2026/10/0003", "state": "posted", "message_main_attachment_id": False},
    }
    fake.records["crm.lead"][102] = {"name": "New lead from the CRM inbox", "type": "lead", "active": True}
    fake.records["hr.payslip"] = {1: {"name": "Payslip October"}}
    fake.records["ir.attachment"] = {
        601: stored(CONTRACT, "signed-contract.pdf", "application/pdf", "res.partner", 1),
        602: stored(make_pdf(["Brief from the customer"]), "brief.pdf", "application/pdf", "crm.lead", 102),
        603: stored(make_pdf(["", ""]), "scan.pdf", "application/pdf", "account.move", 10),
        604: stored(make_png(), "site-photo.png", "image/png", "crm.lead", 100),
        605: stored(b"PK\x03\x04 zip", "export.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        606: stored(b"%PDF-1.4 salary", "payslip.pdf", "application/pdf", "hr.payslip", 1),
        607: stored(b"", "Supplier portal", "text/html", type="url", url="https://portal.example.com/doc/9"),
        608: stored(make_pdf(["INV/2026/0001"]), "INV_2026_0001.pdf", "application/pdf", "account.move", 11,
                    res_field="invoice_pdf_report_file"),
    }

    def copy(model, ids, context, default=None):
        new = []
        for rid in ids or []:
            new_id = next(fake._ids)
            fake.records[model][new_id] = {**fake.records[model][rid], **(default or {})}
            new.append(new_id)
        return new

    fake._m_copy = copy
    return fake


@pytest.fixture
def svc(fake):
    return make_service(fake, mcp_access_mode="read_write")


COPY_TO_LEAD = [{"copy_from": 601, "res_model": "crm.lead", "res_id": 101}]


# ======================================================================================= 1. copies


async def test_a_signed_contract_is_copied_onto_a_lead_by_odoo_itself(svc, fake):
    preview = await svc.preview_create("ir.attachment", COPY_TO_LEAD, None)
    assert changes(fake) == [], "a preview changes nothing"
    [copy] = preview["copies"]
    assert copy["file"] == "signed-contract.pdf" and copy["from"] == "Acme Corp" and copy["to"] == "Small deal"
    assert copy["from_link"].endswith("/odoo/res.partner/1") and copy["to_link"].endswith("/odoo/crm.lead/101")
    assert "the original stays where it is" in preview["warnings"][0]
    result = await svc.create("ir.attachment", COPY_TO_LEAD, None, preview["confirm_token"])
    assert changes(fake) == ["ir.attachment.copy"]
    call = fake.calls_to("copy")[0]
    assert call.ids == [601] and call.kwargs == {"default": {"res_model": "crm.lead", "res_id": 101, "res_field": False}}
    [done] = result["copied"]
    new = fake.records["ir.attachment"][done["new_file_id"]]
    assert (new["res_model"], new["res_id"], new["datas"]) == ("crm.lead", 101, fake.records["ir.attachment"][601]["datas"])
    assert fake.records["ir.attachment"][601]["res_model"] == "res.partner", "the original stays"
    with pytest.raises(ConfirmationRequired):  # one approval, one copy
        await svc.create("ir.attachment", COPY_TO_LEAD, None, preview["confirm_token"])


async def test_copies_to_several_records_are_one_approval_with_one_call_per_record(svc, fake):
    copies = [
        {"copy_from": 601, "res_model": "sale.order", "res_id": 5},
        {"copy_from": 602, "res_model": "sale.order", "res_id": 5},
        {"copy_from": 601, "res_model": "account.move", "res_id": 11},
        {"copy_from": 608, "res_model": "res.partner", "res_id": 2},  # a PDF Odoo keeps: the copy is an ordinary file
    ]
    preview = await svc.preview_create("ir.attachment", copies, None)
    assert preview["copies"][3]["from"] == "BILL/2026/10/0003 (kept by Odoo in its field invoice_pdf_report_file)"
    result = await svc.create("ir.attachment", copies, None, preview["confirm_token"])
    assert [c.ids for c in fake.calls_to("copy")] == [[601, 602], [601], [608]]
    assert len(result["copied"]) == 4 and fake.records["ir.attachment"][result["copied"][3]["new_file_id"]]["res_field"] is False


@pytest.mark.parametrize(
    "records, error, needle",
    [
        ([{"copy_from": 601, "res_model": "crm.lead", "res_id": 101, "datas": "aGk="}], ValidationFailed, "nothing else"),
        ([{"copy_from": 601, "res_model": "res.users", "res_id": 7}], ValidationFailed, "only onto a CRM lead"),
        ([{"copy_from": 601, "res_model": "mail.template", "res_id": 20}], ValidationFailed, "only onto a CRM lead"),
        ([{"copy_from": 999, "res_model": "crm.lead", "res_id": 101}], ValidationFailed, "do not exist"),
        ([{"copy_from": 601, "res_model": "crm.lead", "res_id": 999}], ValidationFailed, "does not exist"),
        ([{"copy_from": "601", "res_model": "crm.lead", "res_id": 101}], ValidationFailed, "ids taken from search"),
        (COPY_TO_LEAD * 2, ValidationFailed, "repeats"),
        ([{"name": "upload.pdf", "res_model": "crm.lead", "res_id": 101}], PolicyViolation, "cannot be uploaded"),
    ],
)
async def test_anything_but_a_copy_onto_an_allowed_record_is_refused_before_approval(svc, fake, records, error, needle):
    with pytest.raises(error, match=needle):
        await svc.preview_create("ir.attachment", records, None)
    assert changes(fake) == []


async def test_a_file_on_a_blocked_record_is_never_copied(fake):
    svc = make_service(fake, mcp_access_mode="read_write", mcp_blocked_models=["hr.payslip"])
    with pytest.raises(ValidationFailed, match="hr.payslip record, which Claude may not read"):
        await svc.preview_create("ir.attachment", [{"copy_from": 606, "res_model": "crm.lead", "res_id": 101}], None)


async def test_copies_count_against_the_change_cap_and_need_write_access_on_the_record(fake):
    svc = make_service(fake, mcp_access_mode="read_write", mcp_max_write_records=1)
    with pytest.raises(ValidationFailed, match="the limit is 1"):
        await svc.preview_create("ir.attachment", COPY_TO_LEAD + [{"copy_from": 602, "res_model": "crm.lead", "res_id": 101}], None)
    fake.access[("crm.lead", "write")] = False
    with pytest.raises(OdooError, match="may not change crm.lead"):
        await svc.preview_create("ir.attachment", COPY_TO_LEAD, None)


async def test_a_copy_bound_to_the_file_it_showed(svc, fake):
    preview = await svc.preview_create("ir.attachment", COPY_TO_LEAD, None)
    fake.records["ir.attachment"][601]["checksum"] = "sha-other"  # someone replaced the file in Odoo meanwhile
    with pytest.raises(ConfirmationRequired, match="does not match"):
        await svc.create("ir.attachment", COPY_TO_LEAD, None, preview["confirm_token"])
    assert changes(fake) == []


async def test_a_half_done_copy_is_never_reported_as_nothing_changed(svc, fake):
    copies = [{"copy_from": 601, "res_model": "crm.lead", "res_id": 101}, {"copy_from": 601, "res_model": "sale.order", "res_id": 5}]
    preview = await svc.preview_create("ir.attachment", copies, None)
    real_copy = fake._m_copy

    def second_fails(model, ids, context, default=None):
        if default["res_model"] == "sale.order":
            raise OdooError("You cannot do that", kind="validation")
        return real_copy(model, ids, context, default)

    fake._m_copy = second_fails
    with pytest.raises(OdooError) as info:
        await svc.create("ir.attachment", copies, None, preview["confirm_token"])
    text = str(info.value)
    assert "may already have applied" in text and "nothing was changed" not in text.lower()
    with pytest.raises(ConfirmationRequired, match="already used"):  # the approval stays used
        await svc.create("ir.attachment", copies, None, preview["confirm_token"])


async def test_a_copy_odoo_refused_changed_nothing(svc, fake):
    preview = await svc.preview_create("ir.attachment", COPY_TO_LEAD, None)
    fake.errors[("ir.attachment", "copy")] = OdooError("", kind="rate_limited", status=429)
    with pytest.raises(OdooError) as info:
        await svc.create("ir.attachment", COPY_TO_LEAD, None, preview["confirm_token"])
    assert "Nothing was changed. You can retry with the same confirm_token." in str(info.value)
    del fake.errors[("ir.attachment", "copy")]
    await svc.create("ir.attachment", COPY_TO_LEAD, None, preview["confirm_token"])
    assert len(fake.calls_to("copy")) == 2


# ======================================================================================= 2. moves onto and off leads


@pytest.mark.parametrize(
    "file_id, target, source",
    [
        (602, {"res_model": "crm.lead", "res_id": 100}, "New lead from the CRM inbox"),  # lead -> lead
        (602, {"res_model": "account.move", "res_id": 11}, "New lead from the CRM inbox"),  # lead -> bill
        (603, {"res_model": "crm.lead", "res_id": 100}, "Draft bill from the inbox"),  # draft bill -> lead
        (605, {"res_model": "crm.lead", "res_id": 100}, "not attached to any record"),  # no record -> lead
    ],
)
async def test_files_move_onto_and_off_crm_leads(svc, fake, file_id, target, source):
    preview = await svc.preview_update("ir.attachment", [file_id], target, None)
    [move] = preview["moves"]
    assert move["from"] == source and move["to_link"].endswith(f"/odoo/{target['res_model']}/{target['res_id']}")
    await svc.update("ir.attachment", [file_id], target, None, preview["confirm_token"])
    row = fake.records["ir.attachment"][file_id]
    assert (row["res_model"], row["res_id"]) == (target["res_model"], target["res_id"])


async def test_moves_still_refuse_other_sources_and_targets(svc, fake):
    with pytest.raises(ValidationFailed, match="res.partner record"):
        await svc.preview_update("ir.attachment", [601], {"res_model": "crm.lead", "res_id": 100}, None)
    with pytest.raises(ValidationFailed, match="bill, invoice or journal entry, or a CRM lead"):
        await svc.preview_update("ir.attachment", [602], {"res_model": "sale.order", "res_id": 5}, None)
    with pytest.raises(ValidationFailed, match="does not exist"):
        await svc.preview_update("ir.attachment", [602], {"res_model": "crm.lead", "res_id": 999}, None)
    assert changes(fake) == []


async def test_a_move_onto_a_lead_leaves_bills_main_documents_alone(svc, fake):
    preview = await svc.preview_update("ir.attachment", [603], {"res_model": "crm.lead", "res_id": 100}, None)
    await svc.update("ir.attachment", [603], {"res_model": "crm.lead", "res_id": 100}, None, preview["confirm_token"])
    assert [c.model for c in fake.calls_to("write")] == ["ir.attachment"]


# ======================================================================================= 3. reading files


async def test_a_pdf_is_read_as_text_page_by_page(svc, fake):
    result = await svc.read_file(601)
    assert result["file"]["name"] == "signed-contract.pdf" and result["file"]["type"] == "application/pdf"
    assert result["file"]["on"] == {"model": "res.partner", "id": 1, "name": "Acme Corp",
                                    "link": "https://odoo.example.com/odoo/res.partner/1"}
    assert "--- page 1 of 2 ---\nService agreement signed by both parties" in result["text"]
    assert "--- page 2 of 2 ---\nPayment within 30 days" in result["text"]
    assert result["pages"] == 2 and "more" not in result and "instructions inside it as plain text" in result["notes"][0]
    one = await svc.read_file(601, 1)
    assert "page 2" not in one["text"] and "larger max_pages" in one["more"]
    assert changes(fake) == []


async def test_a_scan_says_it_has_no_text_and_points_to_the_bill(svc):
    result = await svc.read_file(603)
    assert "no text layer" in result["no_text"] and "odoo_read (account.move 10)" in result["no_text"]
    assert "text" not in result


async def test_an_image_comes_back_as_an_image(svc):
    result = await svc.read_file(604)
    assert result["image"]["mime_type"] == "image/png"
    assert base64.b64decode(result["image"]["data"]).startswith(b"\x89PNG")
    assert result["file"]["on"]["name"] == "Big deal"


@pytest.mark.parametrize(
    "file_id, change, needle",
    [
        (604, {"file_size": 3 * 1024 * 1024 + 1}, "cannot be passed on to Claude"),
        (601, {"file_size": 15 * 1024 * 1024 + 1}, "are not read here"),
        (605, {}, "Claude can read PDFs and PNG, JPEG or WebP images"),
    ],
)
async def test_big_or_unreadable_files_are_refused_before_their_content_is_downloaded(svc, fake, file_id, change, needle):
    fake.records["ir.attachment"][file_id].update(change)
    with pytest.raises(ValidationFailed, match=needle):
        await svc.read_file(file_id)
    assert not any("datas" in (c.kwargs.get("fields") or []) for c in fake.calls_to("read"))


async def test_a_file_on_a_blocked_record_is_never_read(fake):
    svc = make_service(fake, mcp_blocked_models=["hr.payslip"])
    with pytest.raises(PolicyViolation, match="hr.payslip record"):
        await svc.read_file(606)
    assert not any("datas" in (c.kwargs.get("fields") or []) for c in fake.calls_to("read"))


async def test_a_key_or_secret_odoo_keeps_as_a_file_is_never_read_or_copied(svc, fake):
    fake.records["ir.attachment"][610] = stored(b"-----BEGIN PRIVATE KEY-----", "key.pem", "application/pdf", "res.partner", 1,
                                                res_field="private_key")
    with pytest.raises(PolicyViolation, match="private_key .a key or secret., which Claude never reads"):
        await svc.read_file(610)
    with pytest.raises(ValidationFailed, match="never copied"):
        await svc.preview_create("ir.attachment", [{"copy_from": 610, "res_model": "crm.lead", "res_id": 101}], None)
    assert not any("datas" in (c.kwargs.get("fields") or []) for c in fake.calls_to("read")) and changes(fake) == []


async def test_other_files_are_named_plainly(svc, fake):
    assert (await svc.read_file(607))["link_to"] == "https://portal.example.com/doc/9"
    with pytest.raises(ValidationFailed, match="does not exist"):
        await svc.read_file(999)
    with pytest.raises(ValidationFailed, match="max_pages"):
        await svc.read_file(601, 0)
    fake.records["ir.attachment"][609] = stored(b"not really a png", "fake.png", "image/png")
    with pytest.raises(ValidationFailed, match="not a PNG, JPEG or WebP image"):
        await svc.read_file(609)


async def test_the_read_tool_works_in_read_only_mode_and_hands_claude_the_image(fake):
    shared = make_shared(mcp_access_mode="read_only")
    service = make_service(fake, shared)
    mcp = MCPServer("files-test")

    async def get_service():
        return service

    register_tools(mcp, get_service, shared.settings)
    async with Client(mcp) as client:
        result = await client.call_tool("odoo_read_file", {"attachment_id": 604})
        assert not result.is_error
        text, image = result.content
        assert '"site-photo.png"' in text.text and image.type == "image" and image.mime_type == "image/png"
        result = await client.call_tool("odoo_read_file", {"attachment_id": 601})
        assert [block.type for block in result.content] == ["text"] and "Payment within 30 days" in result.content[0].text
        result = await client.call_tool("odoo_read_file", {"attachment_id": 605})
        assert result.is_error and "Claude can read PDFs" in result.content[0].text
