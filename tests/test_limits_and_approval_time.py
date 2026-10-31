"""How many records one change may touch, how long previews stay readable, and how long an approval lasts.

Create and edit: up to mcp_max_write_records (default 100). Buttons, dialogs and deleting: up to
mcp_max_action_records (default 20). An approval is usable for mcp_confirm_ttl_seconds (default one hour); a record
changed since the preview still voids it.
"""

from __future__ import annotations

import pytest

from conftest import FakeOdoo, build_settings
from sahajta_odoo_mcp import confirm as confirm_module
from sahajta_odoo_mcp.confirm import DEFAULT_TTL_SECONDS, ConfirmationSigner, duration_text
from sahajta_odoo_mcp.errors import ConfirmationRequired, ValidationFailed
from sahajta_odoo_mcp.server import build_shared
from sahajta_odoo_mcp.service import OdooService
from test_service_offline import changes, make_service

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

LIMITS = dict(mcp_max_write_records=100, mcp_max_action_records=20)  # the defaults (SAFE_DEFAULTS lowers the first)


@pytest.fixture
def clock(monkeypatch):
    now = {"t": 1_800_000_000.0}
    monkeypatch.setattr(confirm_module.time, "time", lambda: now["t"])
    return now


def leads(fake: FakeOdoo, count: int) -> list[int]:
    for rid in range(1000, 1000 + count):
        fake.records["crm.lead"][rid] = {"name": f"Lead {rid}", "type": "lead", "expected_revenue": 10.0,
                                         "active": True, "write_date": "2026-10-15 10:00:00"}
    return list(range(1000, 1000 + count))


def quotations(fake: FakeOdoo, count: int) -> list[int]:
    for rid in range(500, 500 + count):
        fake.records["sale.order"][rid] = {"name": f"S{rid:05d}", "partner_id": [1, "Acme Corp"], "state": "draft",
                                           "order_line": [], "write_date": "2026-10-15 10:00:00"}
    return list(range(500, 500 + count))


# ====================================================================================== how long an approval lasts


def test_an_approval_lasts_one_hour_by_default():
    assert DEFAULT_TTL_SECONDS == 3600
    assert ConfirmationSigner(b"k" * 32).valid_for == "1 hour"


@pytest.mark.parametrize("seconds, text", [(3600, "1 hour"), (7200, "2 hours"), (5400, "90 minutes"),
                                           (60, "1 minute"), (900, "15 minutes")])
def test_the_time_is_said_in_words(seconds, text):
    assert duration_text(seconds) == text


async def test_an_approval_given_59_minutes_after_the_preview_still_applies(clock):
    fake = FakeOdoo()
    svc = make_service(fake)
    preview = await svc.preview_update("crm.lead", [100], {"expected_revenue": 5000}, None)
    assert "valid 1 hour" in preview["next_step"]
    clock["t"] += 59 * 60
    await svc.update("crm.lead", [100], {"expected_revenue": 5000}, None, preview["confirm_token"])
    assert changes(fake) == ["crm.lead.write"]


async def test_an_approval_older_than_one_hour_is_refused_and_nothing_changes(clock):
    fake = FakeOdoo()
    svc = make_service(fake)
    preview = await svc.preview_update("crm.lead", [100], {"expected_revenue": 5000}, None)
    clock["t"] += 61 * 60
    with pytest.raises(ConfirmationRequired, match=r"expired \(1 hour\)") as info:
        await svc.update("crm.lead", [100], {"expected_revenue": 5000}, None, preview["confirm_token"])
    assert "Nothing was changed" in str(info.value) and changes(fake) == []


async def test_within_the_hour_a_record_changed_since_the_preview_still_voids_the_approval(clock):
    fake = FakeOdoo()
    svc = make_service(fake)
    preview = await svc.preview_update("crm.lead", [100], {"expected_revenue": 5000}, None)
    clock["t"] += 10 * 60
    fake.touch("crm.lead", 100, expected_revenue=2000.0)  # someone edits it in Odoo meanwhile
    with pytest.raises(ConfirmationRequired, match="modified in Odoo since the preview"):
        await svc.update("crm.lead", [100], {"expected_revenue": 5000}, None, preview["confirm_token"])
    assert changes(fake) == []


async def test_the_server_uses_the_configured_time_everywhere(clock):
    settings = build_settings(mcp_access_mode="read_write", mcp_confirm_ttl_seconds=7200)
    shared = build_shared(settings, b"k" * 32, http=object())
    fake = FakeOdoo()
    svc = OdooService(shared, fake, fake.identity_obj)
    create = await svc.preview_create("crm.lead", [{"name": "x", "type": "lead"}], None)
    update = await svc.preview_update("crm.lead", [100], {"expected_revenue": 5000}, None)
    assert "valid 2 hours" in create["next_step"] and "valid 2 hours" in update["next_step"]
    assert int(update["confirm_token"].partition(".")[0]) == int(clock["t"]) + 7200
    assert (await svc.whoami())["permissions"]["approval_valid_for"] == "2 hours"


# ====================================================================================== how many records


async def test_one_edit_takes_up_to_100_records():
    fake = FakeOdoo()
    svc = make_service(fake, **LIMITS)
    ids = leads(fake, 101)
    preview = await svc.preview_update("crm.lead", ids[:100], {"expected_revenue": 50}, None)
    await svc.update("crm.lead", ids[:100], {"expected_revenue": 50}, None, preview["confirm_token"])
    with pytest.raises(ValidationFailed, match="the limit is 100"):
        await svc.preview_update("crm.lead", ids, {"expected_revenue": 50}, None)


async def test_one_create_takes_up_to_100_records():
    svc = make_service(FakeOdoo(), **LIMITS)
    records = [{"name": f"Lead {n}", "type": "lead"} for n in range(101)]
    assert len((await svc.preview_create("crm.lead", records[:100], None))["records"]) == 100
    with pytest.raises(ValidationFailed, match="the limit is 100"):
        await svc.preview_create("crm.lead", records, None)


async def test_a_button_takes_up_to_20_records_although_an_edit_takes_100():
    fake = FakeOdoo()
    svc = make_service(fake, **LIMITS)
    ids = quotations(fake, 21)
    assert (await svc.preview_action("sale.order", ids[:20], "action_confirm", None))["confirm_token"]
    with pytest.raises(ValidationFailed, match="too many records at once"):
        await svc.preview_action("sale.order", ids, "action_confirm", None)
    with pytest.raises(ValidationFailed, match="too many records at once"):
        await svc.run_action("sale.order", ids, "action_confirm", None, "4102444800.forged")
    assert changes(fake) == []


# ====================================================================================== long previews


async def test_a_long_create_preview_shows_one_line_per_record():
    fake = FakeOdoo()
    svc = make_service(fake, **LIMITS)
    records = [{"name": f"Lead {n}", "type": "lead", "expected_revenue": n} for n in range(1, 31)]
    preview = await svc.preview_create("crm.lead", records, None)
    assert len(preview["records"]) == 30 and all(isinstance(line, str) for line in preview["records"])
    assert preview["records"][29].startswith("30. ") and "Lead 30" in preview["records"][29]
    assert "first 20 records" in str(preview["warnings"])
    # Odoo's own form (onchange) is asked for the first 20 records only, so the preview stays quick
    assert len(fake.calls_to("onchange")) <= 20
    done = await svc.create("crm.lead", records, None, preview["confirm_token"])
    assert len(done["created"]) == 30


async def test_a_long_edit_preview_shows_the_new_values_once_and_one_line_per_record():
    fake = FakeOdoo()
    svc = make_service(fake, **LIMITS)
    ids = leads(fake, 30)
    preview = await svc.preview_update("crm.lead", ids, {"expected_revenue": 50}, None)
    [group] = preview["changes"]
    assert len(group["records"]) == 30 and group["records"][0].startswith("Lead 1000 (id 1000): now ")
    assert "/odoo/crm.lead/<id>" in preview["links"]
    short = await svc.preview_update("crm.lead", ids[:20], {"expected_revenue": 50}, None)
    assert len(short["changes"]) == 20 and short["changes"][0]["link"].endswith("/odoo/crm.lead/1000")


async def test_a_preview_too_long_to_show_whole_is_refused():
    fake = FakeOdoo()
    svc = make_service(fake, mcp_max_response_chars=10_000, **LIMITS)
    records = [{"name": "x" * 300 + f" {n}", "type": "lead"} for n in range(60)]
    with pytest.raises(ValidationFailed, match="too long to show in one answer") as info:
        await svc.preview_create("crm.lead", records, None)
    assert "smaller parts" in str(info.value) and changes(fake) == []
