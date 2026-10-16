"""Formatter: what the AI gets back. No secrets, no blobs, unambiguous values, bounded size."""

from __future__ import annotations

import json
from zoneinfo import ZoneInfo

import pytest

from sahajta_odoo_mcp.formatting import MAX_X2MANY_IDS, UNTRUSTED_NOTE, Formatter, html_to_text


def fmt(tz: str = "Asia/Kolkata", max_text: int = 4000, max_response: int = 120_000) -> Formatter:
    return Formatter(zone=ZoneInfo(tz), max_text_chars=max_text, max_response_chars=max_response)


M2O = {"type": "many2one", "relation": "res.partner"}


# ------------------------------------------------------------------------------- scalars


@pytest.mark.parametrize("ftype", ["char", "text", "many2one", "date", "datetime", "selection", "html", "float", "monetary"])
def test_odoo_false_means_empty_for_non_booleans(ftype):
    assert fmt().value({"type": ftype}, False) is None
    assert fmt().value({"type": ftype}, None) is None


def test_booleans_keep_false():
    f = fmt()
    assert f.value({"type": "boolean"}, False) is False
    assert f.value({"type": "boolean"}, True) is True
    assert f.value({"type": "boolean"}, None) is False


def test_zero_numbers_are_not_turned_into_null():
    f = fmt()
    assert f.value({"type": "integer"}, 0) == 0
    assert f.value({"type": "float"}, 0.0) == 0.0
    assert f.value({"type": "monetary"}, 0.0) == 0.0


def test_many2one_becomes_id_and_name():
    f = fmt()
    assert f.value(M2O, [3, "Globex"]) == {"id": 3, "name": "Globex"}
    assert f.value(M2O, (3, "Globex")) == {"id": 3, "name": "Globex"}
    assert f.value(M2O, 3) == {"id": 3}
    assert f.value(M2O, False) is None


def test_unknown_field_meta_passes_values_through():
    assert fmt().value(None, 5) == 5
    assert fmt().value({}, "x") == "x"


def test_selection_values_are_unchanged():
    assert fmt().value({"type": "selection"}, "sale") == "sale"


# ------------------------------------------------------------------------------- x2many


def test_x2many_short_lists_are_kept():
    assert fmt().value({"type": "many2many"}, [1, 2, 3]) == [1, 2, 3]
    assert fmt().value({"type": "one2many"}, []) == []


@pytest.mark.parametrize("ftype", ["one2many", "many2many"])
def test_x2many_long_lists_are_truncated_with_total(ftype):
    ids = list(range(1, 251))
    out = fmt().value({"type": ftype}, ids)
    assert out == {"ids": ids[:MAX_X2MANY_IDS], "total": 250, "truncated": True}


# ------------------------------------------------------------------------------- binary


@pytest.mark.parametrize("ftype", ["binary", "image"])
def test_binary_content_is_never_returned(ftype):
    blob = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk" * 50
    out = fmt().value({"type": ftype}, blob)
    assert out == "<file omitted>"
    assert blob[:30] not in json.dumps(out)


def test_binary_size_hint_is_kept_when_odoo_sends_bin_size():
    assert fmt().value({"type": "binary"}, "12.50 Kb") == "<file omitted (12.50 Kb)>"


# ------------------------------------------------------------------------------- html and text


def test_html_to_text():
    html = "<p>Hello <b>Bob</b><br/>Line two</p><p>A &amp; B &lt;tag&gt;</p><ul><li>one</li><li>two</li></ul>"
    assert html_to_text(html) == "Hello Bob\nLine two\nA & B <tag>\none\ntwo"


def test_html_field_scripts_become_inert_text():
    out = fmt().value({"type": "html"}, "<p>Hi</p><script>alert('x')</script><img src=x onerror=alert(1)>")
    assert "<script" not in out and "<img" not in out
    assert "Hi" in out


def test_html_collapses_whitespace_and_blank_lines():
    assert html_to_text("<p>a</p>\n\n\n\n<p>b</p>   c\t\td") == "a\n\nb\n c d"


def test_long_text_is_truncated_with_a_marker():
    f = fmt(max_text=200)
    out = f.value({"type": "text"}, "x" * 500)
    assert out.startswith("x" * 200)
    assert "truncated, 300 more characters" in out
    assert f.value({"type": "char"}, "x" * 200) == "x" * 200


def test_long_html_is_truncated_after_conversion():
    out = fmt(max_text=200).value({"type": "html"}, "<p>" + "y" * 1000 + "</p>")
    assert out.startswith("y" * 200) and "truncated, 800 more characters" in out


# ------------------------------------------------------------------------------- datetimes


@pytest.mark.parametrize(
    "tz, utc, expected",
    [
        ("Asia/Kolkata", "2026-07-01 08:00:00", "2026-07-01T13:30:00+05:30"),
        ("Europe/Berlin", "2026-07-01 08:00:00", "2026-07-01T10:00:00+02:00"),  # CEST
        ("Europe/Berlin", "2026-01-15 08:00:00", "2026-01-15T09:00:00+01:00"),  # CET
        ("America/New_York", "2026-03-08 06:59:59", "2026-03-08T01:59:59-05:00"),  # just before the DST jump
        ("America/New_York", "2026-03-08 07:00:00", "2026-03-08T03:00:00-04:00"),
        ("UTC", "2026-07-01 08:00:00", "2026-07-01T08:00:00+00:00"),
        ("Asia/Kolkata", "2026-07-01 08:00:00.123456", "2026-07-01T13:30:00+05:30"),
    ],
)
def test_datetimes_are_shown_in_local_time_with_offset(tz, utc, expected):
    assert fmt(tz).value({"type": "datetime"}, utc) == expected


def test_unparseable_datetime_is_passed_through():
    assert fmt().value({"type": "datetime"}, "not a date") == "not a date"


def test_dates_are_not_shifted():
    assert fmt("America/New_York").value({"type": "date"}, "2026-07-01") == "2026-07-01"


# ------------------------------------------------------------------------------- records


def test_record_drops_sensitive_keys_even_if_odoo_returned_them():
    meta = {"name": {"type": "char"}, "partner_id": M2O, "password": {"type": "char"}}
    row = {
        "id": 1,
        "name": "Acme",
        "partner_id": [3, "Globex"],
        "password": "hunter2",
        "api_key_ids": [1],
        "signup_token": "abc",
        "access_token": "tok",
        "totp_secret": "JBSW",
    }
    out = fmt().record(row, meta)
    assert out == {"id": 1, "name": "Acme", "partner_id": {"id": 3, "name": "Globex"}}
    assert "hunter2" not in json.dumps(out)


def test_records_handles_none():
    assert fmt().records(None, {}) == []


# ------------------------------------------------------------------------------- fit()


def test_fit_leaves_small_payloads_alone():
    payload = {"records": [{"id": 1}], "notes": [UNTRUSTED_NOTE]}
    assert fmt().fit(payload) is payload
    assert "truncated_for_size" not in payload


def test_fit_ignores_payloads_without_a_list():
    payload = {"records": "nope", "big": "x" * 500_000}
    assert fmt(max_response=10_000).fit(payload) is payload


def test_fit_trims_trailing_items_and_explains():
    budget = 10_000
    records = [{"id": i, "name": f"record {i}", "blob": "z" * 1000} for i in range(100)]
    payload = {"model": "crm.lead", "records": records, "notes": [UNTRUSTED_NOTE]}
    out = fmt(max_response=budget).fit(payload)

    assert out["truncated_for_size"] is True
    kept = out["records"]
    assert 0 < len(kept) < 100
    assert kept == records[: len(kept)], "must keep a prefix, in order"
    assert any(f"Only {len(kept)} of 100 items" in note for note in out["notes"])
    assert UNTRUSTED_NOTE in out["notes"], "the untrusted-data warning must survive trimming"
    # the list itself fits the budget; the added note/flag may add a few hundred characters
    assert len(json.dumps({**payload, "records": kept})) <= budget
    assert len(json.dumps(out)) <= budget + 500


def test_fit_with_custom_list_key():
    groups = [{"stage": f"s{i}", "count": i, "pad": "p" * 500} for i in range(200)]
    out = fmt(max_response=10_000).fit({"groups": groups}, "groups")
    assert out["truncated_for_size"] is True and len(out["groups"]) < 200


def test_fit_with_one_giant_item_returns_no_items_rather_than_overflowing():
    out = fmt(max_response=10_000).fit({"records": [{"id": 1, "blob": "x" * 50_000}]})
    assert out["records"] == [] and out["truncated_for_size"] is True
