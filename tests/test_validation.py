"""Validator: anti-hallucination checks and relational-command safety, against a fake Odoo schema."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError as PydanticValidationError

from conftest import FakeOdoo, build_settings
from sahajta_odoo_mcp.errors import OdooError, PolicyViolation, ValidationFailed
from sahajta_odoo_mcp.policy import SafetyPolicy
from sahajta_odoo_mcp.schema import REFRESH_MIN_SECONDS, SchemaCache
from sahajta_odoo_mcp.state import MemoryState
from sahajta_odoo_mcp.validation import (
    MAX_DOMAIN_TERMS,
    MAX_IDS_PER_COMMAND,
    MAX_VALUES_PER_RECORD,
    Validator,
    suggest,
    to_utc_string,
    user_zone,
)

pytestmark = pytest.mark.usefixtures("no_unlink_ever")


def make_validator(
    fake: FakeOdoo | None = None, tz: str = "Europe/Berlin", schema: SchemaCache | None = None, **settings
) -> Validator:
    fake = fake or FakeOdoo()
    policy = SafetyPolicy(build_settings(mcp_access_mode="read_write", **settings))
    return Validator(client=fake, schema=schema or SchemaCache(), policy=policy, tz=tz)


@pytest.fixture
def fake() -> FakeOdoo:
    return FakeOdoo()


@pytest.fixture
def v(fake) -> Validator:
    return make_validator(fake)


async def rejected(coro, *needles: str) -> ValidationFailed:
    with pytest.raises(ValidationFailed) as info:
        await coro
    text = str(info.value)
    for needle in needles:
        assert needle in text, text
    return info.value


# ================================================================================ helpers


def test_user_zone_falls_back_to_utc():
    assert user_zone(None) == ZoneInfo("UTC")
    assert user_zone("") == ZoneInfo("UTC")
    assert user_zone("Not/AZone") == ZoneInfo("UTC")
    assert user_zone("../../etc/passwd") == ZoneInfo("UTC")
    assert user_zone("Asia/Kolkata") == ZoneInfo("Asia/Kolkata")


def test_user_zone_uses_the_default_when_the_user_has_none():
    assert user_zone(None, "Asia/Kolkata") == ZoneInfo("Asia/Kolkata")
    assert user_zone("", "Asia/Kolkata") == ZoneInfo("Asia/Kolkata")
    assert user_zone("Not/AZone", "Asia/Kolkata") == ZoneInfo("Asia/Kolkata")
    assert user_zone("Europe/Berlin", "Asia/Kolkata") == ZoneInfo("Europe/Berlin")  # the user's own zone wins
    assert user_zone("", "Not/AZone") == ZoneInfo("UTC")
    assert user_zone("", None) == ZoneInfo("UTC")


async def test_validator_uses_the_default_time_zone(fake):
    policy = SafetyPolicy(build_settings(mcp_access_mode="read_write"))
    v = Validator(client=fake, schema=SchemaCache(), policy=policy, tz="", default_tz="Asia/Kolkata")
    assert v.zone == ZoneInfo("Asia/Kolkata")
    out = await v.normalize_domain("crm.lead", [["next_call_at", ">=", "2026-10-26 10:00:00"]])
    assert out == [["next_call_at", ">=", "2026-10-26 04:30:00"]]


def test_default_time_zone_setting(monkeypatch):
    monkeypatch.delenv("MCP_DEFAULT_TIMEZONE", raising=False)
    assert build_settings().mcp_default_timezone == "UTC"
    monkeypatch.setenv("MCP_DEFAULT_TIMEZONE", "Asia/Kolkata")
    assert build_settings().mcp_default_timezone == "Asia/Kolkata"
    assert build_settings(mcp_default_timezone=" ").mcp_default_timezone == "UTC"
    for bad in ("India", "../../etc/passwd"):
        with pytest.raises(PydanticValidationError, match="MCP_DEFAULT_TIMEZONE"):
            build_settings(mcp_default_timezone=bad)


@pytest.mark.parametrize(
    "value, tz, expected",
    [
        ("2026-07-01 10:00:00", "Europe/Berlin", "2026-07-01 08:00:00"),  # CEST, UTC+2
        ("2026-01-15 10:00:00", "Europe/Berlin", "2026-01-15 09:00:00"),  # CET, UTC+1
        ("2026-07-01T10:00:00", "Asia/Kolkata", "2026-07-01 04:30:00"),
        ("2026-07-01T10:00:00Z", "Asia/Kolkata", "2026-07-01 10:00:00"),  # explicit UTC wins over the user tz
        ("2026-07-01T10:00:00+05:30", "Europe/Berlin", "2026-07-01 04:30:00"),
        ("2026-07-01T10:00:00-04:00", "Asia/Kolkata", "2026-07-01 14:00:00"),
        ("2026-07-01", "Europe/Berlin", "2026-06-30 22:00:00"),  # date only = local midnight
        ("2026-07-01 10:00", "UTC", "2026-07-01 10:00:00"),
        ("2026-07-01 10:00:00.999", "UTC", "2026-07-01 10:00:00"),
        ("  2026-07-01 10:00:00  ", "UTC", "2026-07-01 10:00:00"),
        # DST edges in Europe/Berlin (2026-03-29 02:00 -> 03:00, 2026-10-25 03:00 -> 02:00)
        ("2026-03-29 01:59:59", "Europe/Berlin", "2026-03-29 00:59:59"),
        ("2026-03-29 03:00:00", "Europe/Berlin", "2026-03-29 01:00:00"),
        ("2026-10-25 02:30:00", "Europe/Berlin", "2026-10-25 00:30:00"),  # ambiguous: first (summer) occurrence
        ("2026-10-25 03:30:00", "Europe/Berlin", "2026-10-25 02:30:00"),
    ],
)
def test_to_utc_string(value, tz, expected):
    assert to_utc_string(value, ZoneInfo(tz)) == expected


def test_nonexistent_local_time_in_dst_gap_is_silently_accepted():
    # 02:30 does not exist in Berlin on 2026-03-29. It is interpreted with the pre-gap offset (UTC+1) instead of
    # being rejected. Documented behaviour, not a safety problem.
    assert to_utc_string("2026-03-29 02:30:00", ZoneInfo("Europe/Berlin")) == "2026-03-29 01:30:00"


@pytest.mark.parametrize("bad", ["", "tomorrow", "2026-13-01", "2026-02-30 10:00:00", "15/10/2026", "2026-07-01 25:00"])
def test_to_utc_string_rejects_garbage(bad):
    with pytest.raises(ValueError):
        to_utc_string(bad, ZoneInfo("UTC"))


def test_suggest_by_name_and_by_label():
    fields = FakeOdoo().schema["crm.lead"]
    assert "stage_id" in suggest("stage_naem", fields)
    assert "partner_id" in suggest("customer", fields)  # label "Customer"
    assert suggest("zzzzzz", fields) == ""


# ================================================================================ schema cache


async def test_schema_cache_adds_id_and_caches_per_user(fake):
    cache = SchemaCache()
    fields = await cache.fields(fake, "crm.tag")
    assert fields["id"]["type"] == "integer" and fields["id"]["readonly"] is True
    await cache.fields(fake, "crm.tag")
    assert len(fake.calls_to("fields_get")) == 1

    other_user = FakeOdoo(uid=8)
    await cache.fields(other_user, "crm.tag")
    assert len(other_user.calls_to("fields_get")) == 1, "field visibility depends on the user's groups"


async def test_schema_cache_unknown_model_is_a_validation_error(fake):
    await rejected(SchemaCache().fields(fake, "crm.leads"), "does not exist")


async def test_schema_cache_other_odoo_errors_propagate(fake):
    fake.errors[("crm.lead", "fields_get")] = OdooError("denied", kind="access")
    with pytest.raises(OdooError):
        await SchemaCache().fields(fake, "crm.lead")


def shared_key(model: str) -> str:
    return f"fields:https://odoo.example.com|testdb|7|{model}"


async def stale_shared_state(fake: FakeOdoo, *models: str) -> MemoryState:
    """Another server instance cached these models' fields in the shared (Redis) cache."""
    state = MemoryState()
    for model in models:
        await SchemaCache(shared=state).fields(fake, model)
    return state


GSTIN = {"type": "char", "string": "GSTIN", "store": True, "readonly": False}


@pytest.mark.parametrize("entry", ["domain", "dotted path", "field list", "values"])
async def test_field_added_in_odoo_is_found_past_stale_caches(fake, entry):
    state = await stale_shared_state(fake, "crm.lead", "res.partner")
    fake.schema["crm.lead"]["x_gstin"] = dict(GSTIN)  # e.g. GST was enabled after caching
    fake.schema["res.partner"]["x_gstin"] = dict(GSTIN)
    v = make_validator(fake, schema=SchemaCache(shared=state))
    calls = {
        "domain": lambda: v.normalize_domain("crm.lead", [["x_gstin", "=", "29ABCDE1234F1Z5"]]),
        "dotted path": lambda: v.normalize_domain("crm.lead", [["partner_id.x_gstin", "=", "29ABCDE1234F1Z5"]]),
        "field list": lambda: v.check_field_names("crm.lead", ["name", "x_gstin"]),
        "values": lambda: v.normalize_values("crm.lead", {"x_gstin": "29ABCDE1234F1Z5"}, mode="create"),
    }
    assert await calls[entry]()
    model = "res.partner" if entry == "dotted path" else "crm.lead"
    assert "x_gstin" in state.get_json(shared_key(model)), "the shared cache is updated too"
    assert len([c for c in fake.calls_to("fields_get") if c.model == model]) == 2


@pytest.mark.parametrize("entry", ["domain", "values"])
async def test_choice_added_in_odoo_is_found_past_stale_caches(fake, entry):
    state = await stale_shared_state(fake, "crm.lead")
    fake.schema["crm.lead"]["priority"]["selection"].append(["4", "Urgent"])
    v = make_validator(fake, schema=SchemaCache(shared=state))
    if entry == "domain":
        assert await v.normalize_domain("crm.lead", [["priority", "=", "Urgent"]]) == [["priority", "=", "4"]]
    else:
        assert await v.normalize_values("crm.lead", {"priority": "4"}, mode="create") == {"priority": "4"}
    assert ["4", "Urgent"] in state.get_json(shared_key("crm.lead"))["priority"]["selection"]


async def test_unknown_names_refetch_fields_at_most_once(fake):
    state = await stale_shared_state(fake, "crm.lead")
    v = make_validator(fake, schema=SchemaCache(shared=state))
    for _ in range(3):
        await rejected(v.normalize_domain("crm.lead", [["x_nope", "=", 1]]), "not a field")
        await rejected(v.normalize_domain("crm.lead", [["priority", "=", "9"]]), "not a valid choice")
        await rejected(v.check_field_names("crm.lead", ["x_nope"]), "not a field")
        await rejected(v.normalize_values("crm.lead", {"priority": "9"}, mode="create"), "not a valid choice")
    assert len(fake.calls_to("fields_get")) == 2  # the other instance's fetch, then a single refetch


async def test_no_refetch_right_after_fetching_from_odoo(v, fake):
    await rejected(v.normalize_domain("crm.lead", [["x_nope", "=", 1]]), "not a field")
    await rejected(v.normalize_domain("crm.lead", [["priority", "=", "9"]]), "not a valid choice")
    assert len(fake.calls_to("fields_get")) == 1


async def test_refetch_is_allowed_again_after_the_quiet_period(fake):
    cache = SchemaCache()
    v = make_validator(fake, schema=cache)
    await v.fields_of("crm.lead")
    fake.schema["crm.lead"]["x_gstin"] = dict(GSTIN)
    await rejected(v.check_field_names("crm.lead", ["x_gstin"]), "not a field")  # fetched moments ago
    (key, (expires, fields, fetched)), = cache._data.items()
    cache._data[key] = (expires, fields, fetched - REFRESH_MIN_SECONDS)
    assert await v.check_field_names("crm.lead", ["x_gstin"]) == ["x_gstin"]


# ================================================================================ field lists


async def test_check_field_names(v):
    assert await v.check_field_names("crm.lead", ["name", "partner_id", "name"]) == ["name", "partner_id"]
    await rejected(v.check_field_names("crm.lead", ["stage_naem"]), "not a field of crm.lead", "Did you mean: stage_id")
    await rejected(v.check_field_names("crm.lead", ["partner_id.name"]), "dotted")
    await rejected(v.check_field_names("crm.lead", ["access_token"]), "credential")
    await rejected(v.check_field_names("res.users", ["login", "password"]), "credential")
    await rejected(v.check_field_names("crm.lead", ["", None, 5]), "invalid field name")
    await rejected(v.check_field_names("crm.lead", "name"), "must be a list")


# ================================================================================ domains


async def test_domain_none_and_empty(v):
    assert await v.normalize_domain("crm.lead", None) == []
    assert await v.normalize_domain("crm.lead", []) == []


async def test_domain_basic_terms_and_prefix_operators(v):
    domain = ["|", ("name", "ILIKE", "acme"), "!", ["probability", ">=", 50], ["tag_ids", "in", [1, 2]]]
    assert await v.normalize_domain("crm.lead", domain) == [
        "|", ["name", "ilike", "acme"], "!", ["probability", ">=", 50], ["tag_ids", "in", [1, 2]],
    ]


@pytest.mark.parametrize(
    "operator",
    ["=", "!=", ">", ">=", "<", "<=", "=?", "like", "not like", "ilike", "not ilike", "=like", "=ilike", "in",
     "not in", "child_of", "parent_of"],
)
async def test_domain_known_operators(v, operator):
    out = await v.normalize_domain("crm.lead", [["name", operator, "x"]])
    assert out == [["name", operator, "x"]]


@pytest.mark.parametrize("operator", ["==", "<>", "~", "regex", "sql", "", None, 1, "inselect", "= ; DROP"])
async def test_domain_unknown_operators_rejected(v, operator):
    await rejected(v.normalize_domain("crm.lead", [["name", operator, "x"]]), "operator")


async def test_domain_dotted_paths_through_relations(v):
    out = await v.normalize_domain("crm.lead", [["partner_id.country_id.code", "=", "IN"]])
    assert out == [["partner_id.country_id.code", "=", "IN"]]


async def test_domain_path_through_non_relation_is_rejected(v):
    await rejected(v.normalize_domain("crm.lead", [["name.length", "=", 3]]), "not a relation")


async def test_domain_path_too_deep(v):
    await rejected(
        v.normalize_domain("res.partner", [["parent_id.parent_id.parent_id.parent_id.name", "=", "x"]]),
        "nested too deeply",
    )


async def test_domain_unknown_field_gets_a_suggestion(v):
    await rejected(v.normalize_domain("crm.lead", [["stage_naem", "=", 1]]), "Did you mean: stage_id")
    await rejected(v.normalize_domain("crm.lead", [["partner_id.nmae", "=", 1]]), "not a field of res.partner")


async def test_domain_path_into_a_blocked_model_is_refused(v):
    with pytest.raises(PolicyViolation):
        await v.normalize_domain("res.users", [["log_ids.create_date", ">", "2026-01-01"]])
    with pytest.raises(PolicyViolation):
        await v.normalize_domain("crm.lead", [["user_id.log_ids.create_date", ">", "2026-01-01"]])
    with pytest.raises(PolicyViolation):
        await v.normalize_domain("crm.lead", [["x_cron_id.name", "=", "x"]])


async def test_domain_path_into_a_configured_blocked_model_is_refused(fake):
    v = make_validator(fake, mcp_blocked_models=["hr.payslip*"])
    fake.schema["hr.payslip"] = {"net_wage": {"type": "monetary"}}
    with pytest.raises(PolicyViolation):
        await v.normalize_domain("crm.lead", [["x_payslip_id.net_wage", ">", 1000]])


@pytest.mark.parametrize(
    "path",
    ["password", "user_id.password", "api_key_ids.name", "access_token", "partner_id.signup_token", "x_api_key"],
)
async def test_domain_sensitive_paths_are_refused(v, path):
    model = "res.users" if path in ("password", "api_key_ids.name") else "crm.lead"
    await rejected(v.normalize_domain(model, [[path, "!=", False]]), "credential")


async def test_domain_any_subdomain(v):
    domain = [["partner_id", "any", [["name", "ilike", "acme"], ["country_id.code", "=", "IN"]]]]
    assert await v.normalize_domain("crm.lead", domain) == [
        ["partner_id", "any", [["name", "ilike", "acme"], ["country_id.code", "=", "IN"]]]
    ]
    out = await v.normalize_domain("crm.lead", [["tag_ids", "not any", [["name", "=", "Hot"]]]])
    assert out == [["tag_ids", "not any", [["name", "=", "Hot"]]]]


async def test_domain_any_subdomain_is_validated_too(v):
    await rejected(v.normalize_domain("crm.lead", [["partner_id", "any", [["nmae", "=", "x"]]]]), "not a field of res.partner")
    await rejected(v.normalize_domain("crm.lead", [["partner_id", "any", [["signup_token", "!=", False]]]]), "credential")
    await rejected(v.normalize_domain("crm.lead", [["partner_id", "any", "name = 'x'"]]), "domain must be a list")
    await rejected(v.normalize_domain("crm.lead", [["name", "any", []]]), "only works on relational")


async def test_domain_any_nesting_is_limited(v):
    inner = [["name", "=", "x"]]
    for _ in range(5):
        inner = [["parent_id", "any", inner]]
    await rejected(v.normalize_domain("res.partner", inner), "nested too deeply")


# Regression test (was a bug, now fixed): BUG: validation.py normalize_domain() does not check_read() the comodel of an 'any'/'not any' term, so a sub-domain can filter on a hard-blocked model (res.users.log) that a dotted path would refuse
async def test_domain_any_into_a_blocked_model_is_refused(v):
    with pytest.raises(PolicyViolation):
        await v.normalize_domain("res.users", [["log_ids", "any", [["create_date", ">", "2026-01-01"]]]])


async def test_domain_datetime_values_are_converted_to_utc(v):
    # Validator tz is Europe/Berlin
    out = await v.normalize_domain(
        "crm.lead",
        [
            ["next_call_at", ">=", "2026-07-01 10:00:00"],
            ["next_call_at", "in", ["2026-01-15 10:00:00", "2026-07-01T10:00:00Z", False]],
            ["next_call_at", "=", False],
            ["date_deadline", "=", "2026-07-01"],  # plain dates are not shifted
        ],
    )
    assert out == [
        ["next_call_at", ">=", "2026-07-01 08:00:00"],
        ["next_call_at", "in", ["2026-01-15 09:00:00", "2026-07-01 10:00:00", False]],
        ["next_call_at", "=", False],
        ["date_deadline", "=", "2026-07-01"],
    ]


async def test_domain_datetime_values_through_paths_are_converted(fake):
    v = make_validator(fake, tz="Asia/Kolkata")
    out = await v.normalize_domain("sale.order.line", [["order_id.date_order", "<", "2026-07-01 05:30:00"]])
    assert out == [["order_id.date_order", "<", "2026-07-01 00:00:00"]]


async def test_domain_invalid_datetime_value_is_rejected(v):
    await rejected(v.normalize_domain("crm.lead", [["next_call_at", ">", "last tuesday"]]), "not a valid date/time")


@pytest.mark.parametrize("day", ["0001-01-01", "9999-12-31"])
async def test_domain_whole_day_at_the_calendar_edges_is_a_validation_error(fake, day):
    v = make_validator(fake, tz="Asia/Kolkata")
    await rejected(v.normalize_domain("crm.lead", [["next_call_at", "=", day]]), "not a valid date/time")


# --------------------------------------------------------------------- whole days on datetime fields


@pytest.fixture
def ist(fake) -> Validator:
    return make_validator(fake, tz="Asia/Kolkata")


@pytest.mark.parametrize(
    "operator, expected",
    [
        # 31 October in India runs from 2026-10-30 18:30 to 2026-10-31 18:30 UTC
        ("<=", [["date_order", "<", "2026-10-31 18:30:00"]]),
        (">", [["date_order", ">=", "2026-10-31 18:30:00"]]),
        ("<", [["date_order", "<", "2026-10-30 18:30:00"]]),
        (">=", [["date_order", ">=", "2026-10-30 18:30:00"]]),
        ("=", ["&", ["date_order", ">=", "2026-10-30 18:30:00"], ["date_order", "<", "2026-10-31 18:30:00"]]),
        ("=?", ["&", ["date_order", ">=", "2026-10-30 18:30:00"], ["date_order", "<", "2026-10-31 18:30:00"]]),
        ("!=", ["!", "&", ["date_order", ">=", "2026-10-30 18:30:00"], ["date_order", "<", "2026-10-31 18:30:00"]]),
    ],
)
async def test_domain_whole_day_on_a_datetime_field(ist, operator, expected):
    assert await ist.normalize_domain("sale.order", [["date_order", operator, "2026-10-31"]]) == expected


async def test_domain_whole_day_through_a_path_and_in_a_subdomain(ist):
    out = await ist.normalize_domain("sale.order.line", [["order_id.date_order", "<=", "2026-10-31"]])
    assert out == [["order_id.date_order", "<", "2026-10-31 18:30:00"]]
    out = await ist.normalize_domain("crm.lead", [["partner_id", "any", [["create_date", "=", "2026-10-26"]]]])
    assert out == [
        ["partner_id", "any", ["&", ["create_date", ">=", "2026-10-25 18:30:00"], ["create_date", "<", "2026-10-26 18:30:00"]]]
    ]


async def test_domain_whole_day_follows_the_local_calendar_across_dst(fake):
    v = make_validator(fake, tz="Europe/Berlin")  # 2026-10-25 has 25 hours in Berlin
    assert await v.normalize_domain("crm.lead", [["create_date", "=", "2026-10-25"]]) == [
        "&", ["create_date", ">=", "2026-10-24 22:00:00"], ["create_date", "<", "2026-10-25 23:00:00"],
    ]


async def test_domain_values_with_a_time_keep_their_meaning(ist):
    assert await ist.normalize_domain("crm.lead", [["create_date", "=", "2026-10-26 10:00:00"]]) == [
        ["create_date", "=", "2026-10-26 04:30:00"]
    ]


@pytest.mark.parametrize(
    "term",
    [
        ["create_date", "in", ["2026-10-26"]],
        ["create_date", "not in", ["2026-10-26 10:00:00", "2026-10-27"]],
        ["create_date", "in", "2026-10-26"],
        ["create_date", "=", ["2026-10-26"]],
        ["create_date", "like", "2026-10-26"],
    ],
)
async def test_domain_whole_days_need_a_range_for_other_operators(ist, term):
    await rejected(ist.normalize_domain("crm.lead", [term]), "Use a range")


def _matches(domain: list, record: dict) -> bool:
    """Evaluates a normalised domain (prefix operators, implicit '&') on one record of UTC strings."""
    compare = {
        "=": lambda a, b: a == b, "!=": lambda a, b: a != b, "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b, ">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
    }

    def operand(pos: int) -> tuple[bool, int]:
        element = domain[pos]
        if element == "!":
            result, pos = operand(pos + 1)
            return not result, pos
        if element in ("&", "|"):
            left, pos = operand(pos + 1)
            right, pos = operand(pos)
            return (left and right) if element == "&" else (left or right), pos
        field, operator, value = element
        return compare[operator](record[field], value), pos + 1

    pos, result = 0, True
    while pos < len(domain):
        found, pos = operand(pos)
        result = result and found
    return result


@pytest.mark.parametrize(
    "domain, wanted",
    [
        ([["create_date", "=", "2026-10-26"]], lambda d: d == 26),
        ([["create_date", "!=", "2026-10-26"]], lambda d: d != 26),
        (["!", ["create_date", "=", "2026-10-26"]], lambda d: d != 26),
        (["!", ["create_date", "!=", "2026-10-26"]], lambda d: d == 26),
        (["|", ["create_date", "=", "2026-10-24"], ["create_date", "=", "2026-10-26"]], lambda d: d in (24, 26)),
        ([["create_date", "!=", "2026-10-26"], ["create_date", ">=", "2026-10-25"]], lambda d: d >= 25 and d != 26),
        (["&", "!", ["create_date", "=", "2026-10-26"], ["create_date", "<=", "2026-10-26"]], lambda d: d <= 25),
        (["|", "!", ["create_date", "<", "2026-10-27"], ["create_date", "=", "2026-10-24"]], lambda d: d == 24 or d >= 27),
        ([["create_date", ">", "2026-10-25"], ["create_date", "<", "2026-10-27"]], lambda d: d == 26),
    ],
)
async def test_domain_whole_days_keep_prefix_operators_correct(ist, domain, wanted):
    out = await ist.normalize_domain("crm.lead", domain)
    india = ZoneInfo("Asia/Kolkata")
    for day in range(23, 29):
        for local_time in ("00:00:00", "00:00:01", "12:00:00", "23:59:59"):
            local = datetime.fromisoformat(f"2026-10-{day} {local_time}").replace(tzinfo=india)
            record = {"create_date": local.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")}
            assert _matches(out, record) == wanted(day), (local, out)


# --------------------------------------------------------------------- choices (selection fields)


PAYMENT_STATES = [
    ["not_paid", "Not Paid"], ["in_payment", "In Payment"], ["paid", "Paid"], ["partial", "Partially Paid"],
    ["reversed", "Reversed"],
]


@pytest.fixture
def moves(fake) -> Validator:
    fake.schema["account.move"] = {
        "payment_state": {"type": "selection", "string": "Payment Status", "selection": PAYMENT_STATES, "store": True},
        "x_twin": {"type": "selection", "string": "Twin", "selection": [["a", "Same"], ["b", "same"]], "store": True},
    }
    fake.schema["account.move.line"] = {
        "move_id": {"type": "many2one", "string": "Journal Entry", "relation": "account.move", "store": True},
    }
    return make_validator(fake)


@pytest.mark.parametrize(
    "model, domain",
    [
        ("account.move", [["payment_state", "=", "unpaid"]]),
        ("account.move", [["payment_state", "!=", "unpaid"]]),
        ("account.move", [["payment_state", "in", ["paid", "unpaid"]]]),
        ("account.move", [["payment_state", "not in", ["unpaid"]]]),
        ("account.move", [["payment_state", "=?", "unpaid"]]),
        ("account.move", [["x_twin", "=", "same"]]),  # the label fits two choices: no guessing
        ("account.move.line", [["move_id.payment_state", "=", "unpaid"]]),
        ("account.move.line", [["move_id", "any", [["payment_state", "=", "unpaid"]]]]),
    ],
)
async def test_domain_wrong_choice_is_rejected_instead_of_matching_nothing(moves, model, domain):
    await rejected(moves.normalize_domain(model, domain), "not a valid choice", "Valid values:")


async def test_domain_wrong_choice_lists_the_valid_keys(moves):
    await rejected(
        moves.normalize_domain("account.move", [["payment_state", "=", "unpaid"]]),
        "'unpaid' is not a valid choice", "'not_paid', 'in_payment', 'paid', 'partial', 'reversed'",
    )


@pytest.mark.parametrize(
    "model, term, expected",
    [
        ("account.move", ["payment_state", "=", "not_paid"], ["payment_state", "=", "not_paid"]),
        ("account.move", ["payment_state", "=", "Not Paid"], ["payment_state", "=", "not_paid"]),
        ("account.move", ["payment_state", "!=", "partially paid"], ["payment_state", "!=", "partial"]),
        ("account.move", ["payment_state", "in", ["PAID", "in_payment", False]], ["payment_state", "in", ["paid", "in_payment", False]]),
        ("account.move", ["payment_state", "not in", ["Reversed"]], ["payment_state", "not in", ["reversed"]]),
        ("account.move", ["payment_state", "=", False], ["payment_state", "=", False]),
        ("account.move", ["payment_state", "in", []], ["payment_state", "in", []]),
        ("account.move", ["payment_state", "ilike", "pai"], ["payment_state", "ilike", "pai"]),  # patterns are left alone
        ("account.move.line", ["move_id.payment_state", "=", "Paid"], ["move_id.payment_state", "=", "paid"]),
        ("crm.lead", ["kanban_level", "in", ["2", "one"]], ["kanban_level", "in", [2, 1]]),  # integer keys
    ],
)
async def test_domain_choices_are_sent_as_their_keys(moves, model, term, expected):
    assert await moves.normalize_domain(model, [term]) == [expected]


@pytest.mark.parametrize(
    "domain",
    [
        "[('name', '=', 'x')]",
        {"name": "x"},
        ["name", "=", "x"],  # a flat condition instead of a list of conditions
        [["name", "="]],
        [["name", "=", "x", "y"]],
        [None],
        [5],
        ["AND"],
        ["&&"],
        [[1, "=", 1]],  # Odoo's TRUE_LEAF is not accepted either
        [["", "=", 1]],
        [[None, "=", 1]],
        [["name", "=", "x"], "|"] * (MAX_DOMAIN_TERMS // 2 + 1),
    ],
)
async def test_malformed_domains_are_rejected_never_emptied(v, domain):
    with pytest.raises(ValidationFailed):
        await v.normalize_domain("crm.lead", domain)


@pytest.mark.parametrize("domain", [["|", ["name", "=", "a"]], ["!"], ["&", "|", ["name", "=", "a"], ["name", "=", "b"]]])
async def test_dangling_prefix_operators_are_rejected(v, domain):
    await rejected(v.normalize_domain("crm.lead", domain), "malformed domain")


async def test_well_formed_prefix_domains_pass(v):
    domain = ["|", "!", ["name", "=", "a"], "&", ["name", "=", "b"], ["name", "=", "c"]]
    assert await v.normalize_domain("crm.lead", domain) == domain


# ================================================================================ values: scalars


async def test_unknown_field_with_suggestion(v):
    await rejected(v.normalize_values("crm.lead", {"customer_name": "Bob"}, mode="create"), "is not a field of crm.lead")
    await rejected(v.normalize_values("crm.lead", {"stage_naem": 1}, mode="create"), "Did you mean: stage_id")


@pytest.mark.parametrize("values", [None, {}, [], "name=x", [{"name": "x"}]])
async def test_values_must_be_a_non_empty_object(v, values):
    await rejected(v.normalize_values("crm.lead", values, mode="create"), "non-empty object")


async def test_all_problems_are_reported_together(v):
    err = await rejected(
        v.normalize_values("crm.lead", {"nmae": "x", "priority": "9", "probability": "high"}, mode="create")
    )
    assert len(err.problems) == 3


async def test_selection_validation(v):
    assert await v.normalize_values("crm.lead", {"priority": "2", "type": "lead"}, mode="create") == {
        "priority": "2",
        "type": "lead",
    }
    await rejected(v.normalize_values("crm.lead", {"priority": "9"}, mode="create"), "not a valid choice", "'0', '1'")
    await rejected(v.normalize_values("crm.lead", {"priority": ["2"]}, mode="create"), "not a valid choice")
    # integer-keyed selections accept the textual form but send the real key
    assert await v.normalize_values("crm.lead", {"kanban_level": "2"}, mode="create") == {"kanban_level": 2}
    assert await v.normalize_values("crm.lead", {"kanban_level": 1}, mode="create") == {"kanban_level": 1}


@pytest.mark.parametrize(
    "field, good, bad",
    [
        ("is_hot", [True, False], [1, 0, "true", "yes"]),
        ("color", [0, 5, -1], [True, 1.5, "5", 5.0]),  # (False clears an optional integer: allowed)
        ("probability", [0, 10, 10.5], [True, "10", float("nan"), float("inf"), -float("inf"), [1]]),
        ("expected_revenue", [1234.5, 0], ["1,234", math.nan]),
        ("email_from", ["a@b.example", ""], [5, ["x"], {"en_US": "x"}]),
    ],
)
async def test_scalar_type_checks(v, field, good, bad):
    for value in good:
        out = await v.normalize_values("crm.lead", {field: value}, mode="create")
        assert out[field] == value
    for value in bad:
        await rejected(v.normalize_values("crm.lead", {field: value}, mode="create"), f"crm.lead.{field}")


async def test_overlong_text_is_rejected(v):
    await rejected(v.normalize_values("crm.lead", {"description": "x" * 100_001}, mode="create"), "too long")


@pytest.mark.parametrize("good, expected", [("2026-10-15", "2026-10-15"), (" 2026-10-15 ", "2026-10-15")])
async def test_date_values(v, good, expected):
    assert (await v.normalize_values("crm.lead", {"date_deadline": good}, mode="create"))["date_deadline"] == expected


@pytest.mark.parametrize("bad", ["15/10/2026", "2026-02-30", "20261015", "2026-10-15 10:00:00", "tomorrow", 20261015, ""])
async def test_date_values_rejected(v, bad):
    await rejected(v.normalize_values("crm.lead", {"date_deadline": bad}, mode="create"), "not a valid date")


async def test_datetime_values_are_stored_in_utc(v):
    out = await v.normalize_values(
        "crm.lead", {"next_call_at": "2026-07-01 10:00:00"}, mode="create"
    )
    assert out == {"next_call_at": "2026-07-01 08:00:00"}  # Europe/Berlin summer
    out = await v.normalize_values("crm.lead", {"next_call_at": "2026-07-01T10:00:00Z"}, mode="create")
    assert out == {"next_call_at": "2026-07-01 10:00:00"}
    await rejected(v.normalize_values("crm.lead", {"next_call_at": 1751364000}, mode="create"), "date-time string")
    await rejected(v.normalize_values("crm.lead", {"next_call_at": "soon"}, mode="create"), "not a valid date-time")


async def test_properties_fields_are_refused(v):
    # free-form JSON can't be previewed field by field, so it is never written (security review finding L1)
    await rejected(v.normalize_values("crm.lead", {"lead_properties": {"a": 1}}, mode="create"), "never writes")
    await rejected(v.normalize_values("crm.lead", {"lead_properties": [{"name": "evil", "type": "many2one"}]}, mode="create"), "never writes")


async def test_unknown_field_types_are_not_writable(v):
    await rejected(v.normalize_values("crm.lead", {"x_mystery": "x"}, mode="create"), "cannot be written")


async def test_policy_field_rules_apply_to_values(v):
    for field, value, needle in [
        ("x_api_key", "abc", "secret"),
        ("x_attachment", "aGVsbG8=", "binary"),
        ("create_uid", 7, "automatically"),
        ("write_date", "2026-01-01 00:00:00", "automatically"),
        ("id", 5, "automatically"),
        ("display_name", "x", "automatically"),
        ("date_closed", "2026-01-01 00:00:00", "read-only"),
        ("active", False, "archiving is switched off"),
        ("x_cron_id", 1, "blocked model"),
        ("x_server_action_ids", [1], "blocked model"),
    ]:
        await rejected(v.normalize_values("crm.lead", {field: value}, mode="write", record_ids=[100]), needle)
    await rejected(v.normalize_values("sale.order", {"state": "sale"}, mode="write", record_ids=[5]), "workflow")
    await rejected(v.normalize_values("sale.order", {"invoice_status": "no"}, mode="write", record_ids=[5]), "workflow")


async def test_active_is_writable_with_the_archive_flag(fake):
    v = make_validator(fake, mcp_allow_archive=True)
    assert await v.normalize_values("crm.lead", {"active": False}, mode="write", record_ids=[100]) == {"active": False}
    await rejected(v.normalize_values("crm.lead", {"active": "no"}, mode="write", record_ids=[100]), "true or false")


async def test_too_many_values(v):
    values = {f"x_{i}": 1 for i in range(MAX_VALUES_PER_RECORD + 1)}
    await rejected(v.normalize_values("crm.lead", values, mode="create"), "too many fields")


async def test_required_field_cannot_be_emptied(v):
    for empty in (None, False):
        await rejected(v.normalize_values("crm.lead", {"name": empty}, mode="write", record_ids=[100]), "is required")
        await rejected(v.normalize_values("sale.order", {"partner_id": empty}, mode="write", record_ids=[5]), "is required")
    # optional fields can be cleared
    assert await v.normalize_values("crm.lead", {"partner_id": False, "email_from": None}, mode="write", record_ids=[100]) == {
        "partner_id": False,
        "email_from": False,
    }


# Regression test (was a bug, now fixed): BUG: validation.py _value() lets '' through for a required char field
async def test_required_char_cannot_be_blanked_with_empty_string(v):
    await rejected(v.normalize_values("crm.lead", {"name": ""}, mode="write", record_ids=[100]), "is required")


# Regression test (was a bug, now fixed): BUG: validation.py _many2many() turns [] into [[6, 0, []]] even for a required many2many, emptying it
async def test_required_many2many_cannot_be_emptied(v):
    await rejected(
        v.normalize_values("crm.lead", {"required_tag_ids": []}, mode="write", record_ids=[100]), "is required"
    )


# ================================================================================ many2one / reference


async def test_many2one_existing_ids_accepted_and_checked_in_one_search(v, fake):
    out = await v.normalize_values("crm.lead", {"partner_id": 1, "user_id": [8, "Sam Sales"]}, mode="create")
    assert out == {"partner_id": 1, "user_id": 8}
    searches = fake.calls_to("search")
    assert {c.model for c in searches} == {"res.partner", "res.users"}
    for c in searches:
        assert c.context == {"active_test": False}, "archived records are real records, not hallucinations"


async def test_many2one_missing_ids_are_rejected(v):
    await rejected(v.normalize_values("crm.lead", {"partner_id": 987654321}, mode="create"), "do not exist", "987654321")


@pytest.mark.parametrize("bad", [0, -1, True, "1", "Acme Corp", 1.0, [], ["Acme"], {"id": 1}])
async def test_many2one_must_be_a_positive_id(v, bad):
    await rejected(v.normalize_values("crm.lead", {"partner_id": bad}, mode="create"), "numeric id", "never guess")


async def test_many2one_access_error_on_lookup_is_reported(v, fake):
    fake.errors[("res.partner", "search")] = OdooError("no", kind="access")
    await rejected(v.normalize_values("crm.lead", {"partner_id": 1}, mode="create"), "read access to res.partner")


async def test_many2one_other_lookup_errors_propagate(v, fake):
    fake.errors[("res.partner", "search")] = OdooError("boom", kind="server")
    with pytest.raises(OdooError):
        await v.normalize_values("crm.lead", {"partner_id": 1}, mode="create")


async def test_reference_fields(v, fake):
    assert await v.normalize_values("crm.lead", {"x_source_ref": "res.partner, 3"}, mode="create") == {
        "x_source_ref": "res.partner,3"
    }
    await rejected(v.normalize_values("crm.lead", {"x_source_ref": "res.partner,999"}, mode="create"), "do not exist")
    for bad in ["res.partner", "res.partner,abc", "res.partner,-1", 3, ["res.partner", 3], "ir.config_parameter,1",
                "res.users.apikeys,1", "Res.Partner,1"]:
        await rejected(v.normalize_values("crm.lead", {"x_source_ref": bad}, mode="create"), "x_source_ref")


# Regression test (was a bug, now fixed): BUG: validation.py reference branch uses str.isdigit(); '²' passes it and int() raises ValueError instead of ValidationFailed
async def test_reference_with_unicode_digit_is_a_validation_error(v):
    await rejected(v.normalize_values("crm.lead", {"x_source_ref": "res.partner,²"}, mode="create"), "x_source_ref")


async def test_many2one_reference_is_an_integer(v):
    assert await v.normalize_values("crm.lead", {"x_res_id": 5}, mode="create") == {"x_res_id": 5}
    await rejected(v.normalize_values("crm.lead", {"x_res_id": "5"}, mode="create"), "whole number")


# ================================================================================ many2many


async def test_many2many_plain_ids_become_replace_command(v):
    out = await v.normalize_values("crm.lead", {"tag_ids": [1, 2, 2, 3]}, mode="write", record_ids=[100])
    assert out == {"tag_ids": [[6, 0, [1, 2, 3]]]}


async def test_many2many_plain_ids_must_exist(v):
    await rejected(v.normalize_values("crm.lead", {"tag_ids": [1, 99]}, mode="write", record_ids=[100]), "[99]")


async def test_many2many_ids_must_be_positive_and_bounded(v):
    await rejected(v.normalize_values("crm.lead", {"tag_ids": [1, -2]}, mode="write", record_ids=[100]), "positive")
    await rejected(
        v.normalize_values("crm.lead", {"tag_ids": list(range(1, MAX_IDS_PER_COMMAND + 2))}, mode="write", record_ids=[100]),
        "too many ids",
    )


async def test_many2many_allowed_commands(v, fake):
    commands = [
        [0, 0, {"name": "New tag"}],
        [3, 1, 0],
        [4, 3],
        [5],
        [6, 0, [1, 3, 1]],
        (4, 2, 0),
    ]
    out = await v.normalize_values("crm.lead", {"tag_ids": commands}, mode="write", record_ids=[100])
    assert out == {
        "tag_ids": [[0, 0, {"name": "New tag"}], [3, 1, 0], [4, 3, 0], [5, 0, 0], [6, 0, [1, 3]], [4, 2, 0]]
    }


async def test_many2many_command_1_would_edit_shared_records_and_is_refused(v):
    # e.g. an invoice line's tax_ids [1, tax_id, {...}] would edit the tax itself for every invoice
    await rejected(v.normalize_values("crm.lead", {"tag_ids": [[1, 2, {"color": 4}]]}, mode="write", record_ids=[100]), "shared")


async def test_many2many_command_2_deletes_and_is_refused(v):
    await rejected(v.normalize_values("crm.lead", {"tag_ids": [[2, 1, 0]]}, mode="write", record_ids=[100]), "DELETE")


@pytest.mark.parametrize(
    "command, needle",
    [
        ([7, 1, 0], "unknown command"),
        ([-1, 1], "unknown command"),
        (["4", 1], "invalid relational command"),
        ([], "invalid relational command"),
        ([True, 1], "invalid relational command"),
        ([4], "needs a record id"),
        ([4, 0], "needs a record id"),
        ([3, "1"], "needs a record id"),
        ([1, 2], "shared"),
        ([0, 0, "name=x"], "needs an object of values"),
        ([6, 0, "1,2"], "command 6 needs a list of ids"),
        ([6, 0, [1, "2"]], "command 6 needs a list of ids"),
        ([6, 0, [0]], "positive"),
        ([4, 99], "do not exist"),
        ([6, 0, [1, 99]], "do not exist"),
        ([1, 99, {"color": 1}], "shared"),
    ],
)
async def test_many2many_bad_commands(v, command, needle):
    await rejected(v.normalize_values("crm.lead", {"tag_ids": [command]}, mode="write", record_ids=[100]), needle)


async def test_many2many_nested_create_is_validated(v):
    await rejected(
        v.normalize_values("crm.lead", {"tag_ids": [[0, 0, {"nmae": "x"}]]}, mode="write", record_ids=[100]),
        "not a field of crm.tag",
    )


async def test_many2many_create_or_edit_in_a_readonly_comodel_is_refused(fake):
    v = make_validator(fake, mcp_readonly_models=["crm.tag"])
    with pytest.raises(PolicyViolation):
        await v.normalize_values("crm.lead", {"tag_ids": [[0, 0, {"name": "x"}]]}, mode="write", record_ids=[100])
    with pytest.raises(ValidationFailed):
        await v.normalize_values("crm.lead", {"tag_ids": [[1, 1, {"name": "x"}]]}, mode="write", record_ids=[100])
    # linking existing tags is still fine
    assert await v.normalize_values("crm.lead", {"tag_ids": [[4, 1]]}, mode="write", record_ids=[100]) == {
        "tag_ids": [[4, 1, 0]]
    }


# ================================================================================ one2many


async def test_one2many_dicts_become_create_commands(v):
    lines = [{"product_id": 10, "product_uom_qty": 2}, [0, 0, {"product_id": 11, "price_unit": 9.5}]]
    out = await v.normalize_values("sale.order", {"order_line": lines}, mode="write", record_ids=[5])
    assert out == {
        "order_line": [[0, 0, {"product_id": 10, "product_uom_qty": 2}], [0, 0, {"product_id": 11, "price_unit": 9.5}]]
    }


async def test_one2many_on_create(v):
    out = await v.normalize_values(
        "sale.order", {"partner_id": 1, "order_line": [{"product_id": 10}]}, mode="create"
    )
    assert out == {"partner_id": 1, "order_line": [[0, 0, {"product_id": 10}]]}


async def test_invoice_type_is_accepted_on_create_and_refused_on_update(fake):
    selection = [["entry", "Journal Entry"], ["out_invoice", "Customer Invoice"], ["in_invoice", "Vendor Bill"]]
    fake.schema["account.move"] = {
        "move_type": {"type": "selection", "string": "Type", "selection": selection, "store": True, "readonly": True},
        "state": {"type": "selection", "string": "Status", "selection": [["draft", "Draft"], ["posted", "Posted"]],
                  "store": True, "readonly": False},
        "partner_id": {"type": "many2one", "string": "Customer", "relation": "res.partner", "store": True, "readonly": False},
    }
    fake.records["account.move"] = {5: {"name": "INV/2026/00001"}}
    v = make_validator(fake)
    out = await v.normalize_values("account.move", {"move_type": "out_invoice", "partner_id": 1}, mode="create")
    assert out == {"move_type": "out_invoice", "partner_id": 1}
    await rejected(v.normalize_values("account.move", {"move_type": "out_refund"}, mode="create"), "move_type")
    await rejected(
        v.normalize_values("account.move", {"move_type": "in_invoice"}, mode="write", record_ids=[5]),
        "only when the record is created",
    )
    await rejected(v.normalize_values("account.move", {"state": "posted"}, mode="create"), "workflow status")


async def test_one2many_nested_values_are_validated_and_refs_checked(v):
    await rejected(
        v.normalize_values("sale.order", {"order_line": [{"product_id": 999}]}, mode="write", record_ids=[5]),
        "product.product record id(s) [999] do not exist",
    )
    await rejected(
        v.normalize_values("sale.order", {"order_line": [{"qty": 2}]}, mode="write", record_ids=[5]),
        "not a field of sale.order.line",
    )


async def test_one2many_edit_only_lines_of_the_record(v, fake):
    ok = await v.normalize_values(
        "sale.order", {"order_line": [[1, 51, {"product_uom_qty": 3}]]}, mode="write", record_ids=[5]
    )
    assert ok == {"order_line": [[1, 51, {"product_uom_qty": 3}]]}
    read = [c for c in fake.calls_to("read") if c.model == "sale.order"]
    assert read and read[0].ids == [5] and read[0].kwargs["fields"] == ["order_line"]
    assert read[0].context == {"active_test": False}

    # line 60 belongs to order 6, not order 5
    await rejected(
        v.normalize_values("sale.order", {"order_line": [[1, 60, {"product_uom_qty": 3}]]}, mode="write", record_ids=[5]),
        "does not belong",
    )
    await rejected(
        v.normalize_values("sale.order", {"order_line": [[1, 987654321, {"product_uom_qty": 3}]]}, mode="write", record_ids=[5]),
        "does not belong",
    )


async def test_one2many_edit_when_writing_several_records(v):
    out = await v.normalize_values(
        "sale.order", {"order_line": [[1, 60, {"price_unit": 1.0}]]}, mode="write", record_ids=[5, 6]
    )
    assert out == {"order_line": [[1, 60, {"price_unit": 1.0}]]}


async def test_one2many_edit_is_impossible_on_create(v):
    await rejected(
        v.normalize_values("sale.order", {"partner_id": 1, "order_line": [[1, 50, {"price_unit": 1.0}]]}, mode="create"),
        "only be edited on an existing record",
    )


@pytest.mark.parametrize(
    "command, needle",
    [
        ([2, 50, 0], "delete or detach"),
        ([3, 50, 0], "delete or detach"),
        ([5, 0, 0], "delete or detach"),
        ([5], "delete or detach"),
        ([6, 0, []], "delete or detach"),
        ([6, 0, [50]], "delete or detach"),
        ([4, 60, 0], "move a line away"),
        ([9, 0, 0], "unknown command"),
    ],
)
async def test_one2many_destructive_commands_are_refused(v, command, needle):
    await rejected(v.normalize_values("sale.order", {"order_line": [command]}, mode="write", record_ids=[5]), needle)


async def test_one2many_plain_ids_are_refused(v):
    await rejected(v.normalize_values("sale.order", {"order_line": [50, 51]}, mode="write", record_ids=[5]), "replace")
    await rejected(v.normalize_values("sale.order", {"order_line": [{"product_id": 10}, 50]}, mode="write", record_ids=[5]), "replace")


async def test_one2many_must_be_a_list(v):
    await rejected(v.normalize_values("sale.order", {"order_line": {"product_id": 10}}, mode="write", record_ids=[5]), "must be a list")


async def test_one2many_inverse_field_is_refused_in_nested_values(v):
    # setting order_id on a new line could attach it to ANOTHER order
    await rejected(
        v.normalize_values("sale.order", {"order_line": [{"order_id": 6, "product_id": 10}]}, mode="write", record_ids=[5]),
        "set automatically from the parent",
    )
    await rejected(
        v.normalize_values("sale.order", {"order_line": [[1, 50, {"order_id": 6}]]}, mode="write", record_ids=[5]),
        "set automatically from the parent",
    )


async def test_one2many_nested_blocked_comodel_is_refused(v):
    # relation to a hard-blocked model: the field itself is refused
    await rejected(
        v.normalize_values("sale.order", {"order_line": [{"x_config_ids": [{"key": "a", "value": "b"}]}]}, mode="write", record_ids=[5]),
        "blocked model",
    )
    await rejected(
        v.normalize_values("sale.order", {"order_line": [{"x_cron_line_ids": [{"name": "x"}]}]}, mode="write", record_ids=[5]),
        "blocked model",
    )
    # relation to a write-protected model (mail.message): creating lines in it is a policy violation
    with pytest.raises(PolicyViolation):
        await v.normalize_values("sale.order", {"order_line": [{"x_note_ids": [{"body": "hi"}]}]}, mode="write", record_ids=[5])
    with pytest.raises(PolicyViolation):
        await v.normalize_values("crm.lead", {"message_ids": [{"body": "hi"}]}, mode="write", record_ids=[100])


async def test_one2many_into_a_write_protected_comodel_is_refused(v):
    # bank accounts: the field itself is refused now, before any line is looked at
    await rejected(
        v.normalize_values("res.partner", {"bank_ids": [{"acc_number": "DE00"}]}, mode="write", record_ids=[1]),
        "res.partner.bank_ids holds bank details",
    )
    with pytest.raises(PolicyViolation):
        await v.normalize_values("res.partner", {"user_ids": [{"login": "eve"}]}, mode="write", record_ids=[1])


async def test_nesting_depth_limit(v):
    deepest = {"name": "4"}
    ok = {"order_line": [{"x_sub_ids": [{"x_deep_ids": [{"name": "3"}]}]}]}
    assert await v.normalize_values("sale.order", ok, mode="write", record_ids=[5])
    too_deep = {"order_line": [{"x_sub_ids": [{"x_deep_ids": [{"x_deeper_ids": [deepest]}]}]}]}
    await rejected(v.normalize_values("sale.order", too_deep, mode="write", record_ids=[5]), "nested too deeply")


async def test_values_size_limit(v):
    lines = [{"name": "x" * 90_000} for _ in range(12)]
    await rejected(v.normalize_values("sale.order", {"order_line": lines}, mode="write", record_ids=[5]), "too large")


# ================================================================================ fields Odoo cannot search


async def test_fields_odoo_cannot_search_are_refused_up_front_with_a_stored_alternative(setup_fake):
    v = make_validator(setup_fake)
    problem = await rejected(v.normalize_domain("ir.ui.menu", [["complete_name", "ilike", "Sales"]]), "cannot be searched")
    assert "Search on a stored field instead, e.g. name." in str(problem)
    await rejected(v.normalize_domain("ir.ui.menu", [["parent_id.complete_name", "ilike", "Sales"]]), "cannot be searched")
    await rejected(v.normalize_domain("ir.ui.menu", [["parent_id", "any", [["complete_name", "=", "x"]]]]), "cannot be searched")
    assert await v.normalize_domain("ir.ui.menu", [["name", "ilike", "Sales"]]) == [["name", "ilike", "Sales"]]
    # stored fields, and fields whose metadata does not say, are searched as before
    assert await v.normalize_domain("crm.lead", [["name", "=", "x"]]) == [["name", "=", "x"]]


# ================================================================================ analytic distribution


async def test_analytic_distribution_is_validated_and_normalised(setup_fake):
    v = make_validator(setup_fake)
    out = await v.normalize_values("account.move.line", {"analytic_distribution": {"7": 60, "8": 40.5}}, mode="write", record_ids=[700])
    assert out == {"analytic_distribution": {"7": 60, "8": 40.5}}
    # one key may join one account per plan; ids may come as numbers
    out = await v.normalize_values(
        "account.move.line", {"analytic_distribution": {" 7 , 31 ": 100, 8: 25}}, mode="write", record_ids=[700]
    )
    assert out == {"analytic_distribution": {"7,31": 100, "8": 25}}
    checked = [c.kwargs["domain"] for c in setup_fake.calls if c.model == "account.analytic.account" and c.method == "search"]
    assert checked[-1] == [["id", "in", [7, 8, 31]]]
    # emptying it is allowed
    assert await v.normalize_values(
        "account.move.line", {"analytic_distribution": False}, mode="write", record_ids=[700]
    ) == {"analytic_distribution": False}


@pytest.mark.parametrize(
    "value, needle",
    [
        ({"7": 0}, "above 0 and at most 100"),
        ({"7": 100.5}, "above 0 and at most 100"),
        ({"7": -5}, "above 0 and at most 100"),
        ({"7": "60"}, "must be a number"),
        ({"7": True}, "must be a number"),
        ({"7": float("nan")}, "must be a number"),
        ({"7": None}, "must be a number"),
        ({"Project Alpha": 60}, "not an analytic account id"),
        ({"7,7": 50}, "not an analytic account id"),
        ({"0": 50}, "not an analytic account id"),
        ({"7,": 50}, "not an analytic account id"),
        ({"-7": 50}, "not an analytic account id"),
        ({"7": 50, " 7": 50}, "listed twice"),
        ({"7,31": 50, "31,7": 50}, "listed twice"),
        ({}, "must be an object"),
        ([["7", 60]], "must be an object"),
        ("7:60", "must be an object"),
        ({"999": 50}, "account.analytic.account record id(s) [999] do not exist"),
    ],
)
async def test_bad_analytic_distributions_are_refused(setup_fake, value, needle):
    v = make_validator(setup_fake)
    await rejected(
        v.normalize_values("account.move.line", {"analytic_distribution": value}, mode="write", record_ids=[700]), needle
    )


async def test_other_json_fields_stay_unwritable(setup_fake):
    v = make_validator(setup_fake)
    await rejected(
        v.normalize_values("account.move.line", {"x_other_json": {"7": 100}}, mode="write", record_ids=[700]), "json field"
    )


async def test_analytic_distribution_reads_as_names_in_previews(setup_fake):
    v = make_validator(setup_fake)
    assert await v.describe_analytic_distribution({"7": 60, "8": 40}) == "Project Alpha 60%, Project Beta 40%"
    # the plain name: Odoo's display name adds the code and partner ("Project Alpha - Acme Corp")
    assert setup_fake.calls_to("read")[-1].kwargs["fields"] == ["name"]
    assert await v.describe_analytic_distribution({"7,31": 33.333, "999": 66.67}) == (
        "Project Alpha / Marketing 33.33%, #999 66.67%"
    )
    assert await v.describe_analytic_distribution({}) == "none"
    assert await v.describe_analytic_distribution(False) == "none"
    setup_fake.errors[("account.analytic.account", "read")] = OdooError("no access", kind="access")
    assert await v.describe_analytic_distribution({"7": 100.0}) == "#7 100%"


# ================================================================================ app settings


async def test_settings_take_feature_switches_and_refuse_apps_identity_and_edits(setup_fake):
    v = make_validator(setup_fake)
    values = {"group_analytic_accounting": True, "quotation_validity_days": 15}
    assert await v.normalize_values("res.config.settings", values, mode="create") == values
    await rejected(v.normalize_values("res.config.settings", {"module_crm": True}, mode="create"), "installs or removes an Odoo app")
    await rejected(
        v.normalize_values("res.config.settings", {"l10n_in_gstin": "27AAAAA0000A1Z5", "l10n_in_pan": "AAAAA0000A"}, mode="create"),
        "l10n_in_gstin is part of the company's identity", "l10n_in_pan is part of the company's identity",
    )
    await rejected(v.normalize_values("res.config.settings", {"account_fiscal_country_id": 104}, mode="create"), "identity")
    with pytest.raises(PolicyViolation, match="new settings record"):
        await v.normalize_values("res.config.settings", {"quotation_validity_days": 15}, mode="write", record_ids=[1])


# ================================================================================ e-mail templates


async def test_templates_take_text_and_recipient_changes_only(setup_fake):
    v = make_validator(setup_fake)
    values = {
        "subject": "Your quotation {{ object.name }}", "body_html": "<p>Hello</p>", "email_to": "a@example.com",
        "email_cc": "accounts@sahajta.com", "partner_to": "{{ object.partner_id.id }}", "use_default_to": False,
        "reply_to": "sales@sahajta.com",
    }
    assert await v.normalize_values("mail.template", values, mode="write", record_ids=[20]) == values
    for name, value in [("email_from", "ceo@elsewhere.example"), ("attachment_ids", [1]), ("model_id", 90), ("name", "x")]:
        await rejected(v.normalize_values("mail.template", {name: value}, mode="write", record_ids=[20]), "only these fields")
    with pytest.raises(PolicyViolation, match="cannot be created"):
        await v.normalize_values("mail.template", {"subject": "x"}, mode="create")


# ================================================================================ accounting setup and bank details


TAX = {
    "name": "GST 5%", "amount": 5.0, "type_tax_use": "sale",
    "invoice_repartition_line_ids": [
        {"repartition_type": "base", "document_type": "invoice", "factor_percent": 100},
        {"repartition_type": "tax", "document_type": "invoice", "factor_percent": 100, "account_id": 50},
    ],
}


async def test_accounting_setup_is_created_with_its_lines(setup_fake):
    v = make_validator(setup_fake)
    out = await v.normalize_values("account.tax", TAX, mode="create")
    assert out["invoice_repartition_line_ids"] == [[0, 0, line] for line in TAX["invoice_repartition_line_ids"]]
    journal = {"name": "HDFC Current", "code": "HDFC", "type": "bank"}
    assert await v.normalize_values("account.journal", journal, mode="create") == journal
    assert await v.normalize_values("account.account", {"name": "GST Payable", "code": "2101"}, mode="create")


async def test_accounting_setup_is_never_changed_or_archived(setup_fake):
    v = make_validator(setup_fake, mcp_allow_archive=True)
    for model, rid, values in [("account.tax", 1, {"amount": 12.0}), ("account.tax", 1, {"active": False}),
                               ("account.account", 50, {"code": "4001"}), ("account.journal", 60, {"name": "x"})]:
        with pytest.raises(PolicyViolation, match="changes past reports and GST returns"):
            await v.normalize_values(model, values, mode="write", record_ids=[rid])
    # a tax's lines are part of it: they cannot be written through any other record
    setup_fake.schema["sale.order"]["x_tax_line_ids"] = {
        "type": "one2many", "string": "Tax lines", "relation": "account.tax.repartition.line", "relation_field": "x_order_id",
    }
    line = {"repartition_type": "base", "document_type": "invoice", "factor_percent": 100}
    with pytest.raises(PolicyViolation, match="only inside their account.tax record"):
        await v.normalize_values("sale.order", {"x_tax_line_ids": [line]}, mode="write", record_ids=[5])


async def test_journals_never_take_bank_details(setup_fake):
    v = make_validator(setup_fake)
    base = {"name": "HDFC Current", "code": "HDFC", "type": "bank"}
    for name, value in [("bank_acc_number", "50100012345678"), ("bank_account_id", 1), ("bank_id", 1)]:
        await rejected(v.normalize_values("account.journal", {**base, name: value}, mode="create"), f"{name} holds bank details")


async def test_bills_never_get_a_recipient_bank_account(setup_fake):
    v = make_validator(setup_fake)
    await rejected(
        v.normalize_values("account.move", {"partner_bank_id": 3}, mode="write", record_ids=[70]),
        "account.move.partner_bank_id holds bank details",
    )
    assert await v.normalize_values("account.move", {"ref": "Bill 42"}, mode="write", record_ids=[70]) == {"ref": "Bill 42"}


# ================================================================================ automation rules


def lead_rule(**extra) -> dict:
    return {
        "name": "Hot leads go to Sam",
        "model_id": 91,
        "trigger": "on_create_or_write",
        "filter_domain": "[('priority', '=', 'High'), ('expected_revenue', '>', 1000)]",
        "action_server_ids": [
            {"name": "Assign Sam", "state": "object_write", "update_path": "user_id", "value": "8"},
            {"name": "Plan a call", "state": "next_activity", "activity_type_id": 4, "activity_summary": "Call"},
        ],
        **extra,
    }


async def test_automation_rule_is_created_with_a_literal_filter_and_safe_actions(setup_fake):
    v = make_validator(setup_fake)
    out = await v.normalize_values("base.automation", lead_rule(), mode="create")
    # the filter is checked like a search and stored with Odoo's own keys
    assert out["filter_domain"] == "[['priority', '=', '2'], ['expected_revenue', '>', 1000]]"
    assert out["action_server_ids"] == [
        [0, 0, {"name": "Assign Sam", "state": "object_write", "update_path": "user_id", "value": "8", "model_id": 91}],
        [0, 0, {"name": "Plan a call", "state": "next_activity", "activity_type_id": 4, "activity_summary": "Call",
                "model_id": 91}],
    ]
    checked = {c.model for c in setup_fake.calls if c.method == "search"}
    assert {"res.users", "mail.activity.type", "ir.model"} <= checked


@pytest.mark.parametrize(
    "text, needle",
    [
        ("[('user_id', '=', uid)]", "fixed values"),
        ("[('date_deadline', '<', context_today())]", "fixed values"),
        ("__import__('os').system('id')", "fixed values"),
        ("{'state': 'draft'}", "fixed values"),
        ("[('nmae', '=', 'x')", "fixed values"),
        ("[('nmae', '=', 'x')]", "'nmae' (in 'nmae') is not a field of crm.lead"),
        ("[('priority', '=', 'Urgent')]", "not a valid choice"),
        ("[('x_api_key', '!=', False)]", "credential"),
    ],
)
async def test_rule_filters_must_be_literal_domains_checked_like_a_search(setup_fake, text, needle):
    v = make_validator(setup_fake)
    await rejected(v.normalize_values("base.automation", lead_rule(filter_domain=text), mode="create"), needle)
    await rejected(v.normalize_values("base.automation", lead_rule(filter_pre_domain=text), mode="create"), needle)


async def test_rule_filters_cannot_reach_blocked_models(setup_fake):
    v = make_validator(setup_fake)
    with pytest.raises(PolicyViolation):
        await v.normalize_values("base.automation", lead_rule(filter_domain="[('x_cron_id.name', '=', 'x')]"), mode="create")


@pytest.mark.parametrize("trigger, needle", [("on_change", "Python code"), ("on_webhook", "outside system"), ("on_unlink", "deleted")])
async def test_rules_with_unsafe_triggers_are_refused(setup_fake, trigger, needle):
    v = make_validator(setup_fake)
    await rejected(v.normalize_values("base.automation", lead_rule(trigger=trigger), mode="create"), needle)


@pytest.mark.parametrize(
    "action, needle",
    [
        ({"name": "Run code", "state": "code"}, "runs Python code"),
        ({"name": "Run code", "state": "code", "code": "env['res.users'].search([])"}, "hidden for safety"),
        ({"name": "Hook", "state": "webhook"}, "outside web address"),
        ({"name": "Hook", "state": "webhook", "webhook_url": "https://example.com/x"}, "hidden for safety"),
        ({"name": "SMS", "state": "sms"}, "text messages"),
        ({"name": "Multi", "state": "multi"}, "other server actions"),
        ({"name": "New", "state": "object_create"}, "creates new records"),
        ({"name": "Calc", "state": "object_write", "update_path": "probability", "evaluation_type": "equation",
          "value": "record.probability * 2"}, "fixed value"),
        ({"name": "Deep", "state": "object_write", "update_path": "partner_id.email", "value": "x@y.z"}, "own record"),
        ({"name": "Nothing", "state": "object_write", "value": "1"}, "update_path"),
        ({"name": "Close", "state": "object_write", "update_path": "date_closed", "value": "2026-01-01 00:00:00"}, "read-only"),
        ({"name": "Key", "state": "object_write", "update_path": "x_api_key", "value": "k"}, "credential"),
        ({"name": "Cron", "state": "object_write", "update_path": "x_cron_id", "value": "1"},
         "crm.lead.x_cron_id, which points to a blocked model (ir.cron)"),
        ({"name": "Archive", "state": "object_write", "update_path": "active", "update_boolean_value": "false"},
         "archiving is switched off"),
        ({"name": "Typo", "state": "object_write", "update_path": "stage_naem", "value": "1"}, "not a field of crm.lead"),
        ({"name": "Prio", "state": "object_write", "update_path": "priority", "value": "Urgent"}, "not a valid choice"),
        ({"name": "Stage", "state": "object_write", "update_path": "stage_id", "value": "999"},
         "crm.stage record id(s) [999] do not exist"),
        ({"name": "Stage", "state": "object_write", "update_path": "stage_id", "resource_ref": "crm.tag,1"},
         "must point at a crm.stage record"),
        ({"name": "Stage", "state": "object_write", "update_path": "stage_id", "value": "two"}, "numeric id"),
        ({"name": "Tag", "state": "object_write", "update_path": "tag_ids", "update_m2m_operation": "add"}, "name the crm.tag"),
        ({"name": "Color", "state": "object_write", "update_path": "color", "value": "red"}, "whole number"),
        ({"name": "Rev", "state": "object_write", "update_path": "expected_revenue", "value": "lots"}, "must be a number"),
        ({"name": "Props", "state": "object_write", "update_path": "lead_properties", "value": "{}"}, "properties"),
        ({"name": "Lines", "state": "object_write", "update_path": "message_ids", "value": "1"}, "type 'one2many'"),
        ({"name": "Ref", "state": "object_write", "update_path": "x_source_ref", "value": "res.partner,1"}, "type 'reference'"),
        ({"name": "Name", "state": "object_write", "update_path": "name", "value": ""}, "required"),
        ({"name": "Groups", "state": "next_activity", "group_ids": [1]}, "only these fields"),
        ({"name": "Model", "state": "next_activity", "model_id": 90}, "rule's model"),
        ({"name": "Rule link", "state": "next_activity", "base_automation_id": 300}, "set automatically from the parent"),
    ],
)
async def test_rule_actions_outside_the_safe_set_are_refused(setup_fake, action, needle):
    v = make_validator(setup_fake)
    await rejected(v.normalize_values("base.automation", lead_rule(action_server_ids=[action]), mode="create"), needle)


async def test_update_actions_pass_the_same_field_rules_as_a_direct_change(setup_fake):
    v = make_validator(setup_fake)
    confirm = {"name": "Confirm", "state": "object_write", "update_path": "state", "value": "sale"}
    rule = {"name": "Auto-confirm", "model_id": 94, "trigger": "on_create", "action_server_ids": [confirm]}
    await rejected(v.normalize_values("base.automation", rule, mode="create"), "sale.order.state, which is a workflow status")
    ok = lead_rule(action_server_ids=[
        {"name": "Hot", "state": "object_write", "update_path": "is_hot", "update_boolean_value": "true"},
        {"name": "Prio", "state": "object_write", "update_path": "priority", "value": "3"},
        {"name": "Tag", "state": "object_write", "update_path": "tag_ids", "update_m2m_operation": "add", "resource_ref": "crm.tag,2"},
        {"name": "Call", "state": "object_write", "update_path": "next_call_at", "value": "2026-11-02 10:00:00"},
        {"name": "Due", "state": "object_write", "update_path": "date_deadline", "value": "2026-11-30"},
        {"name": "Rev", "state": "object_write", "update_path": "expected_revenue", "value": "1500.5"},
        {"name": "Notes", "state": "object_write", "update_path": "description", "html_value": "<p>Hot</p>"},
        {"name": "No stage", "state": "object_write", "update_path": "stage_id", "value": "0"},
    ])
    out = await v.normalize_values("base.automation", ok, mode="create")
    # a fixed date-time is the user's local time (here Berlin, UTC+1 in November) and Odoo stores UTC
    assert out["action_server_ids"][3][2]["value"] == "2026-11-02 09:00:00"


async def test_email_and_follower_actions_need_the_outbound_switch(setup_fake):
    v = make_validator(setup_fake)
    mail = {"name": "Thank you", "state": "mail_post", "template_id": 20, "mail_post_method": "email"}
    follow = {"name": "Follow", "state": "followers", "partner_ids": [1]}
    for action in (mail, follow):
        await rejected(
            v.normalize_values("base.automation", lead_rule(action_server_ids=[action]), mode="create"), "switched off for Claude"
        )
    note = {"name": "Note", "state": "mail_post", "template_id": 20, "mail_post_method": "note"}
    assert await v.normalize_values("base.automation", lead_rule(action_server_ids=[note]), mode="create")
    on = make_validator(setup_fake, mcp_allow_outbound_messages=True)
    out = await on.normalize_values("base.automation", lead_rule(action_server_ids=[mail, follow]), mode="create")
    assert [a[2]["state"] for a in out["action_server_ids"]] == ["mail_post", "followers"]
    await rejected(
        on.normalize_values("base.automation", lead_rule(trigger="on_message_received", action_server_ids=[mail]), mode="create"),
        "endless e-mail loop",
    )


async def test_rules_may_watch_only_records_claude_may_change(setup_fake):
    v = make_validator(setup_fake)
    with pytest.raises(PolicyViolation, match="system or security setup"):
        await v.normalize_values("base.automation", lead_rule(model_id=92, filter_domain=False), mode="create")
    with pytest.raises(PolicyViolation, match="setup records"):
        await v.normalize_values("base.automation", lead_rule(model_id=93, filter_domain=False), mode="create")
    await rejected(v.normalize_values("base.automation", lead_rule(model_id=999), mode="create"), "does not exist")
    await rejected(v.normalize_values("base.automation", {"name": "x", "trigger": "on_create"}, mode="create"), "model_id is required")
    await rejected(v.normalize_values("base.automation", lead_rule(trigger=False), mode="create"), "trigger is required")


async def test_editing_a_rule_checks_the_rule_as_it_will_be(setup_fake):
    v = make_validator(setup_fake)
    out = await v.normalize_values(
        "base.automation",
        {"name": "Renamed", "action_server_ids": [
            [1, 400, {"activity_summary": "Call them"}],
            {"name": "Prio", "state": "object_write", "update_path": "priority", "value": "2"},
        ]},
        mode="write", record_ids=[300],
    )
    assert out["action_server_ids"] == [
        [1, 400, {"activity_summary": "Call them"}],
        [0, 0, {"name": "Prio", "state": "object_write", "update_path": "priority", "value": "2", "model_id": 91}],
    ]
    for values, needle in [
        ({"action_server_ids": [[1, 400, {"state": "code"}]]}, "runs Python code"),
        ({"action_server_ids": [[1, 400, {"model_id": 90}]]}, "only when the record is created"),
        ({"action_server_ids": [[1, 401, {"name": "x"}]]}, "does not belong"),
        ({"trigger": "on_webhook"}, "outside system"),
        ({"model_id": 90}, "only when the record is created"),
        ({"filter_domain": "[('user_id', '=', uid)]"}, "fixed values"),
    ]:
        await rejected(v.normalize_values("base.automation", values, mode="write", record_ids=[300]), needle)
    # a rule a person set up with Python code is not touched through Claude...
    await rejected(v.normalize_values("base.automation", {"name": "x"}, mode="write", record_ids=[301]), "'Python thing' runs Python code")
    await rejected(v.normalize_values("base.automation", {"name": "x"}, mode="write", record_ids=[300, 301]), "one at a time")


async def test_rules_can_always_be_switched_off_but_only_safe_ones_on(setup_fake):
    v = make_validator(setup_fake, mcp_allow_archive=True)
    assert await v.normalize_values("base.automation", {"active": False}, mode="write", record_ids=[300, 301]) == {"active": False}
    assert await v.normalize_values("base.automation", {"active": True}, mode="write", record_ids=[300]) == {"active": True}
    await rejected(v.normalize_values("base.automation", {"active": True}, mode="write", record_ids=[301]), "runs Python code")
    await rejected(
        make_validator(setup_fake).normalize_values("base.automation", {"active": False}, mode="write", record_ids=[300]),
        "archiving is switched off",
    )


async def test_secrets_and_code_on_rules_and_actions_are_hidden_everywhere(setup_fake):
    v = make_validator(setup_fake)
    fields = await v.fields_of("base.automation")
    assert "url" not in fields and "webhook_uuid" not in fields and "trigger" in fields
    assert "code" not in await v.fields_of("ir.actions.server")
    assert "code" in setup_fake.schema["ir.actions.server"], "the cached schema itself is untouched"
    await rejected(v.check_field_names("base.automation", ["name", "webhook_uuid"]), "hidden for safety")
    await rejected(v.check_field_names("ir.actions.server", ["code"]), "hidden for safety")
    await rejected(v.normalize_domain("base.automation", [["webhook_uuid", "=", "abc"]]), "hidden for safety")
    await rejected(v.normalize_domain("base.automation", [["action_server_ids.code", "ilike", "password"]]), "hidden for safety")
    # hidden names never cost an extra trip to Odoo
    assert len(setup_fake.calls_to("fields_get")) == 2


async def test_server_actions_are_never_written_outside_a_rule(setup_fake):
    v = make_validator(setup_fake)
    await rejected(
        v.normalize_values("crm.lead", {"x_server_action_ids": [[0, 0, {"name": "x", "state": "next_activity"}]]},
                           mode="write", record_ids=[100]),
        "server actions can be added only inside an automation rule",
    )
