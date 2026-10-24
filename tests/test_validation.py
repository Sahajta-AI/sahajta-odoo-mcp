"""Validator: anti-hallucination checks and relational-command safety, against a fake Odoo schema."""

from __future__ import annotations

import math
from zoneinfo import ZoneInfo

import pytest

from conftest import FakeOdoo, build_settings
from sahajta_odoo_mcp.errors import OdooError, PolicyViolation, ValidationFailed
from sahajta_odoo_mcp.policy import SafetyPolicy
from sahajta_odoo_mcp.schema import SchemaCache
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


def make_validator(fake: FakeOdoo | None = None, tz: str = "Europe/Berlin", **settings) -> Validator:
    fake = fake or FakeOdoo()
    policy = SafetyPolicy(build_settings(mcp_access_mode="read_write", **settings))
    return Validator(client=fake, schema=SchemaCache(), policy=policy, tz=tz)


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
        ("active", False, "MCP_ALLOW_ARCHIVE"),
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
    with pytest.raises(PolicyViolation):
        await v.normalize_values("res.partner", {"bank_ids": [{"acc_number": "DE00"}]}, mode="write", record_ids=[1])
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
