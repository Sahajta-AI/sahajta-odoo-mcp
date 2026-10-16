"""Preview tokens: bound to the exact change, the user, and a 15-minute window."""

from __future__ import annotations

import copy

import pytest

from sahajta_odoo_mcp import confirm as confirm_module
from sahajta_odoo_mcp.confirm import DEFAULT_TTL_SECONDS, ConfirmationSigner, canonical
from sahajta_odoo_mcp.errors import ConfirmationRequired

SECRET = b"s" * 32

PAYLOAD = {
    "op": "update",
    "who": "https://odoo.example.com|testdb|7",
    "model": "crm.lead",
    "ids": [100, 101],
    "values": {"expected_revenue": 5000, "tag_ids": [[6, 0, [1, 2]]]},
    "context": {},
    "fingerprint": {"100": {"write_date": "2026-10-15 10:00:00", "expected_revenue": 1000.0}},
}


@pytest.fixture
def signer() -> ConfirmationSigner:
    return ConfirmationSigner(SECRET)


@pytest.fixture
def frozen_time(monkeypatch):
    now = {"t": 1_800_000_000.0}
    monkeypatch.setattr(confirm_module.time, "time", lambda: now["t"])
    return now


def test_round_trip(signer):
    token = signer.issue(PAYLOAD)
    signer.verify(token, copy.deepcopy(PAYLOAD))  # no exception


def test_token_shape_reveals_nothing_but_expiry(signer, frozen_time):
    token = signer.issue(PAYLOAD)
    expires, _, mac = token.partition(".")
    assert int(expires) == int(frozen_time["t"]) + DEFAULT_TTL_SECONDS
    assert "crm.lead" not in token and "5000" not in token
    assert len(mac) == 32  # 24 bytes, urlsafe base64, unpadded


def test_dict_key_order_does_not_matter(signer):
    token = signer.issue(PAYLOAD)
    reordered = dict(reversed(list(PAYLOAD.items())))
    reordered["values"] = dict(reversed(list(PAYLOAD["values"].items())))
    signer.verify(token, reordered)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p["values"].__setitem__("expected_revenue", 5001),
        lambda p: p["values"].__setitem__("expected_revenue", 5000.0),  # int vs float is a different change
        lambda p: p["values"].__setitem__("probability", 10),
        lambda p: p["values"].pop("tag_ids"),
        lambda p: p["values"]["tag_ids"][0][2].append(3),
        lambda p: p.__setitem__("ids", [100, 101, 102]),
        lambda p: p.__setitem__("ids", [101, 100]),  # list order is significant: the service sorts ids first
        lambda p: p.__setitem__("model", "sale.order"),
        lambda p: p.__setitem__("op", "create"),
        lambda p: p.__setitem__("context", {"lang": "fr_FR"}),
        lambda p: p["fingerprint"]["100"].__setitem__("write_date", "2026-10-15 10:00:01"),
        lambda p: p["fingerprint"]["100"].__setitem__("expected_revenue", 999.0),
        lambda p: p.__setitem__("extra", None),
    ],
)
def test_any_change_to_the_payload_invalidates_the_token(signer, mutate):
    token = signer.issue(PAYLOAD)
    changed = copy.deepcopy(PAYLOAD)
    mutate(changed)
    with pytest.raises(ConfirmationRequired, match="does not match"):
        signer.verify(token, changed)


def test_token_is_bound_to_the_user(signer):
    token = signer.issue(PAYLOAD)
    other_user = {**PAYLOAD, "who": "https://odoo.example.com|testdb|8"}
    with pytest.raises(ConfirmationRequired):
        signer.verify(token, other_user)
    other_db = {**PAYLOAD, "who": "https://odoo.example.com|otherdb|7"}
    with pytest.raises(ConfirmationRequired):
        signer.verify(token, other_db)


def test_token_expires(signer, frozen_time):
    token = signer.issue(PAYLOAD)
    frozen_time["t"] += DEFAULT_TTL_SECONDS  # exactly at the expiry second: still valid
    signer.verify(token, PAYLOAD)
    frozen_time["t"] += 1.5
    with pytest.raises(ConfirmationRequired, match="expired"):
        signer.verify(token, PAYLOAD)


def test_custom_ttl(frozen_time):
    signer = ConfirmationSigner(SECRET, ttl_seconds=10)
    token = signer.issue(PAYLOAD)
    frozen_time["t"] += 11
    with pytest.raises(ConfirmationRequired, match="expired"):
        signer.verify(token, PAYLOAD)


def test_extending_the_expiry_breaks_the_mac(signer, frozen_time):
    token = signer.issue(PAYLOAD)
    expires, _, mac = token.partition(".")
    forged = f"{int(expires) + 86_400}.{mac}"
    with pytest.raises(ConfirmationRequired, match="does not match"):
        signer.verify(forged, PAYLOAD)


def test_token_from_a_different_secret_is_rejected(signer):
    other = ConfirmationSigner(b"t" * 32)
    with pytest.raises(ConfirmationRequired, match="does not match"):
        signer.verify(other.issue(PAYLOAD), PAYLOAD)


def test_same_secret_in_another_process_accepts_the_token(signer):
    # Tokens are deterministic in (secret, expiry, payload): a restarted server with the same MCP_SECRET accepts them.
    ConfirmationSigner(SECRET).verify(signer.issue(PAYLOAD), PAYLOAD)


def test_secret_must_not_be_short():
    with pytest.raises(ValueError):
        ConfirmationSigner(b"short")


@pytest.mark.parametrize(
    "token",
    [None, "", "   ", "abc", "abc.def", ".", ".abc", "12", "-5.abc", "1e9.abc", "0x10.abc", " 99999999999.abc",
     "99999999999 .abc", 123, 12.5, ["1.2"], {"t": 1}, b"99999999999.abc"],
)
def test_malformed_tokens_are_refused_cleanly(signer, token):
    with pytest.raises(ConfirmationRequired):
        signer.verify(token, PAYLOAD)


def test_mac_bit_flip_is_refused(signer):
    token = signer.issue(PAYLOAD)
    expires, _, mac = token.partition(".")
    flipped = mac[:-1] + ("A" if mac[-1] != "A" else "B")
    with pytest.raises(ConfirmationRequired):
        signer.verify(f"{expires}.{flipped}", PAYLOAD)
    with pytest.raises(ConfirmationRequired):
        signer.verify(f"{expires}.{mac[:-2]}", PAYLOAD)  # truncated
    with pytest.raises(ConfirmationRequired):
        signer.verify(f"{expires}.{mac}=", PAYLOAD)  # padding added


# Regression test (was a bug, now fixed): BUG: confirm.py verify() uses str.isdigit(), which accepts '²' etc.; int() then raises ValueError instead of ConfirmationRequired
def test_unicode_digit_expiry_is_refused_as_confirmation_error(signer):
    with pytest.raises(ConfirmationRequired):
        signer.verify("²²²²²²²²²².abc", PAYLOAD)


def test_missing_token_message_explains_the_flow(signer):
    with pytest.raises(ConfirmationRequired) as info:
        signer.verify(None, PAYLOAD)
    assert "preview" in str(info.value)


def test_canonical_is_stable_and_compact():
    assert canonical({"b": 1, "a": [2, 1]}) == b'{"a":[2,1],"b":1}'
    # non-JSON values are stringified instead of crashing
    assert canonical({"s": {1}}) == b'{"s":"{1}"}'
