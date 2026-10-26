"""When a change goes wrong, the person is never told the wrong thing and nothing is done twice.

Odoo is the in-memory FakeOdoo; Redis is fakeredis or a stand-in that fails. Covers:
  * an approval is handed back when Odoo provably did not apply the change, and kept when it may have;
  * a change that went through is never reported as failed because a read afterwards failed;
  * a change is not sent when the call is too close to the platform's time limit;
  * Redis trouble: rate limits let calls through, approvals that cannot be recorded stop the change;
  * a button that appeared after the button list was cached is found;
  * every error from a change tool says whether anything changed.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import fakeredis
import pytest
import redis

from conftest import SALE_ORDER_FORM, FakeOdoo
from sahajta_odoo_mcp import service as service_module
from sahajta_odoo_mcp import state as state_module
from sahajta_odoo_mcp.confirm import ConfirmationSigner
from sahajta_odoo_mcp.errors import (
    ConfirmationRequired,
    NotSent,
    OdooError,
    OdooMCPError,
    PolicyViolation,
    StateUnavailable,
)
from sahajta_odoo_mcp.ratelimit import RateLimiter
from sahajta_odoo_mcp.state import MemoryState, RedisState, SQLiteState
from test_service_offline import LEAD, changes, make_service, make_shared

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

APPLIED_MAYBE = "Odoo may already have applied this change. Check before doing it again."
RETRY_SAME_TOKEN = "Nothing was changed. You can retry with the same confirm_token."
READ_BACK_FAILED = "Applied; could not read the new values back."

# the Odoo call each change tool makes
WRITES = {
    "create": ("crm.lead", "create"),
    "update": ("crm.lead", "write"),
    "action": ("sale.order", "action_confirm"),
    "message": ("crm.lead", "message_post"),
}


@pytest.fixture
def fake() -> FakeOdoo:
    return FakeOdoo()


@pytest.fixture
def svc(fake):
    return make_service(fake, mcp_allow_outbound_messages=True)


@pytest.fixture
def clock(monkeypatch):
    """The service's clock, moved by hand."""
    now = SimpleNamespace(t=1000.0)
    monkeypatch.setattr(service_module, "time", SimpleNamespace(monotonic=lambda: now.t))
    return now


async def approved(svc, tool: str):
    """Previews a change, as the person saw and approved it; returns the call that applies it."""
    if tool == "create":
        token = (await svc.preview_create("crm.lead", LEAD, None))["confirm_token"]
        return lambda: svc.create("crm.lead", LEAD, None, token)
    if tool == "update":
        token = (await svc.preview_update("crm.lead", [100], {"expected_revenue": 5000}, None))["confirm_token"]
        return lambda: svc.update("crm.lead", [100], {"expected_revenue": 5000}, None, token)
    if tool == "action":
        token = (await svc.preview_action("sale.order", [5], "action_confirm", None))["confirm_token"]
        return lambda: svc.run_action("sale.order", [5], "action_confirm", None, token)
    if tool == "message":
        token = (await svc.preview_message("crm.lead", 100, "Your quote is ready"))["confirm_token"]
        return lambda: svc.send_message("crm.lead", 100, "Your quote is ready", token)
    return lambda: svc.add_note("crm.lead", 100, "Called the customer.")


def answer_lost(fake: FakeOdoo, method: str, *, then=None) -> None:
    """Odoo carries `method` out, but its answer never arrives."""
    done = getattr(fake, f"_m_{method}", None)

    def handler(model, ids, context, **kwargs):
        if then:
            then(model, ids)
        elif done:
            done(model, ids, context, **kwargs)
        raise OdooError(f"{model}.{method} timed out", kind="timeout")

    setattr(fake, f"_m_{method}", handler)


def busy_after(fake: FakeOdoo, method: str, result=True) -> None:
    """Odoo carries `method` out, then turns every read away as busy."""
    done = getattr(fake, f"_m_{method}", None)

    def handler(model, ids, context, **kwargs):
        answer = done(model, ids, context, **kwargs) if done else result
        for read in ("read", "search", "search_read", "fields_get", "name_search"):
            fake.errors[(model, read)] = OdooError("", kind="rate_limited", status=429)
        return answer

    setattr(fake, f"_m_{method}", handler)


def slow_odoo(fake: FakeOdoo, clock, seconds: float) -> None:
    """From now on every Odoo call takes `seconds` on the service's clock."""
    quick = fake.call

    async def slow(*args, **kwargs):
        clock.t += seconds
        return await quick(*args, **kwargs)

    fake.call = slow


# ================================================================================ 1. approval kept or handed back


@pytest.mark.parametrize("tool", WRITES)
@pytest.mark.parametrize(
    "refusal",
    [
        OdooError("", kind="rate_limited", status=429),
        OdooError("ConnectError", kind="network", maybe_applied=False),
        OdooError("Record is being edited by someone else", kind="busy", status=409),
        OdooError("You cannot do that", kind="validation", status=422),
    ],
    ids=["429", "connect", "concurrency", "validation"],
)
async def test_a_change_odoo_turned_away_can_be_retried_with_the_same_token(svc, fake, tool, refusal):
    commit = await approved(svc, tool)
    fake.errors[WRITES[tool]] = refusal
    with pytest.raises(OdooError) as info:
        await commit()
    # Odoo refusing the values themselves: retrying as is would be refused again, so no retry hint
    expected = "Nothing was changed." if refusal.kind == "validation" else RETRY_SAME_TOKEN
    assert str(info.value).endswith(expected)
    del fake.errors[WRITES[tool]]
    await commit()  # the same approval works once Odoo accepts it
    assert len(fake.calls_to(WRITES[tool][1])) == 2


@pytest.mark.parametrize("tool", WRITES)
@pytest.mark.parametrize(
    "unknown",
    [
        OdooError("timed out", kind="timeout"),
        OdooError("RemoteProtocolError", kind="network"),
        OdooError("HTTP 504", kind="unavailable", status=504),
        OdooError("Odoo returned a non-JSON response", kind="server", status=200),
    ],
    ids=["timeout", "dropped", "504", "garbled"],
)
async def test_a_change_with_an_unknown_outcome_is_never_repeated_with_the_same_token(svc, fake, tool, unknown):
    commit = await approved(svc, tool)
    fake.errors[WRITES[tool]] = unknown
    with pytest.raises(OdooError) as info:
        await commit()
    text = str(info.value)
    assert "may already have" in text and "nothing was changed" not in text.lower()
    del fake.errors[WRITES[tool]]
    with pytest.raises(ConfirmationRequired, match="already used"):
        await commit()
    assert len(fake.calls_to(WRITES[tool][1])) == 1


async def test_create_with_a_lost_answer_lists_what_this_user_just_created(svc, fake):
    commit = await approved(svc, "create")
    answer_lost(fake, "create")
    with pytest.raises(OdooError) as info:
        await commit()
    text = str(info.value)
    assert APPLIED_MAYBE in text
    assert '{"id": 1000, "name": "MCP lead"}' in text  # the invoice/lead that did get created
    search = [c for c in fake.calls_to("search_read") if c.model == "crm.lead"][-1]
    by_user, recent = search.kwargs["domain"]
    assert by_user == ["create_uid", "=", 7] and recent[:2] == ["create_date", ">="]
    since = datetime.strptime(recent[2], "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    assert timedelta(minutes=2, seconds=50) < datetime.now(UTC) - since < timedelta(minutes=3, seconds=10)
    assert len(fake.records["crm.lead"]) == 3  # created once, and the retry is refused
    with pytest.raises(ConfirmationRequired):
        await commit()
    assert len(fake.calls_to("create")) == 1


async def test_create_with_a_lost_answer_and_nothing_found_does_not_claim_it_failed(svc, fake):
    commit = await approved(svc, "create")
    fake.errors[("crm.lead", "create")] = OdooError("timed out", kind="timeout")
    fake._m_search_read = lambda model, ids, context, **kwargs: []
    with pytest.raises(OdooError) as info:
        await commit()
    assert "found yet; Odoo may still be working on it" in str(info.value)


async def test_update_with_a_lost_answer_shows_what_odoo_has_now(svc, fake):
    commit = await approved(svc, "update")
    answer_lost(fake, "write")
    with pytest.raises(OdooError) as info:
        await commit()
    text = str(info.value)
    assert APPLIED_MAYBE in text
    assert "What Odoo shows now (business data" in text and '"expected_revenue": 5000' in text and '"id": 100' in text


async def test_button_with_a_lost_answer_shows_the_status_now(svc, fake):
    commit = await approved(svc, "action")
    answer_lost(fake, "action_confirm", then=lambda model, ids: [fake.touch(model, i, state="sale") for i in ids])
    with pytest.raises(OdooError) as info:
        await commit()
    text = str(info.value)
    assert APPLIED_MAYBE in text and '"state": "sale"' in text


async def test_when_odoo_cannot_be_checked_the_person_is_told_to_look(svc, fake):
    commit = await approved(svc, "update")
    busy = OdooError("", kind="rate_limited", status=429)
    answer_lost(fake, "write", then=lambda model, ids: fake.errors.update({(model, "search"): busy, (model, "read"): busy}))
    with pytest.raises(OdooError) as info:
        await commit()
    assert APPLIED_MAYBE in str(info.value) and "open the record(s) there" in str(info.value)


async def test_message_and_note_with_a_lost_answer_may_have_been_posted(svc, fake):
    send = await approved(svc, "message")
    answer_lost(fake, "message_post")
    with pytest.raises(OdooError) as info:
        await send()
    assert "Odoo may already have posted this message and e-mailed the followers" in str(info.value)
    with pytest.raises(OdooError) as info:
        await svc.add_note("crm.lead", 100, "Called the customer.")
    assert str(info.value).endswith("Odoo may already have posted this note. Check the record's chatter before doing it again.")


async def test_a_note_odoo_turned_away_says_nothing_changed(svc, fake):
    fake.errors[("crm.lead", "message_post")] = OdooError("", kind="rate_limited", status=429)
    with pytest.raises(OdooError) as info:
        await svc.add_note("crm.lead", 100, "Called the customer.")
    assert str(info.value).endswith("Nothing was changed. You can retry.")


async def test_if_the_approval_cannot_be_handed_back_the_person_previews_again(svc, fake, monkeypatch):
    commit = await approved(svc, "update")
    monkeypatch.setattr(svc.shared.signer, "release", lambda token: False)
    fake.errors[("crm.lead", "write")] = OdooError("", kind="rate_limited", status=429)
    with pytest.raises(OdooError) as info:
        await commit()
    assert str(info.value).endswith("Nothing was changed. Run the preview again to retry.")


async def test_what_odoo_shows_now_never_reaches_the_audit_log(tmp_path, fake):
    log = tmp_path / "audit.jsonl"
    svc = make_service(fake, make_shared(str(log)))
    preview = await svc.preview_update("crm.lead", [100], {"name": "TOP-SECRET-NAME"}, None)
    answer_lost(fake, "write")
    with pytest.raises(OdooError) as info:
        await svc.update("crm.lead", [100], {"name": "TOP-SECRET-NAME"}, None, preview["confirm_token"])
    assert "TOP-SECRET-NAME" in str(info.value)  # the person sees it
    text = log.read_text()
    assert "TOP-SECRET-NAME" not in text
    entry = json.loads(text.splitlines()[-1])
    assert entry["tool"] == "odoo_update" and entry["outcome"] == "error" and APPLIED_MAYBE in entry["detail"]


# ================================================================================ 2. success is never reported as failure


async def test_update_that_went_through_is_a_success_even_if_the_read_back_fails(svc, fake):
    commit = await approved(svc, "update")
    busy_after(fake, "write")
    result = await commit()
    assert result["message"] == f"Updated 1 crm.lead record(s). {READ_BACK_FAILED}"
    assert result["ids"] == [100] and changes(fake) == ["crm.lead.write"]


async def test_create_that_went_through_is_a_success_even_if_the_read_back_fails(svc, fake):
    commit = await approved(svc, "create")
    busy_after(fake, "create")
    result = await commit()
    assert result["created"] == [{"id": 1000, "name": None}]
    assert result["message"].endswith(READ_BACK_FAILED)


async def test_button_that_was_pressed_is_a_success_even_if_the_read_back_fails(svc, fake):
    commit = await approved(svc, "action")
    wizard = {"type": "ir.actions.act_window", "res_model": "sale.advance.payment.inv", "target": "new", "res_id": False,
              "name": "Create invoice", "context": {"active_ids": [5], "active_model": "sale.order"}}
    busy_after(fake, "action_confirm", result=wizard)
    result = await commit()
    assert result["done"].startswith("Ran 'Confirm'") and result["note"] == READ_BACK_FAILED
    assert "records_now" not in result
    assert "sale.advance.payment.inv" in result["next_step"]  # the wizard's next step still comes through


async def test_reads_after_a_change_stop_before_the_platform_cuts_the_answer_off(svc, fake, clock):
    commit = await approved(svc, "update")
    write = fake._m_write

    def slow_write(model, ids, context, **kwargs):
        clock.t += 56  # Vercel ends the request at 60 s
        return write(model, ids, context, **kwargs)

    fake._m_write = slow_write
    result = await commit()
    assert result["message"].endswith(READ_BACK_FAILED)
    assert fake.methods()[-1] == "write"  # nothing was read afterwards


# ================================================================================ 4. time budget


@pytest.mark.parametrize("tool", [*WRITES, "note"])
async def test_a_change_is_not_sent_once_the_call_has_used_20_seconds(svc, fake, clock, tool):
    commit = await approved(svc, tool)
    quick = fake.call
    slow_odoo(fake, clock, 21)
    with pytest.raises(NotSent) as info:
        await commit()
    assert changes(fake) == []
    expected = "Nothing was changed. You can retry." if tool == "note" else RETRY_SAME_TOKEN
    assert str(info.value).endswith(expected) and "not sent to Odoo" in str(info.value)
    fake.call = quick
    await commit()  # same approval, now in time
    assert len(changes(fake)) == 1


async def test_the_time_budget_counts_from_the_start_of_the_tool_call(svc, fake, clock):
    # tools.run marks the start before a cold instance spends time looking up the sign-in
    commit = await approved(svc, "update")
    token = service_module.CALL_STARTED.set(clock.t - 25)
    try:
        with pytest.raises(NotSent):
            await commit()
    finally:
        service_module.CALL_STARTED.reset(token)
    assert changes(fake) == []


async def test_a_change_within_the_time_budget_is_sent(svc, fake, clock):
    commit = await approved(svc, "update")
    slow_odoo(fake, clock, 4)  # a few slow reads, still well inside 20 s
    await commit()
    assert changes(fake) == ["crm.lead.write"]


# ================================================================================ 5. Redis blips


class DownRedis:
    """Every command fails, as when Upstash is unreachable."""

    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise redis.ConnectionError("Error 111 connecting to redis:6379. Connection refused.")

        return fail


class LostReplyRedis:
    """Runs SET, then loses the answer (a timeout after the command was carried out)."""

    def __init__(self, client):
        self._client = client

    def set(self, *args, **kwargs):
        self._client.set(*args, **kwargs)
        raise redis.TimeoutError("Timeout reading from socket")

    def __getattr__(self, name):
        return getattr(self._client, name)


PAYLOAD = {"op": "create", "model": "crm.lead"}


def test_an_approval_that_cannot_be_recorded_is_refused():
    signer = ConfirmationSigner(b"s" * 32, state=RedisState(DownRedis()))
    with pytest.raises(StateUnavailable, match="Nothing was changed, please try again"):
        signer.verify(signer.issue(PAYLOAD), PAYLOAD)


def test_a_claim_stored_before_its_answer_was_lost_is_undone():
    server = fakeredis.FakeServer()
    lossy = ConfirmationSigner(b"s" * 32, state=RedisState(LostReplyRedis(fakeredis.FakeRedis(server=server, decode_responses=True))))
    token = lossy.issue(PAYLOAD)
    with pytest.raises(StateUnavailable):
        lossy.verify(token, PAYLOAD)
    healthy = ConfirmationSigner(b"s" * 32, state=RedisState(fakeredis.FakeRedis(server=server, decode_responses=True)))
    healthy.verify(token, PAYLOAD)  # the retry the error asked for works


def test_a_lost_answer_never_undoes_another_instances_claim():
    server = fakeredis.FakeServer()
    first = ConfirmationSigner(b"s" * 32, state=RedisState(fakeredis.FakeRedis(server=server, decode_responses=True)))
    token = first.issue(PAYLOAD)
    first.verify(token, PAYLOAD)  # another instance is applying this change
    lossy = ConfirmationSigner(b"s" * 32, state=RedisState(LostReplyRedis(fakeredis.FakeRedis(server=server, decode_responses=True))))
    with pytest.raises(StateUnavailable):
        lossy.verify(token, PAYLOAD)
    with pytest.raises(ConfirmationRequired, match="already used"):
        first.verify(token, PAYLOAD)


@pytest.mark.parametrize("state", [MemoryState(), RedisState(fakeredis.FakeRedis(decode_responses=True))], ids=["memory", "redis"])
def test_release_makes_a_claim_available_again(state):
    assert state.claim_once("k", 2_000_000_000) is True
    assert state.claim_once("k", 2_000_000_000) is False
    assert state.release("k") is True
    assert state.claim_once("k", 2_000_000_000) is True


def test_release_reports_when_the_store_is_down():
    assert RedisState(DownRedis()).release("k") is False


def test_sqlite_claims_survive_a_restart_until_they_expire(tmp_path):
    # one container without Redis: an approval whose change may have reached Odoo stays used after a restart
    path = tmp_path / "data" / "claims.sqlite3"
    key = "confirm:1999999999.a-confirm-token"
    first = SQLiteState(path)
    assert first.claim_once(key, 2_000_000_000) is True
    assert first.claim_once("old", 1) is True  # expires at once
    first.close()
    second = SQLiteState(path)
    assert second.claim_once(key, 2_000_000_000) is False
    assert second.claim_once("old", 2_000_000_000) is True
    assert second.release(key) is True and second.claim_once(key, 2_000_000_000) is True
    second.close()
    assert b"a-confirm-token" not in path.read_bytes()  # only a digest of the token is stored


def test_a_sqlite_claim_that_cannot_be_recorded_stops_the_change(tmp_path):
    state = SQLiteState(tmp_path / "claims.sqlite3")
    state.close()
    with pytest.raises(StateUnavailable, match="Nothing was changed"):
        state.claim_once("k", 2_000_000_000)
    assert state.release("k") is False


async def test_a_change_is_not_sent_when_its_approval_cannot_be_recorded(fake):
    shared = make_shared()
    shared.signer = ConfirmationSigner(b"k" * 32, state=RedisState(DownRedis()))
    svc = make_service(fake, shared)
    preview = await svc.preview_create("crm.lead", LEAD, None)
    with pytest.raises(StateUnavailable) as info:
        await svc.create("crm.lead", LEAD, None, preview["confirm_token"])
    assert "Nothing was changed, please try again" in str(info.value)
    assert changes(fake) == []


async def test_rate_limits_let_calls_through_when_redis_is_down(fake, caplog):
    shared = make_shared()
    shared.limiter = RateLimiter(1, 1, state=RedisState(DownRedis()))
    svc = make_service(fake, shared)
    with caplog.at_level(logging.WARNING, logger="sahajta_odoo_mcp.state"):
        for _ in range(3):
            await svc.whoami()
    assert "rate limit not applied" in caplog.text


def test_redis_client_gives_up_within_two_seconds():
    kwargs = state_module.redis_client("redis://redis.invalid:6379").connection_pool.connection_kwargs
    assert kwargs["socket_timeout"] == 2 and kwargs["socket_connect_timeout"] == 2


# ================================================================================ 6. stale button list


async def test_a_button_that_appeared_after_the_list_was_cached_is_found(svc, fake):
    await svc.list_actions("sale.order")  # cached for 10 minutes
    fake.views["sale.order"]["views"]["form"]["arch"] = SALE_ORDER_FORM.replace(
        "</header>", '<button name="action_lock" string="Lock" type="object"/></header>'
    )
    preview = await svc.preview_action("sale.order", [5], "action_lock", None)
    await svc.run_action("sale.order", [5], "action_lock", None, preview["confirm_token"])
    assert fake.calls_to("action_lock")[0].ids == [5]


async def test_an_unknown_button_is_looked_up_once_more_then_refused(svc, fake):
    await svc.list_actions("sale.order")
    with pytest.raises(PolicyViolation, match="not a button"):
        await svc.preview_action("sale.order", [5], "action_hidden_helper", None)
    assert len(fake.calls_to("get_views")) == 2


# ================================================================================ 7. every error says what changed


def _no_token(svc, fake):
    return svc.create("crm.lead", LEAD, None, None)


def _wrong_token(svc, fake):
    return svc.update("crm.lead", [100], {"probability": 5}, None, "4102444800.forged")


def _blocked_model(svc, fake):
    return svc.update("res.users", [7], {"name": "x"}, None, None)


def _missing_record(svc, fake):
    return svc.update("crm.lead", [987654321], {"probability": 5}, None, None)


def _odoo_busy_before_sending(svc, fake):
    fake.errors[("crm.lead", "search")] = OdooError("", kind="rate_limited", status=429)
    return svc.update("crm.lead", [100], {"probability": 5}, None, None)


def _odoo_slow_before_sending(svc, fake):
    # a timeout on a read: the change itself was never sent, so this is not an "unknown outcome"
    fake.errors[("crm.lead", "search")] = OdooError("crm.lead.search timed out", kind="timeout")
    return svc.update("crm.lead", [100], {"probability": 5}, None, None)


def _read_only(svc, fake):
    return make_service(fake, mcp_access_mode="read_only").add_note("crm.lead", 100, "hi")


def _messaging_off(svc, fake):
    return make_service(fake).send_message("crm.lead", 100, "hi", None)


def _rate_limited(svc, fake):
    svc.shared.limiter = RateLimiter(1000, 0)
    return svc.add_note("crm.lead", 100, "hi")


@pytest.mark.parametrize(
    "make_call",
    [_no_token, _wrong_token, _blocked_model, _missing_record, _odoo_busy_before_sending, _odoo_slow_before_sending,
     _read_only, _messaging_off, _rate_limited],
)
async def test_every_error_from_a_change_tool_says_whether_anything_changed(svc, fake, make_call):
    with pytest.raises(OdooMCPError) as info:
        await make_call(svc, fake)
    text = str(info.value)
    assert "nothing was changed" in text.lower() and "may already have" not in text
    assert changes(fake) == []
