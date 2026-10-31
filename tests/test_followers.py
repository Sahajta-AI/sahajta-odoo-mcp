"""Followers: adding people to, or removing them from, the followers of records (Odoo's message_subscribe /
message_unsubscribe), each change previewed and approved once. Added followers get e-mails about the record from then
on, so adding needs e-mailing switched on; removing does not.

Odoo is the in-memory FakeOdoo (conftest). Every test also asserts (fixture ``no_unlink_ever``) that no method
containing "unlink" reached it.
"""

from __future__ import annotations

import pytest
from mcp.client import Client
from mcp.server.mcpserver import MCPServer

from conftest import FakeOdoo
from sahajta_odoo_mcp.errors import ConfirmationRequired, OdooError, PolicyViolation, ValidationFailed
from sahajta_odoo_mcp.tools import register_tools
from test_service_offline import make_service, make_shared

pytestmark = pytest.mark.usefixtures("no_unlink_ever")

FOLLOWER_CALLS = {"message_subscribe", "message_unsubscribe"}


def sent(fake: FakeOdoo) -> list[tuple[str, list[int] | None, list[int]]]:
    return [(c.method, c.ids, c.kwargs.get("partner_ids")) for c in fake.calls if c.method in FOLLOWER_CALLS]


@pytest.fixture
def fake() -> FakeOdoo:
    fake = FakeOdoo()
    for partner in fake.records["res.partner"].values():
        partner["active"] = True
    fake.followers = [{"res_id": 100, "partner_id": [1, "Acme Corp"]}]  # crm.lead 100 is followed by Acme Corp

    def subscribe(model, ids, context, partner_ids=None, **kw):
        for rid in ids:
            for partner in partner_ids or []:
                if not any(f["res_id"] == rid and f["partner_id"][0] == partner for f in fake.followers):
                    fake.followers.append({"res_id": rid, "partner_id": [partner, fake.records["res.partner"][partner]["name"]]})
        return True

    def unsubscribe(model, ids, context, partner_ids=None, **kw):
        fake.followers = [f for f in fake.followers if not (f["res_id"] in ids and f["partner_id"][0] in (partner_ids or []))]
        return True

    fake._m_message_subscribe = subscribe
    fake._m_message_unsubscribe = unsubscribe
    return fake


@pytest.fixture
def svc(fake):
    return make_service(fake, mcp_allow_outbound_messages=True)


async def test_the_preview_names_each_person_and_says_they_will_get_e_mails(svc, fake):
    preview = await svc.preview_followers("crm.lead", [100, 101], [2, 1], None)
    assert sent(fake) == [], "a preview changes nothing"
    assert [p["person"] for p in preview["add"]] == ["Jane Buyer <jane@acme.example>", "Acme Corp <info@acme.example>"]
    assert preview["add"][1]["already_follows"] == ["Big deal"]
    assert "From now on, Jane Buyer, Acme Corp will receive e-mails about these records" in preview["warnings"][0]
    assert "sends no e-mail by itself" in preview["warnings"][0]
    assert [r["name"] for r in preview["records"]] == ["Big deal", "Small deal"]


async def test_adding_followers_is_one_approval_and_one_call(svc, fake):
    preview = await svc.preview_followers("crm.lead", [101], [2], None)
    result = await svc.change_followers("crm.lead", [101], [2], None, preview["confirm_token"])
    assert sent(fake) == [("message_subscribe", [101], [2])]
    assert result["followers_now"] == [
        {"record": "Small deal", "link": "https://odoo.example.com/odoo/crm.lead/101", "followers": ["Jane Buyer"]}
    ]
    with pytest.raises(ConfirmationRequired):  # one approval, one change
        await svc.change_followers("crm.lead", [101], [2], None, preview["confirm_token"])
    assert len(sent(fake)) == 1


async def test_the_approval_covers_exactly_the_previewed_change(svc, fake):
    preview = await svc.preview_followers("crm.lead", [101], [2], None)
    with pytest.raises(ConfirmationRequired, match="does not match"):
        await svc.change_followers("crm.lead", [101], [1], None, preview["confirm_token"])
    fake.followers.append({"res_id": 101, "partner_id": [3, "Globex"]})  # someone changed the followers meanwhile
    with pytest.raises(ConfirmationRequired, match="does not match"):
        await svc.change_followers("crm.lead", [101], [2], None, preview["confirm_token"])
    assert sent(fake) == []


async def test_adding_needs_the_e_mail_switch_but_removing_does_not(fake):
    svc = make_service(fake, mcp_allow_outbound_messages=False)
    with pytest.raises(PolicyViolation, match="Adding followers is switched off"):
        await svc.preview_followers("crm.lead", [100], [2], None)
    with pytest.raises(PolicyViolation, match="Adding followers is switched off"):
        await svc.change_followers("crm.lead", [100], [2], None, None)
    preview = await svc.preview_followers("crm.lead", [100], None, [1])
    assert preview["remove"] == [{"person": "Acme Corp <info@acme.example>"}]
    assert "Acme Corp will stop receiving e-mails about this record" in preview["warnings"][0]
    await svc.change_followers("crm.lead", [100], None, [1], preview["confirm_token"])
    assert sent(fake) == [("message_unsubscribe", [100], [1])] and fake.followers == []


async def test_adding_always_needs_an_approval_even_when_previews_are_optional(fake):
    svc = make_service(fake, mcp_allow_outbound_messages=True, mcp_require_preview=False)
    with pytest.raises(ConfirmationRequired):
        await svc.change_followers("crm.lead", [100], [2], None, None)
    await svc.change_followers("crm.lead", [100], None, [1], None)  # removing e-mails nobody
    assert sent(fake) == [("message_unsubscribe", [100], [1])]


async def test_a_half_done_change_is_never_reported_as_nothing_changed(svc, fake):
    preview = await svc.preview_followers("crm.lead", [100], [2], [1])
    fake.errors[("crm.lead", "message_unsubscribe")] = OdooError("You cannot do that", kind="validation")
    with pytest.raises(OdooError) as info:
        await svc.change_followers("crm.lead", [100], [2], [1], preview["confirm_token"])
    text = str(info.value)
    assert "may already have applied" in text and "nothing was changed" not in text.lower()
    assert [method for method, _, _ in sent(fake)] == ["message_subscribe", "message_unsubscribe"]
    del fake.errors[("crm.lead", "message_unsubscribe")]
    fake.followers = [{"res_id": 100, "partner_id": [1, "Acme Corp"]}]  # as previewed, so only the used approval stops it
    with pytest.raises(ConfirmationRequired, match="already used"):  # the approval stays used
        await svc.change_followers("crm.lead", [100], [2], [1], preview["confirm_token"])


async def test_a_change_odoo_refused_changed_nothing_and_can_be_retried(svc, fake):
    preview = await svc.preview_followers("crm.lead", [101], [2], None)
    fake.errors[("crm.lead", "message_subscribe")] = OdooError("", kind="rate_limited", status=429)
    with pytest.raises(OdooError) as info:
        await svc.change_followers("crm.lead", [101], [2], None, preview["confirm_token"])
    assert "Nothing was changed. You can retry with the same confirm_token." in str(info.value)
    del fake.errors[("crm.lead", "message_subscribe")]
    await svc.change_followers("crm.lead", [101], [2], None, preview["confirm_token"])
    assert len(sent(fake)) == 2


@pytest.mark.parametrize(
    "model, ids, add, remove, error, needle",
    [
        ("crm.lead", [100], None, None, ValidationFailed, "give add_partner_ids, remove_partner_ids or both"),
        ("crm.lead", [100], [2], [2], ValidationFailed, "both added and removed"),
        ("crm.lead", [100], [99], None, ValidationFailed, "contacts \\[99\\] do not exist"),
        ("crm.lead", [100], ["2"], None, ValidationFailed, "list of contact ids"),
        ("crm.lead", [999], [2], None, ValidationFailed, "records \\[999\\] do not exist"),
        ("crm.tag", [1], [2], None, ValidationFailed, "have no followers"),
        ("res.users", [7], [2], None, PolicyViolation, "res.users"),
    ],
)
async def test_anything_unclear_is_refused_before_approval(svc, fake, model, ids, add, remove, error, needle):
    with pytest.raises(error, match=needle):
        await svc.preview_followers(model, ids, add, remove)
    assert sent(fake) == []


async def test_archived_contacts_and_records_the_person_may_not_edit_are_refused(svc, fake):
    fake.records["res.partner"][2]["active"] = False
    with pytest.raises(ValidationFailed, match="Jane Buyer: archived contacts cannot follow"):
        await svc.preview_followers("crm.lead", [100], [2], None)
    fake.access[("crm.lead", "write")] = False
    with pytest.raises(OdooError, match="may not change crm.lead"):
        await svc.preview_followers("crm.lead", [100], None, [1])


async def test_followers_use_the_action_cap(fake):
    # followers e-mail people, so they count against the action cap, not the larger cap for edits
    svc = make_service(fake, mcp_allow_outbound_messages=True, mcp_max_write_records=50, mcp_max_action_records=1)
    with pytest.raises(ValidationFailed, match="the limit is 1"):
        await svc.preview_followers("crm.lead", [100, 101], [2], None)
    with pytest.raises(ValidationFailed, match="too many contacts"):
        await svc.preview_followers("crm.lead", [100], [1, 2], None)


@pytest.mark.parametrize("access, has_tools", [("read_only", False), ("read_write", True)])
async def test_the_follower_tools_exist_only_when_claude_may_change_things(fake, access, has_tools):
    shared = make_shared(mcp_access_mode=access, mcp_allow_outbound_messages=True)
    service = make_service(fake, shared)
    mcp = MCPServer("followers-test")

    async def get_service():
        return service

    register_tools(mcp, get_service, shared.settings)
    async with Client(mcp) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        assert ({"odoo_preview_followers", "odoo_change_followers"} <= names) is has_tools
        assert "odoo_read_file" in names
        if has_tools:
            result = await client.call_tool(
                "odoo_preview_followers", {"model": "crm.lead", "ids": [101], "add_partner_ids": [2]}
            )
            assert not result.is_error and "Jane Buyer <jane@acme.example>" in result.content[0].text
