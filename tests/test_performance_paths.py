"""Regression tests for the serverless performance paths (all offline).

1. state.py      MemoryState / RedisState get_json + set_json: round trips, TTLs, size cap, Redis never breaks a request.
2. odoo_client   the JSON-2 probe's context_get is reused by identity(); identity is shared through the cache.
3. schema.py     fields_get is shared through the cache, per Odoo user.
4. server.py     GET /mcp is declined with 405 (no listen stream) and the MCP server has no subscriptions/listen.

Odoo is mocked with respx (assert_all_mocked), Redis with fakeredis; nothing reaches a network host.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import inspect
import json
import os
import time as real_time
import zlib
from contextlib import contextmanager
from types import SimpleNamespace

import fakeredis
import httpx
import pytest
import redis
import respx
import uvicorn
from starlette.testclient import TestClient

from conftest import SCHEMA, build_settings
from mcp.client import Client
from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import METHOD_NOT_FOUND
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from sahajta_odoo_mcp import odoo_client
from sahajta_odoo_mcp import server as server_module
from sahajta_odoo_mcp import state as state_module
from sahajta_odoo_mcp.config import Settings
from sahajta_odoo_mcp.errors import ValidationFailed
from sahajta_odoo_mcp.odoo_client import OdooClient, OdooCredentials
from sahajta_odoo_mcp.schema import FIELD_ATTRIBUTES, SchemaCache
from sahajta_odoo_mcp.server import _NoListenStream, create_http_app, create_stdio_server
from sahajta_odoo_mcp.state import MemoryState, RedisState
from test_oauth import FakeOdoo as OAuthFakeOdoo
from test_oauth import connect as oauth_connect

URL = "https://odoo.example.com"
DB = "testdb"
PUBLIC = "https://mcp.example.com"
PREFIX = "sahajta-odoo-mcp:"
LOGIN = "ai.tester@example.com"
KEY_A = "key-of-user-a-0123456789abcdef0123"
KEY_B = "key-of-user-b-fedcba9876543210fedc"

LEAD_FIELDS = copy.deepcopy(SCHEMA["crm.lead"])
# Field visibility depends on the user's groups: user B must never be served user A's fields_get.
FIELDS_BY_KEY = {
    KEY_A: {"crm.lead": LEAD_FIELDS, "res.partner": {"name": {"type": "char", "string": "Name"}}},
    KEY_B: {"crm.lead": {"name": {"type": "char", "string": "Opportunity"}}, "res.partner": {}},
}
USERS = {
    KEY_A: {
        "ctx": {"uid": 7, "tz": "Asia/Kolkata", "lang": "en_IN"},
        "row": {"id": 7, "login": LOGIN, "name": "AI Tester", "share": False, "company_id": [1, "Sahajta"]},
    },
    KEY_B: {
        "ctx": {"uid": 8, "tz": "Europe/Berlin", "lang": "de_DE"},
        "row": {"id": 8, "login": "other@example.com", "name": "Other", "share": False, "company_id": [1, "Sahajta"]},
    },
}


@pytest.fixture(autouse=True)
def fresh_gates(monkeypatch):
    # The per-URL semaphores are module globals; each test runs in its own event loop.
    monkeypatch.setattr(odoo_client, "_GATES", {})


def body_of(request: httpx.Request) -> dict:
    return json.loads(request.content)


def creds(key: str = KEY_A, *, login: str = LOGIN, db: str | None = DB) -> OdooCredentials:
    return OdooCredentials(URL, db, login, key)


class FakeRedisBackend:
    """One fake Redis server; every `state()` is a new connection to it, like a separate serverless instance."""

    def __init__(self) -> None:
        self.server = fakeredis.FakeServer()

    def client(self) -> fakeredis.FakeRedis:
        return fakeredis.FakeRedis(server=self.server, decode_responses=True)

    def state(self) -> RedisState:
        return RedisState(self.client())


@pytest.fixture(params=["memory", "redis"])
def new_state(request):
    """Factory for 'the shared cache as seen by a new server instance'.

    memory: the same in-process MemoryState object (a docker deployment: one process, many clients).
    redis : a new RedisState on a new connection to the same fake Redis (serverless: many instances).
    """
    if request.param == "memory":
        shared = MemoryState()
        return lambda: shared
    return FakeRedisBackend().state


class BrokenRedis:
    """A redis client whose every command fails, as when Upstash is down or unreachable."""

    def __init__(self, exc: Exception):
        self.exc = exc
        self.commands: list[str] = []

    def get(self, *args, **kwargs):
        self.commands.append("get")
        raise self.exc

    def set(self, *args, **kwargs):
        self.commands.append("set")
        raise self.exc


REDIS_FAILURES = [
    redis.ConnectionError("Error 111 connecting to redis:6379. Connection refused."),
    redis.TimeoutError("Timeout reading from socket"),
    redis.ResponseError("OOM command not allowed when used memory > 'maxmemory'"),
]


class Json2Odoo:
    """JSON-2 endpoints of an Odoo 19 server; answers per API key."""

    def __init__(self, router: respx.MockRouter):
        self.router = router
        self.context_get = router.post("/json/2/res.users/context_get").mock(side_effect=self._context_get)
        self.read = router.post("/json/2/res.users/read").mock(side_effect=self._read)
        self.version = router.get("/web/version").mock(return_value=httpx.Response(200, json={"version": "19.0+e"}))
        self.fields_get = {
            model: router.post(f"/json/2/{model}/fields_get").mock(side_effect=self._fields_get(model))
            for model in ("crm.lead", "res.partner")
        }
        self.search_count = router.post("/json/2/crm.lead/search_count").mock(return_value=httpx.Response(200, json=3))
        self.jsonrpc = router.post("/jsonrpc").mock(return_value=httpx.Response(500))  # must never be needed

    @staticmethod
    def _key(request: httpx.Request) -> str:
        return request.headers["authorization"].split(" ", 1)[1]

    def _context_get(self, request: httpx.Request) -> httpx.Response:
        user = USERS.get(self._key(request))
        return httpx.Response(200, json=user["ctx"]) if user else httpx.Response(401, json={"name": "x", "message": "bad key"})

    def _read(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[USERS[self._key(request)]["row"]])

    def _fields_get(self, model: str):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=copy.deepcopy(FIELDS_BY_KEY[self._key(request)][model]))

        return handler

    @property
    def total_calls(self) -> int:
        return self.router.calls.call_count


class JsonRpcOdoo:
    """/jsonrpc of an Odoo <= 18 server (context_get carries no uid: it comes from authenticate)."""

    UID = 9

    def __init__(self, router: respx.MockRouter):
        self.calls: list[dict] = []
        router.post("/jsonrpc").mock(side_effect=self)
        router.get("/web/version").mock(return_value=httpx.Response(200, json={"version": "17.0"}))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        payload = body_of(request)
        params = payload["params"]
        self.calls.append(params)
        if params["service"] == "common":
            result = self.UID if params["method"] == "authenticate" else {"server_version": "17.0"}
        else:
            result = {
                "context_get": {"tz": "Europe/Berlin", "lang": "de_DE"},
                "read": [{"id": self.UID, "login": LOGIN, "name": "Legacy", "share": False, "company_id": [2, "Sub"]}],
                "search_count": 5,
            }[params["args"][4]]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})

    def methods(self) -> list[str]:
        return [c["method"] if c["service"] == "common" else c["args"][4] for c in self.calls]


@pytest.fixture
def router():
    with respx.mock(base_url=URL, assert_all_called=False, assert_all_mocked=True) as mock:
        yield mock


@pytest.fixture
def odoo(router) -> Json2Odoo:
    return Json2Odoo(router)


# ===================================================================================== 1. state: MemoryState


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def time(self) -> float:
        return real_time.time()


@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(state_module, "time", fake)
    return fake


def test_memory_round_trip_and_miss():
    state = MemoryState()
    value = {"protocol": "json2", "identity": {"uid": 7, "company_id": None, "is_internal_user": True}, "list": [1, "a"]}
    assert state.get_json("missing") is None
    state.set_json("k", value, 60)
    assert state.get_json("k") == value
    assert state.get_json("other") is None


def test_memory_entries_expire_after_their_ttl(clock):
    state = MemoryState()
    state.set_json("k", {"v": 1}, 60)
    clock.now += 59.9
    assert state.get_json("k") == {"v": 1}
    clock.now += 0.1  # exactly at the expiry time: gone
    assert state.get_json("k") is None
    clock.now -= 30  # an expired entry is dropped, not merely hidden
    assert state.get_json("k") is None


def test_memory_set_again_replaces_the_value_and_restarts_the_ttl(clock):
    state = MemoryState()
    state.set_json("k", {"v": 1}, 60)
    clock.now += 50
    state.set_json("k", {"v": 2}, 60)
    clock.now += 50
    assert state.get_json("k") == {"v": 2}


def test_memory_cache_stays_bounded():
    state = MemoryState()
    for i in range(5000):
        state.set_json(f"k{i}", i, 600)
    assert len(state._cache) <= 2001
    assert state.get_json("k4999") == 4999


# ===================================================================================== 1. state: RedisState


def test_redis_round_trip_under_a_hashed_compressed_key():
    backend = FakeRedisBackend()
    value = {"protocol": "json2", "base_context": {"lang": "en_IN"}, "identity": {"uid": 7, "company_id": None}}
    writer, reader = backend.state(), backend.state()
    writer.set_json("identity:secret-ish key|with spaces", value, 600)
    assert reader.get_json("identity:secret-ish key|with spaces") == value  # another instance reads it back

    r = backend.client()
    name = f"{PREFIX}cache:{hashlib.sha256(b'identity:secret-ish key|with spaces').hexdigest()}"
    assert r.keys("*") == [name]  # the plain key never appears in Redis
    stored = r.get(name)
    assert json.loads(zlib.decompress(base64.b64decode(stored))) == value  # zlib + base64 JSON
    assert reader.get_json("identity:another key") is None


def test_redis_custom_prefix_is_used():
    backend = FakeRedisBackend()
    RedisState(backend.client(), prefix="tenant-x:").set_json("k", [1, 2], 60)
    assert [k.split("cache:")[0] for k in backend.client().keys("*")] == ["tenant-x:"]
    assert RedisState(backend.client(), prefix="tenant-x:").get_json("k") == [1, 2]
    assert RedisState(backend.client()).get_json("k") is None


@pytest.mark.parametrize("ttl", [1, 600, 86_400])
def test_redis_entries_get_the_requested_ttl(ttl):
    backend = FakeRedisBackend()
    backend.state().set_json("k", {"v": 1}, ttl)
    r = backend.client()
    (name,) = r.keys("*")
    assert 0 < r.pttl(name) <= ttl * 1000


def test_redis_oversize_value_is_not_stored():
    backend = FakeRedisBackend()
    state = backend.state()
    incompressible = os.urandom(1_000_000).hex()  # ~1.3 MB once compressed and base64-encoded
    state.set_json("big", {"blob": incompressible}, 600)  # must not raise
    assert backend.client().dbsize() == 0
    assert state.get_json("big") is None


def test_redis_size_cap_applies_to_the_compressed_blob(monkeypatch):
    backend = FakeRedisBackend()
    state = backend.state()
    value = {"fields": {f"x_field_{i}": {"type": "char", "string": f"Field {i}"} for i in range(200)}}
    state.set_json("probe", value, 60)
    (name,) = backend.client().keys("*")
    blob_size = len(backend.client().get(name))
    backend.client().flushall()

    monkeypatch.setattr(state_module, "_MAX_CACHED_BYTES", blob_size)
    state.set_json("at-limit", value, 60)
    assert state.get_json("at-limit") == value

    monkeypatch.setattr(state_module, "_MAX_CACHED_BYTES", blob_size - 1)
    state.set_json("over-limit", value, 60)
    assert state.get_json("over-limit") is None


def test_redis_large_but_compressible_value_is_stored():
    state = FakeRedisBackend().state()
    value = {"help": "a" * 3_000_000}  # 3 MB of JSON, a few KB compressed
    state.set_json("k", value, 60)
    assert state.get_json("k") == value


@pytest.mark.parametrize("exc", REDIS_FAILURES, ids=lambda e: type(e).__name__)
def test_redis_errors_never_raise(exc):
    client = BrokenRedis(exc)
    state = RedisState(client)
    assert state.get_json("k") is None
    assert state.set_json("k", {"v": 1}, 60) is None
    assert client.commands == ["get", "set"]  # the commands really were attempted


def test_redis_disconnected_server_never_raises():
    server = fakeredis.FakeServer()
    server.connected = False
    state = RedisState(fakeredis.FakeRedis(server=server, decode_responses=True))
    state.set_json("k", {"v": 1}, 60)
    assert state.get_json("k") is None


@pytest.mark.parametrize(
    "raw",
    [
        "not base64 at all !!!",
        base64.b64encode(b"valid base64, not zlib").decode(),
        base64.b64encode(zlib.compress(b"{not json")).decode(),
        base64.b64encode(zlib.compress(b"\xff\xfe\xfa")).decode(),
        "café",  # non-ASCII
    ],
    ids=["not-base64", "not-zlib", "not-json", "not-utf8", "non-ascii"],
)
def test_redis_corrupt_entries_read_as_a_miss(raw):
    backend = FakeRedisBackend()
    backend.client().set(f"{PREFIX}cache:{hashlib.sha256(b'k').hexdigest()}", raw)
    assert backend.state().get_json("k") is None


@pytest.mark.parametrize("value", [{1, 2}, {"when": object()}], ids=["set", "object"])
def test_redis_unserialisable_values_are_skipped(value):
    backend = FakeRedisBackend()
    backend.state().set_json("k", value, 60)
    assert backend.client().dbsize() == 0


# ===================================================================================== 2a. probe context reused


@pytest.mark.parametrize("protocol", ["auto", "json2"])
async def test_fresh_client_identity_calls_context_get_once(odoo, protocol):
    async with httpx.AsyncClient() as http:
        client = OdooClient(creds(), http, protocol=protocol)
        identity = await client.identity()
        await client.call("crm.lead", "search_count", domain=[])
    assert (identity.uid, identity.tz, identity.lang, identity.protocol) == (7, "Asia/Kolkata", "en_IN", "json2")
    assert odoo.context_get.call_count == 1
    assert odoo.read.call_count == 1
    assert odoo.version.call_count == 1
    assert odoo.jsonrpc.call_count == 0
    assert body_of(odoo.context_get.calls.last.request) == {}
    assert body_of(odoo.search_count.calls.last.request)["context"] == {"lang": "en_IN", "tz": "Asia/Kolkata"}


async def test_auto_probe_from_an_earlier_call_is_reused_by_identity(odoo):
    async with httpx.AsyncClient() as http:
        client = OdooClient(creds(), http, protocol="auto")
        await client.call("crm.lead", "search_count", domain=[])  # probes JSON-2 first
        await client.identity()
    assert odoo.context_get.call_count == 1 and odoo.read.call_count == 1


# ===================================================================================== 2b. identity cache


async def test_identity_cache_lets_a_new_client_skip_odoo(odoo, new_state):
    async with httpx.AsyncClient() as http:
        first = await OdooClient(creds(), http, protocol="auto", cache=new_state()).identity()
        calls_after_first = odoo.total_calls
        assert calls_after_first == 3  # context_get (probe), read, /web/version

        second_client = OdooClient(creds(), http, protocol="auto", cache=new_state())
        second = await second_client.identity()
        assert odoo.total_calls == calls_after_first  # no Odoo request at all
        assert second == first
        assert second_client.protocol == "json2"

        assert await second_client.call("crm.lead", "search_count", domain=[["id", ">", 0]]) == 3
    assert odoo.context_get.call_count == 1  # no new JSON-2 probe either
    assert body_of(odoo.search_count.calls.last.request) == {
        "domain": [["id", ">", 0]],
        "context": {"lang": "en_IN", "tz": "Asia/Kolkata"},
    }


async def test_identity_cache_keeps_caller_context_keys_winning(odoo, new_state):
    async with httpx.AsyncClient() as http:
        await OdooClient(creds(), http, cache=new_state()).identity()
        client = OdooClient(creds(), http, cache=new_state())
        await client.identity()
        await client.call("crm.lead", "search_count", domain=[], context={"lang": "fr_FR", "active_test": False})
    assert body_of(odoo.search_count.calls.last.request)["context"] == {
        "lang": "fr_FR", "tz": "Asia/Kolkata", "active_test": False,
    }


async def test_identity_cache_is_per_api_key(odoo, new_state):
    async with httpx.AsyncClient() as http:
        alice = await OdooClient(creds(KEY_A), http, cache=new_state()).identity()
        bob_client = OdooClient(creds(KEY_B), http, cache=new_state())
        bob = await bob_client.identity()
        await bob_client.call("crm.lead", "search_count", domain=[])
    assert alice.uid == 7 and bob.uid == 8
    assert odoo.context_get.call_count == 2 and odoo.read.call_count == 2
    assert body_of(odoo.search_count.calls.last.request)["context"] == {"lang": "de_DE", "tz": "Europe/Berlin"}


@pytest.mark.parametrize(
    "other", [creds(KEY_A, login="someone.else@example.com"), creds(KEY_A, db="otherdb"), creds(KEY_A, db=None)],
    ids=["login", "db", "no-db"],
)
async def test_identity_cache_key_covers_every_credential_part(odoo, new_state, other):
    async with httpx.AsyncClient() as http:
        await OdooClient(creds(), http, cache=new_state()).identity()
        await OdooClient(other, http, cache=new_state()).identity()
    assert odoo.context_get.call_count == 2 and odoo.read.call_count == 2


async def test_identity_cache_never_stores_the_api_key(odoo):
    backend = FakeRedisBackend()
    memory = MemoryState()
    async with httpx.AsyncClient() as http:
        await OdooClient(creds(), http, cache=backend.state()).identity()
        await OdooClient(creds(), http, cache=memory).identity()
    r = backend.client()
    keys = r.keys("*")
    assert len(keys) == 1
    stored = json.dumps(json.loads(zlib.decompress(base64.b64decode(r.get(keys[0])))))
    assert KEY_A not in keys[0] and KEY_A not in stored and LOGIN not in keys[0]
    (memory_key,) = memory._cache
    assert KEY_A not in memory_key and KEY_A not in json.dumps(memory.get_json(memory_key))


@pytest.mark.parametrize("protocol", ["jsonrpc", "auto"])
async def test_identity_cache_restores_the_jsonrpc_uid(router, new_state, protocol):
    probe = router.post("/json/2/res.users/context_get").mock(return_value=httpx.Response(404, text="Not Found"))
    odoo = JsonRpcOdoo(router)
    async with httpx.AsyncClient() as http:
        first = await OdooClient(creds(), http, protocol=protocol, cache=new_state()).identity()
        assert odoo.methods() == ["authenticate", "context_get", "read"]
        requests_before = router.calls.call_count
        odoo.calls.clear()

        client = OdooClient(creds(), http, protocol=protocol, cache=new_state())
        second = await client.identity()
        assert router.calls.call_count == requests_before
        assert second == first and second.uid == JsonRpcOdoo.UID and second.protocol == "jsonrpc"
        assert client.protocol == "jsonrpc"

        assert await client.call("crm.lead", "search_count", domain=[]) == 5
    assert odoo.methods() == ["search_count"]  # no authenticate: the cached uid is used
    assert odoo.calls[0]["args"] == [
        DB, JsonRpcOdoo.UID, KEY_A, "crm.lead", "search_count", [],
        {"domain": [], "context": {"lang": "de_DE", "tz": "Europe/Berlin"}},
    ]
    assert probe.call_count == (1 if protocol == "auto" else 0)


@pytest.mark.parametrize("exc", REDIS_FAILURES, ids=lambda e: type(e).__name__)
async def test_identity_works_when_redis_is_down(odoo, exc):
    async with httpx.AsyncClient() as http:
        first = await OdooClient(creds(), http, protocol="auto", cache=RedisState(BrokenRedis(exc))).identity()
        second = await OdooClient(creds(), http, protocol="auto", cache=RedisState(BrokenRedis(exc))).identity()
    assert first == second and first.uid == 7
    assert odoo.context_get.call_count == 2  # nothing cached, nothing broken


# ===================================================================================== 3. shared schema cache


async def test_shared_schema_cache_serves_a_new_instance_without_fields_get(odoo, new_state):
    async with httpx.AsyncClient() as http:
        state = new_state()
        client = OdooClient(creds(), http, protocol="json2", cache=state)
        fields = await SchemaCache(shared=state).fields(client, "crm.lead")
        assert odoo.fields_get["crm.lead"].call_count == 1
        assert body_of(odoo.fields_get["crm.lead"].calls.last.request)["attributes"] == FIELD_ATTRIBUTES
        assert fields["id"] == {"type": "integer", "string": "ID", "readonly": True, "store": True}
        assert set(LEAD_FIELDS) < set(fields)
        requests_before = odoo.total_calls

        # A brand-new server instance: new state handle, new client, new SchemaCache.
        state2 = new_state()
        schema2 = SchemaCache(shared=state2)
        client2 = OdooClient(creds(), http, protocol="json2", cache=state2)
        again = await schema2.fields(client2, "crm.lead")
        assert again == fields
        assert odoo.total_calls == requests_before  # neither identity nor fields_get went to Odoo
        assert await schema2.fields(client2, "crm.lead") == fields  # and now from its local cache
    assert odoo.fields_get["crm.lead"].call_count == 1


async def test_shared_schema_cache_is_per_odoo_user(odoo, new_state):
    async with httpx.AsyncClient() as http:
        alice = await SchemaCache(shared=new_state()).fields(OdooClient(creds(KEY_A), http, cache=new_state()), "crm.lead")
        bob = await SchemaCache(shared=new_state()).fields(OdooClient(creds(KEY_B), http, cache=new_state()), "crm.lead")
    assert odoo.fields_get["crm.lead"].call_count == 2
    assert "expected_revenue" in alice and "expected_revenue" not in bob
    assert set(bob) == {"name", "id"}


async def test_shared_schema_cache_is_per_model(odoo, new_state):
    async with httpx.AsyncClient() as http:
        client = OdooClient(creds(), http)
        await SchemaCache(shared=new_state()).fields(client, "crm.lead")
        partner = await SchemaCache(shared=new_state()).fields(client, "res.partner")
    assert set(partner) == {"name", "id"}
    assert odoo.fields_get["crm.lead"].call_count == 1 and odoo.fields_get["res.partner"].call_count == 1


async def test_shared_schema_entry_uses_the_schema_ttl(odoo):
    backend = FakeRedisBackend()
    async with httpx.AsyncClient() as http:
        await SchemaCache(ttl_seconds=123, shared=backend.state()).fields(OdooClient(creds(), http), "crm.lead")
    r = backend.client()
    (name,) = r.keys("*")  # the client has no cache: the only entry is fields_get
    assert 0 < r.ttl(name) <= 123


async def test_unknown_model_is_not_cached(router):
    Json2Odoo(router)
    missing = router.post("/json/2/x_nope/fields_get").mock(
        return_value=httpx.Response(404, json={"name": "werkzeug.exceptions.NotFound", "message": "no such model"})
    )
    backend = FakeRedisBackend()
    async with httpx.AsyncClient() as http:
        client = OdooClient(creds(), http)
        for _ in range(2):
            with pytest.raises(ValidationFailed, match="does not exist"):
                await SchemaCache(shared=backend.state()).fields(client, "x_nope")
    assert missing.call_count == 2
    assert backend.client().dbsize() == 0


@pytest.mark.parametrize("exc", REDIS_FAILURES, ids=lambda e: type(e).__name__)
async def test_schema_works_when_redis_is_down(odoo, exc):
    async with httpx.AsyncClient() as http:
        client = OdooClient(creds(), http)
        fields = await SchemaCache(shared=RedisState(BrokenRedis(exc))).fields(client, "crm.lead")
    assert "expected_revenue" in fields and odoo.fields_get["crm.lead"].call_count == 1


# ===================================================================================== 2+3 wired: stdio server


@pytest.fixture
def shared_redis(monkeypatch) -> FakeRedisBackend:
    """Every redis.Redis.from_url() (state, OAuth store) connects to one fake server."""
    backend = FakeRedisBackend()
    monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, url, **kw: backend.client()))
    return backend


COUNT_ARGS = {"model": "crm.lead", "domain": [["name", "ilike", "acme"]]}


async def test_stdio_servers_share_identity_and_schema_through_redis(odoo, shared_redis):
    settings = build_settings(
        odoo_protocol="auto", odoo_login=LOGIN, odoo_api_key=KEY_A, mcp_redis_url="redis://fake:6379"
    )
    async with httpx.AsyncClient() as http:
        async with Client(create_stdio_server(settings, http)) as first:
            result = await first.call_tool("odoo_count", COUNT_ARGS)
            assert not result.is_error, result.content
            assert json.loads(result.content[0].text) == {"model": "crm.lead", "count": 3}
        assert (odoo.context_get.call_count, odoo.read.call_count, odoo.version.call_count) == (1, 1, 1)
        assert odoo.fields_get["crm.lead"].call_count == 1

        async with Client(create_stdio_server(settings, http)) as second:  # a cold start elsewhere
            result = await second.call_tool("odoo_count", COUNT_ARGS)
            assert not result.is_error, result.content
    assert (odoo.context_get.call_count, odoo.read.call_count, odoo.version.call_count) == (1, 1, 1)
    assert odoo.fields_get["crm.lead"].call_count == 1
    assert odoo.search_count.call_count == 2
    context = body_of(odoo.search_count.calls.last.request)["context"]
    assert context["lang"] == "en_IN" and context["tz"] == "Asia/Kolkata"  # restored from the cached identity


# ===================================================================================== 4a. HTTP app: GET /mcp


def http_settings(tmp_path, **overrides) -> Settings:
    values = {
        "odoo_url": URL,
        "odoo_db": DB,
        "odoo_protocol": "auto",
        "mcp_public_url": PUBLIC,
        "mcp_secret": "test-secret-" + "k" * 28,
        "mcp_data_dir": str(tmp_path / "data"),
        "mcp_access_mode": "read_only",
        "mcp_redis_url": None,
        "mcp_audit_log_file": None,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@contextmanager
def http_app(tmp_path, *, inner: bool = False, **overrides):
    with respx.mock(assert_all_called=False, assert_all_mocked=True):
        app = create_http_app(http_settings(tmp_path, **overrides), httpx.AsyncClient())
        with TestClient(app.app if inner else app, base_url=PUBLIC, follow_redirects=False) as client:
            yield client


@pytest.mark.parametrize(
    "path, headers",
    [
        ("/mcp", {}),
        ("/mcp", {"accept": "text/event-stream"}),
        ("/mcp", {"accept": "text/event-stream", "authorization": "Bearer not-a-real-token"}),
        ("/mcp?session=1", {"accept": "text/event-stream", "last-event-id": "42"}),
    ],
)
def test_get_mcp_is_declined_with_405_before_authentication(tmp_path, path, headers):
    with http_app(tmp_path) as client:
        response = client.get(path, headers=headers)
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"
    assert response.content == b""
    assert "www-authenticate" not in response.headers


def test_without_the_wrapper_get_mcp_would_hit_authentication(tmp_path):
    """Control for the test above: the 405 comes from the wrapper, not from the SDK."""
    with http_app(tmp_path, inner=True) as client:
        assert client.get("/mcp").status_code == 401


def test_other_requests_pass_through_unchanged(tmp_path):
    with http_app(tmp_path) as client:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        post = client.post("/mcp", json=body, headers={"accept": "application/json, text/event-stream"})
        delete = client.delete("/mcp")
        health = client.get("/healthz")
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
    assert post.status_code == 401
    assert post.headers["www-authenticate"].startswith("Bearer ")
    assert f'resource_metadata="{PUBLIC}/.well-known/oauth-protected-resource/mcp"' in post.headers["www-authenticate"]
    assert delete.status_code == 401
    assert health.status_code == 200 and health.json()["status"] == "ok"
    assert metadata.status_code == 200 and metadata.json()["resource"] == f"{PUBLIC}/mcp"


class RecordingApp:
    def __init__(self, *, hang: bool = False):
        self.hang = hang
        self.seen: list[tuple] = []

    async def __call__(self, scope, receive, send):
        self.seen.append((scope, receive, send))
        if self.hang:  # what an open notification stream looks like to the caller
            await asyncio.Event().wait()
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 299, "headers": [(b"x-inner", b"1")]})
            await send({"type": "http.response.body", "body": b"inner"})


async def test_get_mcp_answers_immediately_without_calling_the_app():
    inner = RecordingApp(hang=True)
    transport = httpx.ASGITransport(app=_NoListenStream(inner))
    async with httpx.AsyncClient(transport=transport, base_url=PUBLIC) as client:
        response = await asyncio.wait_for(client.get("/mcp", headers={"accept": "text/event-stream"}), 5)
    assert response.status_code == 405 and response.headers["allow"] == "POST"
    assert response.headers["content-length"] == "0"
    assert inner.seen == []


@pytest.mark.parametrize(
    "method, path",
    [("POST", "/mcp"), ("DELETE", "/mcp"), ("PUT", "/mcp"), ("OPTIONS", "/mcp"), ("HEAD", "/mcp"),
     ("GET", "/mcp/"), ("GET", "/mcp/extra"), ("GET", "/mcpx"), ("GET", "/healthz"), ("GET", "/")],
)
async def test_everything_else_reaches_the_app(method, path):
    inner = RecordingApp()
    transport = httpx.ASGITransport(app=_NoListenStream(inner))
    async with httpx.AsyncClient(transport=transport, base_url=PUBLIC) as client:
        response = await client.request(method, path)
    assert response.status_code == 299 and response.headers["x-inner"] == "1"
    assert len(inner.seen) == 1 and inner.seen[0][0]["path"] == path


@pytest.mark.parametrize(
    "scope", [{"type": "lifespan"}, {"type": "websocket", "path": "/mcp", "headers": []}], ids=["lifespan", "websocket"]
)
async def test_non_http_scopes_pass_through_untouched(scope):
    inner = RecordingApp()

    async def receive():
        return {}

    async def send(message):
        raise AssertionError("the wrapper must not answer by itself")

    await _NoListenStream(inner)(scope, receive, send)
    assert len(inner.seen) == 1
    seen_scope, seen_receive, seen_send = inner.seen[0]
    assert seen_scope is scope and seen_receive is receive and seen_send is send


def test_wrapped_app_is_still_detected_as_an_asgi3_app(tmp_path):
    """Vercel and uvicorn decide ASGI vs WSGI / ASGI2 by inspecting the object."""
    with respx.mock(assert_all_called=False, assert_all_mocked=True):
        app = create_http_app(http_settings(tmp_path), httpx.AsyncClient())
        assert inspect.iscoroutinefunction(app.__call__)
        config = uvicorn.Config(app, lifespan="off", log_config=None)
        config.load()
        assert config.interface == "asgi3"
        with TestClient(app, base_url=PUBLIC):  # run the lifespan once so everything is closed
            pass


# ===================================================================================== 4b. no subscriptions/listen


def test_stdio_server_does_not_serve_subscriptions_listen(make_settings):
    with respx.mock(assert_all_called=False, assert_all_mocked=True):
        mcp = create_stdio_server(make_settings(), httpx.AsyncClient())
    assert isinstance(mcp, MCPServer)
    assert mcp._lowlevel_server.get_request_handler("subscriptions/listen") is None
    assert mcp._lowlevel_server.get_request_handler("tools/call") is not None
    # control: an MCPServer built with the SDK defaults does serve it
    assert MCPServer("control")._lowlevel_server.get_request_handler("subscriptions/listen") is not None


def test_http_server_does_not_serve_subscriptions_listen(tmp_path, monkeypatch):
    built: list[MCPServer] = []
    original = server_module._new_server

    def spy(**kwargs):
        built.append(original(**kwargs))
        return built[-1]

    monkeypatch.setattr(server_module, "_new_server", spy)
    with http_app(tmp_path):
        pass
    assert len(built) == 1
    assert built[0]._lowlevel_server.get_request_handler("subscriptions/listen") is None
    assert built[0]._lowlevel_server.get_request_handler("tools/call") is not None


async def test_listen_request_fails_fast_and_capabilities_say_so(make_settings):
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as mock:
        async with httpx.AsyncClient() as http:
            async with Client(create_stdio_server(make_settings(), http)) as client:
                assert client.protocol_version in MODERN_PROTOCOL_VERSIONS
                assert client.server_capabilities.tools is not None
                assert client.server_capabilities.tools.list_changed is False

                async def listen():
                    async with client.listen(tools_list_changed=True):
                        pytest.fail("the server acknowledged a subscriptions/listen stream")

                with pytest.raises(MCPError) as info:
                    await asyncio.wait_for(listen(), 5)
                assert info.value.code == METHOD_NOT_FOUND
                assert len((await client.list_tools()).tools) > 5  # the session is still usable
    assert mock.calls.call_count == 0  # nothing here needs Odoo


async def test_listen_control_default_server_acknowledges():
    """Control for the test above: the same client call succeeds against an SDK-default server."""
    async with Client(MCPServer("control")) as client:
        assert client.server_capabilities.tools.list_changed is True

        async def listen():
            async with client.listen(tools_list_changed=True) as subscription:
                return subscription.honored

        honored = await asyncio.wait_for(listen(), 5)
    assert honored.tools_list_changed is True


# ===================================================================================== 2+3 wired: HTTP connector


def call_tool(client: TestClient, access_token: str, name: str, arguments: dict) -> httpx.Response:
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-11-25",
        "Authorization": f"Bearer {access_token}",
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    return client.post("/mcp", json=body, headers=headers)


def test_http_connector_instances_share_identity_and_schema_through_redis(tmp_path, shared_redis):
    settings = http_settings(tmp_path, odoo_db="sahajta", mcp_redis_url="redis://fake:6379")
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        odoo = OAuthFakeOdoo(router)  # context_get, read and /web/version, keyed by API key
        fields_get = router.post(f"{URL}/json/2/crm.lead/fields_get").mock(
            return_value=httpx.Response(200, json=LEAD_FIELDS)
        )
        search_count = router.post(f"{URL}/json/2/crm.lead/search_count").mock(return_value=httpx.Response(200, json=4))

        def identity_calls() -> tuple[int, int, int]:
            versions = sum(1 for call in router.calls if call.request.url.path == "/web/version")
            return odoo.context_get.call_count, odoo.read.call_count, versions

        with TestClient(create_http_app(settings, httpx.AsyncClient()), base_url=PUBLIC, follow_redirects=False) as a:
            _, tokens = oauth_connect(SimpleNamespace(client=a))  # sign-in checks the key with Odoo itself
            after_sign_in = identity_calls()
            response = call_tool(a, tokens["access_token"], "odoo_count", COUNT_ARGS)
            assert response.status_code == 200, response.text
            assert response.json()["result"].get("isError") is not True, response.text
            after_first_tool_call = identity_calls()
            assert after_first_tool_call == (after_sign_in[0] + 1, after_sign_in[1] + 1, after_sign_in[2] + 1)
            assert fields_get.call_count == 1

        # Another serverless instance: nothing in memory, only Redis is shared.
        with TestClient(create_http_app(settings, httpx.AsyncClient()), base_url=PUBLIC, follow_redirects=False) as b:
            response = call_tool(b, tokens["access_token"], "odoo_count", COUNT_ARGS)
            assert response.status_code == 200, response.text
            result = response.json()["result"]
            assert result.get("isError") is not True, response.text
            assert json.loads(result["content"][0]["text"]) == {"model": "crm.lead", "count": 4}

        assert identity_calls() == after_first_tool_call
        assert fields_get.call_count == 1
        assert search_count.call_count == 2
        context = body_of(search_count.calls.last.request)["context"]
        assert context["lang"] == "en_US" and context["tz"] == "Asia/Kolkata"  # restored from the cached identity
