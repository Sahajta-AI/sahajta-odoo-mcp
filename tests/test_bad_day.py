"""A bad day, end to end: Odoo and Redis misbehave while Claude calls tools over HTTP.

Drives the real HTTP app (OAuth sign-in, the /mcp endpoint, SQLite and Redis storage) against a
fake Odoo 19 (JSON-2, mocked with respx) and fakeredis. Odoo answers 429 (with and without
Retry-After), 500, 502/503/504, read timeouts, connection errors, dropped connections, slow and
garbled answers, and 401 for a revoked key; Redis refuses some commands or loses their replies.
Tool calls go out alone and several at once, to warm and cold server instances.

Every fault is drawn from a seeded generator owned by the request that meets it, so a scenario
replays from its seed whatever order the event loop runs parallel requests in. Retry waits,
latency and slow answers run on virtual time: the file runs in seconds, and each tool call's
virtual seconds are checked against Vercel's 60-second limit.

Invariants (checked by `Watch`, `says` and `check_round`):
  1. A sign-in ends only when Odoo says the key is invalid (401), or a refresh token is replayed after
     the grace window. Nothing else signs the person out.
  2. An approved change reaches Odoo at most once per approval, whatever fails and however often
     Claude retries with the same token or previews again.
  3. Every error from a change tool says either that nothing was changed or that Odoo may already have
     applied it, never neither and never both. When nothing ran, the same confirm_token works once
     Odoo recovers.
  4. A change Odoo applied (and answered) is never reported as failed, even if every read after it fails.
  5. Reads end with a correct answer or a clear error that does not ask to reconnect. No call hangs, a
     change is never sent late in a call, and a sent change is answered within Vercel's 60 s.
  6. No answer contains the API key, a token, or a setting name meant for operators.

Section 7 holds the bugs this suite found in src/, now fixed; each test says what it guards.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import time
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import fakeredis
import httpx
import pytest
import redis
import respx
from redis.commands.core import Script
from starlette.testclient import TestClient

import sahajta_odoo_mcp.oauth as oauth_package
from conftest import FakeOdoo as Records
from sahajta_odoo_mcp import deadline as deadline_module
from sahajta_odoo_mcp import odoo_client
from sahajta_odoo_mcp import server as server_module
from sahajta_odoo_mcp import service as service_module
from sahajta_odoo_mcp import tools as tools_module
from sahajta_odoo_mcp.config import Settings
from sahajta_odoo_mcp.oauth.redis_store import RedisOAuthStore
from sahajta_odoo_mcp.oauth.store import REFRESH_REUSE_GRACE_SECONDS, OAuthStore
from sahajta_odoo_mcp.server import create_http_app
from test_oauth import ODOO, PRIYA_KEY, PUBLIC, SECRET, UNAUTHORIZED, USERS, connect, refresh

BACKENDS = ["sqlite", "redis"]


def expect(condition: object, what: str) -> None:
    """A precondition of the scenario itself. RuntimeError, so a broken setup is never mistaken for a broken invariant."""
    if not condition:
        raise RuntimeError(f"scenario setup failed: {what}")


# ================================================================================ virtual time


class Timeline:
    """One HTTP request (one tool call): the virtual seconds it used, and its own seeded dice."""

    def __init__(self, seed: str = "outside") -> None:
        self.t = 0.0
        self.deadlines: list[float] = []
        self.rng = random.Random(seed)

    def advance(self, seconds: float) -> None:
        if self.deadlines and self.t + seconds > min(self.deadlines):
            self.t = min(self.deadlines)
            raise TimeoutError("virtual deadline passed")  # what asyncio.wait_for does at its deadline
        self.t += seconds


_NOW: ContextVar[Timeline | None] = ContextVar("bad_day_timeline", default=None)
_OUTSIDE = Timeline()


def timeline() -> Timeline:
    return _NOW.get() or _OUTSIDE


VIRTUAL_TIME = SimpleNamespace(monotonic=lambda: 10_000.0 + timeline().t)  # `time` as service.py, tools.py, deadline.py see it


async def _virtual_sleep(seconds: float, result=None):
    timeline().advance(seconds)
    await asyncio.sleep(0)
    return result


async def _virtual_wait_for(awaitable, timeout):
    if timeout is None:
        return await awaitable
    if timeout <= 0:
        awaitable.close()
        raise TimeoutError
    line = timeline()
    deadline = line.t + timeout
    line.deadlines.append(deadline)
    try:
        return await awaitable
    finally:
        line.deadlines.remove(deadline)


class _VirtualAsyncio:
    """`asyncio` as odoo_client.py and service.py see it: sleeps and timeouts on virtual time."""

    sleep = staticmethod(_virtual_sleep)
    wait_for = staticmethod(_virtual_wait_for)

    def __getattr__(self, name):
        return getattr(asyncio, name)


class _JitterFromTimeline:
    """`random` as odoo_client.py sees it: retry jitter from the current request's dice."""

    def uniform(self, a: float, b: float) -> float:
        return timeline().rng.uniform(a, b)


class VirtualTimeApp:
    """Gives each HTTP request its own timeline and reports the virtual seconds it used in a header."""

    def __init__(self, app, seed: int, shared: Timeline | None = None):
        self.app = app
        self.seed = seed
        self.shared = shared  # one wall clock for every request (to model requests waiting on each other)
        self._count = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        self._count += 1
        name = dict(scope["headers"]).get(b"x-bad-day-call", str(self._count).encode()).decode()
        line = self.shared or Timeline(f"{self.seed}/{name}")
        token = _NOW.set(line)
        started = line.t

        async def send_with_time(message):
            if message["type"] == "http.response.start":
                headers = [*message.get("headers", []), (b"x-virtual-seconds", f"{line.t - started:.3f}".encode())]
                message = {**message, "headers": headers}
            await send(message)

        try:
            await self.app(scope, receive, send_with_time)
        finally:
            _NOW.reset(token)


# ================================================================================ Odoo having a bad day

READS = frozenset(
    {
        "context_get", "read", "search", "search_read", "search_count", "fields_get", "name_search", "get_views",
        "default_get", "has_access", "onchange",
    }
)
CHANGES = frozenset({"create", "write", "action_confirm", "message_post"})
FAULTS = (
    "429", "429+retry-after", "500", "500-html", "502", "503", "504", "timeout", "connect", "dropped", "slow", "garbled",
)
AMBIGUOUS = ("502", "504", "timeout", "dropped")  # Odoo may or may not have carried the request out
GARBLED = ("<html><body>Bad gateway</body></html>", "", '{"jsonrpc": "2.0", "result": [1', "\x00\xff\xfe binary")


@dataclass
class Weather:
    """Which Odoo requests meet a fault, and which one (drawn with the request's own dice)."""

    p: float = 0.0  # chance that a request meets a fault
    faults: tuple[str, ...] = FAULTS
    methods: frozenset[str] | None = None  # only these methods meet faults (None: all)
    carried_out: float = 0.5  # chance that a change behind an AMBIGUOUS fault was carried out

    def draw(self, method: str, rng: random.Random) -> str | None:
        if self.p <= 0 or (self.methods is not None and method not in self.methods):
            return None
        if rng.random() >= self.p:
            return None
        return rng.choice(self.faults)


@dataclass
class Applied:
    approval: str | None  # the approval (confirm_token, or a note's tag) Claude was using
    method: str
    answered: bool  # Odoo's answer reached the server; False: carried out, then the answer was lost


class BadDayOdoo:
    """Odoo 19's JSON-2 API over respx, backed by the in-memory records of conftest.FakeOdoo."""

    def __init__(self, router: respx.MockRouter):
        self.weather = Weather()
        self.records = Records()
        self.revoked_keys: set[str] = set()
        self.approval: str | None = None
        self.applied: list[Applied] = []
        self.change_sent_at: list[float] = []  # virtual seconds into its tool call when each change reached Odoo
        self.on_request = None  # a test's own async hook(request, model, method) -> Response | None
        router.post(url__regex=rf"^{re.escape(ODOO)}/json/2/(?P<model>[\w.]+)/(?P<method>\w+)$").mock(side_effect=self._handle)
        router.get(f"{ODOO}/web/version").mock(return_value=httpx.Response(200, json={"version": "19.0"}))
        self.legacy = router.post(f"{ODOO}/jsonrpc").mock(return_value=httpx.Response(404))  # legacy JSON-RPC

    def calm(self) -> None:
        self.weather = Weather()

    def storm(self, p: float = 1.0, faults=FAULTS, methods=None, carried_out: float = 0.5) -> None:
        self.weather = Weather(p, tuple(faults), frozenset(methods) if methods else None, carried_out)

    def applied_for(self, approval: str) -> list[Applied]:
        return [a for a in self.applied if a.approval == approval]

    async def _handle(self, request: httpx.Request, model: str, method: str) -> httpx.Response:
        line = timeline()
        rng = line.rng
        change = method not in READS
        if change:
            self.change_sent_at.append(line.t)
        if self.on_request is not None:
            answer = await self.on_request(request, model, method)
            if answer is not None:
                return answer
        key = request.headers.get("authorization", "").partition(" ")[2]
        user = USERS.get(key) if key not in self.revoked_keys else None
        if user is None:
            return httpx.Response(401, json=UNAUTHORIZED)
        line.advance(rng.uniform(0.05, 0.5))  # ordinary latency
        fault = self.weather.draw(method, rng)
        if fault in ("429", "429+retry-after"):
            headers = {"Retry-After": str(rng.choice((1, 3, 6, 30)))} if fault == "429+retry-after" else {}
            return httpx.Response(429, headers=headers, text="Too Many Requests")
        if fault == "connect":
            raise rng.choice((httpx.ConnectError, httpx.ConnectTimeout))("connection refused", request=request)
        if fault == "500-html":  # a debug page echoing the request, API key included
            return httpx.Response(500, text=f"<html><pre>Authorization: bearer {key}\nX-Odoo-Database: sahajta</pre></html>")
        if fault == "500":  # Odoo gave up on a serialization conflict and rolled back
            return httpx.Response(500, json={"name": "psycopg2.errors.SerializationFailure", "message": "could not serialize access"})
        if fault == "503":
            return httpx.Response(503, text="Service Unavailable")
        if fault == "slow":
            line.advance(rng.uniform(3, 12))
        if fault == "timeout":
            line.advance(30.0)  # odoo_timeout_seconds
        carried_out = fault in (None, "slow", "garbled") or (fault in AMBIGUOUS and rng.random() < self.weather.carried_out)
        result = self._run(user, model, method, json.loads(request.content or b"{}")) if carried_out else None
        if change and carried_out:
            self.applied.append(Applied(self.approval, method, answered=fault in (None, "slow")))
        if fault in ("502", "504"):
            return httpx.Response(int(fault), text="Gateway error")
        if fault == "timeout":
            raise httpx.ReadTimeout("timed out", request=request)
        if fault == "dropped":
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.", request=request)
        if fault == "garbled":
            return httpx.Response(200, content=rng.choice(GARBLED).encode("utf-8", "surrogatepass"))
        return httpx.Response(200, json=result)

    def _run(self, user: dict, model: str, method: str, body: dict):
        assert "unlink" not in method.lower(), f"{model}.{method} reached Odoo"
        if model == "res.users" and method == "context_get":
            return {"uid": user["id"], "tz": "Asia/Kolkata", "lang": "en_US"}
        if model == "res.users" and method == "read" and body.get("ids") == [user["id"]]:
            return [user]
        ids, context = body.pop("ids", None), body.pop("context", None)
        if method == "action_confirm":  # like Odoo: the order moves on, so its next preview differs
            for rid in ids or []:
                self.records.touch(model, rid, state="sale")
            return True
        handler = getattr(self.records, f"_m_{method}", None)
        if handler is not None:
            return handler(model, ids, context, **body)
        return self.records.action_results.get((model, method), True)  # a button


# ================================================================================ Redis having a bad day


@dataclass
class RedisSky:
    """Which Redis commands fail. down: all of them; otherwise each with chance p (the request's dice)."""

    p: float = 0.0
    down: bool = False
    lost_replies: bool = False  # some failures come after the command ran (the reply was lost)
    commands: frozenset[str] | None = None  # only these commands fail (None: all)

    def check(self, command: str) -> str | None:
        if self.commands is not None and command not in self.commands:
            return None
        if self.down:
            return "refused"
        rng = timeline().rng
        if self.p > 0 and rng.random() < self.p:
            return "lost" if self.lost_replies and rng.random() < 0.5 else "refused"
        return None

    def clear(self) -> None:
        self.p, self.down, self.lost_replies, self.commands = 0.0, False, False, None
        self.__dict__.pop("check", None)  # a test's own script, if any


class FlakyRedis:
    """A fakeredis client whose commands fail as its sky says, like Upstash on a bad day."""

    _SAFE = frozenset({"get_encoder", "close", "connection_pool", "get_connection_kwargs"})

    def __init__(self, server: fakeredis.FakeServer, sky: RedisSky):
        self._r = fakeredis.FakeRedis(server=server, decode_responses=True)
        self._sky = sky

    def register_script(self, script):
        return Script(self, script)  # so EVALSHA goes through the failures below

    def pipeline(self, *args, **kwargs):
        pipe = self._r.pipeline(*args, **kwargs)
        execute = pipe.execute
        pipe.execute = lambda *a, **kw: self._run("pipeline", execute, a, kw)
        return pipe

    def _run(self, name, command, args, kwargs):
        verdict = self._sky.check(name)
        if verdict == "refused":
            raise redis.ConnectionError("Error 111 connecting to fake:6379. Connection refused.")
        result = command(*args, **kwargs)
        if verdict == "lost":
            raise redis.TimeoutError("Timeout reading from socket")
        return result

    def __getattr__(self, name):
        attr = getattr(self._r, name)
        if name in self._SAFE or not callable(attr):
            return attr
        return lambda *args, **kwargs: self._run(name, attr, args, kwargs)


# ================================================================================ the deployment


@dataclass
class ToolResult:
    tool: str
    arguments: dict
    status: int
    is_error: bool
    text: str
    seconds: float  # virtual seconds the call took

    @classmethod
    def of(cls, tool: str, arguments: dict, response: httpx.Response) -> ToolResult:
        seconds = float(response.headers.get("x-virtual-seconds", "nan"))
        if response.status_code != 200:
            return cls(tool, arguments, response.status_code, True, response.text, seconds)
        result = response.json()["result"]
        return cls(tool, arguments, 200, bool(result.get("isError")), result["content"][0]["text"], seconds)

    @property
    def data(self) -> dict:
        expect(not self.is_error, f"{self.tool} failed: {self.text}")
        return json.loads(self.text)


@dataclass
class Deployment:
    """One connector deployment: its storage, a fake Odoo, and the server instances serving it."""

    tmp_path: Path
    backend: str  # "sqlite" (one container) or "redis" (Vercel)
    odoo: BadDayOdoo
    state_sky: RedisSky  # approvals, rate limits, caches, usage history
    auth_sky: RedisSky  # the sign-in store
    redis_server: fakeredis.FakeServer | None
    seed: int = 0
    instances: list[TestClient] = field(default_factory=list)
    oauths: list = field(default_factory=list)  # each instance's OAuth components, in start order
    client: TestClient | None = None  # the instance Claude reaches unless told otherwise
    shared_clock: Timeline | None = None
    calls_made: int = 0
    overrides: dict = field(default_factory=dict)  # settings that differ from production's

    @property
    def settings(self) -> Settings:
        values = dict(
            odoo_url=ODOO, odoo_db="sahajta", odoo_protocol="json2", mcp_public_url=PUBLIC, mcp_secret=SECRET,
            mcp_data_dir=str(self.tmp_path / "data"), mcp_access_mode="read_write", mcp_allow_outbound_messages=True,
            mcp_reads_per_minute=10_000, mcp_writes_per_minute=10_000, mcp_audit_log_file=str(self.tmp_path / "audit.jsonl"),
        )
        if self.backend == "redis":
            values["mcp_redis_url"] = "redis://fake:6379"
        return Settings(_env_file=None, **{**values, **self.overrides})

    def start_instance(self) -> TestClient:
        """A new, cold server instance next to the others (a fresh Vercel function)."""
        app = VirtualTimeApp(create_http_app(self.settings, httpx.AsyncClient()), self.seed * 1000 + len(self.oauths), self.shared_clock)
        client = TestClient(app, base_url=PUBLIC, raise_server_exceptions=False, follow_redirects=False)
        client.__enter__()
        self.instances.append(client)
        self.client = client
        return client

    def restart(self) -> TestClient:
        """Stops every instance and starts one cold one (a container restart, or a new Vercel deployment)."""
        self.close()
        return self.start_instance()

    def close(self) -> None:
        while self.instances:
            self.instances.pop().__exit__(None, None, None)
        self.client = None

    # ------------------------------------------------------------------ talking to it like Claude does

    def sign_in(self) -> tuple[str, dict]:
        return connect(self)

    def refresh(self, client_id: str, refresh_token: str) -> httpx.Response:
        return refresh(self, client_id, refresh_token)

    def call(self, token: str, tool: str, **arguments) -> ToolResult:
        return self.burst(token, [(tool, arguments)])[0]

    def burst(self, token: str, calls: list[tuple[str, dict]], client: TestClient | None = None) -> list[ToolResult]:
        """Sends tool calls at the same time, as Claude does when it fires several at once."""

        async def send_all(http):
            return await asyncio.gather(*(self.post_tool(http, token, tool, args) for tool, args in calls))

        responses = self.run_async(send_all, client)
        return [ToolResult.of(tool, args, response) for (tool, args), response in zip(calls, responses)]

    def run_async(self, script, client: TestClient | None = None):
        """Runs script(http) on an instance's event loop; http posts straight into the app."""
        client = client or self.client

        async def run():
            transport = httpx.ASGITransport(app=client.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url=PUBLIC) as http:
                return await asyncio.wait_for(script(http), timeout=20)  # real seconds: no call may hang

        return client.portal.call(run)

    async def post_tool(self, http: httpx.AsyncClient, token: str, tool: str, arguments: dict) -> httpx.Response:
        self.calls_made += 1
        headers = {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
            "Authorization": f"Bearer {token}",
            "x-bad-day-call": f"c{self.calls_made}",  # names the request's dice, independent of timing
        }
        body = {"jsonrpc": "2.0", "id": self.calls_made, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
        return await http.post("/mcp", json=body, headers=headers)

    # ------------------------------------------------------------------ what happened

    def signouts(self) -> list[dict]:
        path = self.tmp_path / "audit.jsonl"
        lines = path.read_text().splitlines() if path.exists() else []
        return [event for event in map(json.loads, lines) if event["tool"] == "signout"]

    def grants(self) -> list:
        if self.backend == "redis":
            store = RedisOAuthStore("redis://fake", client=fakeredis.FakeRedis(server=self.redis_server, decode_responses=True))
        else:
            store = OAuthStore(self.tmp_path / "data" / "oauth.sqlite3")
        try:
            return store.list_grants(include_inactive=True)
        finally:
            store.close()

    def still_signed_in(self) -> bool:
        return self.signouts() == [] and bool(self.grants()) and all(grant.active for grant in self.grants())


@pytest.fixture
def make_deployment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Builds a Deployment. Retry waits, slow answers and the service's clock run on virtual time."""
    monkeypatch.setattr(odoo_client, "asyncio", _VirtualAsyncio())
    monkeypatch.setattr(odoo_client, "random", _JitterFromTimeline())
    monkeypatch.setattr(odoo_client, "_GATES", {})
    monkeypatch.setattr(service_module, "asyncio", _VirtualAsyncio())
    monkeypatch.setattr(service_module, "time", VIRTUAL_TIME)
    monkeypatch.setattr(tools_module, "time", VIRTUAL_TIME)
    monkeypatch.setattr(deadline_module, "time", VIRTUAL_TIME)  # the call's time budget, as odoo_client.py sees it
    built: list[Deployment] = []
    routers: list[respx.MockRouter] = []

    def factory(backend: str = "sqlite", seed: int = 0, *, shared_clock: bool = False, **settings) -> Deployment:
        router = respx.mock(assert_all_called=False, assert_all_mocked=True)  # nothing reaches a real host
        router.start()
        routers.append(router)
        server = fakeredis.FakeServer() if backend == "redis" else None
        state_sky, auth_sky = RedisSky(), RedisSky()
        if server is not None:
            monkeypatch.setattr(server_module, "redis_client", lambda url: FlakyRedis(server, state_sky))
            monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, url, **kw: FlakyRedis(server, auth_sky)))
        deployment = Deployment(
            tmp_path, backend, BadDayOdoo(router), state_sky, auth_sky, server, seed=seed,
            shared_clock=Timeline(f"{seed}/shared") if shared_clock else None, overrides=settings,
        )
        build_oauth = oauth_package.build_oauth

        def recording_build_oauth(*args, **kwargs):
            components = build_oauth(*args, **kwargs)
            deployment.oauths.append(components)
            return components

        monkeypatch.setattr(oauth_package, "build_oauth", recording_build_oauth)
        deployment.start_instance()
        built.append(deployment)
        return deployment

    yield factory
    for deployment in built:
        deployment.close()
    for router in routers:
        router.stop()


# ================================================================================ what Claude does

CHANGE_TOOLS = frozenset({"odoo_create", "odoo_update", "odoo_run_action", "odoo_add_note", "odoo_send_message"})
CHANGE_KINDS = ("update", "create", "action", "message", "note")
READ_LEAD = {"model": "crm.lead", "ids": [100]}
READ_CALLS = (
    ("odoo_whoami", {}),
    ("odoo_read", READ_LEAD),
    ("odoo_search", {"model": "crm.lead"}),
    ("odoo_count", {"model": "crm.lead"}),
    ("odoo_find", {"model": "res.partner", "name": "Acme"}),
    ("odoo_describe_model", {"model": "crm.lead", "query": "revenue"}),
    ("odoo_list_actions", {"model": "sale.order"}),
)
SAME_TOKEN = "retry with the same confirm_token"
READ_BACK_FAILED = "could not read the new values back"


def change_calls(kind: str, n: int) -> tuple[tuple[str, dict] | None, tuple[str, dict]]:
    """(preview call or None, commit call without its token) for approval number n of a kind of change."""
    if kind == "update":
        args = {"model": "crm.lead", "ids": [100], "values": {"expected_revenue": 5000 + n}}
        return ("odoo_preview_update", args), ("odoo_update", args)
    if kind == "create":
        args = {"model": "crm.lead", "records": [{"name": f"Bad day lead {n}", "type": "opportunity"}]}
        return ("odoo_preview_create", args), ("odoo_create", args)
    if kind == "action":
        args = {"model": "sale.order", "ids": [5], "method": "action_confirm"}
        return ("odoo_preview_action", args), ("odoo_run_action", args)
    if kind == "message":
        args = {"model": "crm.lead", "record_id": 100, "message": f"Quote {n} is ready"}
        return ("odoo_preview_message", args), ("odoo_send_message", args)
    return None, ("odoo_add_note", {"model": "crm.lead", "record_id": 100, "note": f"Called the customer ({n})"})


def approve(env: Deployment, watch: Watch, access: str, kind: str, n: int) -> tuple[str, str, dict] | None:
    """Previews a change as the person saw and approved it: (approval, commit tool, commit arguments)."""
    preview, (tool, args) = change_calls(kind, n)
    if preview is None:
        return f"note:{n}", tool, args  # a note needs no approval; its tag tracks it at Odoo
    for _ in range(3):  # a preview is a read: Claude tries again if Odoo was busy
        shown = watch.check(env.call(access, preview[0], **preview[1]))
        if not shown.is_error:
            token = shown.data["confirm_token"]
            watch.confirm_tokens.add(token)
            return token, tool, {**args, "confirm_token": token}
    return None


# ================================================================================ invariants

OPERATOR_SETTINGS = ("ODOO_DB", "ODOO_API_KEY", "MCP_SECRET", "MCP_REDIS_URL", "REDIS_URL", "KV_URL", "MCP_ADMIN_TOKEN")


def says(result: ToolResult) -> str:
    """Invariant 3: what a change tool's answer says happened: 'done', 'nothing' (changed) or 'maybe' (applied)."""
    if not result.is_error:
        return "done"
    lower = result.text.lower()
    nothing, maybe = "nothing was changed" in lower, "may already have" in lower
    assert nothing != maybe, f"{result.tool} must say exactly one of 'Nothing was changed' / 'may already have': {result.text!r}"
    return "nothing" if nothing else "maybe"


@dataclass
class Watch:
    """Checks every answer Claude gets against invariants 1, 3, 5 and 6."""

    env: Deployment
    secrets: set[str] = field(default_factory=lambda: {PRIYA_KEY, SECRET})
    confirm_tokens: set[str] = field(default_factory=set)

    def tokens(self, tokens: dict) -> None:
        self.secrets |= {tokens["access_token"], tokens["refresh_token"]}

    def check(self, result: ToolResult) -> ToolResult:
        where = f"{result.tool}({result.arguments}) -> {result.text!r}"
        assert result.status == 200, f"HTTP {result.status}: {where}"  # a 401 here sends the person to sign in again
        for secret in self.secrets:
            assert secret not in result.text, f"a secret leaked: {where}"
        if result.is_error:
            for name in OPERATOR_SETTINGS:
                assert name not in result.text, f"an operator setting leaked: {where}"
            for token in self.confirm_tokens:
                assert token not in result.text, f"a confirm_token leaked: {where}"
            lower = result.text.lower()
            assert "unexpected server error" not in lower, where
            assert "reconnect" not in lower, f"asked to reconnect though the key is fine: {where}"
        if result.tool in CHANGE_TOOLS:
            says(result)
        elif not result.is_error:
            self.check_answer(result)
        return result

    def check_answer(self, result: ToolResult) -> None:
        """Invariant 5: a read that succeeds tells the truth about Odoo's records."""
        data, records = json.loads(result.text), self.env.odoo.records.records
        lead = records["crm.lead"][100]
        if result.tool == "odoo_whoami":
            assert data["user"]["login"] == "priya@sahajta.ai"
        elif result.tool == "odoo_read":
            [row] = data["records"]
            assert (row["name"], row["expected_revenue"]) == (lead["name"], lead["expected_revenue"]), row
        elif result.tool == "odoo_search":
            assert data["total_matching"] == len(records["crm.lead"]) == len(data["records"])
        elif result.tool == "odoo_count":
            assert data["count"] == len(records["crm.lead"])
        elif result.tool == "odoo_find":
            assert {"id": 1, "name": "Acme Corp"} in data["matches"]
        elif result.tool == "odoo_describe_model":
            assert [f["name"] for f in data["fields"]] == ["expected_revenue"]
        elif result.tool == "odoo_list_actions":
            assert any(action.get("method") == "action_confirm" for action in data["actions"])


def check_round(env: Deployment, approval: str, before: int, results: list[ToolResult]) -> list[str]:
    """Invariants 2, 4 and 5 for one round of commits that all used the same approval."""
    texts = [r.text for r in results]
    verdicts = [says(result) for result in results]
    applied = env.odoo.applied_for(approval)
    assert len(applied) <= 1, f"one approval reached Odoo {len(applied)} times: {texts}"
    now = applied[before:]
    # Invariant 4: each change Odoo applied and answered is reported as done, and only those are.
    assert verdicts.count("done") == sum(a.answered for a in now), texts
    # "Nothing was changed" never hides a change Odoo carried out in this round.
    assert len(now) <= verdicts.count("done") + verdicts.count("maybe"), texts
    for result, verdict in zip(results, verdicts):
        if verdict != "nothing":  # it was sent: answered before Vercel's 60-second limit
            assert result.seconds <= 60, f"answered after {result.seconds:.1f} virtual seconds: {result.text!r}"
    assert max(env.odoo.change_sent_at, default=0) <= 20.0 + 1e-6, f"a change was sent late: {env.odoo.change_sent_at}"
    return verdicts


# ================================================================================ 1. the seeded bad day


def run_change(env: Deployment, watch: Watch, rng: random.Random, access: str, kind: str, n: int) -> None:
    """The person approves a change; Claude commits and retries it the way it does on a bad day."""
    approved = approve(env, watch, access, kind, n)
    if approved is None:
        return
    approval, tool, args = approved
    env.odoo.approval = approval
    texts: list[str] = []
    for _ in range(rng.randint(1, 3)):
        before = len(env.odoo.applied_for(approval))
        # Claude sometimes fires the same commit two or three times at once. A note has no approval, so
        # firing it twice posts it twice by design: notes go one at a time.
        copies = 1 if kind == "note" else rng.choice((1, 1, 2, 3))
        results = env.burst(access, [(tool, args)] * copies, client=rng.choice(env.instances))
        verdicts = check_round(env, approval, before, [watch.check(r) for r in results])
        texts = [r.text.lower() for r in results]
        if "done" in verdicts or "maybe" in verdicts:
            return  # done, or Claude was told to check in Odoo before doing it again
        if not any(SAME_TOKEN in t or t.endswith("you can retry.") for t in texts):
            return  # e.g. "already used" or "run the preview again"
    if env.odoo.applied_for(approval):
        return
    # Invariant 3: nothing ran and the answer said the same approval can be retried. Once Odoo (and
    # Redis) recover, it works, unless Redis could not undo a claim ("run the preview again", "shared store").
    weather, state_sky, auth_sky = env.odoo.weather, dict(vars(env.state_sky)), dict(vars(env.auth_sky))
    env.odoo.calm()
    env.state_sky.clear()
    env.auth_sky.clear()
    stuck = any("run the preview again" in t or "shared store" in t for t in texts)
    retry = watch.check(env.call(access, tool, **args))
    verdict = check_round(env, approval, 0, [retry])[0]
    assert verdict == "done" or stuck, retry.text
    env.odoo.weather = weather
    vars(env.state_sky).update(state_sky)
    vars(env.auth_sky).update(auth_sky)


@pytest.mark.parametrize("seed", range(16))
@pytest.mark.parametrize("backend", BACKENDS)
def test_a_bad_day(make_deployment, backend, seed):
    """Random storms of every fault; parallel reads, changes and duplicate commits; refreshes; cold instances."""
    rng = random.Random(f"bad-day/{backend}/{seed}")
    env = make_deployment(backend, seed)
    watch = Watch(env)
    client_id, tokens = env.sign_in()
    watch.tokens(tokens)
    for n in range(rng.randint(6, 10)):
        env.odoo.storm(rng.choice((0.15, 0.35, 0.6)), rng.sample(FAULTS, rng.randint(3, len(FAULTS))))
        if backend == "redis":
            env.state_sky.p, env.state_sky.lost_replies = rng.choice((0, 0.1, 0.25)), True
            # Only the sign-in store's last-used bookkeeping (EVALSHA during tool calls) fails here; its
            # lookups failing have their own tests below (one of them shows a bug).
            env.auth_sky.p, env.auth_sky.commands = rng.choice((0, 0.3)), frozenset({"evalsha"})
        step = rng.choice(("reads", "reads", "change", "change", "change", "change", "cold", "refresh"))
        if step == "reads":
            calls = rng.sample(READ_CALLS, rng.randint(2, 5))
            for result in env.burst(tokens["access_token"], calls, client=rng.choice(env.instances)):
                watch.check(result)
        elif step == "change":
            run_change(env, watch, rng, tokens["access_token"], rng.choice(CHANGE_KINDS), n)
        elif step == "cold":
            # Vercel adds a cold instance next to the warm ones; the single container restarts.
            env.start_instance() if backend == "redis" else env.restart()
        else:
            env.auth_sky.p = 0
            old_refresh = tokens["refresh_token"]
            for _ in range(rng.choice((1, 2))):  # twice: the first answer was lost and Claude sends it again
                answer = env.refresh(client_id, old_refresh)
                assert answer.status_code in (200, 503), answer.text  # 503 = try later; never a sign-out
                if answer.status_code == 200:
                    tokens = answer.json()
                    watch.tokens(tokens)
    env.odoo.calm()
    env.state_sky.clear()
    env.auth_sky.clear()
    assert env.still_signed_in(), env.signouts()  # invariant 1
    assert not watch.check(env.call(tokens["access_token"], "odoo_whoami")).is_error
    audit = (env.tmp_path / "audit.jsonl").read_text()
    assert not [secret for secret in watch.secrets | watch.confirm_tokens if secret in audit]  # invariant 6, in the log too


# ================================================================================ 2. each fault on the change itself

CASES = [
    pytest.param(fault, carried, id=f"{fault}-{'carried-out' if carried else 'not-carried-out'}" if fault in AMBIGUOUS else fault)
    for fault in FAULTS
    for carried in ((True, False) if fault in AMBIGUOUS else (True,))
]
EXPECTED = {"429": "nothing", "429+retry-after": "nothing", "connect": "nothing", "slow": "done"}  # the rest: "maybe"


@pytest.mark.parametrize("fault, carried_out", CASES)
@pytest.mark.parametrize("backend", BACKENDS)
def test_a_fault_on_the_change_is_reported_truthfully_and_never_repeated(make_deployment, backend, fault, carried_out):
    env = make_deployment(backend)
    watch = Watch(env)
    _, tokens = env.sign_in()
    watch.tokens(tokens)
    access = tokens["access_token"]
    for n, kind in enumerate(CHANGE_KINDS):
        approval, tool, args = approve(env, watch, access, kind, n)
        env.odoo.approval = approval
        env.odoo.storm(1.0, (fault,), methods=CHANGES, carried_out=float(carried_out))
        first = watch.check(env.call(access, tool, **args))
        verdict = check_round(env, approval, 0, [first])[0]
        assert verdict == EXPECTED.get(fault, "maybe"), first.text
        if verdict == "nothing":
            assert first.text.endswith("You can retry with the same confirm_token." if kind != "note" else "You can retry.")
        env.odoo.calm()  # Odoo recovers
        if kind == "note" and verdict != "nothing":
            continue  # a note has no approval: Claude only posts it again when told nothing was changed
        before = len(env.odoo.applied_for(approval))
        retry = watch.check(env.call(access, tool, **args))  # the same approval again
        check_round(env, approval, before, [retry])
        assert says(retry) == ("done" if verdict == "nothing" else "nothing"), retry.text
        carried = verdict != "maybe" or fault == "garbled" or (fault in AMBIGUOUS and carried_out)
        assert len(env.odoo.applied_for(approval)) == int(carried)
    assert env.still_signed_in()


# ================================================================================ 3. an applied change stays applied

@pytest.mark.parametrize("fault", FAULTS)
@pytest.mark.parametrize("backend", BACKENDS)
def test_a_change_odoo_applied_is_done_even_if_every_read_after_it_fails(make_deployment, backend, fault):
    env = make_deployment(backend)
    watch = Watch(env)
    _, tokens = env.sign_in()
    watch.tokens(tokens)
    access = tokens["access_token"]

    async def after_the_change(request, model, method):
        if method in CHANGES:
            env.odoo.storm(1.0, (fault,), methods=READS)  # from now on every read meets the fault
        return None

    for n, kind in enumerate(CHANGE_KINDS):
        env.odoo.calm()
        approval, tool, args = approve(env, watch, access, kind, n)
        env.odoo.approval = approval
        env.odoo.on_request = after_the_change
        done = watch.check(env.call(access, tool, **args))
        env.odoo.on_request = None
        assert check_round(env, approval, 0, [done]) == ["done"], done.text
    assert env.still_signed_in()


def test_reads_after_a_change_stop_before_the_platform_cuts_the_answer_off(make_deployment):
    env = make_deployment("redis")
    _, tokens = env.sign_in()
    args = {"model": "crm.lead", "ids": [100], "values": {"expected_revenue": 4321}}
    approval = env.call(tokens["access_token"], "odoo_preview_update", **args).data["confirm_token"]
    env.odoo.approval = approval

    async def slow_odoo(request, model, method):
        # every answer is slow: reads 6 s before the write (sent ~13 s in), the write 29 s, reads after it 15 s
        timeline().advance(29.0 if method == "write" else 15.0 if env.odoo.applied else 6.0)
        return None

    env.odoo.on_request = slow_odoo
    done = env.call(tokens["access_token"], "odoo_update", **args, confirm_token=approval)
    assert check_round(env, approval, 0, [done]) == ["done"] and READ_BACK_FAILED in done.text
    assert 55 <= done.seconds <= 56, done.seconds  # the read-back gave up at the 55 s answer deadline


# ================================================================================ 4. sign-ins


@pytest.mark.parametrize("fault", FAULTS)
@pytest.mark.parametrize("backend", BACKENDS)
def test_nothing_but_odoo_rejecting_the_key_signs_the_person_out(make_deployment, backend, fault):
    env = make_deployment(backend)
    watch = Watch(env)
    client_id, tokens = env.sign_in()
    watch.tokens(tokens)
    env.odoo.storm(1.0, (fault,))  # every Odoo request, the identity check of a cold instance included
    for _ in range(2):
        env.restart()
        calls = [("odoo_whoami", {}), ("odoo_read", READ_LEAD), change_calls("note", 1)[1]]
        for result in env.burst(tokens["access_token"], calls):
            watch.check(result)
        answer = env.refresh(client_id, tokens["refresh_token"])
        assert answer.status_code in (200, 503), answer.text
        if answer.status_code == 200:
            tokens = answer.json()
            watch.tokens(tokens)
    assert env.still_signed_in(), env.signouts()
    env.odoo.calm()
    assert not watch.check(env.call(tokens["access_token"], "odoo_read", **READ_LEAD)).is_error


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_revoked_key_ends_the_sign_in_on_a_cold_instance(make_deployment, backend):
    env = make_deployment(backend)
    _, tokens = env.sign_in()
    env.odoo.revoked_keys.add(PRIYA_KEY)
    first = env.call(tokens["access_token"], "odoo_read", **READ_LEAD)
    assert first.is_error and "Reconnect the Odoo connector" in first.text and PRIYA_KEY not in first.text
    assert env.call(tokens["access_token"], "odoo_whoami").status == 401  # Claude now asks the person to sign in
    [signout] = env.signouts()
    assert signout["detail"] == "Odoo rejected the API key"


@pytest.mark.parametrize("fault", [f for f in FAULTS if f != "garbled"])  # a web page instead of JSON means "no JSON-2" by design
def test_the_json2_check_never_signs_out_or_falls_back_when_odoo_is_busy(make_deployment, fault):
    """The Docker setup (ODOO_PROTOCOL=auto) checks for JSON-2 on each cold start; commit 0195c66's incident."""
    env = make_deployment("sqlite", odoo_protocol="auto")
    watch = Watch(env)
    client_id, tokens = env.sign_in()
    watch.tokens(tokens)
    env.odoo.storm(1.0, (fault,), methods={"context_get"})  # the JSON-2 check itself
    for _ in range(2):
        env.restart()
        for result in env.burst(tokens["access_token"], [("odoo_whoami", {}), ("odoo_read", READ_LEAD), change_calls("note", 1)[1]]):
            watch.check(result)
    env.odoo.calm()
    assert not watch.check(env.call(tokens["access_token"], "odoo_read", **READ_LEAD)).is_error
    assert env.still_signed_in(), env.signouts()
    assert env.odoo.legacy.call_count == 0  # never sent down the legacy JSON-RPC path


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_refresh_token_is_forgiven_within_the_grace_window_and_only_then(make_deployment, backend):
    env = make_deployment(backend)
    client_id, first = env.sign_in()
    # Two refreshes at once (two tabs), then a retry of an answer that was lost: all within the window.
    rotated = [env.refresh(client_id, first["refresh_token"]) for _ in range(3)]
    assert [r.status_code for r in rotated] == [200, 200, 200]
    latest = rotated[-1].json()
    assert env.still_signed_in() and not env.call(latest["access_token"], "odoo_whoami").is_error
    env.oauths[-1].provider._clock = lambda: time.time() + REFRESH_REUSE_GRACE_SECONDS + 1
    replay = env.refresh(client_id, first["refresh_token"])
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    assert [s["detail"] for s in env.signouts()] == ["refresh token reused"]
    assert env.call(latest["access_token"], "odoo_whoami").status == 401


# ================================================================================ 5. Redis blips


def test_redis_down_lets_reads_through_and_holds_changes_until_it_is_back(make_deployment):
    env = make_deployment("redis")
    watch = Watch(env)
    _, tokens = env.sign_in()
    watch.tokens(tokens)
    access = tokens["access_token"]
    approval, tool, args = approve(env, watch, access, "update", 1)
    env.odoo.approval = approval
    env.state_sky.down = True  # approvals, rate limits, caches and usage history are unreachable
    reads = [watch.check(r) for r in env.burst(access, list(READ_CALLS))]
    assert [r.text for r in reads if r.is_error] == []  # rate limits fail open
    commits = [watch.check(r) for r in env.burst(access, [(tool, args)] * 2)]
    assert check_round(env, approval, 0, commits) == ["nothing", "nothing"]  # approvals fail closed
    assert all("please try again" in r.text for r in commits)
    env.state_sky.clear()
    assert check_round(env, approval, 0, [watch.check(env.call(access, tool, **args))]) == ["done"]


def test_an_approval_whose_redis_reply_was_lost_works_on_the_retry(make_deployment):
    env = make_deployment("redis")
    watch = Watch(env)
    _, tokens = env.sign_in()
    access = tokens["access_token"]
    approval, tool, args = approve(env, watch, access, "create", 1)
    env.odoo.approval = approval
    env.state_sky.check = lambda command: "lost" if command == "set" else None  # the claim is stored, its reply lost
    assert check_round(env, approval, 0, [watch.check(env.call(access, tool, **args))]) == ["nothing"]
    env.state_sky.clear()
    assert check_round(env, approval, 0, [watch.check(env.call(access, tool, **args))]) == ["done"]


@pytest.mark.parametrize("where", ["token check", "refresh"])
def test_redis_trouble_in_the_sign_in_store_never_signs_anyone_out(make_deployment, where):
    env = make_deployment("redis")
    client_id, tokens = env.sign_in()
    env.auth_sky.down = True
    if where == "token check":
        answer = env.call(tokens["access_token"], "odoo_whoami")
        assert answer.is_error and answer.status != 401  # fails closed for this call; a 401 would ask for a new sign-in
    else:
        answer = env.refresh(client_id, tokens["refresh_token"])
        assert answer.status_code >= 500, answer.text  # "try later", not invalid_grant
    env.auth_sky.clear()
    assert env.still_signed_in()
    assert not env.call(tokens["access_token"], "odoo_whoami").is_error
    assert env.refresh(client_id, tokens["refresh_token"]).status_code == 200


def test_a_refresh_whose_redis_reply_was_lost_can_be_retried(make_deployment):
    env = make_deployment("redis")
    client_id, tokens = env.sign_in()
    env.auth_sky.check = lambda command: "lost" if command == "evalsha" else None  # rotated, but the answer is lost
    assert env.refresh(client_id, tokens["refresh_token"]).status_code >= 500  # "try later"
    env.auth_sky.clear()
    retry = env.refresh(client_id, tokens["refresh_token"])  # Claude retries within the grace window
    assert retry.status_code == 200, retry.text
    assert env.still_signed_in()
    assert not env.call(retry.json()["access_token"], "odoo_whoami").is_error


# ================================================================================ 6. time limits


BUSY = {
    "429": lambda: httpx.Response(429, text="Too Many Requests"),
    "429+retry-after": lambda: httpx.Response(429, headers={"Retry-After": "5"}, text="Too Many Requests"),
    "502": lambda: httpx.Response(502, text="Bad Gateway"),
    "503": lambda: httpx.Response(503, text="Service Unavailable"),
    "504": lambda: httpx.Response(504, text="Gateway Timeout"),
}


@pytest.mark.parametrize("fault", BUSY)
@pytest.mark.parametrize("backend", BACKENDS)
def test_reads_get_through_a_brief_busy_spell(make_deployment, backend, fault):
    """Odoo turns every read away once: safe reads wait (honouring Retry-After) and try again."""
    env = make_deployment(backend)
    watch = Watch(env)
    _, tokens = env.sign_in()
    watch.tokens(tokens)
    env.restart()
    tries = Counter()

    async def busy_once(request, model, method):
        tries[(model, method, request.content)] += 1
        return BUSY[fault]() if tries[(model, method, request.content)] == 1 else None

    env.odoo.on_request = busy_once
    results = [watch.check(r) for r in env.burst(tokens["access_token"], list(READ_CALLS))]
    assert [r.text for r in results if r.is_error] == []
    assert max(r.seconds for r in results) >= (5 if fault == "429+retry-after" else 1.4)  # it waited before retrying
    assert all(r.seconds <= 60 for r in results)


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_change_is_not_sent_late_and_its_approval_works_afterwards(make_deployment, backend):
    env = make_deployment(backend)
    watch = Watch(env)
    _, tokens = env.sign_in()
    access = tokens["access_token"]
    approval, tool, args = approve(env, watch, access, "update", 1)
    env.odoo.approval = approval
    env.restart()  # a cold instance: its sign-in lookup counts too

    async def slow_reads(request, model, method):
        timeline().advance(11.0 if method in READS else 0.0)
        return None

    env.odoo.on_request = slow_reads
    late = watch.check(env.call(access, tool, **args))
    assert check_round(env, approval, 0, [late]) == ["nothing"] and "not sent to Odoo" in late.text
    assert late.text.endswith("You can retry with the same confirm_token.")
    env.odoo.on_request = None
    assert check_round(env, approval, 0, [watch.check(env.call(access, tool, **args))]) == ["done"]



# ================================================================================ 7. bugs found by this suite, now fixed


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_revoked_key_on_a_warm_instance_ends_the_sign_in(make_deployment, backend):
    """The service (10 min) and, on Vercel, the identity in Redis (10 min) skip Odoo's key check; a 401 on a data
    call must still end the sign-in, not give a plain error until the caches expire."""
    env = make_deployment(backend)
    _, tokens = env.sign_in()
    expect(not env.call(tokens["access_token"], "odoo_whoami").is_error, "first call")  # caches service and identity
    env.odoo.revoked_keys.add(PRIYA_KEY)
    if backend == "redis":
        env.start_instance()  # even a cold Vercel instance finds the identity in Redis
    answer = env.call(tokens["access_token"], "odoo_read", **READ_LEAD)
    assert "Reconnect the Odoo connector" in answer.text, answer.text
    assert [s["detail"] for s in env.signouts()] == ["Odoo rejected the API key"]
    assert env.call(tokens["access_token"], "odoo_whoami").status == 401  # Claude now asks the person to sign in


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_change_refused_by_a_401_on_a_warm_instance_says_nothing_was_changed(make_deployment, backend):
    env = make_deployment(backend)
    watch = Watch(env)
    _, tokens = env.sign_in()
    access = tokens["access_token"]
    approval, tool, args = approve(env, watch, access, "update", 1)
    env.odoo.revoked_keys.add(PRIYA_KEY)
    answer = env.call(access, tool, **args)
    assert "Reconnect the Odoo connector" in answer.text and says(answer) == "nothing", answer.text
    assert env.odoo.applied_for(approval) == [] and len(env.signouts()) == 1


def test_an_access_denied_without_a_401_signs_nobody_out(make_deployment):
    env = make_deployment("sqlite")
    _, tokens = env.sign_in()
    expect(not env.call(tokens["access_token"], "odoo_whoami").is_error, "first call")

    async def denied(request, model, method):
        body = {"name": "odoo.exceptions.AccessDenied", "message": "Access Denied"}
        return httpx.Response(403, json=body) if model == "crm.lead" else None

    env.odoo.on_request = denied
    answer = env.call(tokens["access_token"], "odoo_read", **READ_LEAD)
    assert answer.is_error and "reconnect" not in answer.text.lower(), answer.text
    assert env.still_signed_in(), env.signouts()


def test_a_change_refused_for_a_revoked_key_says_nothing_was_changed(make_deployment):
    """Errors raised while the service is built come before anything is sent: they say so."""
    env = make_deployment("sqlite")
    _, tokens = env.sign_in()
    env.odoo.revoked_keys.add(PRIYA_KEY)
    tool, args = change_calls("note", 1)[1]
    answer = env.call(tokens["access_token"], tool, **args)
    expect(answer.is_error, "refused")
    assert says(answer) == "nothing"


def test_a_redis_blip_while_loading_the_sign_in_says_nothing_was_changed(make_deployment):
    """A storage error while a cold instance loads the sign-in is no 'unexpected server error' and no sign-out."""
    env = make_deployment("redis")
    _, tokens = env.sign_in()
    env.restart()  # cold: the service is built, which reads the sign-in again after the token check
    lookups = Counter()

    def third_lookup_fails(command):
        lookups[command] += 1
        return "refused" if command == "hgetall" and lookups[command] > 2 else None  # the token check (2) passes

    env.auth_sky.check = third_lookup_fails
    tool, args = change_calls("note", 1)[1]
    answer = env.call(tokens["access_token"], tool, **args)
    expect(answer.is_error and env.odoo.applied == [], "refused before Odoo")
    assert says(answer) == "nothing", answer.text
    assert "Couldn't load your sign-in" in answer.text and env.still_signed_in()


@pytest.mark.parametrize("body", ['{"error": "upstream timed out"}', "{}"])
def test_an_odd_200_from_odoo_never_signs_the_person_out(make_deployment, body):
    """A 200 from res.users/context_get without a uid (e.g. a proxy's JSON error page) says nothing about the key."""
    env = make_deployment("sqlite")
    _, tokens = env.sign_in()
    env.restart()

    async def odd_identity(request, model, method):
        return httpx.Response(200, content=body.encode()) if method == "context_get" else None

    env.odoo.on_request = odd_identity
    expect(env.call(tokens["access_token"], "odoo_whoami").is_error, "the identity check failed")
    assert env.still_signed_in(), env.signouts()


def test_an_applied_update_with_an_odd_read_back_is_reported_done(make_deployment):
    env = make_deployment("sqlite")
    watch = Watch(env)
    _, tokens = env.sign_in()
    approval, tool, args = approve(env, watch, tokens["access_token"], "update", 1)
    env.odoo.approval = approval

    async def odd_after_write(request, model, method):
        if env.odoo.applied and method == "read":
            return httpx.Response(200, json={"error": "upstream timed out"})
        return None

    env.odoo.on_request = odd_after_write
    answer = env.call(tokens["access_token"], tool, **args)
    expect(len(env.odoo.applied_for(approval)) == 1, "Odoo applied the change")
    assert says(answer) == "done", answer.text
    assert READ_BACK_FAILED in answer.text


def test_a_read_under_throttling_ends_within_the_time_limit(make_deployment):
    """Each request's retry waits are capped, but they add up across requests: a cold odoo_read under steady
    throttling took 69 s. The call now stops retrying before the soft limit and says Odoo is busy.

    (A cold read makes 5 Odoo requests here, each turned away twice with Retry-After: 6. That is 60 s of waiting
    at least, so no answer can arrive in time: a clear error is the right outcome.)"""
    env = make_deployment("sqlite")
    watch = Watch(env)
    _, tokens = env.sign_in()
    watch.tokens(tokens)
    env.restart()
    tries = Counter()

    async def throttled(request, model, method):
        tries[(model, method, request.content)] += 1
        if tries[(model, method, request.content)] % 3:
            return httpx.Response(429, headers={"Retry-After": "6"}, text="Too Many Requests")
        return None

    env.odoo.on_request = throttled
    answer = watch.check(env.call(tokens["access_token"], "odoo_read", **READ_LEAD))  # the record, or a clear error
    assert answer.seconds <= 60, f"{answer.seconds:.0f} virtual seconds"
    assert not answer.is_error or "rate limiting" in answer.text, answer.text
    env.odoo.on_request = None
    assert not watch.check(env.call(tokens["access_token"], "odoo_read", **READ_LEAD)).is_error


def test_a_change_queued_behind_a_slow_call_is_not_sent_late(make_deployment):
    """The 20 s send deadline is checked again once the change gets its turn at the per-Odoo gate: a change checked
    1 s into its call used to be sent 26 s into it, where Vercel can cut it off half-way."""
    env = make_deployment("sqlite", shared_clock=True)
    watch = Watch(env)
    _, tokens = env.sign_in()
    access = tokens["access_token"]
    approval, tool, args = approve(env, watch, access, "update", 1)
    env.odoo.approval = approval
    env.call(access, "odoo_search", model="crm.lead")  # warm caches
    search_now, seen = asyncio.Event(), Counter()

    async def script(request, model, method):
        if method == "read" and b"write_date" in request.content and not seen["read"]:
            seen["read"] += 1  # the update's last read before it sends: Claude's search arrives now
            search_now.set()
            gate = next(iter(odoo_client._GATES.values()))
            for _ in range(5000):  # up to 5 real seconds
                if gate._waiters:
                    seen["queued"] += 1
                    break
                await asyncio.sleep(0.001)
        elif method == "search_read" and seen["queued"] and not seen["slow"]:
            seen["slow"] += 1
            timeline().advance(25)  # Odoo takes 25 s to answer the search
        return None

    env.odoo.on_request = script
    started = env.shared_clock.t

    async def update_then_search(http):
        async def search_later():
            await search_now.wait()
            return await env.post_tool(http, access, "odoo_search", {"model": "crm.lead"})

        return await asyncio.gather(env.post_tool(http, access, tool, args), search_later())

    update, _ = env.run_async(update_then_search)
    expect(seen["queued"] and seen["slow"], "the search queued behind the update and was slow")
    late = [sent_at - started for sent_at in env.odoo.change_sent_at if sent_at - started > 20]
    assert late == [], f"sent {late[0]:.0f} s into the call"
    answer = watch.check(ToolResult.of(tool, args, update))
    assert says(answer) == "nothing" and "not sent to Odoo" in answer.text, answer.text
    assert answer.text.endswith("You can retry with the same confirm_token.")
    env.odoo.on_request = None
    assert says(watch.check(env.call(access, tool, **args))) == "done"
    assert len(env.odoo.applied_for(approval)) == 1


def test_a_maintenance_page_does_not_show_operator_settings(make_deployment):
    """ODOO_PROTOCOL=auto without ODOO_DB: a non-JSON 200 page on the JSON-2 check (e.g. a maintenance page) is not
    taken as 'no JSON-2', since the JSON-RPC fallback cannot work without a database name."""
    env = make_deployment("sqlite", odoo_protocol="auto", odoo_db=None)
    _, tokens = env.sign_in()
    env.restart()
    env.odoo.storm(1.0, ("garbled",), methods={"context_get"})
    answer = env.call(tokens["access_token"], "odoo_whoami")
    expect(answer.is_error and env.still_signed_in(), "a plain error, no sign-out")
    assert "ODOO_DB" not in answer.text, answer.text
    assert env.odoo.legacy.call_count == 0
    env.odoo.calm()
    assert not env.call(tokens["access_token"], "odoo_whoami").is_error


def test_an_approval_with_an_unknown_outcome_is_not_reused_after_a_restart(make_deployment):
    """Single container: used approvals are kept in SQLite in the data directory, not only in memory."""
    env = make_deployment("sqlite")
    watch = Watch(env)
    _, tokens = env.sign_in()
    access = tokens["access_token"]
    approval, tool, args = approve(env, watch, access, "create", 1)
    env.odoo.approval = approval
    env.odoo.storm(1.0, ("timeout",), methods={"create"}, carried_out=1.0)
    expect(says(env.call(access, tool, **args)) == "maybe", "the create timed out after Odoo carried it out")
    env.odoo.calm()
    env.restart()
    retry = env.call(access, tool, **args)  # Claude retries the same approval
    assert len(env.odoo.applied_for(approval)) == 1
    assert says(retry) == "nothing" and "already used" in retry.text, retry.text


def test_an_approval_handed_back_before_a_restart_works_after_it(make_deployment):
    env = make_deployment("sqlite")
    watch = Watch(env)
    _, tokens = env.sign_in()
    access = tokens["access_token"]
    approval, tool, args = approve(env, watch, access, "create", 1)
    env.odoo.approval = approval
    env.odoo.storm(1.0, ("connect",), methods={"create"})
    expect(says(env.call(access, tool, **args)) == "nothing", "the create never reached Odoo")
    env.odoo.calm()
    env.restart()
    assert says(watch.check(env.call(access, tool, **args))) == "done"
    assert len(env.odoo.applied_for(approval)) == 1
