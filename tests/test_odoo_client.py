"""OdooClient wire format, error mapping, protocol detection, retries and the last-line method guard (respx)."""

from __future__ import annotations

import asyncio
import email.utils
import json
import time
from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest
import respx

from sahajta_odoo_mcp import deadline, odoo_client
from sahajta_odoo_mcp.errors import OdooError
from sahajta_odoo_mcp.odoo_client import OdooClient, OdooCredentials, new_http_client

URL = "https://odoo.example.com"
KEY = "s3cr3t-api-key-0123456789abcdef"
LOGIN = "ai.tester@example.com"
DEBUG_MARKER = "File \"/opt/odoo/odoo/models.py\", line 4242, in _secret_internals"


@pytest.fixture(autouse=True)
def fresh_gates(monkeypatch):
    # The per-URL semaphores are module globals; each test runs in its own event loop.
    monkeypatch.setattr(odoo_client, "_GATES", {})


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    recorded: list[float] = []

    async def fake_sleep(delay, *args, **kwargs):
        recorded.append(delay)

    monkeypatch.setattr(odoo_client.asyncio, "sleep", fake_sleep)
    # jitter pinned to the middle of its range, so waits are exact (see test_retry_waits_are_jittered)
    monkeypatch.setattr(odoo_client, "random", SimpleNamespace(uniform=lambda low, high: (low + high) / 2), raising=False)
    return recorded


@pytest.fixture
def jitter(monkeypatch) -> list[tuple]:
    """Jitter always at the low end of its range; records each range asked for."""
    asked: list[tuple] = []

    def uniform(low, high):
        asked.append((low, high))
        return low

    monkeypatch.setattr(odoo_client, "random", SimpleNamespace(uniform=uniform), raising=False)
    return asked


@pytest.fixture
def router():
    with respx.mock(base_url=URL, assert_all_called=False, assert_all_mocked=True) as mock:
        yield mock


def make_client(http: httpx.AsyncClient, *, protocol: str = "json2", db: str | None = "testdb", login: str = LOGIN,
                **kwargs) -> OdooClient:
    return OdooClient(OdooCredentials(URL, db, login, KEY), http, protocol=protocol, **kwargs)


def odoo_error_body(name: str, message: str = "Human readable problem") -> dict:
    return {
        "name": name,
        "message": message,
        "arguments": [message],
        "context": {},
        "debug": f"Traceback (most recent call last):\n  {DEBUG_MARKER}\n{name}: {message}",
    }


def body_of(request: httpx.Request) -> dict:
    return json.loads(request.content)


class JsonRpcServer:
    """Answers /jsonrpc like an Odoo <= 18 server, recording each call's params."""

    def __init__(self, uid=7, results: dict | None = None, errors: dict | None = None):
        self.uid = uid
        self.results = results or {}
        self.errors = errors or {}
        self.calls: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        payload = body_of(request)
        params = payload["params"]
        self.calls.append(params)
        key = params["method"] if params["service"] == "common" else params["args"][4]
        if key in self.errors:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "error": self.errors[key]})
        if key == "authenticate":
            result = self.uid
        elif key == "version":
            result = {"server_version": "17.0"}
        else:
            result = self.results.get(key, True)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": result})

    def object_calls(self) -> list[list]:
        return [c["args"] for c in self.calls if c["service"] == "object"]


# ===================================================================================== JSON-2 wire format


async def test_json2_request_shape(router):
    route = router.post("/json/2/res.partner/search_read").mock(return_value=httpx.Response(200, json=[{"id": 1}]))
    async with httpx.AsyncClient() as http:
        result = await make_client(http).call(
            "res.partner", "search_read", ids=[3, 1], context={"lang": "en_US", "active_test": False},
            domain=[["is_company", "=", True]], fields=["name"], limit=5,
        )
    assert result == [{"id": 1}]
    request = route.calls.last.request
    assert str(request.url) == f"{URL}/json/2/res.partner/search_read"
    assert request.method == "POST"
    assert request.headers["authorization"] == f"bearer {KEY}"
    assert request.headers["x-odoo-database"] == "testdb"
    assert request.headers["content-type"].startswith("application/json")
    assert request.headers["user-agent"].startswith("sahajta-odoo-mcp/")
    assert "cookie" not in request.headers
    assert body_of(request) == {
        "domain": [["is_company", "=", True]],
        "fields": ["name"],
        "limit": 5,
        "ids": [3, 1],
        "context": {"lang": "en_US", "active_test": False},
    }


async def test_json2_omits_empty_ids_context_and_db_header(router):
    route = router.post("/json/2/res.partner/search_count").mock(return_value=httpx.Response(200, json=4))
    async with httpx.AsyncClient() as http:
        assert await make_client(http, db=None).call("res.partner", "search_count", ids=[], domain=[]) == 4
    request = route.calls.last.request
    assert "x-odoo-database" not in request.headers
    assert body_of(request) == {"domain": []}


async def test_json2_create_sends_vals_list(router):
    route = router.post("/json/2/crm.lead/create").mock(return_value=httpx.Response(200, json=[41]))
    async with httpx.AsyncClient() as http:
        assert await make_client(http).call("crm.lead", "create", vals_list=[{"name": "x"}]) == [41]
    assert body_of(route.calls.last.request) == {"vals_list": [{"name": "x"}]}


async def test_json2_non_json_200_is_a_server_error(router):
    router.post("/json/2/res.partner/read").mock(return_value=httpx.Response(200, text="<html>login</html>"))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("res.partner", "read", ids=[1])
    assert info.value.kind == "server"


# ===================================================================================== JSON-2 error mapping


@pytest.mark.parametrize(
    "status, name, kind",
    [
        (401, "odoo.exceptions.AccessDenied", "auth"),
        (403, "odoo.exceptions.AccessError", "access"),
        (404, "odoo.exceptions.MissingError", "missing"),
        (404, "werkzeug.exceptions.NotFound", "missing"),
        (409, "odoo.exceptions.ConcurrencyError", "user_error"),
        (422, "odoo.exceptions.UserError", "user_error"),
        (422, "odoo.exceptions.ValidationError", "validation"),
        (422, "odoo.exceptions.RedirectWarning", "user_error"),
        (422, "something.Unknown", "validation"),
        (400, "werkzeug.exceptions.BadRequest", "validation"),
        (429, "", "rate_limited"),
        (500, "builtins.ValueError", "validation"),
        (500, "builtins.KeyError", "validation"),
        (500, "odoo.exceptions.AccessError", "access"),
        (500, "odoo.exceptions.UserError", "user_error"),
        (500, "builtins.ZeroDivisionError", "server"),
        (502, "", "unavailable"),
        (503, "", "unavailable"),
        (504, "", "unavailable"),
    ],
)
async def test_json2_error_mapping_never_leaks_debug_traceback(router, status, name, kind):
    router.post("/json/2/sale.order/action_confirm").mock(
        return_value=httpx.Response(status, json=odoo_error_body(name))
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("sale.order", "action_confirm", ids=[5])
    exc = info.value
    text = str(exc)
    assert exc.kind == kind
    assert exc.status == status
    assert "Human readable problem" in text
    assert DEBUG_MARKER not in text and "Traceback" not in text
    assert KEY not in text and KEY not in repr(exc.args)


async def test_json2_401_explains_the_rpc_scope(router):
    router.post("/json/2/res.users/context_get").mock(return_value=httpx.Response(401, json={}))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("res.users", "context_get")
    text = str(info.value)
    assert info.value.kind == "auth"
    assert "Invalid API key" in text and "RPC" in text and "expired" in text
    assert KEY not in text


async def test_json2_traceback_inside_the_message_is_cut(router):
    message = "Wrong value for partner_id\nTraceback (most recent call last):\n  " + DEBUG_MARKER
    router.post("/json/2/crm.lead/write").mock(
        return_value=httpx.Response(422, json=odoo_error_body("odoo.exceptions.ValidationError", message))
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("crm.lead", "write", ids=[1], vals={"name": "x"})
    assert str(info.value).endswith("Wrong value for partner_id")


async def test_json2_non_json_error_body_is_never_echoed(router):
    # An HTML/plain-text error page (proxy page, login redirect, traceback) must not reach the AI's context.
    text = "<html>Internal Server Error\nTraceback (most recent call last):\n  " + DEBUG_MARKER + "\n" + "x" * 1000
    router.post("/json/2/crm.lead/write").mock(return_value=httpx.Response(500, text=text))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("crm.lead", "write", ids=[1], vals={})
    assert info.value.kind == "server"
    assert DEBUG_MARKER not in str(info.value)
    assert "<html>" not in str(info.value)
    assert "non-JSON answer (HTTP 500)" in str(info.value)


async def test_json2_empty_500_says_http_500(router):
    router.post("/json/2/crm.lead/write").mock(return_value=httpx.Response(500, text=""))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError, match="HTTP 500"):
            await make_client(http).call("crm.lead", "write", ids=[1], vals={})


async def test_json2_long_messages_are_capped(router):
    router.post("/json/2/crm.lead/write").mock(
        return_value=httpx.Response(422, json=odoo_error_body("odoo.exceptions.UserError", "y" * 5000))
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("crm.lead", "write", ids=[1], vals={})
    assert len(info.value.args[0]) == 1500


async def test_network_errors_do_not_leak_urls_or_keys(router):
    router.post("/json/2/res.partner/read").mock(
        side_effect=httpx.ConnectError(f"cannot connect to {URL}/json/2 with bearer {KEY}")
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("res.partner", "read", ids=[1])
    assert info.value.kind == "network"
    assert KEY not in str(info.value) and URL not in str(info.value)


async def test_timeouts_are_reported_as_timeouts(router):
    router.post("/json/2/res.partner/write").mock(side_effect=httpx.ReadTimeout("slow"))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("res.partner", "write", ids=[1], vals={})
    assert info.value.kind == "timeout"


def test_credentials_repr_hides_the_api_key():
    creds = OdooCredentials(URL, "db", LOGIN, KEY)
    assert KEY not in repr(creds) and KEY not in str(creds)


# ===================================================================================== last-line guard


@pytest.mark.parametrize(
    "method",
    ["unlink", "UNLINK", "Unlink", "action_unlink_lines", "unlink_all", "button_immediate_uninstall",
     "module_uninstall", "sudo", "action_sudo_confirm", "_private", "_action_confirm", "__init__", "_unlink"],
)
@pytest.mark.parametrize("protocol", ["json2", "jsonrpc", "auto"])
async def test_client_refuses_forbidden_methods_without_any_http_request(router, method, protocol):
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol=protocol)
        with pytest.raises(OdooError, match="refusing") as info:
            await client.call("sale.order", method, ids=[5])
    assert info.value.kind == "access"
    assert router.calls.call_count == 0


# ===================================================================================== protocol detection


async def test_auto_uses_json2_when_available_and_probes_once(router):
    probe = router.post("/json/2/res.users/context_get").mock(return_value=httpx.Response(200, json={"uid": 7}))
    read = router.post("/json/2/res.partner/read").mock(return_value=httpx.Response(200, json=[]))
    jsonrpc = router.post("/jsonrpc")
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol="auto")
        await client.call("res.partner", "read", ids=[1])
        await client.call("res.partner", "read", ids=[2])
    assert client.protocol == "json2"
    assert probe.call_count == 1 and read.call_count == 2 and jsonrpc.call_count == 0


async def test_auto_falls_back_to_jsonrpc_on_404_and_authenticates(router):
    router.post("/json/2/res.users/context_get").mock(return_value=httpx.Response(404, text="Not Found"))
    server = JsonRpcServer(uid=7, results={"read": [{"id": 1, "name": "Acme"}]})
    router.post("/jsonrpc").mock(side_effect=server)
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol="auto")
        result = await client.call("res.partner", "read", ids=[1], fields=["name"], context={"lang": "en_US"})
    assert client.protocol == "jsonrpc"
    assert result == [{"id": 1, "name": "Acme"}]
    assert server.calls[0] == {"service": "common", "method": "authenticate", "args": ["testdb", LOGIN, KEY, {}]}
    assert server.object_calls() == [
        ["testdb", 7, KEY, "res.partner", "read", [[1]], {"fields": ["name"], "context": {"lang": "en_US"}}]
    ]


async def test_auto_does_not_fall_back_on_auth_errors(router):
    router.post("/json/2/res.users/context_get").mock(
        return_value=httpx.Response(401, json=odoo_error_body("odoo.exceptions.AccessDenied", "Access Denied"))
    )
    jsonrpc = router.post("/jsonrpc")
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http, protocol="auto").call("res.partner", "read", ids=[1])
    assert info.value.kind == "auth" and jsonrpc.call_count == 0


@pytest.mark.parametrize("answer", [httpx.Response(404), httpx.Response(200, text="<html>Down for maintenance</html>")])
async def test_auto_without_a_database_never_falls_back(router, answer):
    # JSON-RPC needs a database name, so without one the probe's own error is the answer
    router.post("/json/2/res.users/context_get").mock(return_value=answer)
    jsonrpc = router.post("/jsonrpc")
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http, protocol="auto", db=None).call("res.partner", "read", ids=[1])
    assert info.value.status == answer.status_code and jsonrpc.call_count == 0
    assert info.value.kind != "auth"  # not a bad key: must never end the person's sign-in
    assert "ODOO_DB" not in str(info.value)  # operator settings are for the log, not the person


async def test_jsonrpc_needs_a_database(router):
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http, protocol="jsonrpc", db=None).call("res.partner", "read", ids=[1])
    # a server setting, not a bad key: must never end the person's sign-in
    assert info.value.kind == "config" and "ODOO_DB" not in str(info.value)


async def test_auto_probe_retries_when_odoo_is_busy(router, sleeps):
    # Odoo.com answers 429 when several requests arrive at once; that is not "no JSON-2 here"
    probe = router.post("/json/2/res.users/context_get").mock(
        side_effect=[httpx.Response(429, text="<html>Too Many Requests</html>"), httpx.Response(200, json={"uid": 7})]
    )
    read = router.post("/json/2/res.partner/read").mock(return_value=httpx.Response(200, json=[]))
    jsonrpc = router.post("/jsonrpc")
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol="auto", db=None)
        await client.call("res.partner", "read", ids=[1])
    assert client.protocol == "json2" and sleeps == [2.0]
    assert probe.call_count == 2 and read.call_count == 1 and jsonrpc.call_count == 0


@pytest.mark.parametrize(
    "failure, kind",
    [
        (httpx.Response(429, text="<html>Too Many Requests</html>"), "rate_limited"),
        (httpx.Response(503, text="<html>Service Unavailable</html>"), "unavailable"),
        (httpx.Response(500, text="<html>Internal Server Error</html>"), "server"),
        (httpx.ReadTimeout("slow"), "timeout"),
        (httpx.ConnectError("refused"), "network"),
    ],
)
async def test_auto_never_falls_back_to_jsonrpc_on_temporary_failures(router, sleeps, failure, kind):
    kwargs = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
    router.post("/json/2/res.users/context_get").mock(**kwargs)
    jsonrpc = router.post("/jsonrpc")
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol="auto", db=None)
        with pytest.raises(OdooError) as info:
            await client.call("res.partner", "read", ids=[1])
    assert info.value.kind == kind  # the real reason, never "auth"
    assert client.protocol == "auto" and jsonrpc.call_count == 0


async def test_auto_falls_back_when_json2_answers_with_a_web_page(router):
    router.post("/json/2/res.users/context_get").mock(return_value=httpx.Response(200, text="<html>Odoo</html>"))
    router.post("/jsonrpc").mock(side_effect=JsonRpcServer())
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol="auto")
        await client.call("res.partner", "search_count", domain=[])
    assert client.protocol == "jsonrpc"


async def test_jsonrpc_wrong_key_is_an_auth_error(router):
    router.post("/jsonrpc").mock(side_effect=JsonRpcServer(uid=False))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http, protocol="jsonrpc").call("res.partner", "read", ids=[1])
    assert info.value.kind == "auth"


# ===================================================================================== legacy JSON-RPC shapes


async def test_jsonrpc_create_passes_vals_list_positionally(router):
    server = JsonRpcServer(results={"create": [41, 42]})
    router.post("/jsonrpc").mock(side_effect=server)
    async with httpx.AsyncClient() as http:
        result = await make_client(http, protocol="jsonrpc").call(
            "crm.lead", "create", vals_list=[{"name": "a"}, {"name": "b"}], context={"lang": "en_US"}
        )
    assert result == [41, 42]
    assert server.object_calls()[-1] == [
        "testdb", 7, KEY, "crm.lead", "create", [[{"name": "a"}, {"name": "b"}]], {"context": {"lang": "en_US"}}
    ]


async def test_jsonrpc_write_and_button_shapes(router):
    server = JsonRpcServer()
    router.post("/jsonrpc").mock(side_effect=server)
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol="jsonrpc")
        await client.call("crm.lead", "write", ids=[1, 2], vals={"name": "x"})
        await client.call("sale.order", "action_confirm", ids=[5])
        await client.call("res.partner", "search_count", domain=[["id", ">", 0]])
    assert server.object_calls() == [
        # write's values go positionally: Odoo <= 18 overrides call the parameter `vals` or `values`
        ["testdb", 7, KEY, "crm.lead", "write", [[1, 2], {"name": "x"}], {}],
        ["testdb", 7, KEY, "sale.order", "action_confirm", [[5]], {}],
        ["testdb", 7, KEY, "res.partner", "search_count", [], {"domain": [["id", ">", 0]]}],
    ]
    # authenticated once only
    assert sum(1 for c in server.calls if c["method"] == "authenticate") == 1


@pytest.mark.parametrize(
    "error, kind",
    [
        ({"code": 200, "message": "Odoo Server Error",
          "data": {"name": "odoo.exceptions.AccessError", "message": "You are not allowed", "debug": DEBUG_MARKER}},
         "access"),
        ({"code": 200, "message": "Odoo Server Error",
          "data": {"name": "odoo.exceptions.UserError", "message": "Cannot confirm", "debug": DEBUG_MARKER}},
         "user_error"),
        ({"code": 200, "message": "Odoo Server Error",
          "data": {"name": "builtins.KeyError", "message": "Object foo.bar doesn't exist", "debug": DEBUG_MARKER}},
         "missing"),
        ({"code": 200, "message": "Odoo Server Error",
          "data": {"name": "builtins.RuntimeError", "message": "boom", "debug": DEBUG_MARKER}},
         "server"),
        ({"code": 100, "message": "Odoo Session Expired",
          "data": {"name": "odoo.http.SessionExpiredException", "message": "Session expired", "debug": DEBUG_MARKER}},
         "auth"),
    ],
)
async def test_jsonrpc_error_mapping_never_leaks_debug(router, error, kind):
    router.post("/jsonrpc").mock(side_effect=JsonRpcServer(errors={"action_confirm": error}))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http, protocol="jsonrpc").call("sale.order", "action_confirm", ids=[5])
    assert info.value.kind == kind
    assert DEBUG_MARKER not in str(info.value) and KEY not in str(info.value)


@pytest.mark.parametrize("status, kind", [(429, "rate_limited"), (502, "unavailable"), (503, "unavailable"),
                                          (504, "unavailable"), (500, "server"), (403, "server")])
async def test_jsonrpc_http_status_mapping(router, status, kind):
    calls = {"n": 0}

    def handler(request):
        params = body_of(request)["params"]
        if params["method"] == "authenticate":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": 7})
        calls["n"] += 1
        return httpx.Response(status, text="busy")

    router.post("/jsonrpc").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http, protocol="jsonrpc").call("sale.order", "action_confirm", ids=[5])
    assert info.value.kind == kind and calls["n"] == 1


# ===================================================================================== retries


@pytest.mark.parametrize("status", [429, 502, 503, 504])
async def test_read_methods_are_retried_after_a_busy_answer(router, sleeps, status):
    route = router.post("/json/2/res.partner/search_read").mock(
        side_effect=[httpx.Response(status, json={}), httpx.Response(200, json=[{"id": 1}])]
    )
    async with httpx.AsyncClient() as http:
        assert await make_client(http).call("res.partner", "search_read", domain=[]) == [{"id": 1}]
    assert route.call_count == 2
    assert sleeps == [2.0]


async def test_read_retry_backs_off_and_gives_up_after_three_attempts(router, sleeps):
    route = router.post("/json/2/res.partner/read").mock(return_value=httpx.Response(503, json={}))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("res.partner", "read", ids=[1])
    assert info.value.kind == "unavailable"
    assert route.call_count == 3 and sleeps == [2.0, 4.0]


async def test_retry_waits_are_jittered(router, sleeps, jitter):
    # parallel serverless instances turned away together must not all come back at the same moment
    router.post("/json/2/res.partner/read").mock(return_value=httpx.Response(429, json={}))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError):
            await make_client(http).call("res.partner", "read", ids=[1])
    assert jitter == [(0.7, 1.3), (0.7, 1.3)]  # +-30%
    assert sleeps == pytest.approx([1.4, 2.8])


async def test_retry_waits_at_least_as_long_as_retry_after(router, sleeps, jitter):
    route = router.post("/json/2/res.partner/read").mock(
        side_effect=[httpx.Response(429, json={}, headers={"Retry-After": "5"}), httpx.Response(200, json=[])]
    )
    async with httpx.AsyncClient() as http:
        assert await make_client(http).call("res.partner", "read", ids=[1]) == []
    assert route.call_count == 2 and sleeps == [5.0]


async def test_retry_after_as_an_http_date_is_understood(router, sleeps, jitter):
    when = email.utils.formatdate(time.time() + 6, usegmt=True)
    router.post("/json/2/res.partner/read").mock(
        side_effect=[httpx.Response(503, json={}, headers={"Retry-After": when}), httpx.Response(200, json=[])]
    )
    async with httpx.AsyncClient() as http:
        await make_client(http).call("res.partner", "read", ids=[1])
    assert 4.0 < sleeps[0] <= 6.0


async def test_a_retry_after_longer_than_eight_seconds_is_not_waited_for(router, sleeps):
    route = router.post("/json/2/res.partner/read").mock(
        return_value=httpx.Response(429, json={}, headers={"Retry-After": "30"})
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("res.partner", "read", ids=[1])
    assert info.value.kind == "rate_limited" and info.value.retry_after == 30.0
    assert route.call_count == 1 and sleeps == []


async def test_total_retry_waiting_stays_under_fifteen_seconds(router, sleeps):
    route = router.post("/json/2/res.partner/read").mock(
        return_value=httpx.Response(429, json={}, headers={"Retry-After": "8"})
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError):
            await make_client(http).call("res.partner", "read", ids=[1])
    assert route.call_count == 2 and sleeps == [8.0]  # a second 8 s wait would pass 15 s


@contextmanager
def call_started(seconds_ago: float | None):
    """Inside a tool call that started `seconds_ago` (as tools.run marks it); None: outside any tool call."""
    if seconds_ago is None:
        yield
        return
    token = deadline.CALL_STARTED.set(time.monotonic() - seconds_ago)
    try:
        yield
    finally:
        deadline.CALL_STARTED.reset(token)


async def test_no_retry_wait_runs_past_the_calls_soft_limit(router, sleeps):
    route = router.post("/json/2/res.partner/read").mock(
        return_value=httpx.Response(429, json={}, headers={"Retry-After": "6"})
    )
    async with httpx.AsyncClient() as http:
        with call_started(deadline.SOFT_LIMIT - 5), pytest.raises(OdooError) as info:  # a 6 s wait would end too late
            await make_client(http).call("res.partner", "read", ids=[1])
    assert info.value.kind == "rate_limited" and route.call_count == 1 and sleeps == []


async def test_the_json2_probe_waits_only_within_the_calls_soft_limit(router, sleeps):
    route = router.post("/json/2/res.users/context_get").mock(return_value=httpx.Response(503, json={}))
    async with httpx.AsyncClient() as http:
        with call_started(deadline.SOFT_LIMIT - 1), pytest.raises(OdooError) as info:
            await make_client(http, protocol="auto").call("res.partner", "read", ids=[1])
    assert info.value.kind == "unavailable" and route.call_count == 1 and sleeps == []


@pytest.mark.parametrize("seconds_ago, expected", [(None, 30.0), (10, 30.0), (30, 20.0), (48, 5.0), (70, 5.0)])
async def test_each_request_ends_before_the_calls_soft_limit(router, seconds_ago, expected):
    route = router.post("/json/2/res.partner/read").mock(return_value=httpx.Response(200, json=[]))
    async with httpx.AsyncClient() as http:
        with call_started(seconds_ago):
            await make_client(http, timeout=30.0).call("res.partner", "read", ids=[1])
    timeout = route.calls[0].request.extensions["timeout"]
    assert timeout["read"] == pytest.approx(expected, abs=0.5)


async def test_a_change_past_its_send_by_time_is_not_sent(router):
    route = router.post("/json/2/res.partner/write").mock(return_value=httpx.Response(200, json=True))
    token = deadline.SEND_BY.set(time.monotonic() - 1)
    try:
        async with httpx.AsyncClient() as http:
            with pytest.raises(OdooError) as info:
                await make_client(http).call("res.partner", "write", ids=[1], vals={"name": "x"})
    finally:
        deadline.SEND_BY.reset(token)
    assert info.value.kind == "late" and info.value.maybe_applied is False and route.call_count == 0


async def test_jsonrpc_busy_answers_carry_retry_after(router, sleeps):
    def handler(request):
        params = body_of(request)["params"]
        if params["method"] == "authenticate":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": 7})
        return httpx.Response(429, text="slow down", headers={"Retry-After": "3"})

    router.post("/jsonrpc").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http, protocol="jsonrpc").call("res.partner", "search_count", domain=[])
    assert info.value.retry_after == 3.0
    assert sleeps == [pytest.approx(3.45), pytest.approx(4.0)]


async def test_auto_probe_backs_off_like_reads(router, sleeps):
    busy = httpx.Response(429, text="<html>Too Many Requests</html>")
    probe = router.post("/json/2/res.users/context_get").mock(
        side_effect=[busy, busy, httpx.Response(200, json={"uid": 7})]
    )
    router.post("/json/2/res.partner/read").mock(return_value=httpx.Response(200, json=[]))
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol="auto", db=None)
        await client.call("res.partner", "read", ids=[1])
    assert client.protocol == "json2" and probe.call_count == 3 and sleeps == [2.0, 4.0]


@pytest.mark.parametrize(
    "method, kwargs",
    [
        ("write", {"vals": {"name": "x"}}),
        ("create", {"vals_list": [{"name": "x"}]}),
        ("action_confirm", {}),
        ("message_post", {"body": "hi"}),
    ],
)
@pytest.mark.parametrize("status", [429, 502, 503, 504])
async def test_changes_are_never_retried(router, sleeps, method, kwargs, status):
    route = router.post(f"/json/2/sale.order/{method}").mock(return_value=httpx.Response(status, json={}))
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError):
            await make_client(http).call("sale.order", method, ids=[5], **kwargs)
    assert route.call_count == 1
    assert sleeps == []


@pytest.mark.parametrize("failure", [httpx.Response(500, json={}), httpx.Response(403, json={}), httpx.ReadTimeout("slow")])
async def test_reads_are_not_retried_for_other_failures(router, sleeps, failure):
    kwargs = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
    route = router.post("/json/2/res.partner/read").mock(**kwargs)
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError):
            await make_client(http).call("res.partner", "read", ids=[1])
    assert route.call_count == 1 and sleeps == []


async def test_jsonrpc_reads_are_retried_too(router, sleeps):
    state = {"object_calls": 0}

    def handler(request):
        payload = body_of(request)
        params = payload["params"]
        if params["method"] == "authenticate":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": 7})
        state["object_calls"] += 1
        if state["object_calls"] == 1:
            return httpx.Response(429, text="slow down")
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": 3})

    router.post("/jsonrpc").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        assert await make_client(http, protocol="jsonrpc").call("res.partner", "search_count", domain=[]) == 3
    assert state["object_calls"] == 2 and sleeps == [2.0]


# ===================================================================================== did Odoo apply it?


@pytest.mark.parametrize(
    "failure, maybe_applied",
    [
        # never reached Odoo
        (httpx.ConnectError("refused"), False),
        (httpx.ConnectTimeout("no route"), False),
        (httpx.PoolTimeout("pool full"), False),
        # sent: Odoo may be working on it, or may have finished
        (httpx.ReadTimeout("slow"), True),
        (httpx.WriteTimeout("slow"), True),
        (httpx.ReadError("reset"), True),
        (httpx.RemoteProtocolError("Server disconnected without sending a response"), True),
        # Odoo refused it or rolled its transaction back
        (httpx.Response(429, json={}), False),
        (httpx.Response(401, json={}), False),
        (httpx.Response(403, json=odoo_error_body("odoo.exceptions.AccessError")), False),
        (httpx.Response(404, json=odoo_error_body("odoo.exceptions.MissingError")), False),
        (httpx.Response(400, json=odoo_error_body("werkzeug.exceptions.BadRequest")), False),
        (httpx.Response(422, json=odoo_error_body("odoo.exceptions.ValidationError")), False),
        (httpx.Response(422, json=odoo_error_body("odoo.exceptions.UserError")), False),
        (httpx.Response(409, json=odoo_error_body("odoo.exceptions.ConcurrencyError")), False),
        (httpx.Response(500, json=odoo_error_body("odoo.exceptions.LockError")), False),
        (httpx.Response(500, json=odoo_error_body("odoo.exceptions.UserError")), False),
        # unknown
        (httpx.Response(500, json=odoo_error_body("builtins.ZeroDivisionError")), True),
        (httpx.Response(500, text="<html>Internal Server Error</html>"), True),
        (httpx.Response(502, text="Bad Gateway"), True),
        (httpx.Response(503, text="Service Unavailable"), True),
        (httpx.Response(504, text="Gateway Timeout"), True),
        (httpx.Response(200, text="<html>half a page"), True),
    ],
    ids=lambda v: type(v).__name__ if isinstance(v, Exception) else getattr(v, "status_code", v),
)
async def test_errors_say_whether_odoo_may_have_applied_the_change(router, failure, maybe_applied):
    kwargs = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
    router.post("/json/2/account.move/create").mock(**kwargs)
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).call("account.move", "create", vals_list=[{"move_type": "out_invoice"}])
    assert info.value.maybe_applied is maybe_applied


@pytest.mark.parametrize(
    "failure, maybe_applied",
    [
        (httpx.ConnectError("refused"), False),
        (httpx.ReadTimeout("slow"), True),
        (httpx.Response(429, text="slow down"), False),
        (httpx.Response(502, text="Bad Gateway"), True),
        ({"code": 200, "message": "Odoo Server Error", "data": {"name": "odoo.exceptions.UserError", "message": "no"}}, False),
        ({"code": 200, "message": "Odoo Server Error", "data": {"name": "builtins.RuntimeError", "message": "boom"}}, True),
    ],
    ids=["connect", "read-timeout", "429", "502", "user-error", "crash"],
)
async def test_jsonrpc_errors_say_whether_odoo_may_have_applied_the_change(router, failure, maybe_applied):
    def handler(request):
        payload = body_of(request)
        if payload["params"]["method"] == "authenticate":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "result": 7})
        if isinstance(failure, Exception):
            raise failure
        if isinstance(failure, dict):
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"], "error": failure})
        return failure

    router.post("/jsonrpc").mock(side_effect=handler)
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http, protocol="jsonrpc").call("account.move", "create", vals_list=[{}])
    assert info.value.maybe_applied is maybe_applied


def test_refusals_before_sending_never_count_as_applied():
    assert OdooError("refusing to send 'unlink' to Odoo", kind="access").maybe_applied is False
    assert OdooError("ODOO_DB must be set", kind="config").maybe_applied is False
    assert OdooError("anything else").maybe_applied is True  # when in doubt, assume it may have happened


# ===================================================================================== concurrency gate


def _slow_route(router, path: str, tracker: dict):
    async def handler(request):
        tracker["active"] += 1
        tracker["peak"] = max(tracker["peak"], tracker["active"])
        await asyncio.sleep(0.01)
        tracker["active"] -= 1
        return httpx.Response(200, json=[])

    return router.post(path).mock(side_effect=handler)


async def test_calls_to_one_odoo_are_serialised_across_clients(router):
    tracker = {"active": 0, "peak": 0}
    _slow_route(router, "/json/2/res.partner/read", tracker)
    async with httpx.AsyncClient() as http:
        alice = make_client(http)
        bob = OdooClient(OdooCredentials(URL, "testdb", "bob@example.com", "another-key"), http, protocol="json2")
        await asyncio.gather(*(c.call("res.partner", "read", ids=[1]) for c in [alice, bob] * 3))
    assert tracker["peak"] == 1


async def test_max_parallel_allows_some_concurrency(router):
    tracker = {"active": 0, "peak": 0}
    _slow_route(router, "/json/2/res.partner/read", tracker)
    async with httpx.AsyncClient() as http:
        client = make_client(http, max_parallel=3)
        await asyncio.gather(*(client.call("res.partner", "read", ids=[1]) for _ in range(8)))
    assert 1 < tracker["peak"] <= 3


async def test_max_parallel_below_one_is_treated_as_one(router):
    tracker = {"active": 0, "peak": 0}
    _slow_route(router, "/json/2/res.partner/read", tracker)
    async with httpx.AsyncClient() as http:
        client = make_client(http, max_parallel=0)
        await asyncio.gather(*(client.call("res.partner", "read", ids=[1]) for _ in range(4)))
    assert tracker["peak"] == 1


# ===================================================================================== cookies


async def test_new_http_client_never_replays_cookies_from_odoo(router):
    route = router.post("/json/2/res.partner/read").mock(
        side_effect=[
            httpx.Response(200, json=[], headers={"Set-Cookie": "session_id=stolen-session; Path=/; HttpOnly"}),
            httpx.Response(200, json=[]),
        ]
    )
    async with new_http_client() as http:
        client = make_client(http)
        await client.call("res.partner", "read", ids=[1])
        await client.call("res.partner", "read", ids=[2])
        assert len(http.cookies) == 0
    assert "cookie" not in route.calls[1].request.headers


async def test_a_default_httpx_client_would_replay_the_cookie(router):
    """Control for the test above: proves the Set-Cookie really is something httpx would store."""
    route = router.post("/json/2/res.partner/read").mock(
        side_effect=[
            httpx.Response(200, json=[], headers={"Set-Cookie": "session_id=stolen-session; Path=/"}),
            httpx.Response(200, json=[]),
        ]
    )
    async with httpx.AsyncClient() as http:
        client = make_client(http)
        await client.call("res.partner", "read", ids=[1])
        await client.call("res.partner", "read", ids=[2])
    assert "session_id=stolen-session" in route.calls[1].request.headers.get("cookie", "")


def test_new_http_client_does_not_follow_redirects():
    http = new_http_client()
    assert http.follow_redirects is False


# ===================================================================================== identity


def mock_identity(router, *, ctx=None, user=None, version_status=200):
    ctx = {"uid": 7, "tz": "Asia/Kolkata", "lang": "en_IN"} if ctx is None else ctx
    user = user if user is not None else [
        {"id": 7, "login": " AI.Tester@Example.com ", "name": "AI Tester", "share": False, "company_id": [1, "Sahajta"]}
    ]
    routes = {
        "context_get": router.post("/json/2/res.users/context_get").mock(return_value=httpx.Response(200, json=ctx)),
        "read": router.post("/json/2/res.users/read").mock(return_value=httpx.Response(200, json=user)),
        "version": router.get("/web/version").mock(
            return_value=httpx.Response(version_status, json={"version": "19.0+e"})
        ),
    }
    return routes


async def test_identity_reads_the_user_once_and_caches(router):
    routes = mock_identity(router)
    async with httpx.AsyncClient() as http:
        client = make_client(http)
        identity = await client.identity()
        again = await client.identity()
    assert again is identity
    assert identity.uid == 7 and identity.name == "AI Tester"
    assert identity.tz == "Asia/Kolkata" and identity.lang == "en_IN"
    assert identity.company_id == 1 and identity.company_name == "Sahajta"
    assert identity.is_internal_user is True
    assert identity.server_version == "19.0+e" and identity.protocol == "json2"
    assert routes["context_get"].call_count == 1 and routes["read"].call_count == 1
    assert body_of(routes["read"].calls.last.request)["ids"] == [7]


async def test_identity_is_safe_under_concurrency(router):
    routes = mock_identity(router)
    async with httpx.AsyncClient() as http:
        client = make_client(http)
        results = await asyncio.gather(*(client.identity() for _ in range(5)))
    assert all(r is results[0] for r in results)
    assert routes["read"].call_count == 1


async def test_lang_and_tz_from_identity_go_on_every_later_call_and_caller_keys_win(router):
    mock_identity(router)
    route = router.post("/json/2/crm.lead/read").mock(return_value=httpx.Response(200, json=[]))
    async with httpx.AsyncClient() as http:
        client = make_client(http)
        await client.identity()
        await client.call("crm.lead", "read", ids=[1])
        await client.call("crm.lead", "read", ids=[1], context={"lang": "fr_FR", "active_test": False})
    assert body_of(route.calls[0].request)["context"] == {"lang": "en_IN", "tz": "Asia/Kolkata"}
    assert body_of(route.calls[1].request)["context"] == {"lang": "fr_FR", "tz": "Asia/Kolkata", "active_test": False}


async def test_portal_users_are_marked_as_not_internal(router):
    mock_identity(router, user=[{"id": 7, "login": LOGIN, "name": "Customer", "share": True, "company_id": False}])
    async with httpx.AsyncClient() as http:
        identity = await make_client(http).identity()
    assert identity.is_internal_user is False and identity.company_id is None


async def test_identity_without_uid_is_not_an_auth_error(router):
    # Odoo accepted the key (HTTP 200); an odd answer (e.g. a proxy's error page) says nothing about it
    mock_identity(router, ctx={"tz": "UTC"})
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).identity()
    assert info.value.kind == "server"


async def test_identity_with_unknown_user_is_not_an_auth_error(router):
    mock_identity(router, user=[])
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError) as info:
            await make_client(http).identity()
    assert info.value.kind == "server"


async def test_identity_defaults_when_context_lacks_tz_and_lang(router):
    mock_identity(router, ctx={"uid": 7, "tz": False, "lang": False})
    route = router.post("/json/2/crm.lead/read").mock(return_value=httpx.Response(200, json=[]))
    async with httpx.AsyncClient() as http:
        client = make_client(http)
        identity = await client.identity()
        await client.call("crm.lead", "read", ids=[1])
    # no time zone in the profile: left empty so MCP_DEFAULT_TIMEZONE applies (see validation.user_zone)
    assert identity.tz == "" and identity.lang == "en_US"
    assert "context" not in body_of(route.calls.last.request)


async def test_server_version_falls_back_to_jsonrpc_then_unknown(router):
    mock_identity(router, version_status=404)
    router.post("/jsonrpc").mock(side_effect=JsonRpcServer())
    async with httpx.AsyncClient() as http:
        assert (await make_client(http).identity()).server_version == "17.0"

    async with httpx.AsyncClient() as http:
        router.post("/jsonrpc").mock(return_value=httpx.Response(500))
        assert await make_client(http).server_version() == "unknown"


async def test_identity_over_jsonrpc_uses_the_authenticated_uid(router):
    server = JsonRpcServer(
        uid=9,
        results={
            "context_get": {"tz": "Europe/Berlin", "lang": "de_DE"},
            "read": [{"id": 9, "login": LOGIN, "name": "Legacy", "share": False, "company_id": [2, "Sub"]}],
        },
    )
    router.post("/jsonrpc").mock(side_effect=server)
    router.get("/web/version").mock(return_value=httpx.Response(200, json={"version": "17.0"}))
    async with httpx.AsyncClient() as http:
        identity = await make_client(http, protocol="jsonrpc").identity()
    assert identity.uid == 9 and identity.tz == "Europe/Berlin" and identity.protocol == "jsonrpc"
    read = [c for c in server.object_calls() if c[4] == "read"][0]
    assert read[5] == [[9]]


async def test_verify_login_matches_is_case_and_space_insensitive(router):
    mock_identity(router)
    async with httpx.AsyncClient() as http:
        identity = await make_client(http, login="ai.tester@example.com").verify_login_matches()
    assert identity.uid == 7


async def test_verify_login_mismatch_is_refused(router):
    mock_identity(router)
    async with httpx.AsyncClient() as http:
        with pytest.raises(OdooError, match="different Odoo user") as info:
            await make_client(http, login="ceo@example.com").verify_login_matches()
    assert info.value.kind == "auth"


async def test_jsonrpc_legacy_positional_shapes(router):
    server = JsonRpcServer()
    router.post("/jsonrpc").mock(side_effect=server)
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol="jsonrpc")
        await client.call("res.partner", "default_get", fields=["name"])
        await client.call("res.partner", "name_search", name="Acme", domain=[["is_company", "=", True]], operator="ilike", limit=5)
        await client.call("res.partner", "name_search", name="Acme", limit=5)
    calls = server.object_calls()
    assert calls[0][4:] == ["default_get", [["name"]], {}]
    assert calls[1][4:] == ["name_search", ["Acme", [["is_company", "=", True]], "ilike", 5], {}]
    assert calls[2][4:] == ["name_search", ["Acme", [], "ilike", 5], {}]


async def test_auto_detection_treats_login_redirect_as_no_json2(router):
    # Odoo 18's web module answers unknown /json/... paths with a 303 to /web/login instead of 404.
    router.post("/json/2/res.users/context_get").mock(
        return_value=httpx.Response(303, headers={"Location": "/web/login?redirect=/json/2/res.users/context_get"}, text="<html>Redirecting</html>")
    )
    server = JsonRpcServer()
    router.post("/jsonrpc").mock(side_effect=server)
    async with httpx.AsyncClient() as http:
        client = make_client(http, protocol="auto")
        await client.call("res.partner", "search_count", domain=[])
        assert client.protocol == "jsonrpc"
