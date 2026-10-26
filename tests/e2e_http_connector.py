"""Full connector flow against the running HTTP server + live test Odoo: discovery, DCR, PKCE, sign-in page,
token, MCP tool calls with the bearer token, refresh rotation + replay detection."""
import asyncio, base64, hashlib, html, json, os, re, secrets, sys, urllib.parse
import httpx
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

BASE = os.environ.get("BASE", "http://localhost:8765")
LOGIN, KEY = os.environ["L"], os.environ["K"]
REDIRECT = "http://localhost:9999/callback"

def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: sys.exit(1)

def form_fields(page: str):
    action = html.unescape(re.search(r'<form[^>]*action="([^"]*)"', page).group(1))
    fields = {}
    for tag in re.findall(r"<input[^>]*>", page):
        name = re.search(r'name="([^"]+)"', tag); typ = re.search(r'type="([^"]+)"', tag)
        val = re.search(r'value="([^"]*)"', tag)
        if name: fields[name.group(1)] = (typ.group(1) if typ else "text", html.unescape(val.group(1)) if val else "")
    return action, fields

async def sign_in(h, client_id, login, key):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    r = await h.get("/authorize", params=dict(response_type="code", client_id=client_id, redirect_uri=REDIRECT,
        code_challenge=challenge, code_challenge_method="S256", state="st8", resource=f"{BASE}/mcp"))
    ok(r.status_code in (302, 303), f"/authorize redirects to sign-in page ({r.status_code})")
    page_url = r.headers["location"]
    page = await h.get(page_url)
    ok(page.status_code == 200 and "API key" in page.text or "api" in page.text.lower(), "sign-in page renders")
    ok("frame-ancestors 'none'" in page.headers.get("content-security-policy", ""), "sign-in page cannot be framed")
    action, fields = form_fields(page.text)
    data = {}
    for name, (typ, val) in fields.items():
        if typ == "password": data[name] = key
        elif typ in ("text", "email") and re.search("login|email|user", name): data[name] = login
        else: data[name] = val
    post = await h.post(urllib.parse.urljoin(str(page.url), action), data=data)
    return post, verifier

async def main():
    async with httpx.AsyncClient(base_url=BASE, follow_redirects=False, timeout=30) as h:
        r = await h.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers={"Accept": "application/json, text/event-stream"})
        ok(r.status_code == 401 and "resource_metadata" in r.headers.get("www-authenticate", ""), "unauthenticated /mcp -> 401 + resource_metadata")
        prm = (await h.get("/.well-known/oauth-protected-resource/mcp")).json()
        ok(prm["resource"] == f"{BASE}/mcp", f"PRM resource = {prm['resource']}")
        meta = (await h.get("/.well-known/oauth-authorization-server")).json()
        ok(meta.get("client_id_metadata_document_supported") is True and "S256" in meta["code_challenge_methods_supported"], "AS metadata advertises CIMD + S256")
        bad = await h.post("/register", json={"client_name": "evil", "redirect_uris": ["https://evil.example/cb"], "token_endpoint_auth_method": "none"})
        ok(bad.status_code == 400, "DCR with foreign redirect rejected")
        reg = await h.post("/register", json={"client_name": "E2E", "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none",
                                              "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]})
        ok(reg.status_code == 201, f"DCR ok ({reg.status_code})")
        client_id = reg.json()["client_id"]

        post, _ = await sign_in(h, client_id, LOGIN, "not-the-right-key")
        ok(post.status_code in (200, 400) and "code=" not in post.headers.get("location", "") and "<form" in post.text, "wrong API key -> form shown again, no code")

        post, verifier = await sign_in(h, client_id, LOGIN, KEY)
        loc = post.headers.get("location", "")
        ok(post.status_code in (302, 303) and loc.startswith(REDIRECT), "sign-in redirects back with code")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        ok(q.get("state") == ["st8"], "state preserved")
        tok = await h.post("/token", data=dict(grant_type="authorization_code", code=q["code"][0], redirect_uri=REDIRECT,
                                                client_id=client_id, code_verifier=verifier, resource=f"{BASE}/mcp"))
        ok(tok.status_code == 200, f"token exchange ({tok.status_code} {tok.text[:200]})")
        t = tok.json()

        http = create_mcp_http_client(headers={"Authorization": f"Bearer {t['access_token']}"})
        async with Client(streamable_http_client(f"{BASE}/mcp", http_client=http)) as mcp:
            tools = [x.name for x in (await mcp.list_tools()).tools]
            ok("odoo_search" in tools, f"tools over HTTP: {len(tools)}")
            who = json.loads((await mcp.call_tool("odoo_whoami", {})).content[0].text)
            ok(who["user"]["login"] == LOGIN, f"acting as {who['user']['login']} (uid {who['user']['id']})")
            res = await mcp.call_tool("odoo_search", {"model": "crm.lead", "limit": 2, "fields": ["name"]})
            ok(not res.is_error, "search over HTTP works")
            blocked = await mcp.call_tool("odoo_search", {"model": "res.users.apikeys"})
            ok(blocked.is_error, "api keys model blocked over HTTP")

        r1 = await h.post("/token", data=dict(grant_type="refresh_token", refresh_token=t["refresh_token"], client_id=client_id))
        ok(r1.status_code == 200 and r1.json()["refresh_token"] != t["refresh_token"], "refresh rotates")
        # a client retry within the 120 s grace window gets a fresh pair; replay after it revokes (offline tests)
        r2 = await h.post("/token", data=dict(grant_type="refresh_token", refresh_token=t["refresh_token"], client_id=client_id))
        ok(r2.status_code == 200 and r2.json()["refresh_token"] != r1.json()["refresh_token"], "quick retry of old refresh token tolerated")
        r3 = await h.post("/token", data=dict(grant_type="refresh_token", refresh_token=r1.json()["refresh_token"], client_id=client_id))
        ok(r3.status_code == 200, "grant still alive after a tolerated retry")
        # code replay: a second use of the same code fails AND kills the tokens issued from it
        post, verifier = await sign_in(h, client_id, LOGIN, KEY)
        code = urllib.parse.parse_qs(urllib.parse.urlparse(post.headers["location"]).query)["code"][0]
        args = dict(grant_type="authorization_code", code=code, redirect_uri=REDIRECT, client_id=client_id, code_verifier=verifier)
        first = await h.post("/token", data=args)
        ok(first.status_code == 200, "fresh sign-in token exchange")
        again = await h.post("/token", data=args)
        ok(again.status_code == 400, "authorization code is single-use")
        r = await h.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                         headers={"Authorization": f"Bearer {first.json()['access_token']}", "Accept": "application/json, text/event-stream"})
        ok(r.status_code == 401, "code replay revoked the tokens issued from that code")
        # wrong PKCE verifier
        post, verifier = await sign_in(h, client_id, LOGIN, KEY)
        code = urllib.parse.parse_qs(urllib.parse.urlparse(post.headers["location"]).query)["code"][0]
        bad = await h.post("/token", data=dict(grant_type="authorization_code", code=code, redirect_uri=REDIRECT, client_id=client_id, code_verifier="x" * 50))
        ok(bad.status_code == 400, "wrong PKCE verifier rejected")
    print("ALL HTTP E2E CHECKS PASSED")

asyncio.run(main())
