"""The sign-in page people see when they connect Claude: Odoo login + Odoo API key.

GET renders the form for a pending authorization; POST checks the CSRF token, rate limits,
verifies the key with Odoo, then sends the browser back to the client with a code.

CSRF tokens are an HMAC over (pending request id, a random per-browser cookie nonce): the token
is useless without the cookie, which only our own origin can set, so a form pre-filled by an
attacker cannot be submitted from somebody else's browser.
"""

from __future__ import annotations

import html
import logging
import re
import secrets
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..config import Settings
from ..errors import OdooError
from ..odoo_client import OdooIdentity
from .clients import LOOPBACK_HOSTS
from .crypto import CsrfSigner
from .limits import SlidingWindow, client_ip
from .provider import OdooAuthProvider
from .store import PendingAuthorization

logger = logging.getLogger(__name__)

LOGIN_PATH = "/oauth/login"
MAX_FAILURES_PER_REQUEST = 5
MAX_FAILURES_PER_IP = 20
IP_WINDOW_SECONDS = 600
COOKIE_MAX_AGE = 1800

_REQUEST_ID = re.compile(r"[A-Za-z0-9_\-]{20,100}")
_NONCE = re.compile(r"[A-Za-z0-9_\-]{32}")
_API_KEY = re.compile(r"[\x21-\x7e]{16,256}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SCHEME = re.compile(r"[a-z][a-z0-9+.\-]*")

GENERIC_FAILURE = (
    "That login and API key did not work together. Check that the login is the email you sign in to Odoo with, "
    "that you copied the whole key, and that the key has not expired. If Odoo asked for a scope when you made "
    "the key, it must be RPC."
)
PORTAL_FAILURE = (
    "This Odoo account can't be used here. Only internal Odoo users (employees) can connect Claude, "
    "not portal or customer accounts."
)
UNREACHABLE = "We couldn't reach Odoo just now. Please wait a minute and try again."
IP_LIMITED = "Too many failed sign-in attempts from your network. Wait 10 minutes and try again."


class LoginPage:
    def __init__(self, provider: OdooAuthProvider, settings: Settings, csrf: CsrfSigner, *, public_url: str):
        self._provider = provider
        self._csrf = csrf
        self._trust_proxy = settings.mcp_trust_proxy_headers
        self._domains = tuple(d.strip().lstrip("@").lower() for d in settings.mcp_allowed_login_domains if d.strip())
        self._logins = frozenset(x.strip().lower() for x in settings.mcp_allowed_logins if x.strip())
        self._read_only = not settings.read_write
        self._odoo_host = urlsplit(settings.odoo_url).netloc
        self._odoo_url = settings.odoo_url.rstrip("/")
        self._secure_cookie = public_url.startswith("https://")
        self._cookie = "__Host-sahajta-oauth" if self._secure_cookie else "sahajta-oauth"
        self._ip_failures = SlidingWindow(MAX_FAILURES_PER_IP, IP_WINDOW_SECONDS)

    async def handle(self, request: Request) -> Response:
        if request.method == "POST":
            return await self._post(request)
        return await self._get(request)

    # ------------------------------------------------------------------ GET

    async def _get(self, request: Request) -> Response:
        request_id = request.query_params.get("request", "")
        pending = await self._pending(request_id)
        if pending is None:
            return _expired_page()
        nonce = request.cookies.get(self._cookie, "")
        new_nonce = not _NONCE.fullmatch(nonce)
        if new_nonce:
            nonce = secrets.token_urlsafe(24)
        response = self._form(pending, request_id, self._csrf.token(request_id, nonce))
        if new_nonce:
            response.set_cookie(
                self._cookie,
                nonce,
                max_age=COOKIE_MAX_AGE,
                path="/",
                secure=self._secure_cookie,
                httponly=True,
                samesite="strict",
            )
        return response

    # ------------------------------------------------------------------ POST

    async def _post(self, request: Request) -> Response:
        form = await request.form()
        request_id = _field(form.get("request"))
        csrf_token = _field(form.get("csrf"))
        login = _field(form.get("login")).strip()
        api_key = _field(form.get("api_key")).strip()

        pending = await self._pending(request_id)
        if pending is None:
            return _expired_page()
        nonce = request.cookies.get(self._cookie, "")
        if not _NONCE.fullmatch(nonce) or not self._csrf.verify(request_id, nonce, csrf_token):
            logger.warning("Sign-in form rejected: CSRF check failed (client %s)", pending.client_id)
            return _message_page(
                "We couldn't verify this sign-in",
                "Make sure cookies are allowed for this site, then go back to Claude and connect again.",
                status_code=403,
            )

        def again(message: str, status_code: int) -> Response:
            return self._form(pending, request_id, csrf_token, login=login, error=message, status_code=status_code)

        ip = client_ip(request, self._trust_proxy)
        if self._ip_failures.exceeded(ip):
            return again(IP_LIMITED, 429)

        problem: str | None = None
        identity: OdooIdentity | None = None
        if len(login) > 254 or not login or _CONTROL.search(login) or not _API_KEY.fullmatch(api_key):
            problem = GENERIC_FAILURE
        elif not self._login_allowed(login):
            problem = self._domain_message()
        else:
            try:
                identity = await self._provider.verify_odoo_identity(login, api_key)
            except OdooError as exc:
                if exc.kind not in ("auth", "access"):
                    logger.warning("Odoo unavailable during sign-in (%s)", exc.kind)
                    return again(UNREACHABLE, 503)
                problem = GENERIC_FAILURE
            except Exception:
                logger.exception("Unexpected error while checking credentials with Odoo")
                return again(UNREACHABLE, 503)
            else:
                if not identity.is_internal_user:
                    problem = PORTAL_FAILURE
                elif not self._login_allowed(identity.login):
                    problem = self._domain_message()

        if problem is not None or identity is None:
            self._ip_failures.add(ip)
            failures = await self._provider.record_failure(pending)
            logger.warning("Failed Odoo sign-in for client %s from %s (attempt %d)", pending.client_id, ip, failures)
            if failures >= MAX_FAILURES_PER_REQUEST:
                await self._provider.discard_pending(pending)
                return _message_page(
                    "Too many failed attempts",
                    "For your security this sign-in was stopped. Go back to Claude and connect again when you "
                    "have the right Odoo login and API key.",
                    status_code=429,
                    link=(self._provider.denial_redirect(pending, "Too many failed sign-in attempts"), "Return to the app"),
                )
            return again(problem or GENERIC_FAILURE, 400)

        redirect = await self._provider.complete_authorization(pending, identity, api_key)
        if redirect is None:
            return _expired_page()
        return RedirectResponse(redirect, status_code=302, headers=_security_headers(None))

    # ------------------------------------------------------------------ helpers

    async def _pending(self, request_id: str) -> PendingAuthorization | None:
        if not _REQUEST_ID.fullmatch(request_id):
            return None
        return await self._provider.get_pending(request_id)

    def _login_allowed(self, login: str) -> bool:
        lowered = login.strip().lower()
        if self._logins and lowered not in self._logins:
            return False
        if not self._domains:
            return True
        return any(lowered.endswith("@" + domain) for domain in self._domains)

    def _domain_message(self) -> str:
        if self._logins or not self._domains:
            return "This Odoo login is not allowed to connect here."
        allowed = " or ".join("@" + domain for domain in self._domains)
        return f"Only Odoo logins ending in {allowed} can connect here."

    def _form(
        self,
        pending: PendingAuthorization,
        request_id: str,
        csrf_token: str,
        *,
        login: str = "",
        error: str | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        e = _escape
        if pending.verified_host:
            who = f'<strong>{e(pending.client_name)}</strong> <span class="badge">verified by {e(pending.verified_host)}</span>'
        else:
            who = f'<strong>{e(pending.client_name)}</strong> <span class="badge">name not verified</span>'
        mode = (
            "This server is currently read-only, so Claude can look things up but can't change anything."
            if self._read_only
            else "When Claude changes something, Odoo records it under your name."
        )
        cancel = self._provider.denial_redirect(pending, "The user cancelled the sign-in")
        error_html = f'<div class="error" role="alert">{e(error)}</div>' if error else ""
        body = f"""
<p class="eyebrow">Sahajta Odoo</p>
<h1>Connect Claude to Sahajta Odoo</h1>
<p>{who} wants to use Odoo as you.</p>
<p class="muted">After you sign in, you'll go back to <strong>{e(_redirect_label(pending.redirect_uri))}</strong>.</p>
<div class="note">
  <p>Claude will act as <strong>you</strong> in Odoo ({e(self._odoo_host)}). It can only see and do what your own
  Odoo account is allowed to, and this server's safety rules apply on top: it can never delete records.</p>
  <p>{e(mode)}</p>
</div>
{error_html}
<form method="post" action="{LOGIN_PATH}">
  <input type="hidden" name="request" value="{e(request_id)}">
  <input type="hidden" name="csrf" value="{e(csrf_token)}">
  <label for="login">Odoo login (email)</label>
  <input id="login" name="login" type="text" value="{e(login)}" required maxlength="254"
         autocomplete="username" inputmode="email" autocapitalize="none" spellcheck="false"{"" if login else " autofocus"}>
  <label for="api_key">Odoo API key</label>
  <input id="api_key" name="api_key" type="password" required maxlength="256" autocomplete="off"{" autofocus" if login else ""}>
  <details open>
    <summary>How do I get an API key?</summary>
    <ol>
      <li><a href="{e(self._odoo_url)}/odoo" target="_blank" rel="noopener noreferrer">Open your Odoo</a>, click
          your profile picture (top right) and open <strong>My Preferences</strong>.</li>
      <li>Open the <strong>Security</strong> tab (<strong>Account Security</strong> in older versions) and click
          <strong>New API Key</strong>.</li>
      <li>Confirm your password and name the key, for example &ldquo;Claude&rdquo;. For how long it lasts, pick the
          longest option Odoo offers you. When the key ends, Claude will ask you to connect again with a new one.
          If Odoo asks for a <strong>scope</strong>, choose <strong>RPC</strong>.</li>
      <li>Copy the key and paste it above. Odoo shows it only once, so keep it in your password manager.</li>
    </ol>
  </details>
  <div class="actions">
    <a class="cancel" href="{e(cancel)}">Cancel</a>
    <button type="submit">Sign in and connect</button>
  </div>
</form>
<footer class="muted">Your API key is stored encrypted on this server, used only for your requests, and never
shown to Claude. To disconnect Claude at any time, delete the key in Odoo under My Preferences &rarr; Security.</footer>
"""
        return HTMLResponse(
            _page("Connect Claude to Sahajta Odoo", body),
            status_code=status_code,
            headers=_security_headers(_csp_origin(pending.redirect_uri)),
        )


def _field(value: object) -> str:
    return value if isinstance(value, str) else ""


def _escape(value: str | None) -> str:
    return html.escape(value or "", quote=True)


def _redirect_label(uri: str) -> str:
    parts = urlsplit(uri)
    if parts.scheme in ("http", "https") and parts.hostname:
        if parts.hostname in LOOPBACK_HOSTS:
            return f"an app on this computer ({parts.netloc})"
        return parts.netloc
    return f"{parts.scheme}: app"


def _csp_origin(uri: str) -> str | None:
    """The CSP source for the redirect target; the form's 302 goes there, so form-action must allow it."""
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if not _SCHEME.fullmatch(scheme):
        return None
    if scheme not in ("http", "https"):
        return f"{scheme}:"
    host = (parts.hostname or "").lower()
    if not re.fullmatch(r"[a-z0-9.\-]+|[0-9a-f:]+", host):
        return None
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}" + (f":{port}" if port else "")


def _security_headers(form_target: str | None) -> dict[str, str]:
    form_action = "'self'" + (f" {form_target}" if form_target else "")
    return {
        "Content-Security-Policy": (
            f"default-src 'none'; style-src 'unsafe-inline'; form-action {form_action}; "
            "frame-ancestors 'none'; base-uri 'none'"
        ),
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "X-Content-Type-Options": "nosniff",
    }


def _expired_page() -> HTMLResponse:
    return _message_page(
        "This sign-in link has expired",
        "Sign-in links work once and only for 10 minutes. Go back to Claude and connect again.",
        status_code=400,
    )


def _message_page(title: str, message: str, *, status_code: int, link: tuple[str, str] | None = None) -> HTMLResponse:
    link_html = f'<p><a href="{_escape(link[0])}">{_escape(link[1])}</a></p>' if link else ""
    body = f"""
<p class="eyebrow">Sahajta Odoo</p>
<h1>{_escape(title)}</h1>
<p>{_escape(message)}</p>
{link_html}
"""
    return HTMLResponse(_page(title, body), status_code=status_code, headers=_security_headers(None))


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<title>{_escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>{body}</main>
</body>
</html>
"""


_CSS = """
:root{--bg:#f4f5f7;--card:#fff;--text:#1d2127;--muted:#5b6470;--border:#dde1e6;--accent:#2f5bd3;--on-accent:#fff;
--note:#f1f5ff;--note-border:#cfdaf7;--err-bg:#fdecec;--err-text:#9b1c1c;--err-border:#f5c2c2}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1e24;--text:#e8eaed;--muted:#a3abb5;--border:#30363e;
--accent:#7aa2ff;--on-accent:#0b1020;--note:#18213a;--note-border:#2c3d6b;--err-bg:#3a1717;--err-text:#ffb4b4;--err-border:#6b2a2a}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);display:flex;justify-content:center;
align-items:flex-start;padding:48px 16px;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{width:100%;max-width:460px;background:var(--card);border:1px solid var(--border);border-radius:14px;
padding:32px 28px;box-shadow:0 1px 2px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.06)}
.eyebrow{margin:0 0 6px;font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h1{margin:0 0 14px;font-size:22px;line-height:1.3}
p{margin:0 0 12px}
a{color:var(--accent)}
.muted{color:var(--muted);font-size:14px}
.badge{display:inline-block;font-size:12px;line-height:18px;padding:0 8px;border:1px solid var(--border);
border-radius:999px;color:var(--muted);white-space:nowrap;vertical-align:1px}
.note{background:var(--note);border:1px solid var(--note-border);border-radius:10px;padding:12px 14px;margin:18px 0 20px;font-size:14px}
.note p:last-child{margin-bottom:0}
.error{background:var(--err-bg);color:var(--err-text);border:1px solid var(--err-border);border-radius:10px;
padding:10px 14px;margin:0 0 16px;font-size:14px}
label{display:block;font-weight:600;font-size:14px;margin:14px 0 6px}
input[type=text],input[type=password]{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--border);
border-radius:8px;background:var(--card);color:var(--text)}
input:focus-visible,button:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
details{margin:14px 0 0;font-size:14px}
summary{cursor:pointer;color:var(--accent)}
ol{margin:8px 0 0;padding-left:20px}
li{margin:4px 0}
.actions{display:flex;gap:12px;align-items:center;justify-content:flex-end;margin-top:24px}
button{font:inherit;font-weight:600;padding:10px 18px;border:0;border-radius:8px;background:var(--accent);
color:var(--on-accent);cursor:pointer}
.cancel{color:var(--muted);text-decoration:none;padding:10px 6px}
.cancel:hover{text-decoration:underline}
footer{margin-top:22px;padding-top:16px;border-top:1px solid var(--border)}
"""
