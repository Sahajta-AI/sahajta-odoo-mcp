"""OAuth client records and redirect-URI rules.

Two kinds of clients exist:
  * CIMD clients: client_id is an https URL on a trusted host (claude.ai, claude.com); the
    metadata document at that URL is the registration (see cimd.py).
  * DCR clients: registered through POST /register and stored in SQLite.

Every redirect URI, for either kind, must also match MCP_ALLOWED_REDIRECT_URIS. That is checked
at registration/fetch time and again at every authorization request, so tightening the
allowlist takes effect for clients that registered earlier.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from urllib.parse import SplitResult, urlsplit, urlunsplit

from pydantic import AnyUrl, PrivateAttr

from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull

SCOPE = "odoo"
SUPPORTED_GRANT_TYPES = ("authorization_code", "refresh_token")
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
MAX_REDIRECT_URIS = 10
MAX_CLIENT_NAME = 100

# "scheme://host:*" optionally followed by an exact path: any port; any path when no path is given.
_WILDCARD_PATTERN = re.compile(r"(https?)://(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.\-]+):\*(/[^?#\s]*)?")
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")


def _split(uri: str) -> SplitResult | None:
    """Parse a redirect URI, refusing anything ambiguous (fragments, userinfo, bad ports, whitespace)."""
    if not uri or len(uri) > 2048 or _CONTROL_OR_SPACE.search(uri) or "#" in uri or "\\" in uri:
        return None
    try:
        parts = urlsplit(uri)
        _ = parts.port  # raises ValueError for a malformed port
    except ValueError:
        return None
    if not parts.scheme or parts.username is not None or parts.password is not None:
        return None
    if parts.scheme.lower() in ("http", "https") and not parts.hostname:
        return None
    return parts


def _normalise(parts: SplitResult) -> str:
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def is_loopback_uri(uri: str) -> bool:
    parts = _split(uri)
    return bool(parts and parts.scheme.lower() == "http" and parts.hostname in LOOPBACK_HOSTS)


def is_redirect_allowed(uri: str, patterns: Iterable[str]) -> bool:
    """True when `uri` matches one of the admin's MCP_ALLOWED_REDIRECT_URIS patterns.

    A pattern is either an exact URI, or "scheme://host:*[/path]" meaning any port (or none)
    on that host, with any path unless a path is given.
    """
    parts = _split(uri)
    if parts is None:
        return False
    for raw in patterns:
        pattern = raw.strip()
        if not pattern:
            continue
        wildcard = _WILDCARD_PATTERN.fullmatch(pattern)
        if wildcard:
            scheme, host, path = wildcard.group(1).lower(), wildcard.group(2).lower().strip("[]"), wildcard.group(3)
            if parts.scheme.lower() == scheme and parts.hostname == host and (path is None or parts.path == path):
                return True
            continue
        pattern_parts = _split(pattern)
        if pattern_parts is not None and _normalise(pattern_parts) == _normalise(parts):
            return True
    return False


def redirect_uri_matches(registered: str, requested: str) -> bool:
    """Exact match, except that the port of a loopback redirect is ignored (RFC 8252 section 7.3).

    Native apps such as Claude Code register http://localhost/callback and then listen on a
    random port. Only http loopback hosts get this treatment, and scheme, host, path and query
    must still match exactly.
    """
    reg, req = _split(registered), _split(requested)
    if reg is None or req is None:
        return False
    if _normalise(reg) == _normalise(req):
        return True
    return (
        reg.scheme.lower() == "http"
        and req.scheme.lower() == "http"
        and reg.hostname in LOOPBACK_HOSTS
        and reg.hostname == req.hostname
        and (reg.path or "/") == (req.path or "/")
        and reg.query == req.query
    )


def clean_client_name(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    name = " ".join(_CONTROL_OR_SPACE.sub(" ", name).split())
    return name[:MAX_CLIENT_NAME] or None


class OdooOAuthClient(OAuthClientInformationFull):
    """A client record with RFC 8252 loopback matching, the redirect allowlist, and one fixed scope."""

    _allowed_redirects: tuple[str, ...] = PrivateAttr(default=())
    # Host that vouched for this client's metadata (CIMD), or None for self-registered (DCR) clients.
    _verified_host: str | None = PrivateAttr(default=None)

    @classmethod
    def build(
        cls, data: dict, *, allowed_redirects: Sequence[str], verified_host: str | None = None
    ) -> OdooOAuthClient:
        client = cls.model_validate(data)
        client._allowed_redirects = tuple(allowed_redirects)
        client._verified_host = verified_host
        return client

    @property
    def verified_host(self) -> str | None:
        return self._verified_host

    @property
    def display_name(self) -> str:
        return clean_client_name(self.client_name) or "An application"

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        registered = [str(uri) for uri in self.redirect_uris or []]
        if redirect_uri is None:
            if len(registered) != 1:
                raise InvalidRedirectUriError(
                    "redirect_uri must be specified unless the client has exactly one registered URI"
                )
            chosen = self.redirect_uris[0]  # type: ignore[index]
        else:
            if not any(redirect_uri_matches(uri, str(redirect_uri)) for uri in registered):
                raise InvalidRedirectUriError("redirect_uri is not registered for this client")
            chosen = redirect_uri
        if not is_redirect_allowed(str(chosen), self._allowed_redirects):
            raise InvalidRedirectUriError("redirect_uri is not allowed by this server")
        return chosen

    def validate_scope(self, requested_scope: str | None) -> list[str] | None:
        # There is exactly one scope. Unknown requested scopes are ignored rather than refused
        # (RFC 6749 section 3.3 lets the server narrow the request); the token response says what was granted.
        return [SCOPE]
