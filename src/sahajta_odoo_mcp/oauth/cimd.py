"""OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).

The client_id is an https URL; the JSON document served there is the client's registration.
To rule out SSRF, a document is only ever fetched from hosts listed in MCP_CIMD_ALLOWED_HOSTS,
without following redirects, with a short deadline and a small size cap.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

import httpx

from .clients import (
    MAX_REDIRECT_URIS,
    SCOPE,
    SUPPORTED_GRANT_TYPES,
    OdooOAuthClient,
    clean_client_name,
    is_redirect_allowed,
)

logger = logging.getLogger(__name__)

MAX_DOCUMENT_BYTES = 64 * 1024
FETCH_TIMEOUT_SECONDS = 5.0
CACHE_TTL_SECONDS = 3600.0
NEGATIVE_CACHE_TTL_SECONDS = 60.0
MAX_CACHE_ENTRIES = 256
MAX_FETCHES_PER_MINUTE = 30

_PATH = re.compile(r"/[A-Za-z0-9._~\-/]*[A-Za-z0-9._~\-]")


class _Rejected(Exception):
    pass


def looks_like_cimd(client_id: str) -> bool:
    return client_id.startswith("https://")


class CIMDResolver:
    def __init__(
        self,
        http: httpx.AsyncClient,
        allowed_hosts: Sequence[str],
        allowed_redirects: Sequence[str],
        clock: Callable[[], float] = time.monotonic,
    ):
        self._http = http
        self._allowed_hosts = frozenset(host.strip().lower() for host in allowed_hosts if host.strip())
        self._allowed_redirects = tuple(allowed_redirects)
        self._clock = clock
        self._cache: OrderedDict[str, tuple[float, OdooOAuthClient | None]] = OrderedDict()
        self._recent_fetches: deque[float] = deque()

    def is_allowed_url(self, url: str) -> bool:
        """https, an allowlisted host (exact, lowercase, default port), a plain path, nothing else."""
        if len(url) > 512 or any(ch in url for ch in "?#@\\%") or url != url.strip():
            return False
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme != "https" or parts.netloc not in self._allowed_hosts:
            return False
        if not _PATH.fullmatch(parts.path):
            return False
        return not any(segment in (".", "..") for segment in parts.path.split("/"))

    async def resolve(self, client_id: str) -> OdooOAuthClient | None:
        if not self.is_allowed_url(client_id):
            return None
        now = self._clock()
        cached = self._cache.get(client_id)
        if cached and cached[0] > now:
            return cached[1]
        if not self._may_fetch(now):
            logger.warning("CIMD fetch budget exhausted; refusing to fetch %s", client_id)
            return None
        try:
            client = self._build(client_id, await asyncio.wait_for(self._fetch(client_id), FETCH_TIMEOUT_SECONDS))
            ttl = CACHE_TTL_SECONDS
        except (_Rejected, httpx.HTTPError, TimeoutError, ValueError) as exc:
            logger.warning("Rejected client metadata document %s: %s", client_id, _describe(exc))
            client, ttl = None, NEGATIVE_CACHE_TTL_SECONDS
        self._cache[client_id] = (now + ttl, client)
        self._cache.move_to_end(client_id)
        while len(self._cache) > MAX_CACHE_ENTRIES:
            self._cache.popitem(last=False)
        return client

    def _may_fetch(self, now: float) -> bool:
        while self._recent_fetches and self._recent_fetches[0] < now - 60:
            self._recent_fetches.popleft()
        if len(self._recent_fetches) >= MAX_FETCHES_PER_MINUTE:
            return False
        self._recent_fetches.append(now)
        return True

    async def _fetch(self, url: str) -> object:
        async with self._http.stream(
            "GET",
            url,
            headers={"Accept": "application/json"},
            timeout=FETCH_TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as response:
            if response.status_code != 200:
                raise _Rejected(f"HTTP {response.status_code}")
            content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type != "application/json" and not content_type.endswith("+json"):
                raise _Rejected("not served as JSON")
            declared = response.headers.get("content-length")
            if declared is not None and (not declared.isdigit() or int(declared) > MAX_DOCUMENT_BYTES):
                raise _Rejected("document too large")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_DOCUMENT_BYTES:
                    raise _Rejected("document too large")
        return json.loads(bytes(body))

    def _build(self, url: str, doc: object) -> OdooOAuthClient:
        if not isinstance(doc, dict):
            raise _Rejected("document is not a JSON object")
        if doc.get("client_id") != url:
            raise _Rejected("client_id in the document does not equal its URL")
        if "client_secret" in doc or "client_secret_expires_at" in doc:
            raise _Rejected("document must not contain a client secret")
        if doc.get("token_endpoint_auth_method", "none") != "none":
            raise _Rejected("only public clients (token_endpoint_auth_method 'none') are supported")

        raw_uris = doc.get("redirect_uris")
        if not isinstance(raw_uris, list) or not raw_uris or len(raw_uris) > MAX_REDIRECT_URIS:
            raise _Rejected("redirect_uris missing or invalid")
        redirect_uris = []
        for uri in raw_uris:
            if isinstance(uri, str) and is_redirect_allowed(uri, self._allowed_redirects):
                redirect_uris.append(uri)
            else:
                logger.warning("Ignoring redirect URI %r from %s: not in MCP_ALLOWED_REDIRECT_URIS", uri, url)
        if not redirect_uris:
            raise _Rejected("none of its redirect_uris are allowed by MCP_ALLOWED_REDIRECT_URIS")

        grant_types = doc.get("grant_types", list(SUPPORTED_GRANT_TYPES))
        if not isinstance(grant_types, list) or "authorization_code" not in grant_types:
            raise _Rejected("grant_types must include authorization_code")
        response_types = doc.get("response_types", ["code"])
        if not isinstance(response_types, list) or "code" not in response_types:
            raise _Rejected("response_types must include code")

        return OdooOAuthClient.build(
            {
                "client_id": url,
                "client_name": clean_client_name(doc.get("client_name")),
                "redirect_uris": redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": [g for g in SUPPORTED_GRANT_TYPES if g in grant_types],
                "response_types": ["code"],
                "scope": SCOPE,
            },
            allowed_redirects=self._allowed_redirects,
            verified_host=urlsplit(url).netloc,
        )


def _describe(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return "timed out"
    if isinstance(exc, httpx.HTTPError):
        return type(exc).__name__
    if isinstance(exc, ValueError) and not isinstance(exc, _Rejected):
        return "invalid JSON or metadata"
    return str(exc)
