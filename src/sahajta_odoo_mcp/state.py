"""Small pieces of shared state: single-use markers and rate-limit counters.

In-memory by default (one server process). With Redis configured they are shared by every
instance, which serverless hosting (Vercel) needs: one approval must work exactly once and
rate limits must add up across instances.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import zlib
from collections import defaultdict, deque
from typing import Protocol

import redis


class SharedState(Protocol):
    def claim_once(self, key: str, expires_at: int) -> bool:
        """True the first time `key` is claimed (until it expires), False afterwards."""

    def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        """Counts one event; True while the count within the window is at most `limit`."""

    def get_json(self, key: str):
        """A cached JSON value, or None."""

    def set_json(self, key: str, value, ttl_seconds: int) -> None:
        """Caches a JSON value for `ttl_seconds`."""


class MemoryState:
    def __init__(self) -> None:
        self._claims: dict[str, int] = {}
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._cache: dict[str, tuple[float, object]] = {}

    def get_json(self, key: str):
        hit = self._cache.get(key)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        self._cache.pop(key, None)
        return None

    def set_json(self, key: str, value, ttl_seconds: int) -> None:
        if len(self._cache) > 2000:
            self._cache.clear()
        self._cache[key] = (time.monotonic() + ttl_seconds, value)

    def claim_once(self, key: str, expires_at: int) -> bool:
        now = int(time.time())
        for claimed, expiry in list(self._claims.items()):
            if expiry < now:
                del self._claims[claimed]
        if key in self._claims:
            return False
        self._claims[key] = expires_at
        return True

    def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        window = self._hits[key]
        while window and window[0] < now - window_seconds:
            window.popleft()
        if len(window) >= limit:
            return False
        window.append(now)
        return True


class RedisState:
    def __init__(self, client: redis.Redis, *, prefix: str = "sahajta-odoo-mcp:"):
        self._r = client
        self._prefix = prefix

    def claim_once(self, key: str, expires_at: int) -> bool:
        digest = hashlib.sha256(key.encode()).hexdigest()
        return bool(self._r.set(f"{self._prefix}once:{digest}", "1", nx=True, exat=max(expires_at, int(time.time()) + 1)))

    def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        bucket = int(time.time() // window_seconds)
        name = f"{self._prefix}rate:{hashlib.sha256(key.encode()).hexdigest()}:{bucket}"
        with self._r.pipeline() as pipe:
            pipe.incr(name)
            pipe.expire(name, window_seconds * 2)
            count, _ = pipe.execute()
        return int(count) <= limit

    def get_json(self, key: str):
        try:
            raw = self._r.get(self._cache_name(key))
            return json.loads(zlib.decompress(base64.b64decode(raw))) if raw else None
        except (redis.RedisError, ValueError, zlib.error):
            return None  # a cache problem must never break a request

    def set_json(self, key: str, value, ttl_seconds: int) -> None:
        try:
            blob = base64.b64encode(zlib.compress(json.dumps(value, separators=(",", ":")).encode(), 6)).decode()
            if len(blob) <= _MAX_CACHED_BYTES:
                self._r.set(self._cache_name(key), blob, ex=ttl_seconds)
        except (redis.RedisError, TypeError, ValueError):
            pass

    def _cache_name(self, key: str) -> str:
        return f"{self._prefix}cache:{hashlib.sha256(key.encode()).hexdigest()}"


_MAX_CACHED_BYTES = 800_000  # stay well under Upstash's per-request size limit


def redis_client(url: str) -> redis.Redis:
    return redis.Redis.from_url(url, decode_responses=True, socket_timeout=5, health_check_interval=30)
