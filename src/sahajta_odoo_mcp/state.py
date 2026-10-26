"""Small pieces of shared state: single-use markers and rate-limit counters.

In-memory by default (one server process). With Redis configured they are shared by every
instance, which serverless hosting (Vercel) needs: one approval must work exactly once and
rate limits must add up across instances. A single container without Redis keeps its
single-use markers in SQLite, so they survive a restart.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import sqlite3
import threading
import time
import zlib
from collections import defaultdict, deque
from pathlib import Path
from typing import Protocol

import redis

from .errors import StateUnavailable

logger = logging.getLogger(__name__)


class SharedState(Protocol):
    def claim_once(self, key: str, expires_at: int) -> bool:
        """True the first time `key` is claimed (until it expires), False afterwards.

        Raises StateUnavailable when the store does not answer: a change must never run unmarked."""

    def release(self, key: str) -> bool:
        """Undoes a claim (for a change Odoo provably did not apply). False if that could not be done."""

    def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        """Counts one event; True while the count within the window is at most `limit` (or cannot be counted)."""

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

    def release(self, key: str) -> bool:
        self._claims.pop(key, None)
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


class SQLiteState(MemoryState):
    """MemoryState whose single-use markers live in a SQLite file, for one container without Redis.

    An approval whose change may have reached Odoo stays used after a restart, so it can never apply twice.
    Rate limits and caches stay in memory: losing them on a restart is harmless.
    """

    def __init__(self, path: Path | str) -> None:
        super().__init__()
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=5.0)
        self._db.execute("CREATE TABLE IF NOT EXISTS claims (key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)")

    def claim_once(self, key: str, expires_at: int) -> bool:
        try:
            with self._lock:
                self._db.execute("DELETE FROM claims WHERE expires_at < ?", (int(time.time()),))
                cursor = self._db.execute(
                    "INSERT OR IGNORE INTO claims (key, expires_at) VALUES (?, ?)", (_digest(key), expires_at)
                )
                return cursor.rowcount == 1
        except sqlite3.Error as exc:
            logger.warning("local store unavailable while claiming a single-use marker: %s", type(exc).__name__)
            raise StateUnavailable(
                "The server's store did not answer, so this approval could not be recorded. "
                "Nothing was changed, please try again."
            ) from exc

    def release(self, key: str) -> bool:
        try:
            with self._lock:
                self._db.execute("DELETE FROM claims WHERE key = ?", (_digest(key),))
            return True
        except sqlite3.Error as exc:
            logger.warning("local store unavailable while releasing a single-use marker: %s", type(exc).__name__)
            return False

    def close(self) -> None:
        with self._lock:
            self._db.close()


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class RedisState:
    def __init__(self, client: redis.Redis, *, prefix: str = "sahajta-odoo-mcp:"):
        self._r = client
        self._prefix = prefix

    def claim_once(self, key: str, expires_at: int) -> bool:
        name = self._once_name(key)
        mark = secrets.token_hex(8)
        try:
            return bool(self._r.set(name, mark, nx=True, exat=max(expires_at, int(time.time()) + 1)))
        except redis.RedisError as exc:
            # The claim may have been stored even though the answer was lost; undo it (only if it is ours),
            # or the retry this error asks for would be refused as "already used".
            try:
                if self._r.get(name) == mark:
                    self._r.delete(name)
            except redis.RedisError:
                pass
            logger.warning("shared store unavailable while claiming a single-use marker: %s", type(exc).__name__)
            raise StateUnavailable(
                "The server's shared store did not answer, so this approval could not be recorded. "
                "Nothing was changed, please try again."
            ) from exc

    def release(self, key: str) -> bool:
        try:
            self._r.delete(self._once_name(key))
            return True
        except redis.RedisError as exc:
            logger.warning("shared store unavailable while releasing a single-use marker: %s", type(exc).__name__)
            return False

    def hit(self, key: str, limit: int, window_seconds: int) -> bool:
        bucket = int(time.time() // window_seconds)
        name = f"{self._prefix}rate:{hashlib.sha256(key.encode()).hexdigest()}:{bucket}"
        try:
            with self._r.pipeline() as pipe:
                pipe.incr(name)
                pipe.expire(name, window_seconds * 2)
                count, _ = pipe.execute()
        except redis.RedisError as exc:
            # A rate limit protects Odoo from runaway loops; a store hiccup must not block people's work.
            logger.warning("shared store unavailable, rate limit not applied: %s", type(exc).__name__)
            return True
        return int(count) <= limit

    def _once_name(self, key: str) -> str:
        return f"{self._prefix}once:{_digest(key)}"

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
    # Short timeouts: every tool call waits on these, and a whole call must fit in 60 seconds on Vercel.
    return redis.Redis.from_url(
        url, decode_responses=True, socket_timeout=2, socket_connect_timeout=2, health_check_interval=30
    )
