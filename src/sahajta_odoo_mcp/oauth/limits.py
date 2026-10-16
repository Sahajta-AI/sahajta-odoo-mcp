"""In-memory sliding-window counters for abuse limits, and client-IP detection."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable

from starlette.requests import Request


class SlidingWindow:
    """Counts events per key over a trailing window. Memory is bounded by `max_keys`."""

    def __init__(
        self, limit: int, window_seconds: float, *, max_keys: int = 10_000, clock: Callable[[], float] = time.monotonic
    ):
        self.limit = limit
        self.window = window_seconds
        self._max_keys = max_keys
        self._clock = clock
        self._events: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _current(self, key: str, now: float) -> deque[float]:
        events = self._events.get(key)
        if events is None:
            events = self._events[key] = deque()
        while events and events[0] <= now - self.window:
            events.popleft()
        self._events.move_to_end(key)
        while len(self._events) > self._max_keys:
            self._events.popitem(last=False)
        return events

    def exceeded(self, key: str) -> bool:
        with self._lock:
            return len(self._current(key, self._clock())) >= self.limit

    def add(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            self._current(key, now).append(now)

    def allow(self, key: str) -> bool:
        """Counts one event if the key is under its limit; returns False (counting nothing) otherwise."""
        with self._lock:
            now = self._clock()
            events = self._current(key, now)
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


def client_ip(request: Request, trust_proxy_headers: bool) -> str:
    """The caller's IP. With MCP_TRUST_PROXY_HEADERS, the right-most X-Forwarded-For entry
    (the one appended by our own reverse proxy; entries to its left are client-supplied)."""
    if trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
        if hops:
            return hops[-1][:64]
    return request.client.host if request.client else "unknown"
