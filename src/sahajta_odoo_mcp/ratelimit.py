"""Per-user rate limits, so a runaway AI loop cannot hammer Odoo."""

from __future__ import annotations

from .errors import RateLimited
from .state import MemoryState, SharedState


class RateLimiter:
    def __init__(self, reads_per_minute: int, writes_per_minute: int, state: SharedState | None = None):
        self._limits = {"read": reads_per_minute, "write": writes_per_minute}
        self._state = state or MemoryState()

    def check(self, user_key: str, kind: str) -> None:
        limit = self._limits[kind]
        if not self._state.hit(f"{kind}:{user_key}", limit, 60):
            raise RateLimited(
                f"Too many {kind} requests ({limit} per minute). Pause, summarise progress for the person, "
                "and continue in a minute."
            )
