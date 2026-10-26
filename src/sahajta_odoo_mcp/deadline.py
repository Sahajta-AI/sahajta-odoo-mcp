"""The time budget of the current tool call.

Vercel stops a request after 60 s. tools.run marks when each tool call starts; Odoo calls stop retrying and
shorten their timeouts as the call nears SOFT_LIMIT, and a change is not sent after its send-by time.
Outside a tool call (sign-in, tests of the client alone) nothing here applies.
"""

from __future__ import annotations

import time
from contextvars import ContextVar

SOFT_LIMIT = 50.0  # seconds after the call started; leaves room to answer before the platform's 60 s

# When the current tool call began (set by tools.run), so the budget also counts the sign-in lookup a cold
# server instance does before the service exists.
CALL_STARTED: ContextVar[float | None] = ContextVar("call_started", default=None)
# Latest time.monotonic() at which the change being sent may still leave this server (set by the service).
SEND_BY: ContextVar[float | None] = ContextVar("send_by", default=None)


def seconds_left() -> float | None:
    """Seconds until the soft limit of the current tool call (negative once past it); None outside a tool call."""
    started = CALL_STARTED.get()
    return None if started is None else SOFT_LIMIT - (time.monotonic() - started)


def send_by_passed() -> bool:
    """True when a change is being sent and its send-by time has passed."""
    send_by = SEND_BY.get()
    return send_by is not None and time.monotonic() > send_by
