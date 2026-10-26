"""Exceptions. Every message here is shown to the AI, so each says what to do next."""

from __future__ import annotations


class OdooMCPError(Exception):
    """Base class. str(exc) is safe to show to the user and the AI."""

    # Set by the change tools. outcome: whether anything changed in Odoo (no record data, so it may be
    # audited). found: what Odoo shows now when that is unknown (record data: never audited).
    outcome: str = ""
    found: str = ""

    def __str__(self) -> str:
        text = self.describe()
        if self.outcome:
            text = f"{text.rstrip('. ')}. {self.outcome}"
        return f"{text}\n{self.found}" if self.found else text

    def describe(self) -> str:
        """The error itself, without what it means for a change."""
        return super().__str__()


class PolicyViolation(OdooMCPError):
    """The request is blocked by this server's safety policy."""

    def describe(self) -> str:
        return f"Blocked by safety policy: {super().describe()}"


class ValidationFailed(OdooMCPError):
    """The request is malformed or refers to fields/records that do not exist."""

    def __init__(self, problems: list[str] | str):
        self.problems = [problems] if isinstance(problems, str) else list(problems)
        super().__init__("; ".join(self.problems))

    def describe(self) -> str:
        lines = "\n".join(f"  - {p}" for p in self.problems)
        return f"Request rejected, nothing was changed:\n{lines}"


class ConfirmationRequired(OdooMCPError):
    """A change was attempted without a valid preview token."""


class RateLimited(OdooMCPError):
    pass


class NotSent(OdooMCPError):
    """A change was stopped on this server before it was sent to Odoo."""


class StateUnavailable(OdooMCPError):
    """The shared store (Redis) did not answer where an answer is needed to stay safe."""


# Failures where Odoo refused the request or rolled its transaction back: nothing was applied.
_NOT_APPLIED_KINDS = frozenset({"auth", "access", "user_error", "validation", "missing", "rate_limited", "config"})


class OdooError(OdooMCPError):
    """An error reported by Odoo itself, or while talking to it."""

    def __init__(
        self,
        message: str,
        *,
        kind: str = "odoo_error",
        status: int | None = None,
        odoo_name: str | None = None,
        maybe_applied: bool | None = None,
        retry_after: float | None = None,
    ):
        self.kind = kind
        self.status = status
        self.odoo_name = odoo_name
        self.retry_after = retry_after  # seconds Odoo asked us to wait (Retry-After), if it said
        self._maybe_applied = maybe_applied
        super().__init__(message)

    @property
    def key_rejected(self) -> bool:
        """Odoo itself refused the API key: HTTP 401 on JSON-2, or a failed JSON-RPC login (no status).

        The only Odoo answer that may end a person's sign-in; an AccessDenied for one operation must not.
        """
        return self.kind == "auth" and self.status in (401, None)

    @property
    def maybe_applied(self) -> bool:
        """False only when this failure proves Odoo did not carry the request out.

        Timeouts while waiting for the answer, dropped connections, gateway errors and garbled answers
        all leave open whether Odoo applied it, so a change that failed that way must not be repeated blindly.
        """
        if self._maybe_applied is not None:
            return self._maybe_applied
        return self.kind not in _NOT_APPLIED_KINDS

    def describe(self) -> str:
        prefix = {
            "auth": "Odoo rejected the credentials (the API key may be revoked or expired)",
            "access": "Odoo denied access",
            "user_error": "Odoo refused the operation",
            "validation": "Odoo rejected the values",
            "missing": "Not found in Odoo",
            "network": "Could not reach Odoo",
            "timeout": "Odoo did not answer in time",
            "rate_limited": "Odoo is rate limiting requests; wait a minute and retry",
            "unavailable": "Odoo is temporarily unavailable; try again shortly",
            "server": "Odoo reported an internal error",
            "config": "The connector's server settings are incomplete",
        }.get(self.kind, "Odoo error")
        message = super().describe()
        return f"{prefix}: {message}" if message else prefix
