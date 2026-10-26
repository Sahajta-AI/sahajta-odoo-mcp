"""Exceptions. Every message here is shown to the AI, so each says what to do next."""

from __future__ import annotations


class OdooMCPError(Exception):
    """Base class. str(exc) is safe to show to the user and the AI."""


class PolicyViolation(OdooMCPError):
    """The request is blocked by this server's safety policy."""

    def __str__(self) -> str:
        return f"Blocked by safety policy: {super().__str__()}"


class ValidationFailed(OdooMCPError):
    """The request is malformed or refers to fields/records that do not exist."""

    def __init__(self, problems: list[str] | str):
        self.problems = [problems] if isinstance(problems, str) else list(problems)
        super().__init__("; ".join(self.problems))

    def __str__(self) -> str:
        lines = "\n".join(f"  - {p}" for p in self.problems)
        return f"Request rejected, nothing was changed:\n{lines}"


class ConfirmationRequired(OdooMCPError):
    """A change was attempted without a valid preview token."""


class RateLimited(OdooMCPError):
    pass


class OdooError(OdooMCPError):
    """An error reported by Odoo itself, or while talking to it."""

    def __init__(self, message: str, *, kind: str = "odoo_error", status: int | None = None, odoo_name: str | None = None):
        self.kind = kind
        self.status = status
        self.odoo_name = odoo_name
        super().__init__(message)

    def __str__(self) -> str:
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
        message = super().__str__()
        return f"{prefix}: {message}" if message else prefix
