"""Preview tokens: a change can only be applied with a token from a matching, recent preview.

The token is an HMAC over the exact normalised change (who, what model, which ids,
which values or button) plus a fingerprint of the records' last-modified times.
So the AI must look at real current data before changing it, cannot alter the
change after the person saw the preview, and a record edited by someone else in
the meantime invalidates the token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from .errors import ConfirmationRequired
from .state import MemoryState, SharedState

DEFAULT_TTL_SECONDS = 15 * 60


def canonical(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


class ConfirmationSigner:
    def __init__(self, secret: bytes, ttl_seconds: int = DEFAULT_TTL_SECONDS, state: SharedState | None = None):
        if len(secret) < 16:
            raise ValueError("confirmation secret too short")
        self._key = hashlib.sha256(b"sahajta-odoo-mcp/confirm/v1" + secret).digest()
        self._ttl = ttl_seconds
        # Tokens are single-use: one approval = one change (no duplicate creates or repeated e-mails).
        self._state = state or MemoryState()

    def issue(self, payload: dict) -> str:
        expires = int(time.time()) + self._ttl
        return f"{expires}.{self._mac(expires, payload)}"

    def verify(self, token: str | None, payload: dict) -> None:
        if not token or not isinstance(token, str) or "." not in token:
            raise ConfirmationRequired(
                "No valid confirm_token. Call the matching odoo_preview_* tool first, show the preview to the "
                "person, and only after they approve call this tool again with the same arguments and the "
                "confirm_token from the preview."
            )
        expires_text, _, mac = token.partition(".")
        if not (expires_text.isascii() and expires_text.isdigit()) or len(expires_text) > 12:
            raise ConfirmationRequired("confirm_token is malformed; run the preview again.")
        expires = int(expires_text)
        if expires < time.time():
            raise ConfirmationRequired("confirm_token has expired (15 minutes); run the preview again.")
        if not hmac.compare_digest(mac, self._mac(expires, payload)):
            raise ConfirmationRequired(
                "confirm_token does not match this change. Either the arguments differ from the preview, or the "
                "record(s) were modified in Odoo since the preview. Run the preview again and re-confirm with the person."
            )
        if not self._state.claim_once(f"confirm:{token}", expires):
            raise ConfirmationRequired(
                "this confirm_token was already used, so nothing was changed now. Each approved preview applies at "
                "most once. Before running the preview again, check in Odoo whether the earlier attempt went through."
            )

    def release(self, token: str) -> bool:
        """Makes a used token valid again, for a change Odoo provably did not apply. False if that failed."""
        return self._state.release(f"confirm:{token}")

    def _mac(self, expires: int, payload: dict) -> str:
        digest = hmac.new(self._key, str(expires).encode() + b"|" + canonical(payload), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest[:24]).decode().rstrip("=")
