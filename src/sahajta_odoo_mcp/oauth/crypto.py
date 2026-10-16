"""Key derivation, encryption at rest, and token hashing.

All keys are derived from MCP_SECRET with HKDF-SHA256, one key per purpose, so the
secret itself is never used directly as a key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CREDENTIALS_INFO = b"sahajta-odoo-mcp/credentials/v1"
CSRF_INFO = b"sahajta-odoo-mcp/csrf/v1"

MIN_SECRET_LENGTH = 32


class DecryptionError(Exception):
    """Ciphertext could not be decrypted or is bound to a different record. Carries no details."""


def derive_key(secret: str, info: bytes) -> bytes:
    if len(secret) < MIN_SECRET_LENGTH:
        raise ValueError(f"MCP_SECRET must be at least {MIN_SECRET_LENGTH} characters")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret.encode("utf-8"))


class Sealer:
    """Fernet encryption where each ciphertext is bound to a context string (e.g. "grant:<id>").

    Fernet has no associated data, so the context is stored inside the encrypted payload and
    checked on decryption: a ciphertext copied from one row to another will not decrypt.
    """

    def __init__(self, secret: str):
        self._fernet = Fernet(base64.urlsafe_b64encode(derive_key(secret, CREDENTIALS_INFO)))

    def seal(self, context: str, value: str) -> bytes:
        payload = json.dumps({"c": context, "v": value}, separators=(",", ":")).encode("utf-8")
        return self._fernet.encrypt(payload)

    def open(self, context: str, token: bytes) -> str:
        try:
            data = json.loads(self._fernet.decrypt(token))
        except (InvalidToken, ValueError, TypeError):
            raise DecryptionError() from None
        if not isinstance(data, dict) or data.get("c") != context or not isinstance(data.get("v"), str):
            raise DecryptionError()
        return data["v"]


def new_token() -> str:
    """An opaque bearer secret with 256 bits of entropy."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class CsrfSigner:
    """CSRF tokens bound to a pending authorization AND to the browser (via a cookie nonce)."""

    def __init__(self, secret: str):
        self._key = derive_key(secret, CSRF_INFO)

    def token(self, request_id: str, browser_nonce: str) -> str:
        message = f"{request_id}\x00{browser_nonce}".encode("utf-8")
        return b64url(hmac.new(self._key, message, hashlib.sha256).digest())

    def verify(self, request_id: str, browser_nonce: str, candidate: str) -> bool:
        expected = self.token(request_id, browser_nonce)
        return hmac.compare_digest(expected.encode("ascii"), candidate.encode("utf-8", "replace"))
