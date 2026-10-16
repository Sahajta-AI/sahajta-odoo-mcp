"""SQLite persistence for the authorization server.

Synchronous and guarded by one lock; async callers wrap calls in asyncio.to_thread. Every
secret is stored either hashed (codes, tokens, pending-request ids) or encrypted (Odoo API
keys, client secrets); this module never sees a plaintext secret.

Multi-step state changes (consuming a code, rotating a refresh token) run inside one
BEGIN IMMEDIATE transaction with a conditional UPDATE, so they are safe even with several
server processes sharing the file.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
UNUSED_CLIENT_RETENTION_SECONDS = 30 * 24 * 3600
REVOKED_GRANT_RETENTION_SECONDS = 90 * 24 * 3600
# A new grant has no tokens until its code is exchanged; don't treat it as dead before then.
GRANT_GRACE_SECONDS = 15 * 60

_SCHEMA = """
CREATE TABLE clients (
    client_id   TEXT PRIMARY KEY,
    metadata    TEXT NOT NULL,          -- JSON client record without the secret
    secret_enc  BLOB,                   -- encrypted client secret, NULL for public clients
    created_at  REAL NOT NULL
);
CREATE TABLE pending_authorizations (
    id_hash                TEXT PRIMARY KEY,
    client_id              TEXT NOT NULL,
    client_name            TEXT NOT NULL,
    verified_host          TEXT,
    redirect_uri           TEXT NOT NULL,
    redirect_uri_explicit  INTEGER NOT NULL,
    state                  TEXT,
    scopes                 TEXT NOT NULL,
    code_challenge         TEXT NOT NULL,
    resource               TEXT NOT NULL,
    failures               INTEGER NOT NULL DEFAULT 0,
    created_at             REAL NOT NULL,
    expires_at             REAL NOT NULL
);
CREATE TABLE grants (
    grant_id        TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    client_name     TEXT NOT NULL,
    odoo_uid        INTEGER NOT NULL,
    login           TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    odoo_url        TEXT NOT NULL,
    odoo_db         TEXT,
    api_key_enc     BLOB,               -- wiped (NULL) when the grant is revoked
    scopes          TEXT NOT NULL,
    resource        TEXT NOT NULL,
    created_at      REAL NOT NULL,
    last_used_at    REAL,
    revoked_at      REAL,
    revoked_reason  TEXT
);
CREATE INDEX grants_login ON grants (login);
CREATE TABLE auth_codes (
    code_hash              TEXT PRIMARY KEY,
    grant_id               TEXT NOT NULL REFERENCES grants (grant_id) ON DELETE CASCADE,
    redirect_uri           TEXT NOT NULL,
    redirect_uri_explicit  INTEGER NOT NULL,
    code_challenge         TEXT NOT NULL,
    expires_at             REAL NOT NULL,
    used_at                REAL
);
CREATE INDEX auth_codes_grant ON auth_codes (grant_id);
CREATE TABLE tokens (
    token_hash  TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    grant_id    TEXT NOT NULL REFERENCES grants (grant_id) ON DELETE CASCADE,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    rotated_at  REAL                    -- refresh tokens: set once exchanged, reuse means replay
);
CREATE INDEX tokens_grant ON tokens (grant_id);
"""

_ACTIVE = "g.revoked_at IS NULL AND g.api_key_enc IS NOT NULL"


@dataclass(frozen=True)
class PendingAuthorization:
    id_hash: str
    client_id: str
    client_name: str
    verified_host: str | None
    redirect_uri: str
    redirect_uri_explicit: bool
    state: str | None
    scopes: str
    code_challenge: str
    resource: str
    failures: int
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class Grant:
    grant_id: str
    client_id: str
    client_name: str
    odoo_uid: int
    login: str
    display_name: str
    odoo_url: str
    odoo_db: str | None
    api_key_enc: bytes | None
    scopes: str
    resource: str
    created_at: float
    last_used_at: float | None
    revoked_at: float | None
    revoked_reason: str | None

    @property
    def active(self) -> bool:
        return self.revoked_at is None and self.api_key_enc is not None


@dataclass(frozen=True)
class StoredCode:
    code_hash: str
    redirect_uri: str
    redirect_uri_explicit: bool
    code_challenge: str
    expires_at: float
    used_at: float | None
    grant: Grant


@dataclass(frozen=True)
class StoredToken:
    token_hash: str
    kind: str
    expires_at: float
    rotated_at: float | None
    grant: Grant


@dataclass(frozen=True)
class NewTokens:
    access_hash: str
    access_expires_at: float
    refresh_hash: str
    refresh_expires_at: float


class ExchangeResult(Enum):
    OK = "ok"
    REPLAYED = "replayed"  # the code / refresh token was already used: the grant has been revoked
    INVALID = "invalid"  # unknown, expired, or its grant is no longer active


class OAuthStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        _prepare_file(self.path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None, timeout=5.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            # Overwrite deleted content, so wiped API-key ciphertexts don't linger in free pages.
            self._conn.execute("PRAGMA secure_delete=ON")
            self._migrate()
        _tighten_sidecar_files(self.path)

    # ------------------------------------------------------------------ plumbing

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def _one(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, args).fetchone()

    def _migrate(self) -> None:
        with self._tx() as conn:  # inside the write lock, so concurrent first starts don't race
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"{self.path} was created by a newer version of this server (schema {version}); refusing to use it"
                )
            if version == 0:
                for statement in _SCHEMA.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # ------------------------------------------------------------------ clients

    def insert_client(self, client_id: str, metadata_json: str, secret_enc: bytes | None, now: float) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO clients (client_id, metadata, secret_enc, created_at) VALUES (?, ?, ?, ?)",
                (client_id, metadata_json, secret_enc, now),
            )

    def get_client(self, client_id: str) -> tuple[str, bytes | None] | None:
        row = self._one("SELECT metadata, secret_enc FROM clients WHERE client_id = ?", (client_id,))
        return (row["metadata"], row["secret_enc"]) if row else None

    def count_clients(self) -> int:
        return self._one("SELECT COUNT(*) FROM clients")[0]  # type: ignore[index]

    # ------------------------------------------------------------------ pending authorizations

    def insert_pending(self, pending: PendingAuthorization) -> None:
        with self._tx() as conn:
            conn.execute(
                """INSERT INTO pending_authorizations (id_hash, client_id, client_name, verified_host, redirect_uri,
                       redirect_uri_explicit, state, scopes, code_challenge, resource, failures, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    pending.id_hash,
                    pending.client_id,
                    pending.client_name,
                    pending.verified_host,
                    pending.redirect_uri,
                    int(pending.redirect_uri_explicit),
                    pending.state,
                    pending.scopes,
                    pending.code_challenge,
                    pending.resource,
                    pending.failures,
                    pending.created_at,
                    pending.expires_at,
                ),
            )

    def get_pending(self, id_hash: str, now: float) -> PendingAuthorization | None:
        row = self._one(
            "SELECT * FROM pending_authorizations WHERE id_hash = ? AND expires_at > ?",
            (id_hash, now),
        )
        if row is None:
            return None
        return PendingAuthorization(
            id_hash=row["id_hash"],
            client_id=row["client_id"],
            client_name=row["client_name"],
            verified_host=row["verified_host"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_explicit=bool(row["redirect_uri_explicit"]),
            state=row["state"],
            scopes=row["scopes"],
            code_challenge=row["code_challenge"],
            resource=row["resource"],
            failures=row["failures"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def count_pending(self, now: float) -> int:
        return self._one("SELECT COUNT(*) FROM pending_authorizations WHERE expires_at > ?", (now,))[0]  # type: ignore[index]

    def record_pending_failure(self, id_hash: str) -> int:
        """Adds one failed sign-in attempt; returns the new count (0 if the request is gone)."""
        with self._tx() as conn:
            conn.execute("UPDATE pending_authorizations SET failures = failures + 1 WHERE id_hash = ?", (id_hash,))
            row = conn.execute("SELECT failures FROM pending_authorizations WHERE id_hash = ?", (id_hash,)).fetchone()
        return row["failures"] if row else 0

    def delete_pending(self, id_hash: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM pending_authorizations WHERE id_hash = ?", (id_hash,))

    # ------------------------------------------------------------------ grants and codes

    def create_grant_with_code(
        self,
        *,
        pending_id_hash: str,
        grant: Grant,
        code_hash: str,
        code_expires_at: float,
    ) -> bool:
        """Turns a pending authorization into a grant plus an authorization code, atomically.

        Returns False (and writes nothing) if the pending authorization was already consumed,
        e.g. by a double-submitted form.
        """
        with self._tx() as conn:
            pending = conn.execute(
                "SELECT redirect_uri, redirect_uri_explicit, code_challenge FROM pending_authorizations "
                "WHERE id_hash = ?",
                (pending_id_hash,),
            ).fetchone()
            if pending is None:
                return False
            conn.execute("DELETE FROM pending_authorizations WHERE id_hash = ?", (pending_id_hash,))
            conn.execute(
                """INSERT INTO grants (grant_id, client_id, client_name, odoo_uid, login, display_name, odoo_url,
                       odoo_db, api_key_enc, scopes, resource, created_at, last_used_at, revoked_at, revoked_reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    grant.grant_id,
                    grant.client_id,
                    grant.client_name,
                    grant.odoo_uid,
                    grant.login,
                    grant.display_name,
                    grant.odoo_url,
                    grant.odoo_db,
                    grant.api_key_enc,
                    grant.scopes,
                    grant.resource,
                    grant.created_at,
                    grant.created_at,
                ),
            )
            conn.execute(
                """INSERT INTO auth_codes (code_hash, grant_id, redirect_uri, redirect_uri_explicit, code_challenge,
                       expires_at, used_at) VALUES (?, ?, ?, ?, ?, ?, NULL)""",
                (
                    code_hash,
                    grant.grant_id,
                    pending["redirect_uri"],
                    pending["redirect_uri_explicit"],
                    pending["code_challenge"],
                    code_expires_at,
                ),
            )
        return True

    def get_grant(self, grant_id: str) -> Grant | None:
        row = self._one("SELECT * FROM grants WHERE grant_id = ?", (grant_id,))
        return _grant(row) if row else None

    def get_code(self, code_hash: str) -> StoredCode | None:
        row = self._one(
            "SELECT c.code_hash AS c_code_hash, c.redirect_uri AS c_redirect_uri, "
            "c.redirect_uri_explicit AS c_redirect_uri_explicit, c.code_challenge AS c_code_challenge, "
            "c.expires_at AS c_expires_at, c.used_at AS c_used_at, g.* "
            "FROM auth_codes c JOIN grants g ON g.grant_id = c.grant_id WHERE c.code_hash = ?",
            (code_hash,),
        )
        if row is None:
            return None
        return StoredCode(
            code_hash=row["c_code_hash"],
            redirect_uri=row["c_redirect_uri"],
            redirect_uri_explicit=bool(row["c_redirect_uri_explicit"]),
            code_challenge=row["c_code_challenge"],
            expires_at=row["c_expires_at"],
            used_at=row["c_used_at"],
            grant=_grant(row),
        )

    def consume_code(self, code_hash: str, now: float, tokens: NewTokens) -> ExchangeResult:
        """Marks the code used and issues the first token pair. Reusing a code revokes its grant."""
        with self._tx() as conn:
            row = conn.execute(
                f"SELECT c.grant_id, c.used_at, c.expires_at, ({_ACTIVE}) AS active FROM auth_codes c "
                "JOIN grants g ON g.grant_id = c.grant_id WHERE c.code_hash = ?",
                (code_hash,),
            ).fetchone()
            if row is None or not row["active"]:
                return ExchangeResult.INVALID
            if row["used_at"] is not None:
                # RFC 6749 section 4.1.2: a code used twice revokes what it issued.
                _revoke(conn, row["grant_id"], "authorization code reused", now)
                return ExchangeResult.REPLAYED
            if row["expires_at"] <= now:
                return ExchangeResult.INVALID
            conn.execute("UPDATE auth_codes SET used_at = ? WHERE code_hash = ?", (now, code_hash))
            _insert_tokens(conn, row["grant_id"], now, tokens)
        return ExchangeResult.OK

    # ------------------------------------------------------------------ tokens

    def get_token(self, token_hash: str, kind: str) -> StoredToken | None:
        row = self._one(
            "SELECT t.token_hash AS t_token_hash, t.kind AS t_kind, t.expires_at AS t_expires_at, "
            "t.rotated_at AS t_rotated_at, g.* FROM tokens t JOIN grants g ON g.grant_id = t.grant_id "
            "WHERE t.token_hash = ? AND t.kind = ?",
            (token_hash, kind),
        )
        if row is None:
            return None
        return StoredToken(
            token_hash=row["t_token_hash"],
            kind=row["t_kind"],
            expires_at=row["t_expires_at"],
            rotated_at=row["t_rotated_at"],
            grant=_grant(row),
        )

    def rotate_refresh_token(self, old_hash: str, now: float, tokens: NewTokens) -> ExchangeResult:
        """Retires a refresh token and issues a new pair. Presenting a retired token revokes the grant."""
        with self._tx() as conn:
            row = conn.execute(
                f"SELECT t.grant_id, t.rotated_at, t.expires_at, ({_ACTIVE}) AS active FROM tokens t "
                "JOIN grants g ON g.grant_id = t.grant_id WHERE t.token_hash = ? AND t.kind = 'refresh'",
                (old_hash,),
            ).fetchone()
            if row is None or not row["active"]:
                return ExchangeResult.INVALID
            if row["rotated_at"] is not None:
                _revoke(conn, row["grant_id"], "refresh token reused", now)
                return ExchangeResult.REPLAYED
            if row["expires_at"] <= now:
                return ExchangeResult.INVALID
            conn.execute("UPDATE tokens SET rotated_at = ? WHERE token_hash = ?", (now, old_hash))
            _insert_tokens(conn, row["grant_id"], now, tokens)
        return ExchangeResult.OK

    def touch_grant(self, grant_id: str, now: float) -> None:
        with self._tx() as conn:
            conn.execute("UPDATE grants SET last_used_at = ? WHERE grant_id = ?", (now, grant_id))

    # ------------------------------------------------------------------ revocation

    def revoke_grant(self, grant_id: str, reason: str, now: float) -> bool:
        with self._tx() as conn:
            return _revoke(conn, grant_id, reason, now)

    def revoke_grants_for_login(self, login: str, reason: str, now: float) -> int:
        with self._tx() as conn:
            ids = [
                r["grant_id"]
                for r in conn.execute(
                    "SELECT grant_id FROM grants WHERE lower(login) = lower(?) AND revoked_at IS NULL", (login,)
                )
            ]
            return sum(_revoke(conn, grant_id, reason, now) for grant_id in ids)

    def revoke_all(self, reason: str, now: float) -> int:
        with self._tx() as conn:
            ids = [r["grant_id"] for r in conn.execute("SELECT grant_id FROM grants WHERE revoked_at IS NULL")]
            return sum(_revoke(conn, grant_id, reason, now) for grant_id in ids)

    def list_grants(self, *, include_inactive: bool = False) -> list[Grant]:
        sql = "SELECT * FROM grants"
        if not include_inactive:
            sql += " g WHERE " + _ACTIVE
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY created_at").fetchall()
        return [_grant(row) for row in rows]

    # ------------------------------------------------------------------ housekeeping

    def purge(self, now: float) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM pending_authorizations WHERE expires_at <= ?", (now,))
            conn.execute("DELETE FROM auth_codes WHERE expires_at <= ?", (now,))
            conn.execute("DELETE FROM tokens WHERE expires_at <= ?", (now,))
            # A grant whose every token has expired can never be used again: wipe its key.
            dead = [
                r["grant_id"]
                for r in conn.execute(
                    "SELECT grant_id FROM grants g WHERE revoked_at IS NULL AND created_at <= ? "
                    "AND NOT EXISTS (SELECT 1 FROM tokens t WHERE t.grant_id = g.grant_id AND t.rotated_at IS NULL) "
                    "AND NOT EXISTS (SELECT 1 FROM auth_codes c WHERE c.grant_id = g.grant_id AND c.used_at IS NULL)",
                    (now - GRANT_GRACE_SECONDS,),
                )
            ]
            for grant_id in dead:
                _revoke(conn, grant_id, "expired", now)
            conn.execute("DELETE FROM grants WHERE revoked_at <= ?", (now - REVOKED_GRANT_RETENTION_SECONDS,))
            conn.execute(
                "DELETE FROM clients WHERE created_at <= ? "
                "AND NOT EXISTS (SELECT 1 FROM grants g WHERE g.client_id = clients.client_id)",
                (now - UNUSED_CLIENT_RETENTION_SECONDS,),
            )


def _revoke(conn: sqlite3.Connection, grant_id: str, reason: str, now: float) -> bool:
    cursor = conn.execute(
        "UPDATE grants SET revoked_at = ?, revoked_reason = ?, api_key_enc = NULL "
        "WHERE grant_id = ? AND revoked_at IS NULL",
        (now, reason, grant_id),
    )
    conn.execute("DELETE FROM tokens WHERE grant_id = ?", (grant_id,))
    conn.execute("DELETE FROM auth_codes WHERE grant_id = ?", (grant_id,))
    if cursor.rowcount:
        logger.info("Revoked grant %s (%s)", grant_id, reason)
    return cursor.rowcount > 0


def _insert_tokens(conn: sqlite3.Connection, grant_id: str, now: float, tokens: NewTokens) -> None:
    conn.executemany(
        "INSERT INTO tokens (token_hash, kind, grant_id, created_at, expires_at, rotated_at) "
        "VALUES (?, ?, ?, ?, ?, NULL)",
        [
            (tokens.access_hash, "access", grant_id, now, tokens.access_expires_at),
            (tokens.refresh_hash, "refresh", grant_id, now, tokens.refresh_expires_at),
        ],
    )


def _grant(row: sqlite3.Row) -> Grant:
    return Grant(
        grant_id=row["grant_id"],
        client_id=row["client_id"],
        client_name=row["client_name"],
        odoo_uid=row["odoo_uid"],
        login=row["login"],
        display_name=row["display_name"],
        odoo_url=row["odoo_url"],
        odoo_db=row["odoo_db"],
        api_key_enc=row["api_key_enc"],
        scopes=row["scopes"],
        resource=row["resource"],
        created_at=row["created_at"],
        last_used_at=row["last_used_at"],
        revoked_at=row["revoked_at"],
        revoked_reason=row["revoked_reason"],
    )


def _prepare_file(path: Path) -> None:
    directory = path.parent
    if not directory.exists():
        directory.mkdir(mode=0o700, parents=True)
    elif directory.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        logger.warning("Data directory %s is accessible to other users; chmod 700 is recommended", directory)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)


def _tighten_sidecar_files(path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            os.chmod(sidecar, 0o600)
