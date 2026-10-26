"""Redis persistence for the authorization server, for serverless hosting (e.g. Vercel + Upstash).

Same interface and guarantees as the SQLite OAuthStore: secrets are stored only hashed or
encrypted, and every multi-step change (consuming a code, rotating a refresh token, revoking)
runs as one Lua script, so it is atomic even with many server instances.

Key layout (all under a prefix):
  client:<id>              hash   registered client           (expires 180 days after last use)
  clients                  zset   client ids by creation time (for the registration cap)
  pending:<hash>           hash   pending sign-in              (expires with the request)
  pending_idx              zset   pending ids by expiry        (for the pending cap)
  grant:<id>               hash   a person's connection        (kept 90 days after revocation)
  grants / login:<login>   set    grant ids (all / per login)
  gk:<grant id>            set    code and token keys of a grant, deleted on revocation
  code:<hash>              hash   authorization code (kept 1 h past expiry to detect replay)
  tok:<kind>:<hash>        hash   access/refresh token         (expires with the token)
"""

from __future__ import annotations

import base64
import logging

import redis

from .store import ExchangeResult, Grant, NewTokens, PendingAuthorization, StoredCode, StoredToken
from .store import GRANT_GRACE_SECONDS, REFRESH_REUSE_GRACE_SECONDS, REVOKED_GRANT_RETENTION_SECONDS

logger = logging.getLogger(__name__)

CLIENT_TTL_SECONDS = 180 * 24 * 3600
CODE_REPLAY_WINDOW_SECONDS = 3600

_LUA_HELPERS = """
local p = ARGV[1]
local function active(gid)
  local g = p .. 'grant:' .. gid
  return redis.call('HEXISTS', g, 'revoked_at') == 0 and redis.call('HEXISTS', g, 'api_key_enc') == 1
end
local function revoke(gid, reason, now)
  local g = p .. 'grant:' .. gid
  local members = redis.call('SMEMBERS', p .. 'gk:' .. gid)
  for _, key in ipairs(members) do redis.call('DEL', key) end
  redis.call('DEL', p .. 'gk:' .. gid)
  if redis.call('EXISTS', g) == 0 or redis.call('HEXISTS', g, 'revoked_at') == 1 then return 0 end
  redis.call('HSET', g, 'revoked_at', now, 'revoked_reason', reason)
  redis.call('HDEL', g, 'api_key_enc')
  redis.call('EXPIRE', g, %(retention)d)
  return 1
end
local function insert_tokens(gid, now, access_hash, access_exp, refresh_hash, refresh_exp)
  local a = p .. 'tok:access:' .. access_hash
  local r = p .. 'tok:refresh:' .. refresh_hash
  redis.call('HSET', a, 'grant_id', gid, 'created_at', now, 'expires_at', access_exp)
  redis.call('PEXPIREAT', a, math.floor(tonumber(access_exp) * 1000))
  redis.call('HSET', r, 'grant_id', gid, 'created_at', now, 'expires_at', refresh_exp)
  redis.call('PEXPIREAT', r, math.floor(tonumber(refresh_exp) * 1000))
  redis.call('SADD', p .. 'gk:' .. gid, a, r)
end
""" % {"retention": REVOKED_GRANT_RETENTION_SECONDS}

# ARGV: prefix, now, access_hash, access_exp, refresh_hash, refresh_exp ; KEYS[1] = code key
_CONSUME_CODE = _LUA_HELPERS + """
local now = tonumber(ARGV[2])
local code = KEYS[1]
if redis.call('EXISTS', code) == 0 then return 'invalid' end
local gid = redis.call('HGET', code, 'grant_id')
if not active(gid) then return 'invalid' end
if redis.call('HEXISTS', code, 'used_at') == 1 then
  revoke(gid, 'authorization code reused', ARGV[2])
  return 'replayed'
end
if tonumber(redis.call('HGET', code, 'expires_at')) <= now then return 'invalid' end
redis.call('HSET', code, 'used_at', ARGV[2])
insert_tokens(gid, ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6])
return 'ok'
"""

# Same ARGV ; KEYS[1] = old refresh token key. Reuse within the grace window gets a new pair ('reused').
_ROTATE_REFRESH = _LUA_HELPERS + """
local now = tonumber(ARGV[2])
local old = KEYS[1]
if redis.call('EXISTS', old) == 0 then return 'invalid' end
local gid = redis.call('HGET', old, 'grant_id')
if not active(gid) then return 'invalid' end
local rotated_at = tonumber(redis.call('HGET', old, 'rotated_at'))
if rotated_at and now - rotated_at > %(grace)d then
  revoke(gid, 'refresh token reused', ARGV[2])
  return 'replayed'
end
if tonumber(redis.call('HGET', old, 'expires_at')) <= now then return 'invalid' end
insert_tokens(gid, ARGV[2], ARGV[3], ARGV[4], ARGV[5], ARGV[6])
if rotated_at then return 'reused' end
redis.call('HSET', old, 'rotated_at', ARGV[2])
return 'ok'
""" % {"grace": REFRESH_REUSE_GRACE_SECONDS}

# ARGV: prefix, grant_id, reason, now
_REVOKE = _LUA_HELPERS + """
return revoke(ARGV[2], ARGV[3], ARGV[4])
"""

# ARGV: prefix, grant_id, login_lower, code_hash, code_expires_at, code_ttl_until, field1, value1, ...
# KEYS[1] = pending key
_CREATE_GRANT = _LUA_HELPERS + """
local pending = KEYS[1]
if redis.call('EXISTS', pending) == 0 then return 0 end
local redirect_uri = redis.call('HGET', pending, 'redirect_uri')
local explicit = redis.call('HGET', pending, 'redirect_uri_explicit')
local challenge = redis.call('HGET', pending, 'code_challenge')
redis.call('DEL', pending)
redis.call('ZREM', p .. 'pending_idx', string.sub(pending, string.len(p .. 'pending:') + 1))
local gid = ARGV[2]
local g = p .. 'grant:' .. gid
local fields = {}
for i = 7, #ARGV do table.insert(fields, ARGV[i]) end
redis.call('HSET', g, (table.unpack or unpack)(fields))
redis.call('SADD', p .. 'grants', gid)
redis.call('SADD', p .. 'login:' .. ARGV[3], gid)
local code = p .. 'code:' .. ARGV[4]
redis.call('HSET', code, 'grant_id', gid, 'redirect_uri', redirect_uri, 'redirect_uri_explicit', explicit,
  'code_challenge', challenge, 'expires_at', ARGV[5])
redis.call('PEXPIREAT', code, math.floor(tonumber(ARGV[6]) * 1000))
redis.call('SADD', p .. 'gk:' .. gid, code)
return 1
"""

# ARGV: prefix, grant_id, now. Drops the grant's expired keys and, if nothing usable is left, revokes it,
# in one step: a refresh on another instance cannot land between the check and the revoke.
_PURGE_GRANT = _LUA_HELPERS + """
local gid = ARGV[2]
local now = tonumber(ARGV[3])
if not active(gid) then return 0 end
local gk = p .. 'gk:' .. gid
local alive = false
for _, key in ipairs(redis.call('SMEMBERS', gk)) do
  local f = redis.call('HMGET', key, 'expires_at', 'used_at', 'rotated_at')
  local expires = tonumber(f[1])
  local is_code = string.find(key, ':code:', 1, true) ~= nil
  if expires == nil then
    redis.call('SREM', gk, key)
  elseif expires <= now and not is_code then
    redis.call('DEL', key)
    redis.call('SREM', gk, key)
  elseif expires <= now and not f[2] then
    redis.call('SREM', gk, key)  -- an expired, unused code can never be exchanged
  elseif (is_code and not f[2]) or (not is_code and not f[3]) then
    alive = true
  end
end
if alive then return 0 end
return revoke(gid, 'expired', ARGV[3])
"""

# ARGV: prefix, now ; KEYS[1] = grant key
_TOUCH = """
if redis.call('EXISTS', KEYS[1]) == 1 and redis.call('HEXISTS', KEYS[1], 'revoked_at') == 0 then
  redis.call('HSET', KEYS[1], 'last_used_at', ARGV[2])
end
return 1
"""

# KEYS[1] = pending key
_PENDING_FAILURE = """
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
return redis.call('HINCRBY', KEYS[1], 'failures', 1)
"""


def _b64(data: bytes | None) -> str:
    return base64.b64encode(data).decode("ascii") if data is not None else ""


def _unb64(text: str | None) -> bytes | None:
    return base64.b64decode(text) if text else None


def _float(value: str | None) -> float | None:
    return float(value) if value not in (None, "") else None


class RedisOAuthStore:
    def __init__(self, url: str, *, prefix: str = "sahajta-odoo-mcp:", client: redis.Redis | None = None):
        self.prefix = prefix
        self._r = client or redis.Redis.from_url(url, decode_responses=True, socket_timeout=5, health_check_interval=30)
        self._consume_code = self._r.register_script(_CONSUME_CODE)
        self._rotate_refresh = self._r.register_script(_ROTATE_REFRESH)
        self._revoke = self._r.register_script(_REVOKE)
        self._create_grant = self._r.register_script(_CREATE_GRANT)
        self._purge_grant = self._r.register_script(_PURGE_GRANT)
        self._touch = self._r.register_script(_TOUCH)
        self._pending_failure = self._r.register_script(_PENDING_FAILURE)

    def _k(self, *parts: str) -> str:
        return self.prefix + ":".join(parts)

    def close(self) -> None:
        self._r.close()

    # ------------------------------------------------------------------ clients

    def insert_client(self, client_id: str, metadata_json: str, secret_enc: bytes | None, now: float) -> None:
        key = self._k("client", client_id)
        with self._r.pipeline() as pipe:
            pipe.hset(key, mapping={"metadata": metadata_json, "secret_enc": _b64(secret_enc), "created_at": now})
            pipe.expire(key, CLIENT_TTL_SECONDS)
            pipe.zadd(self._k("clients"), {client_id: now})
            pipe.execute()

    def get_client(self, client_id: str) -> tuple[str, bytes | None] | None:
        key = self._k("client", client_id)
        row = self._r.hgetall(key)
        if not row:
            return None
        self._r.expire(key, CLIENT_TTL_SECONDS)  # clients in use never expire
        return row["metadata"], _unb64(row.get("secret_enc"))

    def count_clients(self) -> int:
        return int(self._r.zcard(self._k("clients")))

    # ------------------------------------------------------------------ pending authorizations

    def insert_pending(self, pending: PendingAuthorization) -> None:
        key = self._k("pending", pending.id_hash)
        mapping = {
            "client_id": pending.client_id,
            "client_name": pending.client_name,
            "verified_host": pending.verified_host or "",
            "redirect_uri": pending.redirect_uri,
            "redirect_uri_explicit": int(pending.redirect_uri_explicit),
            "state": pending.state if pending.state is not None else "",
            "has_state": int(pending.state is not None),
            "scopes": pending.scopes,
            "code_challenge": pending.code_challenge,
            "resource": pending.resource,
            "failures": pending.failures,
            "created_at": pending.created_at,
            "expires_at": pending.expires_at,
        }
        with self._r.pipeline() as pipe:
            pipe.hset(key, mapping=mapping)
            pipe.pexpireat(key, int(pending.expires_at * 1000))
            pipe.zadd(self._k("pending_idx"), {pending.id_hash: pending.expires_at})
            pipe.execute()

    def get_pending(self, id_hash: str, now: float) -> PendingAuthorization | None:
        row = self._r.hgetall(self._k("pending", id_hash))
        if not row or float(row["expires_at"]) <= now:
            return None
        return PendingAuthorization(
            id_hash=id_hash,
            client_id=row["client_id"],
            client_name=row["client_name"],
            verified_host=row.get("verified_host") or None,
            redirect_uri=row["redirect_uri"],
            redirect_uri_explicit=row["redirect_uri_explicit"] == "1",
            state=row.get("state", "") if row.get("has_state") == "1" else None,
            scopes=row["scopes"],
            code_challenge=row["code_challenge"],
            resource=row["resource"],
            failures=int(row.get("failures") or 0),
            created_at=float(row["created_at"]),
            expires_at=float(row["expires_at"]),
        )

    def count_pending(self, now: float) -> int:
        index = self._k("pending_idx")
        self._r.zremrangebyscore(index, "-inf", now)
        return int(self._r.zcard(index))

    def record_pending_failure(self, id_hash: str) -> int:
        return int(self._pending_failure(keys=[self._k("pending", id_hash)]))

    def delete_pending(self, id_hash: str) -> None:
        with self._r.pipeline() as pipe:
            pipe.delete(self._k("pending", id_hash))
            pipe.zrem(self._k("pending_idx"), id_hash)
            pipe.execute()

    # ------------------------------------------------------------------ grants and codes

    def create_grant_with_code(self, *, pending_id_hash: str, grant: Grant, code_hash: str, code_expires_at: float) -> bool:
        fields: list[str] = []
        for name, value in _grant_fields(grant, last_used_at=grant.created_at).items():
            fields += [name, str(value)]
        result = self._create_grant(
            keys=[self._k("pending", pending_id_hash)],
            args=[
                self.prefix, grant.grant_id, grant.login.strip().lower(), code_hash, code_expires_at,
                code_expires_at + CODE_REPLAY_WINDOW_SECONDS, *fields,
            ],
        )
        return int(result) == 1

    def get_grant(self, grant_id: str) -> Grant | None:
        row = self._r.hgetall(self._k("grant", grant_id))
        return _grant(grant_id, row) if row else None

    def get_code(self, code_hash: str) -> StoredCode | None:
        row = self._r.hgetall(self._k("code", code_hash))
        if not row:
            return None
        grant = self.get_grant(row["grant_id"])
        if grant is None:
            return None
        return StoredCode(
            code_hash=code_hash,
            redirect_uri=row["redirect_uri"],
            redirect_uri_explicit=row["redirect_uri_explicit"] == "1",
            code_challenge=row["code_challenge"],
            expires_at=float(row["expires_at"]),
            used_at=_float(row.get("used_at")),
            grant=grant,
        )

    def consume_code(self, code_hash: str, now: float, tokens: NewTokens) -> ExchangeResult:
        result = self._consume_code(keys=[self._k("code", code_hash)], args=[self.prefix, now, *_token_args(tokens)])
        return ExchangeResult(result)

    # ------------------------------------------------------------------ tokens

    def get_token(self, token_hash: str, kind: str) -> StoredToken | None:
        row = self._r.hgetall(self._k("tok", kind, token_hash))
        if not row:
            return None
        grant = self.get_grant(row["grant_id"])
        if grant is None:
            return None
        return StoredToken(
            token_hash=token_hash,
            kind=kind,
            expires_at=float(row["expires_at"]),
            rotated_at=_float(row.get("rotated_at")),
            grant=grant,
        )

    def rotate_refresh_token(self, old_hash: str, now: float, tokens: NewTokens) -> ExchangeResult:
        result = self._rotate_refresh(keys=[self._k("tok", "refresh", old_hash)], args=[self.prefix, now, *_token_args(tokens)])
        return ExchangeResult(result)

    def touch_grant(self, grant_id: str, now: float) -> None:
        self._touch(keys=[self._k("grant", grant_id)], args=[self.prefix, now])

    # ------------------------------------------------------------------ revocation

    def revoke_grant(self, grant_id: str, reason: str, now: float) -> bool:
        revoked = int(self._revoke(args=[self.prefix, grant_id, reason, now])) == 1
        if revoked:
            logger.info("Revoked grant %s (%s)", grant_id, reason)
        return revoked

    def revoke_grants_for_login(self, login: str, reason: str, now: float) -> int:
        ids = self._r.smembers(self._k("login", login.strip().lower()))
        return sum(self.revoke_grant(grant_id, reason, now) for grant_id in ids)

    def revoke_all(self, reason: str, now: float) -> int:
        return sum(self.revoke_grant(grant_id, reason, now) for grant_id in self._r.smembers(self._k("grants")))

    def list_grants(self, *, include_inactive: bool = False) -> list[Grant]:
        grants = []
        for grant_id in self._r.smembers(self._k("grants")):
            grant = self.get_grant(grant_id)
            if grant is None:
                continue
            if include_inactive or grant.active:
                grants.append(grant)
        return sorted(grants, key=lambda g: g.created_at)

    # ------------------------------------------------------------------ housekeeping

    def purge(self, now: float) -> list[str]:
        """Deletes expired records and revokes grants that can never be used again; returns their ids."""
        self._r.zremrangebyscore(self._k("pending_idx"), "-inf", now)
        self._r.zremrangebyscore(self._k("clients"), "-inf", now - CLIENT_TTL_SECONDS)
        revoked: list[str] = []
        for grant_id in list(self._r.smembers(self._k("grants"))):
            grant = self.get_grant(grant_id)
            if grant is not None and grant.revoked_at is not None and grant.revoked_at <= now - REVOKED_GRANT_RETENTION_SECONDS:
                self._r.delete(self._k("grant", grant_id))
                grant = None
            if grant is None:  # revoked long ago and expired: drop it from the indexes
                self._r.srem(self._k("grants"), grant_id)
                for login_key in self._r.scan_iter(match=self._k("login", "*"), count=500):
                    self._r.srem(login_key, grant_id)
                continue
            if not grant.active or grant.created_at > now - GRANT_GRACE_SECONDS:
                continue
            # A grant with no unused code and no live, unrotated token can never be used again: wipe its key.
            if int(self._purge_grant(args=[self.prefix, grant_id, now])) == 1:
                logger.info("Revoked grant %s (expired)", grant_id)
                revoked.append(grant_id)
        return revoked


def _token_args(tokens: NewTokens) -> list:
    return [tokens.access_hash, tokens.access_expires_at, tokens.refresh_hash, tokens.refresh_expires_at]


def _grant_fields(grant: Grant, *, last_used_at: float | None) -> dict:
    fields = {
        "client_id": grant.client_id,
        "client_name": grant.client_name,
        "odoo_uid": grant.odoo_uid,
        "login": grant.login,
        "display_name": grant.display_name,
        "odoo_url": grant.odoo_url,
        "scopes": grant.scopes,
        "resource": grant.resource,
        "created_at": grant.created_at,
    }
    if grant.odoo_db is not None:
        fields["odoo_db"] = grant.odoo_db
    if grant.api_key_enc is not None:
        fields["api_key_enc"] = _b64(grant.api_key_enc)
    if last_used_at is not None:
        fields["last_used_at"] = last_used_at
    return fields


def _grant(grant_id: str, row: dict) -> Grant:
    return Grant(
        grant_id=grant_id,
        client_id=row["client_id"],
        client_name=row["client_name"],
        odoo_uid=int(row["odoo_uid"]),
        login=row["login"],
        display_name=row["display_name"],
        odoo_url=row["odoo_url"],
        odoo_db=row.get("odoo_db"),
        api_key_enc=_unb64(row.get("api_key_enc")),
        scopes=row["scopes"],
        resource=row["resource"],
        created_at=float(row["created_at"]),
        last_used_at=_float(row.get("last_used_at")),
        revoked_at=_float(row.get("revoked_at")),
        revoked_reason=row.get("revoked_reason"),
    )
