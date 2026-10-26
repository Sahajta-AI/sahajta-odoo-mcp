"""The Redis backend (used on Vercel) must behave exactly like the SQLite one.

Runs the whole end-to-end OAuth suite and the store lifecycle tests against Redis (fakeredis,
with real Lua scripting), plus the shared single-use and rate-limit state across instances.
"""

import time

import fakeredis
import pytest
import redis

import test_oauth
from test_oauth import *  # noqa: F401,F403  (re-collects every end-to-end OAuth test against Redis)
from test_oauth_units import _grant, _pending

from sahajta_odoo_mcp.confirm import ConfirmationSigner
from sahajta_odoo_mcp.errors import ConfirmationRequired, RateLimited
from sahajta_odoo_mcp.oauth.crypto import hash_token
from sahajta_odoo_mcp.oauth.redis_store import RedisOAuthStore
from sahajta_odoo_mcp.oauth.store import GRANT_GRACE_SECONDS, REFRESH_REUSE_GRACE_SECONDS, NewTokens
from sahajta_odoo_mcp.ratelimit import RateLimiter
from sahajta_odoo_mcp.state import RedisState

# SQLite-file specific tests; their Redis equivalents are below.
for _name in (
    "test_dcr_rejects_redirects_outside_the_allowlist", "test_expired_code_is_rejected",
    "test_expired_access_token_is_rejected", "test_secrets_never_stored_in_plaintext",
    "test_data_files_are_private", "test_schema_version_is_recorded",
    "test_dcr_confidential_client_secret_is_required_and_encrypted",
):
    globals().pop(_name, None)

_original_make_settings = test_oauth.make_settings
_SERVER: dict = {}


def _fake(server=None):
    return fakeredis.FakeRedis(server=server or _SERVER["server"], decode_responses=True)


def _grant_rows(env):
    r = _fake()
    rows = []
    for gid in r.smembers("sahajta-odoo-mcp:grants"):
        g = r.hgetall(f"sahajta-odoo-mcp:grant:{gid}")
        if g:
            revoked = float(g["revoked_at"]) if g.get("revoked_at") else None
            rows.append((g["login"], revoked, g.get("revoked_reason"), int("api_key_enc" not in g)))
    return rows


@pytest.fixture(autouse=True)
def redis_backend(monkeypatch):
    server = fakeredis.FakeServer()
    _SERVER["server"] = server
    monkeypatch.setattr(test_oauth, "grant_rows", _grant_rows)
    monkeypatch.setattr(
        redis.Redis, "from_url", classmethod(lambda cls, url, **kw: fakeredis.FakeRedis(server=server, decode_responses=True))
    )
    monkeypatch.setattr(
        test_oauth, "make_settings", lambda tmp_path, **o: _original_make_settings(tmp_path, mcp_redis_url="redis://fake:6379", **o)
    )
    return server


def _store(server):
    return RedisOAuthStore("redis://fake", client=fakeredis.FakeRedis(server=server, decode_responses=True))


def test_redis_store_lifecycle_and_purge(redis_backend):
    store = _store(redis_backend)
    now = time.time()
    store.insert_pending(_pending(now))
    assert store.create_grant_with_code(pending_id_hash="p1", grant=_grant(now), code_hash="c1", code_expires_at=now + 300)
    assert not store.create_grant_with_code(pending_id_hash="p1", grant=_grant(now, "g2"), code_hash="c2", code_expires_at=now + 300)
    tokens = NewTokens(hash_token("a"), now + 3600, hash_token("r"), now + 7200)
    assert store.consume_code("c1", now, tokens).value == "ok"
    assert store.consume_code("c1", now, tokens).value == "replayed"  # code reuse revokes the grant
    grant = store.get_grant("g1")
    assert grant is not None and not grant.active and grant.api_key_enc is None
    assert store.get_token(hash_token("a"), "access") is None


def test_redis_refresh_rotation_grace_and_replay(redis_backend):
    store = _store(redis_backend)
    now = time.time()
    store.insert_pending(_pending(now))
    store.create_grant_with_code(pending_id_hash="p1", grant=_grant(now), code_hash="c1", code_expires_at=now + 300)
    store.consume_code("c1", now, NewTokens("a1", now + 3600, "r1", now + 7200))
    assert store.rotate_refresh_token("r1", now, NewTokens("a2", now + 3600, "r2", now + 7200)).value == "ok"
    assert store.get_token("r2", "refresh") is not None
    # Used again soon after (a retry, or two refreshes racing): a new pair, nothing revoked.
    assert store.rotate_refresh_token("r1", now + 60, NewTokens("a3", now + 3600, "r3", now + 7200)).value == "reused"
    assert store.get_token("r2", "refresh") is not None and store.get_token("r3", "refresh") is not None
    assert store.get_grant("g1").active
    # The window counts from the rotation, not from the last reuse; after it, reuse kills the grant.
    late = now + REFRESH_REUSE_GRACE_SECONDS + 1
    assert store.rotate_refresh_token("r1", late, NewTokens("a4", now + 3600, "r4", now + 7200)).value == "replayed"
    assert store.get_token("r2", "refresh") is None and not store.get_grant("g1").active


def test_redis_purge_wipes_dead_grants_and_old_revocations(redis_backend):
    store = _store(redis_backend)
    now = time.time()
    store.insert_pending(_pending(now))
    store.create_grant_with_code(pending_id_hash="p1", grant=_grant(now), code_hash="c1", code_expires_at=now + 300)
    store.consume_code("c1", now, NewTokens("a", now + 3600, "r", now + 7200))
    assert store.purge(now + 100) == []
    assert store.get_grant("g1").active
    assert store.purge(now + 7201) == ["g1"]
    grant = store.get_grant("g1")
    assert not grant.active and grant.revoked_reason == "expired" and grant.api_key_enc is None
    store.purge(now + 91 * 24 * 3600)
    assert store.get_grant("g1") is None and store.list_grants(include_inactive=True) == []


def test_redis_purge_cannot_revoke_a_grant_refreshed_meanwhile(redis_backend):
    """Another instance refreshes while purge looks at the grant: the check and the revoke are one step."""
    now = time.time()
    purge_at = now + GRANT_GRACE_SECONDS + 3700  # the access token has expired, the refresh token has not
    other_instance = _store(redis_backend)
    refreshed = []

    def refresh_elsewhere():
        new = NewTokens("a2", purge_at + 3600, "r2", purge_at + 7200)
        refreshed.append(other_instance.rotate_refresh_token("r1", purge_at, new).value)

    class RefreshAfterSnapshot(fakeredis.FakeRedis):
        def smembers(self, name):
            members = super().smembers(name)
            if ":gk:" in name and not refreshed:
                refresh_elsewhere()  # lands between purge's look at the grant's keys and its decision
            return members

    store = RedisOAuthStore("redis://fake", client=RefreshAfterSnapshot(server=redis_backend, decode_responses=True))
    store.insert_pending(_pending(now))
    store.create_grant_with_code(pending_id_hash="p1", grant=_grant(now), code_hash="c1", code_expires_at=now + 300)
    store.consume_code("c1", now, NewTokens("a1", now + 3600, "r1", now + GRANT_GRACE_SECONDS + 7200))
    revoked = store.purge(purge_at)
    if not refreshed:  # purge never exposed a gap, so the refresh simply comes after it
        refresh_elsewhere()
    assert refreshed == ["ok"]
    assert store.get_grant("g1").active and store.get_token("r2", "refresh") is not None
    assert revoked == []


def test_redis_pending_requests(redis_backend):
    store = _store(redis_backend)
    now = time.time()
    store.insert_pending(_pending(now))
    assert store.get_pending("p1", now) is not None
    assert store.record_pending_failure("p1") == 1 and store.record_pending_failure("p1") == 2
    assert store.count_pending(now) == 1
    store.delete_pending("p1")
    assert store.get_pending("p1", now) is None and store.record_pending_failure("p1") == 0


def test_confirm_tokens_are_single_use_across_instances(redis_backend):
    payload = {"op": "create", "model": "crm.lead"}
    first = ConfirmationSigner(b"s" * 32, state=RedisState(fakeredis.FakeRedis(server=redis_backend, decode_responses=True)))
    second = ConfirmationSigner(b"s" * 32, state=RedisState(fakeredis.FakeRedis(server=redis_backend, decode_responses=True)))
    token = first.issue(payload)
    first.verify(token, payload)
    with pytest.raises(ConfirmationRequired, match="already used"):
        second.verify(token, payload)  # a different server instance still refuses the replay


def test_rate_limits_add_up_across_instances(redis_backend):
    limiters = [
        RateLimiter(2, 1, state=RedisState(fakeredis.FakeRedis(server=redis_backend, decode_responses=True))) for _ in range(2)
    ]
    limiters[0].check("alice", "read")
    limiters[1].check("alice", "read")
    with pytest.raises(RateLimited):
        limiters[0].check("alice", "read")
    limiters[1].check("bob", "read")


# ---------------------------------------------------------------- Redis versions of the SQLite-file tests


def test_redis_dcr_rejects_redirects_outside_the_allowlist(env):
    response = env.client.post("/register", json={"redirect_uris": ["https://evil.example/cb"], "token_endpoint_auth_method": "none"})
    assert response.status_code == 400 and response.json()["error"] == "invalid_redirect_uri"
    assert _fake().zcard("sahajta-odoo-mcp:clients") == 0


def test_redis_expired_code_is_rejected(env):
    client_id = test_oauth.register_client_id(env)
    code, verifier = test_oauth.sign_in(env, client_id)
    r = _fake()
    for key in r.scan_iter("sahajta-odoo-mcp:code:*"):
        r.hset(key, "expires_at", time.time() - 1)
    response = test_oauth.exchange(env, client_id, code, verifier)
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"


def test_redis_expired_access_token_is_rejected(env):
    _, tokens = test_oauth.connect(env)
    r = _fake()
    for key in r.scan_iter("sahajta-odoo-mcp:tok:access:*"):
        r.hset(key, "expires_at", time.time() - 1)
    assert test_oauth.verify(env, tokens["access_token"]) is None
    assert test_oauth.call_whoami(env, tokens["access_token"]).status_code == 401


def test_redis_secrets_never_stored_in_plaintext(env):
    client_id = test_oauth.register_client_id(env)
    code, verifier = test_oauth.sign_in(env, client_id)
    tokens = test_oauth.exchange(env, client_id, code, verifier).json()
    r = _fake()
    dump = []
    for key in r.scan_iter("*"):
        dump.append(key)
        kind = r.type(key)
        if kind == "hash":
            dump += [f"{k}={v}" for k, v in r.hgetall(key).items()]
        elif kind == "set":
            dump += list(r.smembers(key))
        elif kind == "zset":
            dump += list(r.zrange(key, 0, -1))
        elif kind == "string":
            dump.append(r.get(key) or "")
    blob = "\n".join(dump)
    for secret in (test_oauth.PRIYA_KEY, tokens["access_token"], tokens["refresh_token"], code):
        assert secret not in blob


def test_redis_confidential_client_secret_is_required_and_encrypted(env):
    response = env.client.post(
        "/register",
        json={"redirect_uris": [test_oauth.CLAUDE_CALLBACK], "token_endpoint_auth_method": "client_secret_post"},
    )
    assert response.status_code == 201
    client_id, client_secret = response.json()["client_id"], response.json()["client_secret"]
    code, verifier = test_oauth.sign_in(env, client_id)
    assert test_oauth.exchange(env, client_id, code, verifier, client_secret="wrong").status_code == 401
    assert test_oauth.exchange(env, client_id, code, verifier, client_secret=client_secret).status_code == 200
    r = _fake()
    stored = r.hgetall(f"sahajta-odoo-mcp:client:{client_id}")
    assert stored and client_secret not in "".join(stored.values())
