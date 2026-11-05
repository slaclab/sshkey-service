"""
Tests for permanent key disabling (2026-11 incident response).

Covers:
  - POST /disable/{username}/{fp}: owner/admin auth, idempotency, record retention
  - enforcement on refresh, inactivate, notes, destroy, authorized_keys, list
  - upload rejection of disabled fingerprints for any username
  - POST /admin/disable (by usernames / all + confirm)
"""
import fnmatch
import os
import sys

import pendulum
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import app as _app
from app import app, IS_ACTIVE_FIELD, DISABLED_FIELD, DISABLED_FINGERPRINTS_SET, EPOCH_NEVER_EXPIRE
from test_key_parsing import _make_ed25519_key, _wrap_rfc4716

FP = "SHA256:" + "A" * 43
FP2 = "SHA256:" + "B" * 43
ADMIN = "adminuser"


def _stored(username="testuser", fp=FP, disabled=False, active=True, valid_until=None):
    now = pendulum.now()
    item = {
        'username': username,
        'finger_print': fp,
        'public_key': 'AAAAC3NzaC1lZDI1NTE5AAAAIGs4y2orDiyCSpY',
        'key_type': 'ssh-ed25519',
        'key_bits': '256',
        'source_ip': '127.0.0.1',
        'created_at': now.subtract(hours=1).to_iso8601_string(),
        'valid_until': (valid_until or now.add(hours=1)).to_iso8601_string(),
        'expires_at': EPOCH_NEVER_EXPIRE.to_iso8601_string(),
        'user_notes': '',
    }
    if active:
        item[IS_ACTIVE_FIELD] = '1'
    if disabled:
        item.update({DISABLED_FIELD: '1', 'disabled_at': now.to_iso8601_string(),
                     'disabled_by': username, 'disabled_reason': 'lost laptop'})
    return item


class FakeRedis:
    """Tiny in-memory stand-in for the redis calls the app makes."""

    def __init__(self, hashes=None, disabled=None):
        self.hashes = {k: dict(v) for k, v in (hashes or {}).items()}
        self.sets = {DISABLED_FINGERPRINTS_SET: set(disabled or ())}
        self.hset_calls = 0

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def hset(self, key, field=None, value=None, mapping=None):
        self.hset_calls += 1
        h = self.hashes.setdefault(key, {})
        if mapping:
            h.update({k: str(v) for k, v in mapping.items()})
        if field is not None:
            h[field] = str(value)
        return 1

    async def delete(self, key):
        return 1 if self.hashes.pop(key, None) is not None else 0

    async def hexpire(self, *args, **kwargs):
        return [1]

    async def sadd(self, name, *values):
        self.sets.setdefault(name, set()).update(values)
        return len(values)

    async def sismember(self, name, value):
        return 1 if value in self.sets.get(name, set()) else 0

    async def scan_iter(self, pattern):
        for k in list(self.hashes):
            if fnmatch.fnmatchcase(k, pattern):
                yield k


@pytest.fixture
def admins():
    with patch.object(_app, 'ADMINS', frozenset({ADMIN})):
        yield


def _client(fake):
    client = TestClient(app, raise_server_exceptions=False)
    ctx = patch("app.app.state", MagicMock(redis_client=fake))
    return client, ctx


def _call(fake, method, url, user="testuser", **kwargs):
    client, ctx = _client(fake)
    with ctx:
        return client.request(method, url, headers={"REMOTE-USER": user, "accept": "application/json"}, **kwargs)


KEY = f"user:testuser:{FP}"


class TestDisableEndpoint:

    def test_owner_can_disable_own_key(self, admins):
        fake = FakeRedis({KEY: _stored()})
        resp = _call(fake, "POST", f"/disable/testuser/{FP}", json={"reason": "lost laptop"})
        assert resp.status_code == 202
        h = fake.hashes[KEY]
        assert h[DISABLED_FIELD] == '1'
        assert h['disabled_by'] == 'testuser'
        assert h['disabled_reason'] == 'lost laptop'
        assert 'disabled_at' in h
        assert IS_ACTIVE_FIELD not in h
        # record retained, fingerprint recorded globally
        assert h['public_key'] and h['finger_print'] == FP
        assert FP in fake.sets[DISABLED_FINGERPRINTS_SET]

    def test_disable_without_body(self, admins):
        fake = FakeRedis({KEY: _stored()})
        resp = _call(fake, "POST", f"/disable/testuser/{FP}")
        assert resp.status_code == 202
        assert fake.hashes[KEY]['disabled_reason'] == ''

    def test_other_user_cannot_disable(self, admins):
        fake = FakeRedis({KEY: _stored()})
        resp = _call(fake, "POST", f"/disable/testuser/{FP}", user="mallory")
        assert resp.status_code == 403
        assert DISABLED_FIELD not in fake.hashes[KEY]

    def test_admin_can_disable_any_key(self, admins):
        fake = FakeRedis({KEY: _stored()})
        resp = _call(fake, "POST", f"/disable/testuser/{FP}", user=ADMIN)
        assert resp.status_code == 202
        assert fake.hashes[KEY]['disabled_by'] == ADMIN

    def test_disable_is_idempotent(self, admins):
        original = _stored(disabled=True, active=False)
        fake = FakeRedis({KEY: original}, disabled={FP})
        resp = _call(fake, "POST", f"/disable/testuser/{FP}", json={"reason": "again"})
        assert resp.status_code == 200
        assert fake.hashes[KEY]['disabled_reason'] == 'lost laptop'
        assert fake.hset_calls == 0

    def test_missing_key_404(self, admins):
        resp = _call(FakeRedis(), "POST", f"/disable/testuser/{FP}")
        assert resp.status_code == 404

    def test_bad_fingerprint_400(self, admins):
        resp = _call(FakeRedis(), "POST", "/disable/testuser/not-a-fingerprint")
        assert resp.status_code == 400


class TestEnforcementOnDisabledKey:

    @pytest.fixture
    def fake(self):
        return FakeRedis({KEY: _stored(disabled=True, active=False)}, disabled={FP})

    def test_refresh_rejected(self, fake, admins):
        resp = _call(fake, "PATCH", f"/refresh/testuser/{FP}")
        assert resp.status_code == 403
        assert IS_ACTIVE_FIELD not in fake.hashes[KEY]

    def test_refresh_rejected_even_for_admin(self, fake, admins):
        resp = _call(fake, "PATCH", f"/refresh/testuser/{FP}", user=ADMIN)
        assert resp.status_code == 403

    def test_inactivate_rejected(self, fake, admins):
        resp = _call(fake, "DELETE", f"/inactivate/testuser/{FP}")
        assert resp.status_code == 403
        assert fake.hashes[KEY][DISABLED_FIELD] == '1'

    def test_notes_rejected(self, fake, admins):
        resp = _call(fake, "PATCH", f"/notes/testuser/{FP}", json={"user_notes": "x"})
        assert resp.status_code == 403

    def test_destroy_rejected_record_kept(self, fake, admins):
        resp = _call(fake, "DELETE", f"/destroy/testuser/{FP}", user=ADMIN)
        assert resp.status_code == 409
        assert KEY in fake.hashes

    def test_authorized_keys_omits_disabled(self, admins):
        fake = FakeRedis({
            KEY: _stored(disabled=True, active=True),  # even if is_active lingered
            f"user:testuser:{FP2}": _stored(fp=FP2),
        }, disabled={FP})
        resp = _call(fake, "GET", "/authorized_keys/testuser")
        assert resp.status_code == 200
        assert FP not in resp.text
        assert FP2 in resp.text

    def test_list_flags_disabled(self, fake, admins):
        resp = _call(fake, "GET", "/list/testuser")
        keys = resp.json()['message']
        assert len(keys) == 1 and keys[0]['is_disabled'] is True

    def test_list_can_exclude_disabled(self, admins):
        fake = FakeRedis({
            KEY: _stored(disabled=True, active=False),
            f"user:testuser:{FP2}": _stored(fp=FP2),
        }, disabled={FP})
        resp = _call(fake, "GET", "/list/testuser?include_disabled=false")
        keys = resp.json()['message']
        assert [k['finger_print'] for k in keys] == [FP2]
        assert keys[0]['is_disabled'] is False

    def test_list_html_hides_disabled_by_default(self, admins):
        fake = FakeRedis({KEY: _stored(disabled=True, active=False)}, disabled={FP})
        client, ctx = _client(fake)
        with ctx:
            resp = client.get("/list/testuser", headers={"REMOTE-USER": "testuser", "accept": "text/html"})
        assert resp.status_code == 200
        assert 'class="disabled-key"' in resp.text
        assert 'Show revoked keys (1)' in resp.text
        assert '>Revoked</span>' in resp.text


class TestUploadOfDisabledKey:

    @staticmethod
    def _key():
        key = _make_ed25519_key()
        fp = key.fingerprint.rstrip('=').replace('/', '.').replace('+', '.')
        return _wrap_rfc4716(key), fp

    def test_same_user_rejected_and_logged(self, caplog, admins):
        block, fp = self._key()
        fake = FakeRedis(disabled={fp})
        resp = _call(fake, "POST", "/upload/testuser", json={"public_key": block})
        assert resp.status_code == 403
        assert 'revoked' in resp.json()['detail']
        assert fake.hset_calls == 0
        assert 'Reuse of disabled key' in caplog.text

    def test_other_user_rejected(self, admins):
        block, fp = self._key()
        fake = FakeRedis(disabled={fp})
        resp = _call(fake, "POST", "/upload/otheruser", user="otheruser", json={"public_key": block})
        assert resp.status_code == 403
        assert fake.hset_calls == 0

    def test_new_key_still_uploads(self, admins):
        block, fp = self._key()
        fake = FakeRedis(disabled={FP})
        with patch.object(_app, 'EMAIL_ENABLED', False):
            resp = _call(fake, "POST", "/upload/testuser", json={"public_key": block})
        assert resp.status_code == 201
        assert f"user:testuser:{fp}" in fake.hashes


class TestAdminDisable:

    @pytest.fixture
    def fake(self):
        return FakeRedis({
            f"user:alice:{FP}": _stored("alice", FP),
            f"user:bob:{FP2}": _stored("bob", FP2),
        })

    def test_by_usernames(self, fake, admins):
        resp = _call(fake, "POST", "/admin/disable", user=ADMIN,
                     json={"usernames": ["alice"], "reason": "admin rotation"})
        assert resp.status_code == 200
        assert resp.json() == {'disabled': 1, 'already_disabled': 0, 'also_revoked': 0}
        assert fake.hashes[f"user:alice:{FP}"][DISABLED_FIELD] == '1'
        assert DISABLED_FIELD not in fake.hashes[f"user:bob:{FP2}"]

    def test_all_with_confirm(self, fake, admins):
        resp = _call(fake, "POST", "/admin/disable", user=ADMIN,
                     json={"all": True, "reason": "incident", "confirm": "DISABLE ALL"})
        assert resp.json() == {'disabled': 2, 'already_disabled': 0, 'also_revoked': 0}
        assert fake.sets[DISABLED_FINGERPRINTS_SET] == {FP, FP2}
        # second run is a no-op
        resp = _call(fake, "POST", "/admin/disable", user=ADMIN,
                     json={"all": True, "reason": "incident", "confirm": "DISABLE ALL"})
        assert resp.json() == {'disabled': 0, 'already_disabled': 2, 'also_revoked': 0}

    def test_all_without_confirm_400(self, fake, admins):
        resp = _call(fake, "POST", "/admin/disable", user=ADMIN, json={"all": True, "reason": "incident"})
        assert resp.status_code == 400
        assert fake.hset_calls == 0

    def test_requires_reason(self, fake, admins):
        resp = _call(fake, "POST", "/admin/disable", user=ADMIN, json={"usernames": ["alice"], "reason": " "})
        assert resp.status_code == 400

    def test_requires_target(self, fake, admins):
        resp = _call(fake, "POST", "/admin/disable", user=ADMIN, json={"reason": "x"})
        assert resp.status_code == 400

    def test_non_admin_403(self, fake, admins):
        resp = _call(fake, "POST", "/admin/disable", user="alice",
                     json={"all": True, "reason": "x", "confirm": "DISABLE ALL"})
        assert resp.status_code == 403
        assert fake.hset_calls == 0



class TestSameKeyAcrossAccounts:
    """One key registered under two usernames must not survive a revoke on either one."""

    @staticmethod
    def _key():
        return TestUploadOfDisabledKey._key()

    def test_second_account_cannot_register_same_key(self, caplog, admins):
        # i. alice registers K;  ii. bob tries the same K -> rejected
        block, fp = self._key()
        fake = FakeRedis()
        with patch.object(_app, 'EMAIL_ENABLED', False):
            assert _call(fake, "POST", "/upload/alice", user="alice", json={"public_key": block}).status_code == 201
            resp = _call(fake, "POST", "/upload/bob", user="bob", json={"public_key": block})
        assert resp.status_code == 409
        assert 'another account' in resp.json()['detail']
        assert 'alice' not in resp.json()['detail']  # don't reveal who holds it
        assert f"user:bob:{fp}" not in fake.hashes
        assert 'already registered to another account' in caplog.text

    def test_same_user_reupload_still_400(self, admins):
        block, fp = self._key()
        fake = FakeRedis()
        with patch.object(_app, 'EMAIL_ENABLED', False):
            _call(fake, "POST", "/upload/alice", user="alice", json={"public_key": block})
            resp = _call(fake, "POST", "/upload/alice", user="alice", json={"public_key": block})
        assert resp.status_code == 400

    @pytest.fixture
    def shared(self):
        # legacy state: same fingerprint already registered under two accounts
        return FakeRedis({
            f"user:alice:{FP}": _stored("alice", FP),
            f"user:bob:{FP}": _stored("bob", FP),
            f"user:bob:{FP2}": _stored("bob", FP2),
        })

    def test_revoke_fans_out_to_other_accounts(self, shared, admins):
        # iii. alice revokes K -> bob's copy is revoked too
        resp = _call(shared, "POST", f"/disable/alice/{FP}", user="alice", json={"reason": "private note"})
        assert resp.status_code == 202
        assert resp.json()['also_revoked'] == 1
        bob = shared.hashes[f"user:bob:{FP}"]
        assert bob[DISABLED_FIELD] == '1' and IS_ACTIVE_FIELD not in bob
        assert bob['disabled_by'] == 'alice'
        assert 'private note' not in bob['disabled_reason']  # alice's reason stays on alice's record
        assert DISABLED_FIELD not in shared.hashes[f"user:bob:{FP2}"]  # bob's other key untouched

    def test_authorized_keys_other_account_omits_revoked(self, shared, admins):
        # iv. /authorized_keys/bob must not serve K
        _call(shared, "POST", f"/disable/alice/{FP}", user="alice")
        body = _call(shared, "GET", "/authorized_keys/bob").text
        assert shared.hashes[f"user:bob:{FP2}"]['public_key'] in body  # sanity: bob's other key served
        assert body.count('ssh-ed25519') == 1

    def test_global_set_alone_blocks_unmarked_copy(self, shared, admins):
        # even if a copy was never marked individually, the global set wins
        shared.sets[DISABLED_FINGERPRINTS_SET].add(FP)
        assert _call(shared, "GET", "/authorized_keys/bob").text.count('ssh-ed25519') == 1
        assert _call(shared, "PATCH", f"/refresh/bob/{FP}", user="bob").status_code == 403
        listed = {k['finger_print']: k['is_disabled'] for k in _call(shared, "GET", "/list/bob", user="bob").json()['message']}
        assert listed == {FP: True, FP2: False}

    def test_rerevoke_cleans_up_legacy_copy(self, shared, admins):
        # alice's record revoked before fan-out existed; revoking again reaches bob's copy
        shared.hashes[f"user:alice:{FP}"].update({DISABLED_FIELD: '1'})
        resp = _call(shared, "POST", f"/disable/alice/{FP}", user="alice")
        assert resp.status_code == 200 and resp.json()['also_revoked'] == 1
        assert shared.hashes[f"user:bob:{FP}"][DISABLED_FIELD] == '1'

    def test_admin_by_username_fans_out(self, shared, admins):
        resp = _call(shared, "POST", "/admin/disable", user=ADMIN, json={"usernames": ["alice"], "reason": "rotation"})
        assert resp.json() == {'disabled': 1, 'already_disabled': 0, 'also_revoked': 1}
        assert shared.hashes[f"user:bob:{FP}"][DISABLED_FIELD] == '1'
        assert DISABLED_FIELD not in shared.hashes[f"user:bob:{FP2}"]
