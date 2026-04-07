"""
Tests for #004 — Redis Key Fingerprint Validation

Covers:
  - validate_fingerprint() unit tests (AC-1 through AC-6)
  - Integration tests: malformed fingerprint returns 400 at all four path-param
    endpoints (AC-7, AC-8)

Test fingerprints are generated at test time from real paramiko keys — no
private key material committed.
"""
import sys
import os
import struct
import base64
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app import validate_fingerprint, app
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ed25519_key() -> paramiko.Ed25519Key:
    """Generate a real ED25519 key (paramiko 4.0 compat via cryptography library)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pubkey_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    type_str = b'ssh-ed25519'
    wire = struct.pack('>I', len(type_str)) + type_str + struct.pack('>I', len(pubkey_bytes)) + pubkey_bytes
    return paramiko.Ed25519Key(data=wire)


def _real_fingerprint() -> str:
    """Return a real cleaned SHA256 fingerprint from a freshly generated ED25519 key."""
    key = _make_ed25519_key()
    return key.fingerprint.rstrip('=').replace('/', '.').replace('+', '.')


def _make_mock_redis():
    """Return a mock Redis client suitable for endpoint integration tests."""
    mock_redis = AsyncMock()
    mock_redis.hgetall = AsyncMock(return_value={
        'username': 'testuser',
        'finger_print': _real_fingerprint(),
        'public_key': 'AAAA',
        'key_type': 'ssh-ed25519',
        'key_bits': '256',
        'user_notes': '',
        'is_active': '1',
        'created_at': '2026-01-01T00:00:00+00:00',
        'valid_until': '2099-01-01T00:00:00+00:00',
        'expires_at': '1970-01-01T00:00:00+00:00',
    })
    mock_redis.hset = AsyncMock(return_value=True)
    mock_redis.hexpire = AsyncMock(return_value=True)
    mock_redis.delete = AsyncMock(return_value=True)

    async def empty_scan(*args, **kwargs):
        return
        yield

    mock_redis.scan_iter = empty_scan
    return mock_redis


# ---------------------------------------------------------------------------
# Unit tests: validate_fingerprint()
# ---------------------------------------------------------------------------

class TestValidateFingerprint:
    """Direct unit tests of the validate_fingerprint() helper."""

    def test_valid_fingerprint_returns_unchanged(self):
        """AC-1: A well-formed cleaned SHA256 fingerprint passes through unchanged."""
        fp = _real_fingerprint()
        assert validate_fingerprint(fp) == fp

    def test_valid_fingerprint_hardcoded(self):
        """AC-1: A known-good hardcoded fingerprint passes validation."""
        # 43 alphanumeric+dot chars after SHA256:
        fp = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTi1QqQ07ojVE"
        assert validate_fingerprint(fp) == fp

    def test_extra_colon_raises_400(self):
        """AC-2: Fingerprint with ':' beyond the SHA256 prefix raises 400."""
        fp = "SHA256:foo:bar" + "A" * 39  # total > 43 chars but contains extra colon
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400

    def test_colon_in_body_raises_400(self):
        """AC-2: 'SHA256:' prefix with ':' in the 43-char body raises 400."""
        # 42 valid chars + one colon = 43 chars but contains ':'
        fp = "SHA256:" + "A" * 42 + ":"
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400

    def test_wildcard_star_raises_400(self):
        """AC-3: Fingerprint with '*' raises 400."""
        fp = "SHA256:" + "A" * 42 + "*"
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400

    def test_wildcard_question_raises_400(self):
        """AC-3: Fingerprint with '?' raises 400."""
        fp = "SHA256:" + "A" * 42 + "?"
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400

    def test_empty_string_raises_400(self):
        """AC-4: Empty string raises 400."""
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint("")
        assert exc_info.value.status_code == 400

    def test_uncleaned_slash_raises_400(self):
        """AC-5: Raw fingerprint with '/' raises 400 — must be cleaned first."""
        # '/' is valid base64 but not allowed in our cleaned format
        fp = "SHA256:" + "A" * 42 + "/"
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400

    def test_uncleaned_plus_raises_400(self):
        """AC-5: Raw fingerprint with '+' raises 400 — must be cleaned first."""
        fp = "SHA256:" + "A" * 42 + "+"
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400

    def test_error_detail_does_not_contain_fingerprint(self):
        """AC-6: The 400 error detail must not reflect the raw fingerprint value."""
        hostile_fp = "SHA256:evil:injection:attempt" + "X" * 20
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(hostile_fp)
        assert hostile_fp not in exc_info.value.detail

    def test_too_short_body_raises_400(self):
        """Body with fewer than 43 chars raises 400."""
        fp = "SHA256:" + "A" * 42  # 42 chars, one short
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400

    def test_too_long_body_raises_400(self):
        """Body with more than 43 chars raises 400."""
        fp = "SHA256:" + "A" * 44  # 44 chars, one too many
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400

    def test_wrong_prefix_raises_400(self):
        """Non-SHA256 prefix raises 400."""
        fp = "MD5:" + "A" * 43
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400

    def test_underscore_in_body_raises_400(self):
        """'_' is not in the post-cleaning alphabet — must raise 400."""
        fp = "SHA256:" + "A" * 42 + "_"
        with pytest.raises(HTTPException) as exc_info:
            validate_fingerprint(fp)
        assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# Integration tests: malformed fingerprint at path-param endpoints
# ---------------------------------------------------------------------------

MALFORMED_FP = "SHA256:foo:bar"  # contains extra ':' — rejected by validate_fingerprint
VALID_FP = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTi1QqQ07ojVE"  # exactly 43 clean chars


class TestFingerprintValidationAtEndpoints:
    """
    Integration tests via TestClient + mocked Redis.
    All four path-param endpoints must return 400 for a malformed fingerprint
    before any Redis operation fires (AC-8).
    Valid fingerprints proceed normally (AC-7 regression).
    """

    # ---- destroy (/DELETE) -----------------------------------------------
    # destroy is admin_only=True — patch app.ADMINS to include "admin"

    def test_destroy_malformed_fingerprint_returns_400(self):
        """AC-8: DELETE /destroy with ':' in fingerprint → 400, not 404."""
        mock_redis = _make_mock_redis()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("app.app.state", MagicMock(redis_client=mock_redis)), \
             patch("app.ADMINS", frozenset({"admin"})):
            resp = client.delete(
                f"/destroy/testuser/{MALFORMED_FP}",
                headers={"REMOTE-USER": "admin"},
            )
        assert resp.status_code == 400
        mock_redis.hgetall.assert_not_called()

    def test_destroy_valid_fingerprint_proceeds(self):
        """AC-7: DELETE /destroy with valid fingerprint reaches Redis (no validation block)."""
        mock_redis = _make_mock_redis()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("app.app.state", MagicMock(redis_client=mock_redis)), \
             patch("app.ADMINS", frozenset({"admin"})):
            resp = client.delete(
                f"/destroy/testuser/{VALID_FP}",
                headers={"REMOTE-USER": "admin"},
            )
        # 204 = deleted, 404 = not found — either is fine; the key point is NOT 400
        assert resp.status_code in (204, 404)
        mock_redis.hgetall.assert_called_once()

    # ---- inactivate (/DELETE) --------------------------------------------

    def test_inactivate_malformed_fingerprint_returns_400(self):
        """AC-8: DELETE /inactivate with ':' in fingerprint → 400."""
        mock_redis = _make_mock_redis()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.delete(
                f"/inactivate/testuser/{MALFORMED_FP}",
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 400
        mock_redis.hgetall.assert_not_called()

    def test_inactivate_valid_fingerprint_proceeds(self):
        """AC-7: DELETE /inactivate with valid fingerprint reaches Redis."""
        mock_redis = _make_mock_redis()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.delete(
                f"/inactivate/testuser/{VALID_FP}",
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code in (204, 404)
        mock_redis.hgetall.assert_called_once()

    # ---- refresh (/PATCH) ------------------------------------------------

    def test_refresh_malformed_fingerprint_returns_400(self):
        """AC-8: PATCH /refresh with ':' in fingerprint → 400."""
        mock_redis = _make_mock_redis()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.patch(
                f"/refresh/testuser/{MALFORMED_FP}",
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 400
        mock_redis.hgetall.assert_not_called()

    def test_refresh_valid_fingerprint_proceeds(self):
        """AC-7: PATCH /refresh with valid fingerprint reaches Redis."""
        mock_redis = _make_mock_redis()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.patch(
                f"/refresh/testuser/{VALID_FP}",
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code in (202, 404)
        mock_redis.hgetall.assert_called_once()

    # ---- notes (/PATCH) --------------------------------------------------

    def test_notes_malformed_fingerprint_returns_400(self):
        """AC-8: PATCH /notes with ':' in fingerprint → 400."""
        mock_redis = _make_mock_redis()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.patch(
                f"/notes/testuser/{MALFORMED_FP}",
                json={"user_notes": "some note"},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 400
        mock_redis.hgetall.assert_not_called()

    def test_notes_valid_fingerprint_proceeds(self):
        """AC-7: PATCH /notes with valid fingerprint reaches Redis."""
        mock_redis = _make_mock_redis()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.patch(
                f"/notes/testuser/{VALID_FP}",
                json={"user_notes": "some note"},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code in (202, 404)
        mock_redis.hgetall.assert_called_once()

    # ---- error message safety --------------------------------------------

    def test_400_detail_does_not_echo_fingerprint_destroy(self):
        """AC-6: The 400 detail from any endpoint must not echo the raw fingerprint."""
        hostile_fp = "SHA256:x:y:z" + "A" * 30
        mock_redis = _make_mock_redis()
        client = TestClient(app, raise_server_exceptions=False)
        with patch("app.app.state", MagicMock(redis_client=mock_redis)), \
             patch("app.ADMINS", frozenset({"admin"})):
            resp = client.delete(
                f"/destroy/testuser/{hostile_fp}",
                headers={"REMOTE-USER": "admin"},
            )
        assert resp.status_code == 400
        assert hostile_fp not in resp.text
