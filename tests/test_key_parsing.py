"""
Tests for #003 — Comment-Field Key Type Injection

Covers:
  - _key_type_from_wire() unit tests (wire-format extraction, error cases)
  - RFC 4716 header parsing (multi-line continuations, non-Comment headers)
  - determine_public_key() integration tests via upload endpoint (AC-1 through AC-8)

Test keys are generated at test time via paramiko — no private key material committed.
Requires tests/conftest.py for loguru → caplog propagation.
"""
import sys
import os
import base64
import struct
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app import _key_type_from_wire, app


# ---------------------------------------------------------------------------
# Helpers — generate real SSH keys at test time
# ---------------------------------------------------------------------------

def _make_ed25519_key() -> paramiko.Ed25519Key:
    """Generate a real ED25519 key using cryptography library (paramiko 4.0 compat)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pubkey_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    type_str = b'ssh-ed25519'
    wire = struct.pack('>I', len(type_str)) + type_str + struct.pack('>I', len(pubkey_bytes)) + pubkey_bytes
    return paramiko.Ed25519Key(data=wire)


def _make_ed25519_wire() -> bytes:
    """Generate a real ED25519 public key and return raw wire-format bytes."""
    return base64.b64decode(_make_ed25519_key().get_base64())


def _make_rsa_wire() -> bytes:
    """Generate a real RSA-2048 public key and return raw wire-format bytes."""
    key = paramiko.RSAKey.generate(2048)
    return base64.b64decode(key.get_base64())


def _wrap_rfc4716(key: paramiko.PKey, comment: str | None = None) -> str:
    """Wrap a paramiko key in RFC 4716 SSH2 PUBLIC KEY block format."""
    b64 = key.get_base64()
    lines = ["---- BEGIN SSH2 PUBLIC KEY ----"]
    if comment is not None:
        lines.append(f"Comment: {comment}")
    # RFC 4716 lines are max 72 chars
    for i in range(0, len(b64), 72):
        lines.append(b64[i:i+72])
    lines.append("---- END SSH2 PUBLIC KEY ----")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unit tests: _key_type_from_wire()
# ---------------------------------------------------------------------------

class TestKeyTypeFromWire:
    """Wire-format extraction — no paramiko objects needed."""

    def test_ed25519_wire_type_extracted_correctly(self):
        raw = _make_ed25519_wire()
        assert _key_type_from_wire(raw) == "ssh-ed25519"

    def test_rsa_wire_type_extracted_correctly(self):
        raw = _make_rsa_wire()
        assert _key_type_from_wire(raw) == "ssh-rsa"

    def test_too_short_raises_value_error(self):
        with pytest.raises(ValueError, match="too short"):
            _key_type_from_wire(b"\x00\x00")

    def test_exactly_3_bytes_raises_value_error(self):
        with pytest.raises(ValueError, match="too short"):
            _key_type_from_wire(b"\x00\x00\x00")

    def test_type_len_overflow_raises_value_error(self):
        # type_len = 100, but only 4 bytes of data follow (need 100)
        data = struct.pack('>I', 100) + b'x' * 4
        with pytest.raises(ValueError, match="overflows"):
            _key_type_from_wire(data)

    def test_type_len_exceeds_sanity_limit_raises_value_error(self):
        # type_len = 300 > 256 sanity cap
        data = struct.pack('>I', 300) + b'x' * 300
        with pytest.raises(ValueError, match="sanity limit"):
            _key_type_from_wire(data)

    def test_unknown_but_valid_format_returns_string(self):
        # Craft a valid wire-format blob with an unknown type string
        type_str = b"x-fake-key-type"
        data = struct.pack('>I', len(type_str)) + type_str + b'\x00' * 16
        result = _key_type_from_wire(data)
        assert result == "x-fake-key-type"

    def test_non_ascii_type_raises_value_error(self):
        # Non-ASCII bytes in type field → UnicodeDecodeError (subclass of ValueError)
        type_bytes = b"\xff\xfe"
        data = struct.pack('>I', len(type_bytes)) + type_bytes + b'\x00' * 16
        with pytest.raises(ValueError):
            _key_type_from_wire(data)


# ---------------------------------------------------------------------------
# Unit tests: RFC 4716 header parsing loop
# ---------------------------------------------------------------------------

class TestRfc4716HeaderParsing:
    """Verify header skipping logic without involving paramiko key decode."""

    def _parse_base64_from_block(self, block: str) -> str:
        """Replicate the parsing loop to extract raw base64 accumulation."""
        import re as _re
        RFC4716_HEADER_RE = _re.compile(r'^[A-Za-z][A-Za-z0-9-]*:')
        in_key_block = False
        in_header = False
        key_data_base64 = ""
        for line in block.splitlines():
            if line.strip() == "---- BEGIN SSH2 PUBLIC KEY ----":
                in_key_block = True
                continue
            elif line.strip() == "---- END SSH2 PUBLIC KEY ----":
                break
            if in_key_block:
                if in_header:
                    in_header = line.rstrip().endswith('\\')
                    continue
                if RFC4716_HEADER_RE.match(line.strip()):
                    in_header = line.rstrip().endswith('\\')
                    continue
                key_data_base64 += line.strip()
        return key_data_base64

    def test_comment_header_skipped(self):
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            "Comment: my laptop key\n"
            "AAAA\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        assert self._parse_base64_from_block(block) == "AAAA"

    def test_subject_header_skipped(self):
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            "Subject: alice@example.com\n"
            "BBBB\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        assert self._parse_base64_from_block(block) == "BBBB"

    def test_custom_x_header_skipped(self):
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            "x-custom-header: some value\n"
            "CCCC\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        assert self._parse_base64_from_block(block) == "CCCC"

    def test_multiline_header_continuation_skipped(self):
        # Comment spans two lines via backslash continuation
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            "Comment: this is a very long comment that continues \\\n"
            "on the next line\n"
            "DDDD\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        assert self._parse_base64_from_block(block) == "DDDD"

    def test_multiple_headers_all_skipped(self):
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            "Comment: my key\n"
            "Subject: alice\n"
            "x-foo: bar\n"
            "EEEE\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        assert self._parse_base64_from_block(block) == "EEEE"

    def test_no_headers_base64_collected(self):
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            "FFFF\n"
            "GGGG\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        assert self._parse_base64_from_block(block) == "FFFFGGGG"


# ---------------------------------------------------------------------------
# Integration tests: determine_public_key() via upload endpoint
# ---------------------------------------------------------------------------

def _make_upload_client():
    """Return a TestClient with Redis mocked out."""
    mock_redis = AsyncMock()
    mock_redis.hgetall = AsyncMock(return_value={})
    mock_redis.hset = AsyncMock(return_value=True)
    mock_redis.hexpire = AsyncMock(return_value=True)

    async def empty_scan(*args, **kwargs):
        return
        yield

    mock_redis.scan_iter = empty_scan

    client = TestClient(app, raise_server_exceptions=False)
    return client, mock_redis


@pytest.fixture()
def upload_client():
    client, mock_redis = _make_upload_client()
    with patch("app.app.state", MagicMock(redis_client=mock_redis)):
        yield client, mock_redis


def _post_key(client, mock_redis, key_block: str, username: str = "testuser"):
    """POST a key block to /upload/{username} with Redis patched."""
    with patch("app.app.state", MagicMock(redis_client=mock_redis)):
        return client.post(
            f"/upload/{username}",
            json={"public_key": key_block},
            headers={"REMOTE-USER": username},
        )


class TestDeterminePublicKey:
    """Integration tests — uses real paramiko encode/decode."""

    def test_rsa_key_with_ed25519_comment_parsed_as_rsa(self):
        """AC-1: RSA key + 'ED25519' in comment → stored as ssh-rsa."""
        rsa_key = paramiko.RSAKey.generate(2048)
        block = _wrap_rfc4716(rsa_key, comment="256-bit ED25519 key")
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 201
        # Verify the stored key_type is ssh-rsa (not ssh-ed25519)
        stored = mock_redis.hset.call_args[1]["mapping"]
        assert stored["key_type"] == "ssh-rsa"

    def test_ed25519_key_with_rsa_comment_parsed_as_ed25519(self):
        """AC-2: ED25519 key + 'RSA' in comment → stored as ssh-ed25519."""
        ed_key = _make_ed25519_key()
        block = _wrap_rfc4716(ed_key, comment="4096-bit RSA key for servers")
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 201
        stored = mock_redis.hset.call_args[1]["mapping"]
        assert stored["key_type"] == "ssh-ed25519"

    def test_key_with_generic_comment_uploads_successfully(self):
        """AC-3: key with 'my laptop key' comment (no type keyword) → 201."""
        ed_key = _make_ed25519_key()
        block = _wrap_rfc4716(ed_key, comment="my laptop key")
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 201

    def test_key_with_no_comment_uploads_successfully(self):
        """AC-7: valid key with no Comment header → 201."""
        ed_key = _make_ed25519_key()
        block = _wrap_rfc4716(ed_key, comment=None)
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 201

    def test_truncated_base64_returns_400(self):
        """AC-4: base64 that decodes to < 4 bytes → 400."""
        # 3 base64 chars → 2 bytes after decode (too short for wire format)
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            "AAA=\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 400

    def test_wire_type_overflow_returns_400(self):
        """AC-5: type_len overflows available data → 400."""
        # type_len = 100 but only 4 bytes follow
        raw = struct.pack('>I', 100) + b'x' * 4
        b64 = base64.b64encode(raw).decode()
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            f"{b64}\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 400

    def test_unknown_wire_type_returns_400(self):
        """AC-6: unknown wire type string → paramiko rejects it → 400."""
        type_str = b"x-fake-key-type"
        raw = struct.pack('>I', len(type_str)) + type_str + b'\x00' * 32
        b64 = base64.b64encode(raw).decode()
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            f"{b64}\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 400

    def test_invalid_base64_characters_returns_400(self):
        """Invalid base64 characters (not a valid encoding) → 400."""
        block = (
            "---- BEGIN SSH2 PUBLIC KEY ----\n"
            "!!!not-valid-base64!!!\n"
            "---- END SSH2 PUBLIC KEY ----"
        )
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 400

    def test_missing_key_block_returns_400(self):
        """No SSH2 PUBLIC KEY block at all → 400."""
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": "not a key block"},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 400

    def test_rsa_key_correct_comment_still_works(self):
        """AC-8: existing valid upload with correct comment is unaffected."""
        rsa_key = paramiko.RSAKey.generate(2048)
        block = _wrap_rfc4716(rsa_key, comment="RSA 2048 key")
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 201
        stored = mock_redis.hset.call_args[1]["mapping"]
        assert stored["key_type"] == "ssh-rsa"

    def test_ed25519_key_correct_comment_still_works(self):
        """AC-8: existing valid ED25519 upload with correct comment is unaffected."""
        ed_key = _make_ed25519_key()
        block = _wrap_rfc4716(ed_key, comment="ED25519 key")
        client, mock_redis = _make_upload_client()
        with patch("app.app.state", MagicMock(redis_client=mock_redis)):
            resp = client.post(
                "/upload/testuser",
                json={"public_key": block},
                headers={"REMOTE-USER": "testuser"},
            )
        assert resp.status_code == 201
        stored = mock_redis.hset.call_args[1]["mapping"]
        assert stored["key_type"] == "ssh-ed25519"
