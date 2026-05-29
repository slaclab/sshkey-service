"""
Tests for the /refresh/{username}/{finger_print} endpoint.

Business logic under test:
  - NO_EXPIRY=True: always sets expires_at=EPOCH_NEVER_EXPIRE and extends valid_until
  - NO_EXPIRY=False + expired key: raises HTTP 400
  - NO_EXPIRY=False + EPOCH key: converts to expiry key, then extends normally
  - NO_EXPIRY=False + expiry key, extension <= expires_at: valid_until = extension
  - NO_EXPIRY=False + expiry key, extension > expires_at: valid_until capped at expires_at
"""
import pytest
import pendulum
from unittest.mock import Mock, patch, AsyncMock
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app import (
    refresh_user_keypair,
    EPOCH_NEVER_EXPIRE,
    IS_ACTIVE_FIELD,
)

# Valid fingerprint: SHA256: + exactly 43 chars from [A-Za-z0-9.]
VALID_FP = "SHA256:" + "A" * 43


@pytest.fixture
def mock_redis():
    redis_mock = AsyncMock()
    redis_mock.hgetall = AsyncMock()
    redis_mock.hset = AsyncMock()
    redis_mock.delete = AsyncMock()
    redis_mock.hexpire = AsyncMock()
    return redis_mock


def _stored_key(now, expires_at=None):
    """Return the ISO-string dict as stored in Redis."""
    exp = expires_at if expires_at is not None else EPOCH_NEVER_EXPIRE
    return {
        'username': 'testuser',
        'finger_print': VALID_FP,
        'public_key': 'AAAAC3NzaC1lZDI1NTE5AAAAIGs4y2orDiyCSpY',
        'key_type': 'ssh-ed25519',
        'key_bits': '256',
        'source_ip': '127.0.0.1',
        'created_at': now.subtract(hours=1).to_iso8601_string(),
        'valid_until': now.add(hours=1).to_iso8601_string(),
        'expires_at': exp.to_iso8601_string(),
        'user_notes': '',
        IS_ACTIVE_FIELD: '1',
    }


def _pendulum_key(now, expires_at=None):
    """Return the pendulum-object dict as returned by convert_key_bundle_to_pendulum."""
    exp = expires_at if expires_at is not None else EPOCH_NEVER_EXPIRE
    return {
        'username': 'testuser',
        'finger_print': VALID_FP,
        'public_key': 'AAAAC3NzaC1lZDI1NTE5AAAAIGs4y2orDiyCSpY',
        'key_type': 'ssh-ed25519',
        'key_bits': '256',
        'source_ip': '127.0.0.1',
        'created_at': now.subtract(hours=1),
        'valid_until': now.add(hours=1),
        'expires_at': exp,
        'user_notes': '',
        IS_ACTIVE_FIELD: '1',
    }


def _get_written_mapping(mock_redis):
    """Extract the mapping dict passed to redis.hset."""
    return mock_redis.hset.call_args.kwargs['mapping']


class TestRefreshNoExpiryTrue:

    @pytest.mark.asyncio
    async def test_sets_expires_at_to_epoch(self, mock_redis):
        now = pendulum.now()
        mock_redis.hgetall.return_value = _stored_key(now)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', True), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now)):
            await refresh_user_keypair(
                request=mock_request,
                username='testuser',
                finger_print=VALID_FP,
                redis=mock_redis,
            )

        written = _get_written_mapping(mock_redis)
        assert pendulum.parse(written['expires_at']) == EPOCH_NEVER_EXPIRE

    @pytest.mark.asyncio
    async def test_extends_valid_until_forward(self, mock_redis):
        now = pendulum.now()
        mock_redis.hgetall.return_value = _stored_key(now)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', True), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now)):
            await refresh_user_keypair(
                request=mock_request,
                username='testuser',
                finger_print=VALID_FP,
                extend_seconds=3600,
                redis=mock_redis,
            )

        written = _get_written_mapping(mock_redis)
        new_valid_until = pendulum.parse(written['valid_until'])
        assert new_valid_until > now
        expected = now.add(seconds=3600)
        assert abs((new_valid_until - expected).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_returns_json_202_response(self, mock_redis):
        now = pendulum.now()
        mock_redis.hgetall.return_value = _stored_key(now)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', True), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now)):
            response = await refresh_user_keypair(
                request=mock_request,
                username='testuser',
                finger_print=VALID_FP,
                redis=mock_redis,
            )

        assert isinstance(response, JSONResponse)
        assert response.status_code == 202

    @pytest.mark.asyncio
    async def test_no_expiry_true_converts_existing_expiry_key_to_epoch(self, mock_redis):
        """Even if the key had a real expires_at, NO_EXPIRY=True should override it."""
        now = pendulum.now()
        expiry = now.add(days=7)
        mock_redis.hgetall.return_value = _stored_key(now, expires_at=expiry)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', True), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now, expires_at=expiry)):
            await refresh_user_keypair(
                request=mock_request,
                username='testuser',
                finger_print=VALID_FP,
                redis=mock_redis,
            )

        written = _get_written_mapping(mock_redis)
        assert pendulum.parse(written['expires_at']) == EPOCH_NEVER_EXPIRE


class TestRefreshNoExpiryFalse:

    @pytest.mark.asyncio
    async def test_raises_400_on_expired_key(self, mock_redis):
        now = pendulum.now()
        # Use absolute past — pendulum 3.x arithmetic is broken on non-UTC hosts.
        past_expiry = pendulum.datetime(2020, 1, 1)
        mock_redis.hgetall.return_value = _stored_key(now, expires_at=past_expiry)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', False), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now, expires_at=past_expiry)):
            with pytest.raises(HTTPException) as exc:
                await refresh_user_keypair(
                    request=mock_request,
                    username='testuser',
                    finger_print=VALID_FP,
                    redis=mock_redis,
                )

        assert exc.value.status_code == 400
        assert 'expiry' in exc.value.detail.lower()

    @pytest.mark.asyncio
    async def test_converts_epoch_key_to_expiry_key(self, mock_redis):
        """When NO_EXPIRY=False and the key has EPOCH expires_at, assign a real expiry."""
        now = pendulum.now()
        mock_redis.hgetall.return_value = _stored_key(now, expires_at=EPOCH_NEVER_EXPIRE)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', False), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now, expires_at=EPOCH_NEVER_EXPIRE)):
            await refresh_user_keypair(
                request=mock_request,
                username='testuser',
                finger_print=VALID_FP,
                expires_seconds=604800,
                redis=mock_redis,
            )

        written = _get_written_mapping(mock_redis)
        new_expires_at = pendulum.parse(written['expires_at'])
        assert new_expires_at != EPOCH_NEVER_EXPIRE
        expected_expiry = now.add(seconds=604800)
        assert abs((new_expires_at - expected_expiry).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_caps_valid_until_at_expires_at(self, mock_redis):
        """When extension would go past expires_at, clamp valid_until to expires_at."""
        now = pendulum.now()
        soon_expiry = now.add(hours=1)  # expires in 1 hour
        mock_redis.hgetall.return_value = _stored_key(now, expires_at=soon_expiry)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', False), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now, expires_at=soon_expiry)):
            await refresh_user_keypair(
                request=mock_request,
                username='testuser',
                finger_print=VALID_FP,
                extend_seconds=90000,  # > 1 hour, would overshoot
                redis=mock_redis,
            )

        written = _get_written_mapping(mock_redis)
        new_valid_until = pendulum.parse(written['valid_until'])
        assert abs((new_valid_until - soon_expiry).total_seconds()) < 5

    @pytest.mark.asyncio
    async def test_extends_valid_until_when_within_expiry_window(self, mock_redis):
        """When extension fits within expires_at, valid_until = now + extend_seconds."""
        now = pendulum.now()
        far_expiry = now.add(days=30)
        mock_redis.hgetall.return_value = _stored_key(now, expires_at=far_expiry)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        extend_seconds = 3600
        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', False), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now, expires_at=far_expiry)):
            await refresh_user_keypair(
                request=mock_request,
                username='testuser',
                finger_print=VALID_FP,
                extend_seconds=extend_seconds,
                redis=mock_redis,
            )

        written = _get_written_mapping(mock_redis)
        new_valid_until = pendulum.parse(written['valid_until'])
        expected = now.add(seconds=extend_seconds)
        assert abs((new_valid_until - expected).total_seconds()) < 5


class TestRefreshEdgeCases:

    @pytest.mark.asyncio
    async def test_raises_404_when_key_not_found(self, mock_redis):
        mock_redis.hgetall.return_value = {}
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', True):
            with pytest.raises(HTTPException) as exc:
                await refresh_user_keypair(
                    request=mock_request,
                    username='testuser',
                    finger_print=VALID_FP,
                    redis=mock_redis,
                )

        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_redis_hset_called_with_updated_mapping(self, mock_redis):
        """Verify the updated key bundle is persisted to Redis."""
        now = pendulum.now()
        mock_redis.hgetall.return_value = _stored_key(now)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', True), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now)):
            await refresh_user_keypair(
                request=mock_request,
                username='testuser',
                finger_print=VALID_FP,
                redis=mock_redis,
            )

        mock_redis.hset.assert_called_once()
        written = _get_written_mapping(mock_redis)
        assert written['username'] == 'testuser'
        assert written['finger_print'] == VALID_FP
        assert IS_ACTIVE_FIELD in written

    @pytest.mark.asyncio
    async def test_hexpire_is_called_after_hset(self, mock_redis):
        """TTL renewal must be applied after rewriting the key."""
        now = pendulum.now()
        mock_redis.hgetall.return_value = _stored_key(now)
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', True), \
             patch('app.convert_key_bundle_to_pendulum', return_value=_pendulum_key(now)):
            await refresh_user_keypair(
                request=mock_request,
                username='testuser',
                finger_print=VALID_FP,
                extend_seconds=3600,
                redis=mock_redis,
            )

        mock_redis.hexpire.assert_called_once()
        hexpire_args = mock_redis.hexpire.call_args
        assert hexpire_args.args[1] == 3600  # second positional arg is extend_seconds

    @pytest.mark.asyncio
    async def test_invalid_fingerprint_raises_400(self, mock_redis):
        """Fingerprint must match SHA256:[A-Za-z0-9.]{43}."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {}

        with patch('app.auth', return_value='testuser'), \
             patch('app.NO_EXPIRY', True):
            with pytest.raises(HTTPException) as exc:
                await refresh_user_keypair(
                    request=mock_request,
                    username='testuser',
                    finger_print='SHA256:tooshort',
                    redis=mock_redis,
                )

        assert exc.value.status_code == 400
