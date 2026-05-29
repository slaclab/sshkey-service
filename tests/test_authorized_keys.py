"""
Tests for the /authorized_keys/{username} endpoint filtering logic.

The endpoint filters keys based on:
  - IS_ACTIVE_FIELD must be present
  - valid_until must be in the future
  - expires_at must be in the future OR equal EPOCH_NEVER_EXPIRE
  - valid_until must be before expires_at (unless expires_at == EPOCH_NEVER_EXPIRE)

Blacklisted keys are NOT filtered out — they are included in the keys list
with is_blacklisted=True so the template can handle them.
"""
import pytest
import pendulum
from unittest.mock import Mock, patch, AsyncMock
from fastapi import Request

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app import (
    get_authorized_keys,
    EPOCH_NEVER_EXPIRE,
    IS_ACTIVE_FIELD,
    reload_blacklist,
    blacklist_lock,
    blacklist_fingerprints,
)

VALID_FP = "SHA256:" + "A" * 43
VALID_FP2 = "SHA256:" + "B" * 43


@pytest.fixture
def mock_redis():
    redis_mock = AsyncMock()
    redis_mock.hgetall = AsyncMock()
    redis_mock.scan_iter = AsyncMock()
    return redis_mock


PAST = pendulum.datetime(2020, 1, 1)    # unambiguously in the past (not computed via add/subtract)
FUTURE = pendulum.datetime(2030, 1, 1)  # unambiguously in the future


def _make_key(now, *, finger_print=VALID_FP, has_active=True, valid_until=None,
              expires_at=None):
    """Build a key bundle with pendulum DateTime objects.

    Use the module-level PAST/FUTURE constants for valid_until to avoid
    pendulum 3.x arithmetic bugs that corrupt relative add/subtract results.
    """
    key = {
        'username': 'testuser',
        'finger_print': finger_print,
        'public_key': 'AAAAC3NzaC1lZDI1NTE5AAAAIGs4y2orDiyCSpY',
        'key_type': 'ssh-ed25519',
        'key_bits': '256',
        'source_ip': '127.0.0.1',
        'created_at': PAST,
        'valid_until': valid_until if valid_until is not None else FUTURE,
        'expires_at': expires_at if expires_at is not None else EPOCH_NEVER_EXPIRE,
        'user_notes': '',
    }
    if has_active:
        key[IS_ACTIVE_FIELD] = '1'
    return key


async def _call_get_authorized_keys(mock_redis, keys_by_fp, *, username='testuser'):
    """
    Helper: sets up redis mock with multiple keys, calls get_authorized_keys,
    and returns the keys list that would be passed to the template.
    """
    async def mock_scan(*args, **kwargs):
        for fp in keys_by_fp:
            yield f"user:{username}:{fp}"

    mock_redis.scan_iter = mock_scan

    fp_list = list(keys_by_fp.keys())
    call_count = [-1]

    async def mock_hgetall(redis_key):
        call_count[0] += 1
        fp = fp_list[call_count[0] % len(fp_list)]
        key = keys_by_fp[fp]
        return {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v
            for k, v in key.items()
        }

    mock_redis.hgetall.side_effect = mock_hgetall

    mock_request = Mock(spec=Request)

    convert_call_count = [-1]

    def mock_convert(item):
        convert_call_count[0] += 1
        return list(keys_by_fp.values())[convert_call_count[0] % len(keys_by_fp)]

    captured = {}

    def fake_template_response(name, request, context):
        captured.update(context)
        return Mock(status_code=200, context=context)

    with patch('app.BLACKLIST_FILE', ''), \
         patch('app.convert_key_bundle_to_pendulum', side_effect=mock_convert), \
         patch('app.templates') as mock_tmpl:
        mock_tmpl.TemplateResponse.side_effect = fake_template_response
        await get_authorized_keys(
            request=mock_request,
            username=username,
            redis=mock_redis,
        )

    return captured.get('keys', [])


class TestAuthorizedKeysFiltering:

    @pytest.mark.asyncio
    async def test_valid_key_with_epoch_never_expire_is_included(self, mock_redis):
        key = _make_key(None, expires_at=EPOCH_NEVER_EXPIRE)
        keys = await _call_get_authorized_keys(mock_redis, {VALID_FP: key})
        assert len(keys) == 1
        assert keys[0]['finger_print'] == VALID_FP

    @pytest.mark.asyncio
    async def test_key_without_is_active_field_is_excluded(self, mock_redis):
        key = _make_key(None, has_active=False)
        keys = await _call_get_authorized_keys(mock_redis, {VALID_FP: key})
        assert len(keys) == 0

    @pytest.mark.asyncio
    async def test_key_with_expired_valid_until_is_excluded(self, mock_redis):
        # valid_until=PAST (2020) is unambiguously in the past.
        # Avoid pendulum 3.x arithmetic bug where now.subtract() gives a future timestamp.
        key = _make_key(None, valid_until=PAST)
        keys = await _call_get_authorized_keys(mock_redis, {VALID_FP: key})
        assert len(keys) == 0

    @pytest.mark.asyncio
    async def test_key_with_past_expires_at_is_excluded(self, mock_redis):
        key = _make_key(None, expires_at=PAST)
        keys = await _call_get_authorized_keys(mock_redis, {VALID_FP: key})
        assert len(keys) == 0

    @pytest.mark.asyncio
    async def test_key_where_valid_until_exceeds_expires_at_is_excluded(self, mock_redis):
        # expires_at (2028) is in the future; valid_until (2029) exceeds it — violates constraint.
        expires_at = pendulum.datetime(2028, 1, 1)
        valid_until = pendulum.datetime(2029, 1, 1)
        key = _make_key(None, valid_until=valid_until, expires_at=expires_at)
        assert key['valid_until'] > key['expires_at']
        keys = await _call_get_authorized_keys(mock_redis, {VALID_FP: key})
        assert len(keys) == 0

    @pytest.mark.asyncio
    async def test_key_with_future_expiry_and_valid_until_before_expiry_is_included(self, mock_redis):
        expires_at = pendulum.datetime(2029, 1, 1)
        valid_until = pendulum.datetime(2028, 1, 1)
        key = _make_key(None, valid_until=valid_until, expires_at=expires_at)
        assert key['valid_until'] < key['expires_at']
        keys = await _call_get_authorized_keys(mock_redis, {VALID_FP: key})
        assert len(keys) == 1

    @pytest.mark.asyncio
    async def test_multiple_keys_only_valid_ones_included(self, mock_redis):
        valid_key = _make_key(None, finger_print=VALID_FP, expires_at=EPOCH_NEVER_EXPIRE)
        expired_key = _make_key(None, finger_print=VALID_FP2, valid_until=PAST)

        async def mock_scan(*args, **kwargs):
            yield f"user:testuser:{VALID_FP}"
            yield f"user:testuser:{VALID_FP2}"

        mock_redis.scan_iter = mock_scan

        convert_returns = [valid_key, expired_key]
        call_count = [-1]

        def mock_convert(item):
            call_count[0] += 1
            return convert_returns[call_count[0]]

        hgetall_returns = [
            {k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v for k, v in valid_key.items()},
            {k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v for k, v in expired_key.items()},
        ]
        hgetall_count = [-1]

        async def mock_hgetall(redis_key):
            hgetall_count[0] += 1
            return hgetall_returns[hgetall_count[0] % 2]

        mock_redis.hgetall.side_effect = mock_hgetall
        captured = {}

        def fake_template_response(name, request, context):
            captured.update(context)
            return Mock(status_code=200, context=context)

        mock_request = Mock(spec=Request)

        with patch('app.BLACKLIST_FILE', ''), \
             patch('app.convert_key_bundle_to_pendulum', side_effect=mock_convert), \
             patch('app.templates') as mock_tmpl:
            mock_tmpl.TemplateResponse.side_effect = fake_template_response
            await get_authorized_keys(
                request=mock_request,
                username='testuser',
                redis=mock_redis,
            )

        keys = captured.get('keys', [])
        assert len(keys) == 1
        assert keys[0]['finger_print'] == VALID_FP

    @pytest.mark.asyncio
    async def test_blacklisted_key_is_included_but_marked(self, mock_redis, tmp_path):
        key = _make_key(None, finger_print=VALID_FP, expires_at=EPOCH_NEVER_EXPIRE)

        blacklist_file = tmp_path / 'blacklist.txt'
        blacklist_file.write_text(f"{VALID_FP}\n")

        with patch('app.BLACKLIST_FILE', str(blacklist_file)):
            reload_blacklist()

        async def mock_scan(*args, **kwargs):
            yield f"user:testuser:{VALID_FP}"

        mock_redis.scan_iter = mock_scan
        mock_redis.hgetall.return_value = {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v
            for k, v in key.items()
        }
        captured = {}

        def fake_template_response(name, request, context):
            captured.update(context)
            return Mock(status_code=200, context=context)

        mock_request = Mock(spec=Request)

        with patch('app.convert_key_bundle_to_pendulum', return_value=key), \
             patch('app.templates') as mock_tmpl:
            mock_tmpl.TemplateResponse.side_effect = fake_template_response
            await get_authorized_keys(
                request=mock_request,
                username='testuser',
                redis=mock_redis,
            )

        keys = captured.get('keys', [])
        assert len(keys) == 1
        assert keys[0]['is_blacklisted'] is True

        # cleanup
        with patch('app.BLACKLIST_FILE', ''):
            reload_blacklist()

    @pytest.mark.asyncio
    async def test_non_blacklisted_key_is_marked_false(self, mock_redis, tmp_path):
        key = _make_key(None, expires_at=EPOCH_NEVER_EXPIRE)

        blacklist_file = tmp_path / 'blacklist.txt'
        blacklist_file.write_text("# empty\n")

        with patch('app.BLACKLIST_FILE', str(blacklist_file)):
            reload_blacklist()

        async def mock_scan(*args, **kwargs):
            yield f"user:testuser:{VALID_FP}"

        mock_redis.scan_iter = mock_scan
        mock_redis.hgetall.return_value = {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v
            for k, v in key.items()
        }
        captured = {}

        def fake_template_response(name, request, context):
            captured.update(context)
            return Mock(status_code=200, context=context)

        mock_request = Mock(spec=Request)

        with patch('app.convert_key_bundle_to_pendulum', return_value=key), \
             patch('app.templates') as mock_tmpl:
            mock_tmpl.TemplateResponse.side_effect = fake_template_response
            await get_authorized_keys(
                request=mock_request,
                username='testuser',
                redis=mock_redis,
            )

        keys = captured.get('keys', [])
        assert len(keys) == 1
        assert keys[0]['is_blacklisted'] is False

    @pytest.mark.asyncio
    async def test_empty_redis_returns_empty_keys_list(self, mock_redis):
        async def mock_scan(*args, **kwargs):
            return
            yield  # make it an async generator

        mock_redis.scan_iter = mock_scan
        mock_request = Mock(spec=Request)
        captured = {}

        def fake_template_response(name, request, context):
            captured.update(context)
            return Mock(status_code=200, context=context)

        with patch('app.BLACKLIST_FILE', ''), \
             patch('app.templates') as mock_tmpl:
            mock_tmpl.TemplateResponse.side_effect = fake_template_response
            await get_authorized_keys(
                request=mock_request,
                username='testuser',
                redis=mock_redis,
            )

        assert captured.get('keys', []) == []
