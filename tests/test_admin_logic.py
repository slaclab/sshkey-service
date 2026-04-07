"""
Tests for #002 — Weak Admin Logic

Covers:
  - _parse_admins() unit tests (AC-1 through AC-4, FR-1 through FR-7)
  - auth_okay() integration tests (AC-5, AC-6, AC-7)

Follows the same mock patterns as tests/test_blacklist.py.
Requires tests/conftest.py for loguru → caplog propagation.
"""
import sys
import os
import pytest
from unittest.mock import Mock, AsyncMock, patch
from fastapi import HTTPException

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import _parse_admins


# ---------------------------------------------------------------------------
# Unit tests: _parse_admins()
# ---------------------------------------------------------------------------

class TestParseAdmins:
    """FR-1 through FR-7 / AC-1 through AC-4"""

    def test_valid_two_admins(self):
        """AC-1: clean comma-separated list — no warnings, correct frozenset."""
        result = _parse_admins("admin1,admin2")
        assert result == frozenset({'admin1', 'admin2'})

    def test_whitespace_normalisation(self):
        """FR-2: leading/trailing whitespace around each entry is stripped."""
        result = _parse_admins(" admin1 , admin2 ")
        assert result == frozenset({'admin1', 'admin2'})

    def test_empty_string_produces_empty_set_and_both_warnings(self, caplog):
        """AC-3: SLACSSH_ADMINS="" → frozenset(); both empty-entries and no-admins warnings fire.

        ''.split(',') → [''] → 1 empty entry counted, 0 valid entries.
        Both FR-4 and FR-5 warnings must be emitted.
        """
        result = _parse_admins("")
        assert result == frozenset()
        assert "empty" in caplog.text.lower()
        assert "no admin users configured" in caplog.text.lower()

    def test_only_commas_produces_empty_set_and_both_warnings(self, caplog):
        """AC-4: SLACSSH_ADMINS="," → frozenset(); both warnings fire."""
        result = _parse_admins(",")
        assert result == frozenset()
        assert "empty" in caplog.text.lower()
        assert "no admin users configured" in caplog.text.lower()

    def test_multiple_commas_produces_empty_set_and_both_warnings(self, caplog):
        """AC-4 extended: SLACSSH_ADMINS=",,," → frozenset(); both warnings fire."""
        result = _parse_admins(",,,")
        assert result == frozenset()
        assert "empty" in caplog.text.lower()
        assert "no admin users configured" in caplog.text.lower()

    def test_empty_entry_in_middle_is_filtered_with_warning(self, caplog):
        """AC-2 / FR-3 / FR-4: double-comma middle entry is dropped; warning logged."""
        result = _parse_admins("admin1,,admin2")
        assert result == frozenset({'admin1', 'admin2'})
        assert "empty" in caplog.text.lower()

    def test_whitespace_only_entry_is_filtered_with_warning(self, caplog):
        """FR-3 / FR-4: whitespace-only entry is treated as empty and filtered."""
        result = _parse_admins("admin1,   ,admin2")
        assert result == frozenset({'admin1', 'admin2'})
        assert "empty" in caplog.text.lower()

    def test_single_admin(self):
        """Single entry — no warnings expected."""
        result = _parse_admins("admin1")
        assert result == frozenset({'admin1'})

    def test_returns_frozenset(self):
        """FR-1: return type must be frozenset (immutable)."""
        result = _parse_admins("admin1")
        assert isinstance(result, frozenset)

    def test_no_warning_for_clean_input(self, caplog):
        """AC-1: clean input produces no warnings."""
        _parse_admins("admin1,admin2")
        assert "empty" not in caplog.text.lower()
        assert "no admin" not in caplog.text.lower()

    def test_trailing_comma_warns(self, caplog):
        """FR-4: trailing comma creates an empty entry — warning should fire."""
        result = _parse_admins("admin1,")
        assert result == frozenset({'admin1'})
        assert "empty" in caplog.text.lower()


# ---------------------------------------------------------------------------
# Integration tests: auth_okay() uses module-level ADMINS
# ---------------------------------------------------------------------------

class TestAdminCheckInAuthOkay:
    """
    AC-5, AC-6, AC-7 — verifies that auth_okay() uses the module-level ADMINS
    frozenset rather than calling os.getenv() per request.

    Pattern: patch('app.ADMINS') to a known frozenset, patch('app.auth') to
    return a controlled username, then invoke the decorated endpoint directly.
    """

    @pytest.mark.asyncio
    async def test_admin_user_passes_admin_only_endpoint(self):
        """AC-5: known admin can access admin-only endpoint (no 403)."""
        mock_request = Mock()
        mock_redis = AsyncMock()
        # destroy needs hgetall to return something so it doesn't 404 first
        mock_redis.hgetall = AsyncMock(return_value={'username': 'targetuser'})
        mock_redis.delete = AsyncMock(return_value=1)

        with patch('app.ADMINS', frozenset({'superuser'})):
            with patch('app.auth', return_value='superuser'):
                from app import destroy_user_keypair
                # Should NOT raise 403 — any other exception (404 etc.) is acceptable
                try:
                    await destroy_user_keypair(
                        request=mock_request,
                        username='targetuser',
                        finger_print='SHA256:abc123',
                        redis=mock_redis,
                        found_username=None,
                    )
                except HTTPException as e:
                    assert e.status_code != 403, (
                        f"Admin 'superuser' should not get 403, but got {e.status_code}: {e.detail}"
                    )

    @pytest.mark.asyncio
    async def test_non_admin_blocked_from_admin_only_endpoint(self):
        """AC-6: non-admin gets 403 on admin-only endpoint."""
        mock_request = Mock()
        mock_redis = AsyncMock()

        with patch('app.ADMINS', frozenset({'superuser'})):
            with patch('app.auth', return_value='regularuser'):
                from app import destroy_user_keypair
                with pytest.raises(HTTPException) as exc_info:
                    await destroy_user_keypair(
                        request=mock_request,
                        username='targetuser',
                        finger_print='SHA256:abc123',
                        redis=mock_redis,
                        found_username=None,
                    )
                assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_user_can_access_own_resource_regardless_of_admins(self):
        """AC-7: user accessing their own resource succeeds even with empty ADMINS."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_redis = AsyncMock()

        async def empty_scan(*args, **kwargs):
            return
            yield  # make it an async generator

        mock_redis.scan_iter = empty_scan

        with patch('app.ADMINS', frozenset()):   # no admins configured
            with patch('app.auth', return_value='alice'):
                from app import list_user_keypair
                # alice accessing /list/alice — should not raise 403
                try:
                    await list_user_keypair(
                        request=mock_request,
                        username='alice',
                        redis=mock_redis,
                        found_username=None,
                    )
                except HTTPException as e:
                    assert e.status_code != 403, (
                        f"User accessing own resource should not get 403, got {e.status_code}"
                    )

    @pytest.mark.asyncio
    async def test_admin_can_access_other_users_resource(self):
        """FR-6: admin can access another user's non-admin endpoint."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_redis = AsyncMock()

        async def empty_scan(*args, **kwargs):
            return
            yield  # make it an async generator

        mock_redis.scan_iter = empty_scan

        with patch('app.ADMINS', frozenset({'superuser'})):
            with patch('app.auth', return_value='superuser'):
                from app import list_user_keypair
                # superuser accessing /list/alice — should not raise 403
                try:
                    await list_user_keypair(
                        request=mock_request,
                        username='alice',
                        redis=mock_redis,
                        found_username=None,
                    )
                except HTTPException as e:
                    assert e.status_code != 403, (
                        f"Admin accessing other user's resource should not get 403, got {e.status_code}"
                    )
