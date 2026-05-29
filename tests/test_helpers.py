import pytest
import pendulum
from unittest.mock import Mock, patch
from fastapi import Request

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app import (
    convert_key_bundle_to_iso,
    convert_key_bundle_to_pendulum,
    get_user_email,
    get_response_type,
    ResponseType,
    EPOCH_NEVER_EXPIRE,
)


class TestConvertKeyBundleToIso:

    def test_converts_all_three_datetime_fields(self):
        now = pendulum.now()
        bundle = {
            'created_at': now,
            'valid_until': now.add(hours=1),
            'expires_at': EPOCH_NEVER_EXPIRE,
        }
        result = convert_key_bundle_to_iso(bundle)
        assert isinstance(result['created_at'], str)
        assert isinstance(result['valid_until'], str)
        assert isinstance(result['expires_at'], str)

    def test_non_datetime_fields_are_unchanged(self):
        now = pendulum.now()
        bundle = {
            'created_at': now,
            'valid_until': now.add(hours=1),
            'expires_at': EPOCH_NEVER_EXPIRE,
            'username': 'testuser',
            'public_key': 'ssh-ed25519 AAAA',
        }
        result = convert_key_bundle_to_iso(bundle)
        assert result['username'] == 'testuser'
        assert result['public_key'] == 'ssh-ed25519 AAAA'

    def test_already_string_fields_pass_through_unchanged(self):
        bundle = {
            'created_at': '2026-01-01T00:00:00+00:00',
            'valid_until': '2026-12-31T00:00:00+00:00',
            'expires_at': '1970-01-01T00:00:00+00:00',
        }
        result = convert_key_bundle_to_iso(bundle)
        assert result['created_at'] == '2026-01-01T00:00:00+00:00'
        assert result['valid_until'] == '2026-12-31T00:00:00+00:00'

    def test_does_not_mutate_original_dict(self):
        now = pendulum.now()
        bundle = {'created_at': now, 'valid_until': now, 'expires_at': EPOCH_NEVER_EXPIRE}
        convert_key_bundle_to_iso(bundle)
        assert isinstance(bundle['created_at'], pendulum.DateTime)
        assert isinstance(bundle['expires_at'], pendulum.DateTime)

    def test_missing_datetime_fields_are_skipped(self):
        bundle = {'username': 'testuser', 'public_key': 'ssh-ed25519 AAAA'}
        result = convert_key_bundle_to_iso(bundle)
        assert 'created_at' not in result
        assert result['username'] == 'testuser'

    def test_output_strings_are_iso8601_parseable(self):
        now = pendulum.now()
        bundle = {
            'created_at': now,
            'valid_until': now.add(hours=1),
            'expires_at': EPOCH_NEVER_EXPIRE,
        }
        result = convert_key_bundle_to_iso(bundle)
        for field in ('created_at', 'valid_until', 'expires_at'):
            assert pendulum.parse(result[field]) is not None

    def test_epoch_never_expire_serializes_to_1970(self):
        bundle = {
            'created_at': pendulum.now(),
            'valid_until': pendulum.now().add(hours=1),
            'expires_at': EPOCH_NEVER_EXPIRE,
        }
        result = convert_key_bundle_to_iso(bundle)
        assert pendulum.parse(result['expires_at']) == EPOCH_NEVER_EXPIRE


class TestConvertKeyBundleToPendulum:

    def test_converts_all_three_string_fields(self):
        bundle = {
            'created_at': '2026-01-01T00:00:00+00:00',
            'valid_until': '2026-12-31T00:00:00+00:00',
            'expires_at': '1970-01-01T00:00:00+00:00',
        }
        result = convert_key_bundle_to_pendulum(bundle)
        assert isinstance(result['created_at'], pendulum.DateTime)
        assert isinstance(result['valid_until'], pendulum.DateTime)
        assert isinstance(result['expires_at'], pendulum.DateTime)

    def test_non_datetime_fields_are_unchanged(self):
        bundle = {
            'created_at': '2026-01-01T00:00:00+00:00',
            'valid_until': '2026-12-31T00:00:00+00:00',
            'expires_at': '1970-01-01T00:00:00+00:00',
            'username': 'testuser',
            'finger_print': 'SHA256:abc',
        }
        result = convert_key_bundle_to_pendulum(bundle)
        assert result['username'] == 'testuser'
        assert result['finger_print'] == 'SHA256:abc'

    def test_does_not_mutate_original_dict(self):
        bundle = {
            'created_at': '2026-01-01T00:00:00+00:00',
            'valid_until': '2026-12-31T00:00:00+00:00',
            'expires_at': '1970-01-01T00:00:00+00:00',
        }
        convert_key_bundle_to_pendulum(bundle)
        assert bundle['created_at'] == '2026-01-01T00:00:00+00:00'

    def test_roundtrip_preserves_timestamp(self):
        now = pendulum.now()
        iso_bundle = {
            'created_at': now.to_iso8601_string(),
            'valid_until': now.add(hours=1).to_iso8601_string(),
            'expires_at': EPOCH_NEVER_EXPIRE.to_iso8601_string(),
        }
        pendulum_bundle = convert_key_bundle_to_pendulum(iso_bundle)
        restored = convert_key_bundle_to_iso(pendulum_bundle)
        assert pendulum.parse(restored['created_at']) == pendulum.parse(iso_bundle['created_at'])
        assert pendulum.parse(restored['expires_at']) == EPOCH_NEVER_EXPIRE

    def test_epoch_string_parses_to_epoch_datetime(self):
        bundle = {
            'created_at': '2026-01-01T00:00:00+00:00',
            'valid_until': '2026-12-31T00:00:00+00:00',
            'expires_at': EPOCH_NEVER_EXPIRE.to_iso8601_string(),
        }
        result = convert_key_bundle_to_pendulum(bundle)
        assert result['expires_at'] == EPOCH_NEVER_EXPIRE


class TestGetUserEmail:

    def test_appends_domain_to_plain_username(self):
        with patch('app.EMAIL_DOMAIN', '@example.com'):
            assert get_user_email('ytl') == 'ytl@example.com'

    def test_returns_email_unchanged_when_at_sign_present(self):
        assert get_user_email('user@other.org') == 'user@other.org'

    def test_email_with_at_sign_ignores_domain_setting(self):
        with patch('app.EMAIL_DOMAIN', '@slac.stanford.edu'):
            assert get_user_email('user@other.org') == 'user@other.org'

    def test_returns_none_for_empty_string(self):
        assert get_user_email('') is None

    def test_returns_none_for_none(self):
        assert get_user_email(None) is None

    def test_returns_none_when_no_domain_and_plain_username(self):
        with patch('app.EMAIL_DOMAIN', ''):
            assert get_user_email('bareuser') is None

    def test_slac_domain_produces_expected_email(self):
        with patch('app.EMAIL_DOMAIN', '@slac.stanford.edu'):
            assert get_user_email('ytl') == 'ytl@slac.stanford.edu'


class TestGetResponseType:

    def test_returns_html_for_text_html_accept(self):
        mock_request = Mock(spec=Request)
        mock_request.headers = {'accept': 'text/html,application/xhtml+xml'}
        assert get_response_type(mock_request) == ResponseType.HTML

    def test_returns_json_for_application_json_accept(self):
        mock_request = Mock(spec=Request)
        mock_request.headers = {'accept': 'application/json'}
        assert get_response_type(mock_request) == ResponseType.JSON

    def test_returns_json_when_accept_header_absent(self):
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        assert get_response_type(mock_request) == ResponseType.JSON

    def test_returns_html_when_text_html_mixed_with_other_types(self):
        mock_request = Mock(spec=Request)
        mock_request.headers = {'accept': 'application/json, text/html; q=0.9'}
        assert get_response_type(mock_request) == ResponseType.HTML

    def test_returns_json_for_wildcard_accept(self):
        mock_request = Mock(spec=Request)
        mock_request.headers = {'accept': '*/*'}
        assert get_response_type(mock_request) == ResponseType.JSON
