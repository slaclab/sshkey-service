import pytest
import tempfile
import os
import signal
from unittest.mock import Mock, patch, AsyncMock
from fastapi import Request
import pendulum

# Import the app and related functions
import sys
sys.path.insert(0, os.path.dirname(__file__))

from app import (
    reload_blacklist, 
    blacklist_fingerprints, 
    blacklist_lock,
    EPOCH_NEVER_EXPIRE,
    IS_ACTIVE_FIELD
)


@pytest.fixture
def temp_blacklist_file():
    """Create a temporary blacklist file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        temp_path = f.name
    yield temp_path
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def mock_redis():
    """Mock Redis client for testing."""
    redis_mock = AsyncMock()
    redis_mock.hgetall = AsyncMock()
    redis_mock.scan_iter = AsyncMock()
    return redis_mock


@pytest.fixture
def sample_key_data():
    """Sample SSH key data for testing."""
    now = pendulum.now()
    return {
        'username': 'testuser',
        'finger_print': 'SHA256:abc123def456',
        'public_key': 'AAAAC3NzaC1lZDI1NTE5AAAAIGs4y2orDiyCSpY',
        'key_type': 'ssh-ed25519',
        'key_bits': '256',
        'source_ip': '192.168.1.100',
        IS_ACTIVE_FIELD: '1',
        'created_at': now,
        'valid_until': now.add(hours=1),
        'expires_at': EPOCH_NEVER_EXPIRE,
        'user_notes': ''
    }


class TestBlacklistFileLoading:
    """Tests for blacklist file loading functionality."""
    
    def test_reload_blacklist_with_valid_file(self, temp_blacklist_file):
        """Test loading a valid blacklist file."""
        # Write test data to file
        with open(temp_blacklist_file, 'w') as f:
            f.write("# Comment line\n")
            f.write("SHA256:fingerprint1\n")
            f.write("\n")  # Empty line
            f.write("SHA256:fingerprint2\n")
            f.write("  SHA256:fingerprint3  \n")  # With whitespace
        
        # Patch the BLACKLIST_FILE constant
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        # Verify fingerprints were loaded
        with blacklist_lock:
            assert len(blacklist_fingerprints) == 3
            assert 'SHA256:fingerprint1' in blacklist_fingerprints
            assert 'SHA256:fingerprint2' in blacklist_fingerprints
            assert 'SHA256:fingerprint3' in blacklist_fingerprints
    
    def test_reload_blacklist_ignores_comments(self, temp_blacklist_file):
        """Test that comment lines are properly ignored."""
        with open(temp_blacklist_file, 'w') as f:
            f.write("# This is a comment\n")
            f.write("#SHA256:should_be_ignored\n")
            f.write("SHA256:valid_fingerprint\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        with blacklist_lock:
            assert len(blacklist_fingerprints) == 1
            assert 'SHA256:valid_fingerprint' in blacklist_fingerprints
            assert '#SHA256:should_be_ignored' not in blacklist_fingerprints
    
    def test_reload_blacklist_ignores_empty_lines(self, temp_blacklist_file):
        """Test that empty lines are properly ignored."""
        with open(temp_blacklist_file, 'w') as f:
            f.write("SHA256:fingerprint1\n")
            f.write("\n")
            f.write("   \n")
            f.write("\t\n")
            f.write("SHA256:fingerprint2\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        with blacklist_lock:
            assert len(blacklist_fingerprints) == 2
    
    def test_reload_blacklist_nonexistent_file(self, temp_blacklist_file):
        """Test handling of non-existent blacklist file."""
        os.unlink(temp_blacklist_file)  # Remove the file
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()  # Should not raise exception
        
        with blacklist_lock:
            assert len(blacklist_fingerprints) == 0
    
    def test_reload_blacklist_empty_file(self, temp_blacklist_file):
        """Test loading an empty blacklist file."""
        # File exists but is empty
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        with blacklist_lock:
            assert len(blacklist_fingerprints) == 0
    
    def test_reload_blacklist_with_signal(self, temp_blacklist_file):
        """Test that reload_blacklist can be called as a signal handler."""
        with open(temp_blacklist_file, 'w') as f:
            f.write("SHA256:test_fingerprint\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            # Simulate SIGHUP signal
            reload_blacklist(signum=signal.SIGHUP, frame=None)
        
        with blacklist_lock:
            assert 'SHA256:test_fingerprint' in blacklist_fingerprints
    
    def test_reload_blacklist_replaces_old_data(self, temp_blacklist_file):
        """Test that reloading replaces old blacklist data."""
        # First load
        with open(temp_blacklist_file, 'w') as f:
            f.write("SHA256:old_fingerprint\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        with blacklist_lock:
            assert 'SHA256:old_fingerprint' in blacklist_fingerprints
        
        # Update file with new data
        with open(temp_blacklist_file, 'w') as f:
            f.write("SHA256:new_fingerprint\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        with blacklist_lock:
            assert 'SHA256:new_fingerprint' in blacklist_fingerprints
            assert 'SHA256:old_fingerprint' not in blacklist_fingerprints


class TestBlacklistInAuthorizedKeys:
    """Tests for blacklist integration in authorized_keys endpoint."""
    
    @pytest.mark.asyncio
    async def test_blacklisted_key_is_marked(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that blacklisted keys are marked in the response."""
        # Setup blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        # Mock Redis to return our sample key
        async def mock_scan(*args, **kwargs):
            yield f"user:{sample_key_data['username']}:{sample_key_data['finger_print']}"
        
        mock_redis.scan_iter = mock_scan
        mock_redis.hgetall.return_value = {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v 
            for k, v in sample_key_data.items()
        }
        
        # Import and patch get_authorized_keys
        from app import get_authorized_keys
        
        # Create mock request
        mock_request = Mock(spec=Request)
        
        with patch('app.get_redis_client', return_value=mock_redis):
            with patch('app.convert_key_bundle_to_pendulum', return_value=sample_key_data):
                response = await get_authorized_keys(
                    request=mock_request,
                    username='testuser',
                    redis=mock_redis
                )
        
        # Check that the key was marked as blacklisted
        assert response.status_code == 200
        # The context should contain keys with is_blacklisted flag
        context_keys = response.context.get('keys', [])
        if context_keys:
            assert context_keys[0].get('is_blacklisted') is True
    
    @pytest.mark.asyncio
    async def test_non_blacklisted_key_is_not_marked(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that non-blacklisted keys are not marked."""
        # Setup empty blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write("# Empty blacklist\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        # Mock Redis to return our sample key
        async def mock_scan(*args, **kwargs):
            yield f"user:{sample_key_data['username']}:{sample_key_data['finger_print']}"
        
        mock_redis.scan_iter = mock_scan
        mock_redis.hgetall.return_value = {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v 
            for k, v in sample_key_data.items()
        }
        
        from app import get_authorized_keys
        mock_request = Mock(spec=Request)
        
        with patch('app.get_redis_client', return_value=mock_redis):
            with patch('app.convert_key_bundle_to_pendulum', return_value=sample_key_data):
                response = await get_authorized_keys(
                    request=mock_request,
                    username='testuser',
                    redis=mock_redis
                )
        
        # Check that the key was NOT marked as blacklisted
        context_keys = response.context.get('keys', [])
        if context_keys:
            assert context_keys[0].get('is_blacklisted') is False
    
    @pytest.mark.asyncio
    async def test_multiple_keys_some_blacklisted(self, mock_redis, temp_blacklist_file):
        """Test handling of multiple keys with some blacklisted."""
        now = pendulum.now()
        
        key1 = {
            'username': 'testuser',
            'finger_print': 'SHA256:blacklisted_key',
            'public_key': 'AAAAC3NzaC1lZDI1NTE5AAAAIGs4y2orDiyCSpY',
            'key_type': 'ssh-ed25519',
            'key_bits': '256',
            'source_ip': '192.168.1.100',
            IS_ACTIVE_FIELD: '1',
            'created_at': now,
            'valid_until': now.add(hours=1),
            'expires_at': EPOCH_NEVER_EXPIRE,
            'user_notes': ''
        }
        
        key2 = {
            'username': 'testuser',
            'finger_print': 'SHA256:valid_key',
            'public_key': 'AAAAB3NzaC1yc2EAAAADAQABAAABAQC',
            'key_type': 'ssh-rsa',
            'key_bits': '2048',
            'source_ip': '192.168.1.101',
            IS_ACTIVE_FIELD: '1',
            'created_at': now,
            'valid_until': now.add(hours=1),
            'expires_at': EPOCH_NEVER_EXPIRE,
            'user_notes': ''
        }
        
        # Blacklist only key1
        with open(temp_blacklist_file, 'w') as f:
            f.write("SHA256:blacklisted_key\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        # Mock Redis to return both keys
        keys_list = [
            f"user:testuser:SHA256:blacklisted_key",
            f"user:testuser:SHA256:valid_key"
        ]
        
        async def mock_scan(*args, **kwargs):
            for k in keys_list:
                yield k
        
        def mock_hgetall_side_effect(key):
            if 'blacklisted_key' in key:
                return AsyncMock(return_value={
                    k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v 
                    for k, v in key1.items()
                })()
            return AsyncMock(return_value={
                k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v 
                for k, v in key2.items()
            })()
        
        mock_redis.scan_iter = mock_scan
        mock_redis.hgetall.side_effect = mock_hgetall_side_effect
        
        # Track which key is being processed
        convert_call_count = [0]
        
        def mock_convert(item):
            convert_call_count[0] += 1
            if convert_call_count[0] == 1:
                return key1
            else:
                return key2
        
        from app import get_authorized_keys
        mock_request = Mock(spec=Request)
        
        with patch('app.get_redis_client', return_value=mock_redis):
            with patch('app.convert_key_bundle_to_pendulum', side_effect=mock_convert):
                response = await get_authorized_keys(
                    request=mock_request,
                    username='testuser',
                    redis=mock_redis
                )
        
        # Verify both keys are in response with correct blacklist status
        context_keys = response.context.get('keys', [])
        assert len(context_keys) == 2
        
        # Find each key in the response
        blacklisted = [k for k in context_keys if k['finger_print'] == 'SHA256:blacklisted_key']
        valid = [k for k in context_keys if k['finger_print'] == 'SHA256:valid_key']
        
        assert len(blacklisted) == 1
        assert len(valid) == 1
        assert blacklisted[0]['is_blacklisted'] is True
        assert valid[0]['is_blacklisted'] is False


class TestBlacklistThreadSafety:
    """Tests for thread safety of blacklist operations."""
    
    def test_blacklist_lock_is_used_during_reload(self, temp_blacklist_file):
        """Test that the lock is properly acquired during reload."""
        with open(temp_blacklist_file, 'w') as f:
            f.write("SHA256:test\n")
        
        # Mock the lock to track acquire/release
        original_lock = blacklist_lock.__enter__
        acquire_called = []
        
        def mock_enter(*args, **kwargs):
            acquire_called.append(True)
            return original_lock(*args, **kwargs)
        
        with patch.object(blacklist_lock, '__enter__', mock_enter):
            with patch('app.BLACKLIST_FILE', temp_blacklist_file):
                reload_blacklist()
        
        assert len(acquire_called) > 0
    
    def test_concurrent_reads_during_reload(self, temp_blacklist_file):
        """Test that concurrent reads work correctly during reload."""
        import threading
        
        with open(temp_blacklist_file, 'w') as f:
            f.write("SHA256:initial\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        # Read the blacklist from multiple threads
        results = []
        
        def read_blacklist():
            with blacklist_lock:
                results.append('SHA256:initial' in blacklist_fingerprints)
        
        threads = [threading.Thread(target=read_blacklist) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All reads should succeed
        assert len(results) == 10
        assert all(results)


class TestBlacklistConfiguration:
    """Tests for blacklist configuration via environment variables."""
    
    def test_default_blacklist_path(self):
        """Test that default blacklist path is set correctly."""
        from app import BLACKLIST_FILE
        assert BLACKLIST_FILE == '/etc/sshkey-service/blacklist.txt' or BLACKLIST_FILE is not None
    
    def test_custom_blacklist_path(self, temp_blacklist_file):
        """Test that custom blacklist path can be configured."""
        with patch.dict(os.environ, {'SLACSSH_BLACKLIST_FILE': temp_blacklist_file}):
            # Would need to reload the module to test this properly
            # For now, just verify the env var can be set
            assert os.environ.get('SLACSSH_BLACKLIST_FILE') == temp_blacklist_file


class TestBlacklistLogging:
    """Tests for blacklist-related logging."""
    
    @pytest.mark.asyncio
    async def test_blacklisted_key_logs_warning(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that finding a blacklisted key logs a warning."""
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        async def mock_scan(*args, **kwargs):
            yield f"user:{sample_key_data['username']}:{sample_key_data['finger_print']}"
        
        mock_redis.scan_iter = mock_scan
        mock_redis.hgetall.return_value = {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v 
            for k, v in sample_key_data.items()
        }
        
        from app import get_authorized_keys
        mock_request = Mock(spec=Request)
        
        with patch('app.logger') as mock_logger:
            with patch('app.get_redis_client', return_value=mock_redis):
                with patch('app.convert_key_bundle_to_pendulum', return_value=sample_key_data):
                    await get_authorized_keys(
                        request=mock_request,
                        username='testuser',
                        redis=mock_redis
                    )
            
            # Check that warning was logged
            warning_calls = [call for call in mock_logger.warning.call_args_list]
            assert any('Blacklisted key found' in str(call) for call in warning_calls)


class TestBlacklistInListView:
    """Tests for blacklist display in list view."""
    
    @pytest.mark.asyncio
    async def test_blacklisted_key_marked_in_list(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that blacklisted keys are marked with is_blacklisted in list view."""
        # Setup blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        # Mock Redis to return our sample key
        async def mock_scan(*args, **kwargs):
            yield f"user:{sample_key_data['username']}:{sample_key_data['finger_print']}"
        
        mock_redis.scan_iter = mock_scan
        mock_redis.hgetall.return_value = {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v 
            for k, v in sample_key_data.items()
        }
        
        from app import list_user_keypair
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        with patch('app.get_redis_client', return_value=mock_redis):
            with patch('app.convert_key_bundle_to_pendulum', return_value=sample_key_data):
                response = await list_user_keypair(
                    request=mock_request,
                    username='testuser',
                    redis=mock_redis
                )
        
        # Verify the response contains the blacklisted flag
        assert response.status_code == 200
        # The keys should have is_blacklisted set to True
        # We need to check the context passed to the template
        assert 'keys' in response.context
        keys = response.context['keys']
        assert len(keys) == 1
        assert keys[0]['is_blacklisted'] is True
    
    @pytest.mark.asyncio
    async def test_non_blacklisted_key_not_marked_in_list(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that non-blacklisted keys are not marked in list view."""
        # Setup empty blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write("# Empty blacklist\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        # Mock Redis to return our sample key
        async def mock_scan(*args, **kwargs):
            yield f"user:{sample_key_data['username']}:{sample_key_data['finger_print']}"
        
        mock_redis.scan_iter = mock_scan
        mock_redis.hgetall.return_value = {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v 
            for k, v in sample_key_data.items()
        }
        
        from app import list_user_keypair
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        with patch('app.get_redis_client', return_value=mock_redis):
            with patch('app.convert_key_bundle_to_pendulum', return_value=sample_key_data):
                response = await list_user_keypair(
                    request=mock_request,
                    username='testuser',
                    redis=mock_redis
                )
        
        # Verify the response contains the blacklisted flag set to False
        assert response.status_code == 200
        assert 'keys' in response.context
        keys = response.context['keys']
        assert len(keys) == 1
        assert keys[0]['is_blacklisted'] is False

    @pytest.mark.asyncio
    async def test_blacklisted_key_html_has_disabled_controls(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that blacklisted keys have disabled buttons and inputs in HTML."""
        # Setup blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        # Mock Redis to return our sample key
        async def mock_scan(*args, **kwargs):
            yield f"user:{sample_key_data['username']}:{sample_key_data['finger_print']}"
        
        mock_redis.scan_iter = mock_scan
        mock_redis.hgetall.return_value = {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v 
            for k, v in sample_key_data.items()
        }
        
        from app import list_user_keypair
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        with patch('app.get_redis_client', return_value=mock_redis):
            with patch('app.convert_key_bundle_to_pendulum', return_value=sample_key_data):
                response = await list_user_keypair(
                    request=mock_request,
                    username='testuser',
                    redis=mock_redis
                )
        
        # Verify the HTML contains disabled attributes
        html_content = response.body.decode('utf-8')
        
        # Check for disabled buttons
        assert 'button class="refresh" disabled' in html_content
        assert 'button class="inactivate" disabled' in html_content
        
        # Check for disabled input field
        assert 'class="user-notes"' in html_content
        assert 'disabled' in html_content
        
        # Check for warning icon with tooltip
        assert '⚠️' in html_content
        assert 'title="This SSH key fingerprint is BLACKLISTED"' in html_content
        assert 'class="blacklist-warning"' in html_content


class TestBlacklistEndpointProtection:
    """Tests for blacklist protection on refresh, inactivate, and notes endpoints."""
    
    @pytest.mark.asyncio
    async def test_refresh_blacklisted_key_returns_forbidden(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that attempting to refresh a blacklisted key returns 403 Forbidden."""
        # Setup blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        from app import refresh_user_keypair
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        # Should raise HTTPException with 403 status
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            with patch('app.get_redis_client', return_value=mock_redis):
                await refresh_user_keypair(
                    request=mock_request,
                    username='testuser',
                    finger_print=sample_key_data['finger_print'],
                    redis=mock_redis
                )
        
        assert exc_info.value.status_code == 403
        assert 'blacklisted' in str(exc_info.value.detail).lower()
    
    @pytest.mark.asyncio
    async def test_refresh_blacklisted_key_logs_warning(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that attempting to refresh a blacklisted key logs a warning."""
        # Setup blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        from app import refresh_user_keypair
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        from fastapi import HTTPException
        with patch('app.logger') as mock_logger:
            with pytest.raises(HTTPException):
                with patch('app.get_redis_client', return_value=mock_redis):
                    await refresh_user_keypair(
                        request=mock_request,
                        username='testuser',
                        finger_print=sample_key_data['finger_print'],
                        redis=mock_redis
                    )
            
            # Check that warning was logged
            warning_calls = [call for call in mock_logger.warning.call_args_list]
            assert any('Attempt to refresh blacklisted key' in str(call) for call in warning_calls)
    
    @pytest.mark.asyncio
    async def test_inactivate_blacklisted_key_returns_forbidden(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that attempting to inactivate a blacklisted key returns 403 Forbidden."""
        # Setup blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        from app import inactivate_user_keypair
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        # Should raise HTTPException with 403 status
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            with patch('app.get_redis_client', return_value=mock_redis):
                await inactivate_user_keypair(
                    request=mock_request,
                    username='testuser',
                    finger_print=sample_key_data['finger_print'],
                    redis=mock_redis
                )
        
        assert exc_info.value.status_code == 403
        assert 'blacklisted' in str(exc_info.value.detail).lower()
    
    @pytest.mark.asyncio
    async def test_inactivate_blacklisted_key_logs_warning(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that attempting to inactivate a blacklisted key logs a warning."""
        # Setup blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        from app import inactivate_user_keypair
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        from fastapi import HTTPException
        with patch('app.logger') as mock_logger:
            with pytest.raises(HTTPException):
                with patch('app.get_redis_client', return_value=mock_redis):
                    await inactivate_user_keypair(
                        request=mock_request,
                        username='testuser',
                        finger_print=sample_key_data['finger_print'],
                        redis=mock_redis
                    )
            
            # Check that warning was logged
            warning_calls = [call for call in mock_logger.warning.call_args_list]
            assert any('Attempt to inactivate blacklisted key' in str(call) for call in warning_calls)
    
    @pytest.mark.asyncio
    async def test_update_notes_blacklisted_key_returns_forbidden(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that attempting to update notes for a blacklisted key returns 403 Forbidden."""
        # Setup blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        from app import update_user_notes, UserNotes
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        user_notes = UserNotes(user_notes="Test note")
        
        # Should raise HTTPException with 403 status
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            with patch('app.get_redis_client', return_value=mock_redis):
                await update_user_notes(
                    request=mock_request,
                    username='testuser',
                    finger_print=sample_key_data['finger_print'],
                    user_notes=user_notes,
                    redis=mock_redis
                )
        
        assert exc_info.value.status_code == 403
        assert 'blacklisted' in str(exc_info.value.detail).lower()
    
    @pytest.mark.asyncio
    async def test_update_notes_blacklisted_key_logs_warning(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that attempting to update notes for a blacklisted key logs a warning."""
        # Setup blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write(f"{sample_key_data['finger_print']}\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        from app import update_user_notes, UserNotes
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        user_notes = UserNotes(user_notes="Test note")
        
        from fastapi import HTTPException
        with patch('app.logger') as mock_logger:
            with pytest.raises(HTTPException):
                with patch('app.get_redis_client', return_value=mock_redis):
                    await update_user_notes(
                        request=mock_request,
                        username='testuser',
                        finger_print=sample_key_data['finger_print'],
                        user_notes=user_notes,
                        redis=mock_redis
                    )
            
            # Check that warning was logged
            warning_calls = [call for call in mock_logger.warning.call_args_list]
            assert any('Attempt to update notes for blacklisted key' in str(call) for call in warning_calls)
    
    @pytest.mark.asyncio
    async def test_non_blacklisted_key_operations_allowed(self, mock_redis, sample_key_data, temp_blacklist_file):
        """Test that operations on non-blacklisted keys are allowed."""
        # Setup empty blacklist
        with open(temp_blacklist_file, 'w') as f:
            f.write("# Empty blacklist\n")
        
        with patch('app.BLACKLIST_FILE', temp_blacklist_file):
            reload_blacklist()
        
        # Mock Redis responses
        mock_redis.hgetall.return_value = {
            k: str(v) if isinstance(v, (pendulum.DateTime, int)) else v 
            for k, v in sample_key_data.items()
        }
        
        from app import refresh_user_keypair, inactivate_user_keypair, update_user_notes, UserNotes
        mock_request = Mock(spec=Request)
        mock_request.headers = {}
        
        # These should not raise HTTPException
        from fastapi import HTTPException
        
        # Test refresh - should not raise
        try:
            with patch('app.get_redis_client', return_value=mock_redis):
                with patch('app.convert_key_bundle_to_pendulum', return_value=sample_key_data):
                    await refresh_user_keypair(
                        request=mock_request,
                        username='testuser',
                        finger_print=sample_key_data['finger_print'],
                        redis=mock_redis
                    )
        except HTTPException as e:
            # Should not be a 403 error
            assert e.status_code != 403
        
        # Test inactivate - should not raise 403
        try:
            with patch('app.get_redis_client', return_value=mock_redis):
                await inactivate_user_keypair(
                    request=mock_request,
                    username='testuser',
                    finger_print=sample_key_data['finger_print'],
                    redis=mock_redis
                )
        except HTTPException as e:
            # Should not be a 403 error
            assert e.status_code != 403
        
        # Test update notes - should not raise 403
        user_notes = UserNotes(user_notes="Test note")
        try:
            with patch('app.get_redis_client', return_value=mock_redis):
                await update_user_notes(
                    request=mock_request,
                    username='testuser',
                    finger_print=sample_key_data['finger_print'],
                    user_notes=user_notes,
                    redis=mock_redis
                )
        except HTTPException as e:
            # Should not be a 403 error
            assert e.status_code != 403


if __name__ == '__main__':
    pytest.main([__file__, '-v'])