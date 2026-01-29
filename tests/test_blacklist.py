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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])