# Testing Documentation

This document describes how to run and understand the tests for the SSH Key Service, particularly the blacklist functionality.

## Prerequisites

Make sure you have the development environment set up:

```bash
make dev
```

This will create a virtual environment and install all dependencies including:
- pytest
- pytest-asyncio
- httpx (for TestClient)
- All production dependencies

## Running Tests

### Run All Tests

```bash
make test
```

This runs all tests in `test_blacklist.py` with verbose output.

### Run Specific Test Classes

```bash
# Run only file loading tests
./sshkey-service/bin/pytest test_blacklist.py::TestBlacklistFileLoading -v

# Run only authorized_keys integration tests
./sshkey-service/bin/pytest test_blacklist.py::TestBlacklistInAuthorizedKeys -v

# Run only thread safety tests
./sshkey-service/bin/pytest test_blacklist.py::TestBlacklistThreadSafety -v
```

### Run Specific Test Functions

```bash
# Run a single test
./sshkey-service/bin/pytest test_blacklist.py::TestBlacklistFileLoading::test_reload_blacklist_with_valid_file -v
```

### Run with Coverage

```bash
make test-coverage
```

This generates an HTML coverage report in `htmlcov/index.html` and displays a terminal summary.

### Watch Mode

For development, you can run tests in watch mode (auto-rerun on file changes):

```bash
make test-watch
```

Note: You may need to install `pytest-watch` first:
```bash
./sshkey-service/bin/pip install pytest-watch
```

## Test Structure

### Test Classes

The test suite is organized into several test classes:

#### 1. `TestBlacklistFileLoading`

Tests the core functionality of loading and reloading the blacklist file.

**Key tests:**
- `test_reload_blacklist_with_valid_file`: Verifies basic file loading
- `test_reload_blacklist_ignores_comments`: Ensures comment lines (starting with #) are ignored
- `test_reload_blacklist_ignores_empty_lines`: Ensures empty lines don't cause issues
- `test_reload_blacklist_nonexistent_file`: Handles missing files gracefully
- `test_reload_blacklist_with_signal`: Tests SIGHUP signal handling
- `test_reload_blacklist_replaces_old_data`: Verifies that reloading updates the blacklist

#### 2. `TestBlacklistInAuthorizedKeys`

Tests the integration of blacklist checking in the `/authorized_keys` endpoint.

**Key tests:**
- `test_blacklisted_key_is_marked`: Verifies blacklisted keys are marked with `is_blacklisted=True`
- `test_non_blacklisted_key_is_not_marked`: Verifies non-blacklisted keys are marked with `is_blacklisted=False`
- `test_multiple_keys_some_blacklisted`: Tests handling of multiple keys with mixed blacklist status

#### 3. `TestBlacklistThreadSafety`

Tests thread safety of the blacklist implementation.

**Key tests:**
- `test_blacklist_lock_is_used_during_reload`: Verifies proper lock usage
- `test_concurrent_reads_during_reload`: Tests concurrent access patterns

#### 4. `TestBlacklistConfiguration`

Tests configuration and environment variable handling.

**Key tests:**
- `test_default_blacklist_path`: Verifies default configuration
- `test_custom_blacklist_path`: Tests custom path configuration

#### 5. `TestBlacklistLogging`

Tests logging behavior for blacklist operations.

**Key tests:**
- `test_blacklisted_key_logs_warning`: Verifies appropriate warning logs are generated

## Test Fixtures

### `temp_blacklist_file`

Creates a temporary blacklist file for testing. Automatically cleaned up after each test.

```python
def test_example(temp_blacklist_file):
    with open(temp_blacklist_file, 'w') as f:
        f.write("SHA256:test_fingerprint\n")
    # Use temp_blacklist_file...
```

### `mock_redis`

Provides a mocked Redis client with AsyncMock capabilities.

```python
@pytest.mark.asyncio
async def test_example(mock_redis):
    mock_redis.hgetall.return_value = {'key': 'value'}
    # Use mock_redis...
```

### `sample_key_data`

Provides sample SSH key data matching the production data structure.

```python
def test_example(sample_key_data):
    # sample_key_data contains:
    # - username, finger_print, public_key, key_type, etc.
    assert sample_key_data['finger_print'] == 'SHA256:abc123def456'
```

## Understanding Test Patterns

### Async Tests

Tests that interact with async functions use the `@pytest.mark.asyncio` decorator:

```python
@pytest.mark.asyncio
async def test_something(mock_redis):
    result = await some_async_function(mock_redis)
    assert result is not None
```

### Mocking

The tests extensively use mocking to isolate functionality:

```python
# Mock file paths
with patch('app.BLACKLIST_FILE', temp_blacklist_file):
    reload_blacklist()

# Mock Redis operations
async def mock_scan(*args, **kwargs):
    yield "user:testuser:fingerprint"

mock_redis.scan_iter = mock_scan
```

### Testing File Operations

Blacklist file operations are tested using temporary files:

```python
def test_file_operation(temp_blacklist_file):
    with open(temp_blacklist_file, 'w') as f:
        f.write("test_data\n")
    
    with patch('app.BLACKLIST_FILE', temp_blacklist_file):
        reload_blacklist()
    
    # Verify results...
```

## Common Testing Scenarios

### Testing Blacklist Reload

```python
# 1. Create test blacklist file
with open(temp_blacklist_file, 'w') as f:
    f.write("SHA256:test_fingerprint\n")

# 2. Patch the blacklist file path
with patch('app.BLACKLIST_FILE', temp_blacklist_file):
    reload_blacklist()

# 3. Verify fingerprint was loaded
with blacklist_lock:
    assert 'SHA256:test_fingerprint' in blacklist_fingerprints
```

### Testing Authorized Keys with Blacklist

```python
# 1. Setup blacklist
with open(temp_blacklist_file, 'w') as f:
    f.write(f"{sample_key_data['finger_print']}\n")

with patch('app.BLACKLIST_FILE', temp_blacklist_file):
    reload_blacklist()

# 2. Mock Redis to return sample key
async def mock_scan(*args, **kwargs):
    yield f"user:testuser:{sample_key_data['finger_print']}"

mock_redis.scan_iter = mock_scan
mock_redis.hgetall.return_value = sample_key_data

# 3. Call get_authorized_keys
with patch('app.get_redis_client', return_value=mock_redis):
    response = await get_authorized_keys(
        request=mock_request,
        username='testuser',
        redis=mock_redis
    )

# 4. Verify blacklist flag
assert response.context['keys'][0]['is_blacklisted'] is True
```

## Debugging Tests

### Run with Debug Output

```bash
./sshkey-service/bin/pytest test_blacklist.py -v -s
```

The `-s` flag shows print statements and logging output.

### Run with PDB on Failure

```bash
./sshkey-service/bin/pytest test_blacklist.py --pdb
```

This drops into the Python debugger when a test fails.

### Run Only Failed Tests

```bash
./sshkey-service/bin/pytest test_blacklist.py --lf
```

The `--lf` (last-failed) flag reruns only the tests that failed in the last run.

## Continuous Integration

These tests are designed to run in CI/CD pipelines. Example GitHub Actions workflow:

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest test_blacklist.py -v --cov=app
```

## Writing New Tests

When adding new blacklist features, follow this pattern:

1. **Create a test class** for the feature area
2. **Use descriptive test names** that explain what is being tested
3. **Use fixtures** to set up common test data
4. **Mock external dependencies** (Redis, file system where appropriate)
5. **Test edge cases** (empty files, missing files, invalid data)
6. **Verify logging** for important operations

Example:

```python
class TestNewBlacklistFeature:
    """Tests for new blacklist feature."""
    
    def test_feature_basic_functionality(self, temp_blacklist_file):
        """Test basic functionality of new feature."""
        # Arrange
        setup_test_data()
        
        # Act
        result = call_feature()
        
        # Assert
        assert result == expected_value
    
    def test_feature_edge_case(self):
        """Test edge case handling."""
        # Test implementation...
```

## Integration Testing

While these tests focus on unit testing the blacklist functionality, for full integration testing:

1. **Start Redis**: `docker run -d -p 6379:6379 redis`
2. **Start the app**: `make start-app`
3. **Run integration tests**: Use the `test_blacklist.sh` script for manual testing

## Performance Testing

For performance testing of blacklist operations:

```bash
./sshkey-service/bin/pytest test_blacklist.py -v --durations=10
```

This shows the 10 slowest tests.

## Coverage Goals

Target coverage for blacklist functionality:

- **Blacklist loading**: 100%
- **Signal handling**: 100%
- **Authorized keys integration**: >90%
- **Error handling**: 100%

Check current coverage:

```bash
make test-coverage
open htmlcov/index.html  # On macOS
```

## Troubleshooting

### Import Errors

If you get import errors, ensure the virtual environment is activated:

```bash
source sshkey-service/bin/activate
```

### Redis Connection Errors

Tests should not require a real Redis instance (they use mocks). If you see Redis connection errors, check that mocks are properly set up.

### File Permission Errors

Temporary files are created with appropriate permissions. If you see permission errors, check that the test runner has write access to `/tmp`.

### Async Errors

If async tests fail with timeout errors, increase the timeout:

```python
@pytest.mark.asyncio
@pytest.mark.timeout(10)  # 10 second timeout
async def test_slow_operation():
    ...
```

## Best Practices

1. **Keep tests isolated**: Each test should be independent
2. **Use fixtures**: Share common setup code
3. **Test one thing**: Each test should verify one specific behavior
4. **Clear test names**: Names should describe what is being tested
5. **Clean up**: Use fixtures and context managers for cleanup
6. **Mock external dependencies**: Don't rely on external services
7. **Test error paths**: Test both success and failure scenarios
8. **Document complex tests**: Add comments explaining non-obvious logic

## Resources

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-asyncio Documentation](https://pytest-asyncio.readthedocs.io/)
- [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [Python unittest.mock](https://docs.python.org/3/library/unittest.mock.html)