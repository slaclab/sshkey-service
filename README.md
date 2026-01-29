basic proof of concept of utilising a central web service to request private and public ssh keys to gain access to ssh services.

generic idea is that we keep tight control of which ssh keypairs are allowed to be used to access s3df. we only allow ssh keys to obtain access. users have to periodically authenticate against this web app to 'refresh' the keys - meaning that if they do not, the keys are no longer valid. we can therefore control the validity of the keypair (since we can expire the authorized_keys).

i guess we could also do some key signing to be fancy with a validUntil.

this requires that sshd be configured to utilise `AuthorizedKeysCommand` to do something as simple as 

```
curl -sf https://<this-server>/authorized_keys/$1
```

and then add
```
AuthorizedKeysCommand /usr/local/bin/fetch_authorized_keys.sh
AuthorizedKeysCommandUser nobody
```
to sshd_config

## Features

- SSH key registration and management
- Automatic key expiration and validity periods
- Email notifications when users register new SSH keys
- Redis-backed key storage
- REST API and web interface
- Blacklist support for blocking compromised SSH key fingerprints

# Testing

basic data store at present. do not use the keys generated from this in anything put a development environment!

create the venv using 

```
make dev
```

then start the web server with

```
make start-app
```

you can then curl or point your browser to create a keypair; this will spit out the commands that you need to run to configure your local node for ssh

```
curl localhost:8000/create/ytl
```

then you can list your tokens with

```
curl localhost:8000/list/ytl
```

for the sshd side, the script for `AuthorizedKeysCommand` would be 

```
curl localhost:8000/authorized_keys/ytl
```

# Email Notifications

The service supports sending email notifications to users when they register a new SSH public key. This provides both confirmation and security awareness.

## Configuration

Email notifications are disabled by default. To enable them, configure the following environment variables:

```bash
export SLACSSH_EMAIL_ENABLED=true
export SLACSSH_SMTP_HOST=smtp.yourdomain.com
export SLACSSH_SMTP_PORT=587
export SLACSSH_SMTP_USER=your-smtp-username
export SLACSSH_SMTP_PASSWORD=your-smtp-password
export SLACSSH_SMTP_FROM=noreply@yourdomain.com
export SLACSSH_EMAIL_DOMAIN=@yourdomain.com
```

For detailed configuration options and examples, see [EMAIL_CONFIG.md](EMAIL_CONFIG.md).

## What's included in the email

When a user registers a new SSH key, they receive an email containing:
- Key fingerprint
- Key type and size
- Source IP address
- Registration timestamp
- Validity period and expiration date

This helps users track their registered keys and provides a security notification if an unauthorized key is registered.

# Testing

The service includes comprehensive unit tests for all functionality, especially the blacklist feature.

## Running Tests

```bash
# Run all tests
make test

# Run with coverage report
make test-coverage

# Run integration test script
./test_blacklist.sh
```

## Test Coverage

The test suite (`test_blacklist.py`) includes:

- **Blacklist file loading** - Tests for parsing, comments, empty lines, and file errors
- **Signal handling** - Tests for SIGHUP reload functionality
- **Authorized keys integration** - Tests for blacklist checking in the API
- **Thread safety** - Tests for concurrent access to blacklist data
- **Logging** - Tests for appropriate log messages

See [TESTING.md](TESTING.md) for detailed testing documentation.

# SSH Key Blacklist

The service supports maintaining a blacklist of SSH key fingerprints that should be blocked from authentication. When a fingerprint is blacklisted, it will appear as commented-out in the `authorized_keys` output, preventing its use for SSH authentication.

## Quick Start

1. Create a blacklist file (default location: `/etc/sshkey-service/blacklist.txt`):
   ```bash
   # One fingerprint per line, lines starting with # are comments
   SHA256:compromised_fingerprint_here
   ```

2. Set the environment variable (optional, if using a different path):
   ```bash
   export SLACSSH_BLACKLIST_FILE=/path/to/blacklist.txt
   ```

3. Reload the blacklist without restarting the service:
   ```bash
   kill -HUP <pid>
   # or
   pkill -HUP -f app.py
   ```

For detailed information on blacklist configuration, deployment, and management, see:
- [BLACKLIST.md](BLACKLIST.md) - Complete documentation
- [BLACKLIST_QUICKREF.md](BLACKLIST_QUICKREF.md) - Quick reference guide
- [TESTING.md](TESTING.md) - Testing documentation
