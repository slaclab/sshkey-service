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

## Configuration

### Admin Users

Set `SLACSSH_ADMINS` to a comma-separated list of usernames that should have admin privileges:

```bash
export SLACSSH_ADMINS=alice,bob,charlie
```

- Matching is **case-sensitive** — entries must match the username exactly as sent by the proxy
- Whitespace around commas is stripped automatically (`"alice, bob"` → `{'alice', 'bob'}`)
- Leave empty (or unset) to disable admin endpoints — all admin actions will return 403
- A `WARNING` is logged at startup if the list is empty or contains malformed entries
- An `INFO` log at startup confirms the parsed admin set for operator verification

Admin endpoints (e.g. `DELETE /destroy/{username}/{finger_print}`) require admin access.
All other endpoints are user-scoped (users can only access their own keys, admins can access any).

## Features

- SSH key registration and management
- Automatic key expiration and validity periods
- Email notifications when users register new SSH keys
- Redis-backed key storage
- REST API and web interface
- Blacklist support for blocking compromised SSH key fingerprints

# Quick Start

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

The service includes comprehensive unit tests for all functionality.

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

| Test file | Coverage area |
|-----------|--------------|
| `tests/test_admin_logic.py` | `SLACSSH_ADMINS` parsing, `auth_okay()` admin checks |
| `tests/test_blacklist.py` | Blacklist file loading, signal handling, endpoint protection |

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
