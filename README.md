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
