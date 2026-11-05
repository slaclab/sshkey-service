from fastapi import FastAPI, HTTPException, Request, status, Depends

import functools
import paramiko
from pydantic import BaseModel
from typing import Optional

import os
import io
import binascii
import re
import struct
from loguru import logger

from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates

from contextlib import asynccontextmanager
import redis.asyncio as aioredis

import pendulum
import hashlib
import base64
from enum import Enum

# Email imports
import smtplib
from email.mime.text import MIMEText

# Signal handling for blacklist reload
import signal
import threading


templates = Jinja2Templates(directory="templates")

# global parameters from env
REDIS_HOST = os.environ.get('SLACSSH_REDIS_HOST', 'dragonfly')
REDIS_PORT = os.environ.get('SLACSSH_REDIS_PORT', 6379)
REDIS_PASSWORD = os.environ.get('SLACSSH_REDIS_PASSWORD', None)
REDIS_DB = int(os.environ.get('SLACSSH_REDIS_DB', 0))

USERNAME_HEADER_FIELD = os.environ.get('SLACSSH_USERNAME_HEADER_FIELD', 'REMOTE-USER')

# browser origins (e.g. coact) allowed to call the api with the user's session cookie; unset disables cors
CORS_ORIGINS = [o.strip() for o in os.environ.get('SLACSSH_CORS_ORIGINS', '').split(',') if o.strip()]

# validity of key use
VALIDITY_PERIOD = os.environ.get('SLACSSH_VALIDITY_PERIOD', 90000 )

# whether the key expires or not
NO_EXPIRY = True
EPOCH_NEVER_EXPIRE = pendulum.datetime(1970,1,1) # no expiration for keys set to unix epoch

# use this to determine the redis hash field to indicate if the key is active or not; use hexpire where necessary
IS_ACTIVE_FIELD = 'is_active'

# permanent disable: the hash keeps the record (for audit and leaked-key detection) and gets
# DISABLED_FIELD=1 plus disabled_at/by/reason; a disabled key can never be refreshed, inactivated,
# edited, destroyed or served in authorized_keys. there is deliberately no re-enable endpoint.
DISABLED_FIELD = 'disabled'
# global set of disabled fingerprints, so a leaked key can't be re-registered under any username
DISABLED_FINGERPRINTS_SET = 'disabled_fingerprints'
DISABLE_ALL_CONFIRMATION = 'DISABLE ALL'


def is_disabled(item: dict) -> bool:
    """True if a key hash (as returned by hgetall) has been permanently disabled."""
    return str(item.get(DISABLED_FIELD, '')) == '1'

# Email configuration
SMTP_HOST = os.environ.get('SLACSSH_SMTP_HOST', 'smtp.slac.stanford.edu')
SMTP_PORT = int(os.environ.get('SLACSSH_SMTP_PORT', 25))
SMTP_USER = os.environ.get('SLACSSH_SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SLACSSH_SMTP_PASSWORD', '')
SMTP_FROM = os.environ.get('SLACSSH_SMTP_FROM', 's3df-help@slac.stanford.edu')
SMTP_SUBJECT = os.environ.get('SLACSSH_SMTP_SUBJECT', "[Coact] New SSH Public Key Registered")
SMTP_USE_TLS = os.environ.get('SLACSSH_SMTP_USE_TLS', 'false').lower() == 'true'
EMAIL_ENABLED = os.environ.get('SLACSSH_EMAIL_ENABLED', 'false').lower() == 'true'
EMAIL_DOMAIN = os.environ.get('SLACSSH_EMAIL_DOMAIN', '@slac.stanford.edu')

# Blacklist configuration
BLACKLIST_FILE = os.environ.get('SLACSSH_BLACKLIST_FILE', '/etc/sshkey-service/blacklist.txt')

# Admin configuration
def _parse_admins(raw: str) -> frozenset:
    """Parse and normalise the SLACSSH_ADMINS env var into an immutable set.

    Strips whitespace from each entry, filters empty entries, and emits
    startup warnings for misconfiguration. Called once at module load.

    Note: matching is case-sensitive. UNIX usernames are conventionally
    lowercase; if your identity provider sends mixed-case usernames, ensure
    SLACSSH_ADMINS entries match exactly.
    """
    entries = [e.strip() for e in raw.split(',')]
    valid = frozenset(e for e in entries if e)
    empty_count = len(entries) - len(valid)
    if empty_count:
        logger.warning(
            f"SLACSSH_ADMINS contains {empty_count} empty/whitespace "
            f"entries (ignored). Check for trailing commas or extra spaces."
        )
    if not valid:
        logger.warning(
            "SLACSSH_ADMINS is empty — no admin users configured. "
            "Admin-only endpoints will return 403 for all users."
        )
    else:
        logger.info(f"ADMINS configured: {sorted(valid)}")
    return valid

ADMINS: frozenset = _parse_admins(os.getenv('SLACSSH_ADMINS', ''))

# RFC 4716 §3.3: header lines are "Tag: value"; tags start with a letter and
# may contain letters, digits, and hyphens.
_RFC4716_HEADER_RE = re.compile(r'^[A-Za-z][A-Za-z0-9-]*:')


def _key_type_from_wire(data: bytes) -> str:
    """Extract the key type string from OpenSSH wire-format public key data.

    The OpenSSH wire format (RFC 4253 §6.6) begins with a 4-byte big-endian
    length followed by the key type string (e.g. b'ssh-ed25519', b'ssh-rsa').
    This is the authoritative source of key type — not the RFC 4716 Comment field.

    Raises ValueError on malformed data (too short, length overflow, unreasonable length).
    """
    if len(data) < 4:
        raise ValueError(f"Key data too short: {len(data)} bytes")
    (type_len,) = struct.unpack('>I', data[:4])
    if type_len > 256:
        raise ValueError(f"Key type length {type_len} exceeds sanity limit of 256 bytes")
    if type_len > len(data) - 4:
        raise ValueError(
            f"Key type length {type_len} overflows data length {len(data) - 4}"
        )
    return data[4:4 + type_len].decode('ascii')

# SHA256: prefix + exactly 43 chars from the post-cleaning alphabet [A-Za-z0-9.]
# 43 = ceil(32 * 4/3) with padding stripped — holds for ALL key types (RSA, Ed25519,
# ECDSA) because SHA256 always produces 32 bytes regardless of key type.
# Anchored with both ^ and $ (equivalent to re.fullmatch) so trailing garbage is rejected
# even if $ is accidentally removed from one side.
_FINGERPRINT_RE = re.compile(r'^SHA256:[A-Za-z0-9.]{43}$')


def validate_fingerprint(fp: str) -> str:
    """Validate a fingerprint against the SHA256 allowlist regex.

    Accepted format: SHA256:[A-Za-z0-9.]{43}  (post-cleaning — '/' and '+' replaced with '.')

    Raises HTTPException(400) if the fingerprint does not match.
    Returns the fingerprint unchanged if valid.

    IMPORTANT: Call this before any logger.info() that would log the raw
    fingerprint value, to prevent log injection from hostile internal callers.
    """
    if not _FINGERPRINT_RE.match(fp):
        raise HTTPException(
            status_code=400,
            detail="Invalid fingerprint format. Expected SHA256 fingerprint."
        )
    return fp


# Global set to store blacklisted fingerprints
blacklist_fingerprints = set()
blacklist_lock = threading.Lock()


class PublicKey(BaseModel):
    public_key: str

class UserNotes(BaseModel):
    user_notes: str

class DisableRequest(BaseModel):
    reason: str = ''

class AdminDisableRequest(BaseModel):
    usernames: Optional[list[str]] = None
    all: bool = False
    reason: str
    confirm: str = ''

class ResponseType(str, Enum):
    HTML = "html"
    JSON = "json"

def get_response_type(request: Request) -> ResponseType:
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return ResponseType.HTML
    return ResponseType.JSON


# initiate redis client
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load initial blacklist
    reload_blacklist()

    # Set up SIGHUP handler for blacklist reload
    signal.signal(signal.SIGHUP, reload_blacklist)
    logger.info("SIGHUP handler registered for blacklist reload")

    app.state.redis_client = aioredis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True # Decodes responses to strings automatically
    )
    try:
        yield
    finally:
        await app.state.redis_client.close()


def reload_blacklist(signum=None, frame=None):
    """
    Reload the blacklist from the file.
    Can be called as a signal handler (SIGHUP) or directly.
    """
    global blacklist_fingerprints

    if signum:
        logger.info(f"Received signal {signum}, reloading blacklist...")
    else:
        logger.info("Loading blacklist...")

    new_blacklist = set()

    try:
        if os.path.exists(BLACKLIST_FILE):
            with open(BLACKLIST_FILE, 'r') as f:
                for line in f:
                    # Strip whitespace and ignore empty lines and comments
                    line = line.strip()
                    if line and not line.startswith('#'):
                        new_blacklist.add(line)

            with blacklist_lock:
                blacklist_fingerprints = new_blacklist

            logger.info(f"Blacklist loaded: {len(blacklist_fingerprints)} fingerprints")
        else:
            logger.warning(f"Blacklist file not found: {BLACKLIST_FILE}")
            with blacklist_lock:
                blacklist_fingerprints = set()
    except Exception as e:
        logger.error(f"Error loading blacklist: {e}")


app = FastAPI(lifespan=lifespan)

if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=['GET', 'POST', 'PATCH', 'DELETE'],
        allow_headers=['Content-Type'],
    )

async def get_redis_client():
    return app.state.redis_client


def convert_key_bundle_to_iso(item: dict):
    """ Convert pendulum timestamps in the bundle to ISO 8601 strings.
    """
    bundle = item.copy()
    for k in ( 'created_at', 'valid_until', 'expires_at' ):
        if k in bundle and isinstance(bundle[k], pendulum.DateTime):
            bundle[k] = bundle[k].to_iso8601_string()
    return bundle

def convert_key_bundle_to_pendulum(item: dict):
    """ Convert ISO 8601 strings in the bundle to pendulum timestamps.
    """
    bundle = item.copy()
    logger.info(f"Created At: {bundle['created_at']}, Valid Until: {bundle['valid_until']}, Expires At: {bundle['expires_at']}")
    for k in ( 'created_at', 'valid_until', 'expires_at' ):
        if k in bundle:
            bundle[k] = pendulum.parse(bundle[k])
    return bundle


def get_user_email(username: str) -> Optional[str]:
    """
    Determine the user's email address from their username.
    If EMAIL_DOMAIN is set, appends it to the username.
    Otherwise, assumes username is already an email or returns None.
    TODO: we probably want to make use of the user-info microservice since most users probably dont' have a local email (but forwarding works?)
    """
    if not username:
        return None

    if '@' in username:
        return username

    if EMAIL_DOMAIN:
        return f"{username}{EMAIL_DOMAIN}"

    return None


async def send_email(to_email: str, subject: str, body_text: str):
    """
    Send an email notification asynchronously.

    Args:
        to_email: Recipient email address
        subject: Email subject
        body_text: Plain text body
    """
    if not EMAIL_ENABLED:
        logger.debug(f"Email disabled. Would have sent email to {to_email}: {subject}")
        return

    if not to_email:
        logger.warning("Cannot send email: recipient address is empty")
        return

    try:
        # Create message
        msg = MIMEText(body_text, 'plain')
        msg['From'] = SMTP_FROM
        msg['To'] = to_email
        msg['Subject'] = subject

        # Connect to SMTP server and send
        if SMTP_USE_TLS:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)

        if SMTP_USER and SMTP_PASSWORD:
            server.login(SMTP_USER, SMTP_PASSWORD)

        server.send_message(msg)
        server.quit()

        logger.info(f"Email sent successfully to {to_email}: {subject}")

    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")

def auth(request: Request, user_header: str = USERNAME_HEADER_FIELD):
    """
    Check if the request is authenticated.
    """
    # only allow user defined in the request, or if user is admin
    found_username = request.headers.get( user_header )
    logger.debug(f"Found user {found_username} (looking at header {user_header})")
    if not found_username:
        logger.error("No username found in request headers.")
        raise HTTPException(status_code=401, detail="Unauthorized: No username found in request headers. Please check application configuration for env SLACSSH_USERNAME_HEADER_FIELD.")
    # if we reach here, the user is authorized
    return found_username

def auth_okay(admin_only: bool = False, user_header: str = USERNAME_HEADER_FIELD):
    """
    Decorator to check if the logged in user is expected to be allowed to access this resource.

    The decorated function must have 'request' and 'username' parameters.
    Injects 'found_username' as a keyword argument to the wrapped function.

    Args:
        admin_only: If True, only admins can access this resource
        user_header: The header field containing the username
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request and username from kwargs or args
            request = kwargs.get('request')
            username = kwargs.get('username')

            if request is None or username is None:
                raise HTTPException(status_code=500, detail="Internal error: request or username not found in function arguments.")

            # only allow user defined in the request, or if user is admin
            found_username = auth(request, user_header)

            if not admin_only:
                if found_username != username and found_username not in ADMINS:
                    logger.error(f"Unauthorized access attempt by user: {found_username}. Expected user: {username}.")
                    raise HTTPException(status_code=403, detail=f"Forbidden: User {found_username} is not allowed to access this resource.")
            else:
                if found_username not in ADMINS:
                    logger.error(f"Unauthorized admin access attempt by user: {found_username}.")
                    raise HTTPException(status_code=403, detail=f"Forbidden: User {found_username} is not an admin.")

            logger.info(f"User {found_username} is authorized to access the resource.")

            # Inject found_username into the function kwargs
            kwargs['found_username'] = found_username
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(user_header: str = USERNAME_HEADER_FIELD):
    """
    Decorator for admin-only endpoints that have no {username} path parameter.

    The decorated function must have a 'request' parameter.
    Injects 'found_username' as a keyword argument to the wrapped function.
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get('request')
            if request is None:
                raise HTTPException(status_code=500, detail="Internal error: request not found in function arguments.")
            found_username = auth(request, user_header)
            if found_username not in ADMINS:
                logger.error(f"Unauthorized admin access attempt by user: {found_username}.")
                raise HTTPException(status_code=403, detail=f"Forbidden: User {found_username} is not an admin.")
            kwargs['found_username'] = found_username
            return await func(*args, **kwargs)
        return wrapper
    return decorator


async def disable_key(redis: aioredis.Redis, key: str, item: dict, disabled_by: str, reason: str = '') -> bool:
    """
    Permanently disable the key hash at `key` (item is its raw hgetall content).

    Returns False if it was already disabled (left untouched), True if newly disabled.
    The record is kept; is_active is removed and the fingerprint is added to the global set.
    """
    if is_disabled(item):
        return False

    item = dict(item)
    item.pop(IS_ACTIVE_FIELD, None)
    item.setdefault('user_notes', '')
    item.update({
        DISABLED_FIELD: 1,
        'disabled_at': pendulum.now().to_iso8601_string(),
        'disabled_by': disabled_by,
        'disabled_reason': reason or '',
    })
    # dragonfly won't drop the hexpire on is_active, so delete and rewrite the hash (as inactivate does)
    await redis.delete(key)
    await redis.hset(key, mapping=item)
    await redis.sadd(DISABLED_FINGERPRINTS_SET, item['finger_print'])
    logger.info(f"Disabled SSH key {key} by {disabled_by}; reason: {reason!r}")
    return True


async def fingerprint_records(redis: aioredis.Redis, finger_print: str) -> list:
    """All key hashes holding this fingerprint, under any username (user:*:{fp})."""
    # validated fingerprints are [A-Za-z0-9.:] only, so no glob metacharacters
    return [k async for k in redis.scan_iter(f"user:*:{finger_print}")]


async def is_revoked(redis: aioredis.Redis, item: dict, finger_print: str = None) -> bool:
    """A key is revoked if its own record says so OR its fingerprint is in the global set.

    The global set is authoritative: it also covers copies of the same key registered under
    another username that were not (yet) marked individually.
    """
    if is_disabled(item):
        return True
    fp = finger_print or item.get('finger_print')
    return bool(fp) and bool(await redis.sismember(DISABLED_FINGERPRINTS_SET, fp))


async def revoke_fingerprint_everywhere(redis: aioredis.Redis, finger_print: str, disabled_by: str, origin_key: str = None) -> int:
    """Revoke every other record of this fingerprint (same key registered under other usernames).

    Revocation is about the key, not the account: if the private key is compromised it is
    compromised for every account that trusts it. Returns how many extra records were revoked.
    The originating user's free-text reason is not copied to other accounts.
    """
    n = 0
    for k in await fingerprint_records(redis, finger_print):
        if k == origin_key:
            continue
        item = await redis.hgetall(k)
        if item and await disable_key(redis, k, item, disabled_by=disabled_by,
                                      reason="same key was revoked on another account"):
            logger.warning(f"Revoked {k}: same fingerprint revoked via {origin_key} by {disabled_by}")
            n += 1
    return n


@app.get("/list/{username}")
@auth_okay()
async def list_user_keypair(
      request: Request,
      username: str,
      jinja_template: str = 'list.html.j2',
      include_disabled: bool = True,
      redis: aioredis.Redis = Depends(get_redis_client),
      found_username: str = None ):
    """
    List the SSH key pair for the given username.

    Every key carries an is_disabled flag. Disabled keys are included by default (the HTML view
    hides them behind a toggle); JSON callers can pass include_disabled=false to omit them.
    """
    logger.info(f"Listing SSH key pair for user: {username}")

    # TODO: should probably pipeline this...
    keys = []
    async for k in redis.scan_iter(f"user:{username}:*"):
        item = await redis.hgetall(k)
        item = convert_key_bundle_to_pendulum( item )

        # Check if the key is blacklisted
        with blacklist_lock:
            item['is_blacklisted'] = item.get('finger_print') in blacklist_fingerprints

        item['is_disabled'] = await is_revoked(redis, item)
        if item['is_disabled'] and not include_disabled:
            continue

        logger.info(f"Found key: {item}")
        keys.append(item)

    # return type depending on what we got in
    response_type = get_response_type( request )

    if response_type == ResponseType.HTML:
      return templates.TemplateResponse(
          name=jinja_template,  # Name of your Jinja2 template file
          request=request,    # Pass the request object
          context={
              "title": "list",
              "username": username,
              "keys": keys,
              "disabled_count": sum(1 for k in keys if k['is_disabled']),
              "validity_period": int(VALIDITY_PERIOD),
              "no_expiry": NO_EXPIRY
          }
      )

    else:
      serializable_keys = [convert_key_bundle_to_iso(k) for k in keys]
      return JSONResponse( content={"message": serializable_keys}, status_code=status.HTTP_201_CREATED )


@app.get("/register/{username}")
@auth_okay()
async def register_user_keypair( request: Request, username: str, key_type: str = "ed25519", key_bits: int = 2048, jinja_template: str = 'register.html.j2', found_username: str = None):
    """
    shows instructions for how to create a keypair and upload it to us
    """

    logger.info(f"Generating SSH key pair for user: {username} with type: {key_type} and bits: {key_bits}")

    return templates.TemplateResponse(
        name=jinja_template,  # Name of your Jinja2 template file
        request=request,    # Pass the request object
        context={
            "title": "s3df ssh keypair service",
            "username": username,
            "key_type": key_type,
            "key_bits": key_bits,
            "prefix_path": "~/.ssh/s3df",
            "no_expiry": NO_EXPIRY,
            "validity_period": VALIDITY_PERIOD
        }
    )


@app.post("/upload/{username}")
@auth_okay()
async def upload_user_public_key( request: Request, username: str, public_key: PublicKey, source_ip_header_field: str = 'x-real-ip', valid_seconds: int = VALIDITY_PERIOD, expires_seconds: int = 604800, redis: aioredis.Redis = Depends(get_redis_client), found_username: str = None):
    """ Uploads the public key for the given username.
    """

    logger.info(f"Uploading public key for user: {username}: {public_key.public_key}")

    # should check if the public key is already registered
    def determine_public_key(key: str) -> str:
        """
        Strips the public key of any comments or other unnecessary parts.
        Returns the cleaned public key and its fingerprint.
        """
        found = None

        # ---- BEGIN SSH2 PUBLIC KEY ----
        # Comment: "256-bit ED25519, converted by ytl@yees-m3-mac.lan from OpenS"
        # AAAAC3NzaC1lZDI1NTE5AAAAIGs4y2orDiyCSpY/12Psser9E+q9GzF7133Wu4wBtCqE
        #---- END SSH2 PUBLIC KEY ----
        in_key_block = False
        in_header = False
        key_data_base64 = ""
        for line in public_key.public_key.splitlines():
            if line.strip() == "---- BEGIN SSH2 PUBLIC KEY ----":
                in_key_block = True
                continue
            elif line.strip() == "---- END SSH2 PUBLIC KEY ----":
                break

            if in_key_block:
                # RFC 4716 §3.3: headers are "Tag: value" lines; continuation
                # lines end with '\'. Skip all header lines (Comment, Subject, x-*).
                if in_header:
                    # Still in a multi-line header continuation
                    in_header = line.rstrip().endswith('\\')
                    continue
                if _RFC4716_HEADER_RE.match(line.strip()):
                    in_header = line.rstrip().endswith('\\')
                    continue
                key_data_base64 += line.strip()

        # error out if not valid
        if not key_data_base64:
            raise HTTPException(status_code=400, detail="Invalid public key format. Please ensure it is in the correct format.")

        found = None
        try:
            raw = base64.b64decode(key_data_base64)
            wire_type = _key_type_from_wire(raw)
            found = paramiko.PKey.from_type_string(wire_type, raw)
        except ValueError as e:
            logger.debug(f"Key parse ValueError: {e}")
            raise HTTPException(status_code=400, detail="Could not parse the public key. Please ensure it is in the correct format.")
        except Exception as e:
            logger.debug(f"Key parse error: {e}")
            raise HTTPException(status_code=400, detail="Could not parse the public key. Please ensure it is in the correct format.")

        # remove trailing '=' and replace '/' with '.' since we can't have filenames with '/' in them
        finger_print = found.fingerprint.rstrip('=').replace('/','.').replace('+','.')
        finger_print = validate_fingerprint(finger_print)

        logger.info(f"Found public key {finger_print}: {found}")
        return finger_print, found

    finger_print, pkey = determine_public_key(public_key)

    # reject permanently disabled keys under any username; after the 2026-11 incident a hit here
    # is likely a leaked key being reused, so log loudly
    if await redis.sismember(DISABLED_FINGERPRINTS_SET, finger_print):
        source_ip = request.headers.get(source_ip_header_field, request.client.host)
        logger.warning(f"Reuse of disabled key rejected: upload by {found_username} for user {username} from {source_ip}: {finger_print}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This SSH key has been revoked and cannot be registered again. Please generate a new keypair."
        )

    # one key, one account: otherwise revoking it on one account would leave it live on another,
    # and anyone could register someone else's (public) key and then revoke it to lock them out
    this_key = f"user:{username}:{finger_print}"
    others = [k for k in await fingerprint_records(redis, finger_print) if k != this_key]
    if others:
        source_ip = request.headers.get(source_ip_header_field, request.client.host)
        logger.warning(f"Upload of key already registered to another account rejected: upload by {found_username} for user {username} from {source_ip}: {finger_print} (held by {others})")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This SSH key is already registered to another account. Each account needs its own keypair; please generate a new one."
        )

    # check if the public key is already registered
    existing_key = await redis.hgetall(this_key)
    logger.info(f"existing_key: {existing_key}")
    if existing_key:
        raise HTTPException(status_code=400, detail="Public key already registered for this fingerprint. Please upload a different public key or refresh the existing one.")

    # update timestamps, source_ip and user information
    bundle = {
        'username': username,
        'finger_print': finger_print,
        'public_key': pkey.get_base64(),
        'key_type': pkey.get_name(),
        'key_bits': pkey.get_bits(),
        'user_notes': '',  # initialize with empty notes
    }

    # determine time ranges
    now = pendulum.now()
    bundle.update( {
        'source_ip': request.headers.get(source_ip_header_field, request.client.host),
        IS_ACTIVE_FIELD: 1, # use this field to indicate if the key is valid or not, absence of field means invalid; see redis hexpire below. redis does not support bools
        'created_at': now,
        'valid_until': now.add(seconds=valid_seconds),
        'expires_at': EPOCH_NEVER_EXPIRE if NO_EXPIRY else now.add(seconds=expires_seconds) # set non-expiry tokens to epoch
    } )

    # convert pendulum to iso8601 string for storage
    item = convert_key_bundle_to_iso(bundle)
    this_key = f"user:{username}:{bundle['finger_print']}"
    await redis.hset( this_key, mapping=item)

    # use hexpire to automatically determine that the public key is no longer valid after valid_until
    # dragonfly doesn't support hexpiraeat; so use delta offset instead
    await redis.hexpire( this_key, valid_seconds, IS_ACTIVE_FIELD )

    logger.info(f"Registered public key for user {username}: {finger_print}, created at {bundle['created_at']}, valid until {bundle['valid_until']}, expires at {bundle['expires_at']}")

    # Send email notification
    if EMAIL_ENABLED:
        user_email = get_user_email(username)
        if user_email:

            # Format validity information
            valid_until_str = bundle['valid_until'].format('YYYY-MM-DD HH:mm:ss ZZ')
            expires_at_str = "Never" if bundle['expires_at'] == EPOCH_NEVER_EXPIRE else bundle['expires_at'].format('YYYY-MM-DD HH:mm:ss ZZ')

            # Render email body from template
            email_body = templates.get_template('sshkey_registration_email.j2').render(
                username=username,
                fingerprint=finger_print,
                key_type=pkey.get_name(),
                key_bits=pkey.get_bits(),
                source_ip=bundle['source_ip'],
                created_at=bundle['created_at'].format('YYYY-MM-DD HH:mm:ss ZZ'),
                valid_until=valid_until_str,
                expires_at=expires_at_str
            )

            try:
                await send_email(user_email, SMTP_SUBJECT, email_body)
            except Exception as e:
                logger.error(f"Failed to send email notification for key registration: {str(e)}")
                # Don't fail the request if email fails
        else:
            logger.warning(f"Could not determine email address for user {username}. Email notification not sent.")

    return JSONResponse( content={'message': item}, status_code=status.HTTP_201_CREATED )


@app.get("/authorized_keys/{username}", response_class=PlainTextResponse)
async def get_authorized_keys( request: Request, username: str, jinja_template: str = 'authorized_keys.j2', redis: aioredis.Redis = Depends(get_redis_client)):
    """
    Returns the valid public keys in authorized_keys format
    """
    logger.info(f"Fetching authorized keys for user: {username}")

    now = pendulum.now()

    keys = []
    invalid = 0
    blacklisted = 0
    disabled = 0
    async for k in redis.scan_iter(f"user:{username}:*"):
        # get item
        item = await redis.hgetall(k)

        # permanently disabled keys are never served, not even commented out; the global set
        # is checked too, so a copy of a revoked key under this username is never served
        if await is_revoked(redis, item, item.get('finger_print') or k.split(':', 2)[-1]):
            disabled += 1
            continue

        item = convert_key_bundle_to_pendulum(item)

        # Check if fingerprint is blacklisted
        is_blacklisted = False
        with blacklist_lock:
            if item.get('finger_print') in blacklist_fingerprints:
                is_blacklisted = True
                blacklisted += 1
                logger.warning(f"Blacklisted key found for user {username}: {item.get('finger_print')}")

        # Mark the key as blacklisted in the item
        item['is_blacklisted'] = is_blacklisted

        # filter out expired keys or not valid keys
        # allow non-expiry keys to pass through
        # TODO: might be a better idea to keep a field on the hash to indicate if it's valid or not
        if IS_ACTIVE_FIELD in item \
            and item['expires_at'] \
            and item['valid_until'] > now \
            and (item['expires_at'] > now or item['expires_at'] == EPOCH_NEVER_EXPIRE) \
            and (item['valid_until'] < item['expires_at'] or item['expires_at'] == EPOCH_NEVER_EXPIRE):
            keys.append(item)
        else:
            invalid += 1

    logger.info(f"Found {len(keys)} valid keys for user {username}, {invalid} expired keys, {blacklisted} blacklisted keys, {disabled} disabled keys.")

    return templates.TemplateResponse(
        name=jinja_template,  # Name of your Jinja2 template file
        request=request,    # Pass the request object
        context={
            "title": "ssh hackapp",
            "username": username,
            "keys": keys,
            "no_expiry": NO_EXPIRY
        }
    )

@app.delete("/destroy/{username}/{finger_print}", status_code=status.HTTP_204_NO_CONTENT)
@auth_okay(admin_only=True)
async def destroy_user_keypair( request: Request, username: str, finger_print: str, redis: aioredis.Redis = Depends(get_redis_client), found_username: str = None):
    """
    Destroy the SSH key pair for the given username and fingerprint.

    Accepted fingerprint format: SHA256:[A-Za-z0-9.]{43} (cleaned, no '/' or '+').
    Returns HTTP 400 if the fingerprint does not match that format.
    """
    validate_fingerprint(finger_print)
    logger.info(f"Destroying SSH key pair for user: {username} with fingerprint: {finger_print}")

    # TODO: probably better to have a field in the hash to indicate it's invalid/expired to prevent key reuse
    item = await redis.hgetall(f"user:{username}:{finger_print}")
    if not item:
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.")
    if await is_revoked(redis, item, finger_print):
        # keep the audit record of disabled keys
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"SSH key {finger_print} has been revoked; its record is retained and cannot be destroyed.")

    return await redis.delete(f"user:{username}:{finger_print}")

@app.delete("/inactivate/{username}/{finger_print}", status_code=status.HTTP_204_NO_CONTENT)
@auth_okay()
async def inactivate_user_keypair( request: Request, username: str, finger_print: str, redis: aioredis.Redis = Depends(get_redis_client), found_username: str = None):
    """
    Invalidate the SSH key pair for the given username and fingerprint.

    Accepted fingerprint format: SHA256:[A-Za-z0-9.]{43} (cleaned, no '/' or '+').
    Returns HTTP 400 if the fingerprint does not match that format.
    """
    validate_fingerprint(finger_print)
    logger.info(f"Invalidate SSH key pair for user: {username} with fingerprint: {finger_print}")

    # Check if the fingerprint is blacklisted
    with blacklist_lock:
        if finger_print in blacklist_fingerprints:
            logger.warning(f"Attempt to inactivate blacklisted key for user {username}: {finger_print}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot inactivate blacklisted SSH key with fingerprint {finger_print}."
            )

    key = f"user:{username}:{finger_print}"
    # TODO: probably better to have a field in the hash to indicate it's invalid/expired to prevent key reuse
    if not (item := await redis.hgetall(key)):
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.")
    if await is_revoked(redis, item, finger_print):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"SSH key {finger_print} has been revoked and cannot be suspended.")

    # stupid dragonfly won't overwrite the hexpire. so lets delete the hash altogether and rewrite it
    await redis.delete(key)
    item.pop(IS_ACTIVE_FIELD, None) # remove the is_active field so that it's no longer valid
    # preserve user_notes if it exists
    if 'user_notes' not in item:
        item['user_notes'] = ''
    logger.info(f"Setting {item}")
    await redis.hset( key, mapping=convert_key_bundle_to_iso(item))

    return True

@app.patch("/refresh/{username}/{finger_print}")
@auth_okay()
async def refresh_user_keypair( request: Request, username: str, finger_print: str, extend_seconds: int = VALIDITY_PERIOD, expires_seconds: int = 604800, redis: aioredis.Redis = Depends(get_redis_client), found_username: str = None):
    """
    Refresh the SSH key pair for the given username and fingerprint.

    Accepted fingerprint format: SHA256:[A-Za-z0-9.]{43} (cleaned, no '/' or '+').
    Returns HTTP 400 if the fingerprint does not match that format.
    """
    validate_fingerprint(finger_print)
    logger.info(f"Refreshing SSH key pair for user: {username} with fingerprint: {finger_print}")

    # Check if the fingerprint is blacklisted
    with blacklist_lock:
        if finger_print in blacklist_fingerprints:
            logger.warning(f"Attempt to refresh blacklisted key for user {username}: {finger_print}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot refresh blacklisted SSH key with fingerprint {finger_print}."
            )

    # allow an extra number of hours
    now = pendulum.now()
    extension = now.add(seconds=extend_seconds)

    key = f"user:{username}:{finger_print}"

    item = await redis.hgetall(key)
    if not item:
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.")
    if await is_revoked(redis, item, finger_print):
        logger.warning(f"Attempt to refresh disabled key by {found_username} for user {username}: {finger_print}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"SSH key {finger_print} has been revoked and cannot be refreshed. Please register a new key.")
    item = convert_key_bundle_to_pendulum(item)

    # do not extend past expire time
    if not NO_EXPIRY:
        # raise exception on expired keys, save for non-expiry keys
        if now >= item['expires_at'] and item['expires_at'] != EPOCH_NEVER_EXPIRE:
            raise HTTPException(status_code=400, detail="Cannot extend beyond the expiry date.")

    # handle EXPIRES DISABLED by:
    # If a key with an expiration date is refreshed while NO EXPIRE is active, convert it
    # to a non-expiry key, then grant extension
    if NO_EXPIRY:
        item['expires_at'] = EPOCH_NEVER_EXPIRE # set expire
        item['valid_until'] = extension
    # handle EXPIRES ENABLED by:
    # If a non-expiry key is refreshed while EXPIRE is active, convert it
    # to an expiry key by assigning it an expiration date, then extend normally
    else:
        # set a proper expire date
        if item['expires_at'] == EPOCH_NEVER_EXPIRE:
            item['expires_at'] = now.add(seconds=expires_seconds)
        # proceed as normal, increase to extension or only up to expiry
        if extension <= item['expires_at']:
            item['valid_until'] = extension
        else:
            item['valid_until'] = item['expires_at']

    # update storage
    await redis.delete(key)
    item[IS_ACTIVE_FIELD] = 1 # make sure it's active
    # preserve user_notes if it exists
    if 'user_notes' not in item:
        item['user_notes'] = ''
    logger.info(f"Setting {item}")
    await redis.hset( key, mapping=convert_key_bundle_to_iso(item))
    # update is_valid ttl
    await redis.hexpire( key, extend_seconds, IS_ACTIVE_FIELD )

    response_type = get_response_type(request)
    if response_type == ResponseType.HTML:
      return True
    else:
      return JSONResponse( content={'message': True}, status_code=status.HTTP_202_ACCEPTED )


@app.patch("/notes/{username}/{finger_print}")
@auth_okay()
async def update_user_notes( request: Request, username: str, finger_print: str, user_notes: UserNotes, redis: aioredis.Redis = Depends(get_redis_client), found_username: str = None):
    """
    Update the user notes for the SSH key pair for the given username and fingerprint.

    Accepted fingerprint format: SHA256:[A-Za-z0-9.]{43} (cleaned, no '/' or '+').
    Returns HTTP 400 if the fingerprint does not match that format.
    """
    validate_fingerprint(finger_print)
    logger.info(f"Updating user notes for SSH key pair for user: {username} with fingerprint: {finger_print}")

    # Check if the fingerprint is blacklisted
    with blacklist_lock:
        if finger_print in blacklist_fingerprints:
            logger.warning(f"Attempt to update notes for blacklisted key for user {username}: {finger_print}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot update notes for blacklisted SSH key with fingerprint {finger_print}."
            )

    key = f"user:{username}:{finger_print}"

    item = await redis.hgetall(key)
    if not item:
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.")
    if await is_revoked(redis, item, finger_print):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"SSH key {finger_print} has been revoked; its notes cannot be changed.")

    # Update the user_notes field
    await redis.hset(key, 'user_notes', user_notes.user_notes)
    logger.info(f"Updated user notes for {key}: {user_notes.user_notes}")

    response_type = get_response_type(request)
    if response_type == ResponseType.HTML:
      return True
    else:
      return JSONResponse( content={'message': True}, status_code=status.HTTP_202_ACCEPTED )


@app.post("/disable/{username}/{finger_print}")
@auth_okay()
async def disable_user_keypair( request: Request, username: str, finger_print: str, body: Optional[DisableRequest] = None, redis: aioredis.Redis = Depends(get_redis_client), found_username: str = None):
    """
    Permanently disable the SSH key for the given username and fingerprint.

    Unlike /inactivate (undone by /refresh), this cannot be undone: the key is never served in
    authorized_keys again and its fingerprint can never be registered again, by any user.
    The record is kept. The key owner or an admin may call this. Idempotent.
    """
    validate_fingerprint(finger_print)
    key = f"user:{username}:{finger_print}"
    item = await redis.hgetall(key)
    if not item:
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.")

    reason = body.reason if body else ''
    newly = await disable_key(redis, key, item, disabled_by=found_username, reason=reason)
    # always fan out (even if this record was already revoked) so copies registered elsewhere,
    # e.g. before one-key-one-account was enforced, are revoked too
    elsewhere = await revoke_fingerprint_everywhere(redis, finger_print, disabled_by=found_username, origin_key=key)
    if not newly:
        return JSONResponse(content={'message': 'already disabled', 'also_revoked': elsewhere}, status_code=status.HTTP_200_OK)
    return JSONResponse(content={'message': True, 'also_revoked': elsewhere}, status_code=status.HTTP_202_ACCEPTED)


@app.post("/admin/disable")
@admin_required()
async def admin_disable_keys( request: Request, body: AdminDisableRequest, redis: aioredis.Redis = Depends(get_redis_client), found_username: str = None):
    """
    Admin bulk disable: either the keys of the listed usernames, or every key
    (all=true, which also requires confirm="DISABLE ALL").
    """
    if body.all:
        if body.usernames:
            raise HTTPException(status_code=400, detail="Specify either usernames or all, not both.")
        if body.confirm != DISABLE_ALL_CONFIRMATION:
            raise HTTPException(status_code=400, detail=f'Disabling all keys requires confirm="{DISABLE_ALL_CONFIRMATION}".')
        patterns = ["user:*"]
    else:
        if not body.usernames:
            raise HTTPException(status_code=400, detail="Specify usernames, or all=true.")
        patterns = [f"user:{u}:*" for u in body.usernames]
    if not body.reason.strip():
        raise HTTPException(status_code=400, detail="A reason is required.")

    logger.warning(f"Admin bulk disable by {found_username}: {'ALL KEYS' if body.all else body.usernames}; reason: {body.reason!r}")
    disabled = already = elsewhere = 0
    touched = {}  # fingerprint -> originating key, for fanning out to other accounts
    for pattern in patterns:
        async for k in redis.scan_iter(pattern):
            item = await redis.hgetall(k)
            if not item:
                continue
            if await disable_key(redis, k, item, disabled_by=found_username, reason=body.reason):
                disabled += 1
            else:
                already += 1
            if item.get('finger_print'):
                touched.setdefault(item['finger_print'], k)
    if not body.all:  # with all=true every record is already covered
        for fp, origin in touched.items():
            elsewhere += await revoke_fingerprint_everywhere(redis, fp, disabled_by=found_username, origin_key=origin)

    logger.warning(f"Admin bulk disable by {found_username} finished: {disabled} disabled, {already} already disabled, {elsewhere} same-key copies on other accounts")
    return JSONResponse(content={'disabled': disabled, 'already_disabled': already, 'also_revoked': elsewhere}, status_code=status.HTTP_200_OK)


@app.get("/")
async def index( request: Request, jinja_template: str = 'index.html.j2'):
    return templates.TemplateResponse(
        name=jinja_template,  # Name of your Jinja2 template file
        request=request,    # Pass the request object
        context={
            "title": "slac ssh server",
        }
    )


@app.get("/{action}/", response_class=HTMLResponse)
async def create( request: Request, action: str ):
    """
    Redirect to the personal page for action.
    """
    assert action in ('register', 'list') # prob better to do this in the params
    found_username = auth(request)
    return RedirectResponse(url=f"/{action}/{found_username}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
