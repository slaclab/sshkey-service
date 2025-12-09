from fastapi import FastAPI, HTTPException

import paramiko
from pydantic import BaseModel
from typing import Optional

import os
import io
import binascii
from loguru import logger

from fastapi import FastAPI, Request, status, Depends
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from contextlib import asynccontextmanager
import redis.asyncio as aioredis

import pendulum
import hashlib
import base64

templates = Jinja2Templates(directory="templates")

# global parameters from env
REDIS_HOST = os.environ.get('SLACSSH_REDIS_HOST', 'dragonfly')
REDIS_PORT = os.environ.get('SLACSSH_REDIS_PORT', 6379)
REDIS_PASSWORD = os.environ.get('SLACSSH_REDIS_PASSWORD', None)
REDIS_DB = int(os.environ.get('SLACSSH_REDIS_DB', 0))

USERNAME_HEADER_FIELD = os.environ.get('SLACSSH_USERNAME_HEADER_FIELD', 'REMOTE-USER')

# validity of key use
VALIDITY_PERIOD = os.environ.get('SLACSSH_VALIDITY_PERIOD', 90000 )

# whether the key expires or not
NO_EXPIRY = True
EPOCH_NEVER_EXPIRE = pendulum.datetime(1970,1,1) # no expiration for keys set to unix epoch


class PublicKey(BaseModel):
    public_key: str

# use this to determine the redis hash field to indicate if the key is active or not; use hexpire where necessary
IS_ACTIVE_FIELD = 'is_active'

# initiate redis client
@asynccontextmanager
async def lifespan(app: FastAPI):
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

app = FastAPI(lifespan=lifespan)

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

# shudl probably refactor this as a decorator...
# should probably be more defensive about this and default to returning false; only return true if everything checks out
def auth_okay(request: Request, username: str, admin_only: bool = False, user_header: str = USERNAME_HEADER_FIELD):
    """
    Check if the logged in user is expected to be allowed to access this resource
    """
    #logger.debug(f'all headers: {request.headers}')
    # only allow user defined in the request, or if user is admin
    admins = os.getenv('SLACSSH_ADMINS', '').split(',')
    found_username = auth(request, user_header)

    if not admin_only:
        if found_username != username and found_username not in admins:
            logger.error(f"Unauthorized access attempt by user: {found_username}. Expected user: {username}.")
            raise HTTPException(status_code=403, detail=f"Forbidden: User {found_username} is not allowed to access this resource.")
    else:
        if found_username not in admins:
            logger.error(f"Unauthorized admin access attempt by user: {found_username}.")
            raise HTTPException(status_code=403, detail=f"Forbidden: User {found_username} is not an admin.")

    logger.info(f"User {found_username} is authorized to access the resource.")
    # if we reach here, the user is good
    return found_username


@app.get("/list/{username}")
async def list_user_keypair( request: Request, username: str, jinja_template: str = 'list.html.j2', redis: aioredis.Redis = Depends(get_redis_client) ):
    """
    List the SSH key pair for the given username.
    """
    logger.info(f"Listing SSH key pair for user: {username}")

    found_username = auth_okay(request, username)

    # TODO: should probably pipeline this...
    keys = []
    async for k in redis.scan_iter(f"user:{username}:*"):
        item = await redis.hgetall(k)
        item = convert_key_bundle_to_pendulum( item )
        logger.info(f"Found key: {item}")
        keys.append(item)

    return templates.TemplateResponse(
        name=jinja_template,  # Name of your Jinja2 template file
        request=request,    # Pass the request object
        context={
            "title": "list",
            "username": username,
            "keys": keys,
            "no_expiry": NO_EXPIRY
        }
    )



@app.get("/register/{username}")
async def register_user_keypair( request: Request, username: str, key_type: str = "ed25519", key_bits: int = 2048, jinja_template: str = 'register.html.j2'):
    """
    shows instructions for how to create a keypair and upload it to us
    """
    found_username = auth_okay(request, username)

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
async def upload_user_public_key( request: Request, username: str, public_key: PublicKey, source_ip_header_field: str = 'x-real-ip', valid_seconds: int = VALIDITY_PERIOD, expires_seconds: int = 604800, redis: aioredis.Redis = Depends(get_redis_client)):
    """ Uploads the public key for the given username.
    """
    found_username = auth_okay(request, username)

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
        key_data_base64 = ""
        key_type = None
        for line in public_key.public_key.splitlines():
            if line.strip() == "---- BEGIN SSH2 PUBLIC KEY ----":
                in_key_block = True
                continue
            elif line.strip() == "---- END SSH2 PUBLIC KEY ----":
                break

            if in_key_block:
                if line.strip().startswith("Comment:"):
                    # Extract key type from comment
                    comment = line.strip().split(':', 1)[1].strip()
                    if "ED25519" in comment:
                        key_type = "ssh-ed25519"
                    elif "RSA" in comment:
                        key_type = "ssh-rsa"
                    # Add other key types as needed
                    continue
                else:
                    key_data_base64 += line.strip()

        # error out if not valid
        if not key_data_base64 or not key_type:
            raise HTTPException(status_code=400, detail="Invalid public key format. Please ensure it is in the correct format.")

        found = None
        try:
            found = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_data_base64))
        except Exception as e:
            raise HTTPException(status_code=400, detail="Could not parse the public key. Please ensure it is in the correct format.")

        # remove trailing '=' and replace '/' with '.' since we can't have filenames with '/' in them
        finger_print = found.fingerprint.rstrip('=').replace('/','.').replace('+','.')

        logger.info(f"Found public key {finger_print}: {found}")
        return finger_print, found

    finger_print, pkey = determine_public_key(public_key)

    # check if the public key is already registered
    existing_key = await redis.hgetall(f"user:{username}:{finger_print}")
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
    return JSONResponse( content=item, status_code=status.HTTP_201_CREATED )


@app.get("/authorized_keys/{username}", response_class=PlainTextResponse)
async def get_authorized_keys( request: Request, username: str, jinja_template: str = 'authorized_keys.j2', redis: aioredis.Redis = Depends(get_redis_client)):
    """
    Returns the valid public keys in authorized_keys format
    """
    logger.info(f"Fetching authorized keys for user: {username}")

    now = pendulum.now()

    keys = []
    invalid = 0
    async for k in redis.scan_iter(f"user:{username}:*"):
        # get item
        item = await redis.hgetall(k)
        item = convert_key_bundle_to_pendulum(item)

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

    logger.info(f"Found {len(keys)} valid keys for user {username}, {invalid} expired keys.")

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
async def destroy_user_keypair( request: Request, username: str, finger_print: str, redis: aioredis.Redis = Depends(get_redis_client)):
    """
    Destroy the SSH key pair for the given username and fingerprint.
    """
    found_username = auth_okay(request, username, admin_only=True)
    logger.info(f"Destroying SSH key pair for user: {username} with fingerprint: {finger_print}")

    # TODO: probably better to have a field in the hash to indicate it's invalid/expired to prevent key reuse
    item = await redis.hgetall(f"user:{username}:{finger_print}")
    if not item:
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.")

    return await redis.delete(f"user:{username}:{finger_print}")

@app.delete("/inactivate/{username}/{finger_print}", status_code=status.HTTP_204_NO_CONTENT)
async def inactivate_user_keypair( request: Request, username: str, finger_print: str, redis: aioredis.Redis = Depends(get_redis_client)):
    """
    Invalidate the SSH key pair for the given username and fingerprint.
    """
    found_username = auth_okay(request, username)
    logger.info(f"Invalidate SSH key pair for user: {username} with fingerprint: {finger_print}")

    key = f"user:{username}:{finger_print}"
    # TODO: probably better to have a field in the hash to indicate it's invalid/expired to prevent key reuse
    if not (item := await redis.hgetall(key)):
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.")

    # stupid dragonfly won't overwrite the hexpire. so lets delete the hash altogether and rewrite it
    await redis.delete(key)
    item.pop(IS_ACTIVE_FIELD, None) # remove the is_active field so that it's no longer valid
    logger.info(f"Setting {item}")
    await redis.hset( key, mapping=convert_key_bundle_to_iso(item))

    return True

@app.patch("/refresh/{username}/{finger_print}")
async def refresh_user_keypair( request: Request, username: str, finger_print: str, extend_seconds: int = VALIDITY_PERIOD, expires_seconds: int = 604800, redis: aioredis.Redis = Depends(get_redis_client)):
    """
    Refresh the SSH key pair for the given username and fingerprint.
    """
    found_username = auth_okay(request, username)
    logger.info(f"Refreshing SSH key pair for user: {username} with fingerprint: {finger_print}")

    # allow an extra number of hours
    now = pendulum.now()
    extension = now.add(seconds=extend_seconds)

    key = f"user:{username}:{finger_print}"

    item = await redis.hgetall(key)
    if not item:
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.")
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
    logger.info(f"Setting {item}")
    await redis.hset( key, mapping=convert_key_bundle_to_iso(item))
    # update is_valid ttl
    await redis.hexpire( key, extend_seconds, IS_ACTIVE_FIELD )

    return True


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
