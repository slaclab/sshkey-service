import os
import io
import binascii
import hashlib
import base64
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status, Depends
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import paramiko
import pendulum
import redis.asyncio as aioredis
from loguru import logger

from auth_utils import auth_okay
from keybundle import KeyBundle

templates = Jinja2Templates(directory="templates")

# global parameters from env
REDIS_HOST = os.environ.get('SLACSSH_REDIS_HOST', 'dragonfly')
REDIS_PORT = os.environ.get('SLACSSH_REDIS_PORT', 6379)
REDIS_PASSWORD = os.environ.get('SLACSSH_REDIS_PASSWORD', None)
REDIS_DB = int(os.environ.get('SLACSSH_REDIS_DB', 0))

USERNAME_HEADER_FIELD = os.environ.get('SLACSSH_USERNAME_HEADER_FIELD', 'REMOTE-USER')


class PublicKey(BaseModel):
    public_key: str


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

def auth(request: Request, user_header: str = USERNAME_HEADER_FIELD):
    """
    Check if the request is authenticated.
    """
    # only allow user defined in the request, or if user is admin
    found_username = request.headers.get( user_header )
    logger.info(f"Found user {found_username} (looking at header {user_header})")
    if not found_username:
        logger.error("No username found in request headers.")
        raise HTTPException(status_code=401, detail="Unauthorized: No username found in request headers. Please check application configuration for env SLACSSH_USERNAME_HEADER_FIELD.")
    # if we reach here, the user is authorized
    return found_username

@app.get("/list/{username}")
async def list_user_keypair( request: Request, username: str, found_username: str = Depends(auth_okay), jinja_template: str = 'list.html.j2', redis: aioredis.Redis = Depends(get_redis_client) ):
    """
    List the SSH key pair for the given username.
    """
    logger.info(f"Listing SSH key pair for user: {username}")
    
    # TODO: should probably pipeline this...
    keys = []
    async for k in redis.scan_iter(f"user:{username}:*"):
        item = await redis.hgetall(k)
        # convert timestamps back to pendulum
        item = KeyBundle.to_pendulum(item)
        keys.append(item)

    return templates.TemplateResponse(
        name=jinja_template,  # Name of your Jinja2 template file
        request=request,    # Pass the request object
        context={
            "title": "list",
            "username": username, 
            "keys": keys
        }
    )



@app.get("/register/{username}")
async def register_user_keypair( request: Request, username: str, found_username: str = Depends(auth_okay), key_type: str = "ed25519", key_bits: int = 2048, jinja_template: str = 'register.html.j2'):
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
            "prefix_path": "~/.ssh/s3df"
        }
    )


@app.post("/upload/{username}")
async def upload_user_public_key(
    request: Request,
    username: str,
    found_username: str = Depends(auth_okay)
    public_key: PublicKey,
    source_ip_header_field: str = 'x-real-ip',
    valid_seconds: int = 90000,
    expires_seconds: int = 604800,
    redis: aioredis.Redis = Depends(get_redis_client)
):

    """ Uploads the public key for the given username.
    """
    logger.info(f"Uploading public key for user: {username}: {public_key.public_key}")

    finger_print, pkey = KeyBundle.determine_public_key(public_key)

    # check if the public key is already registered
    existing_key = await redis.hgetall(f"user:{username}:{finger_print}")
    logger.info(f"existing_key: {existing_key}")
    if existing_key:
        raise HTTPException(status_code=400, detail="Public key already registered for this fingerprint. Please upload a different public key or refresh the existing one.")
    

    bundle = KeyBundle.build(
        username=username,
        public_key_str=public_key.public_key,
        source_ip=request.headers.get(source_ip_header_field, request.client.host),
        valid_seconds=valid_seconds,
        expires_seconds=expires_seconds
    )
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
        'created_at': now,
        'valid_until': now.add(seconds=valid_seconds),
        'expires_at': now.add(seconds=expires_seconds)
    } ) 

    
    

}

    # convert pendulum to iso8601 string for storage
    item = convert_key_bundle_to_iso(bundle)
    await redis.hset(f"user:{username}:{bundle['finger_print']}", mapping=item)

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
        # TODO: might be a better idea to keep a field on the hash to indicate if it's valid or not
        if item['valid_until'] > now \
            and item['expires_at'] > now \
            and item['valid_until'] < item['expires_at']:
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
            "keys": keys
        }
    )

@app.delete("/destroy/{username}/{finger_print}", status_code=status.HTTP_204_NO_CONTENT)
async def destroy_user_keypair( request: Request, username: str, found_username: str = Depends(auth_okay), finger_print: str, redis: aioredis.Redis = Depends(get_redis_client)):
    """
    Destroy the SSH key pair for the given username and fingerprint.
    """
    logger.info(f"Destroying SSH key pair for user: {username} with fingerprint: {finger_print}")
    
    # TODO: probably better to have a field in the hash to indicate it's invalid/expired to prevent key reuse
    item = await redis.hgetall(f"user:{username}:{finger_print}")
    if not item:
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.") 
    
    return await redis.delete(f"user:{username}:{finger_print}")


@app.patch("/refresh/{username}/{finger_print}")
async def refresh_user_keypair( request: Request, username: str, found_username: str = Depends(auth_okay), finger_print: str, extend_seconds: int = 90000, redis: aioredis.Redis = Depends(get_redis_client)):
    """
    Refresh the SSH key pair for the given username and fingerprint.
    """
    logger.info(f"Refreshing SSH key pair for user: {username} with fingerprint: {finger_print}")
    
    # allow an extra number of hours
    extension = pendulum.now().add(seconds=extend_seconds)

    item = await redis.hgetall(f"user:{username}:{finger_print}")
    if not item:
        raise HTTPException(status_code=404, detail=f"No SSH public key found for {username} with fingerprint {finger_print}.")
    item = convert_key_bundle_to_pendulum(item)

    # okay to extend validity
    if extension < item['expires_at']:
       item['valid_until'] = extension
    # extend upto the expiry
    elif extension > item['expires_at']:
        # extend the expiry date
        item['valid_until'] = item['expires_at'] 
    # nope
    else:
        raise HTTPException(status_code=400, detail="Cannot extend beyond the expiry date.")
    
    # update storage
    await redis.hset(f"user:{username}:{item['finger_print']}", mapping=convert_key_bundle_to_iso(item))

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





