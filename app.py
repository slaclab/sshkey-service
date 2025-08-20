from fastapi import FastAPI, HTTPException

import paramiko
from pydantic import BaseModel
from typing import Optional

import os
import io
import binascii
from loguru import logger

from fastapi import FastAPI, Request, status
from fastapi.responses import PlainTextResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import pendulum
import hashlib
import base64

templates = Jinja2Templates(directory="templates")

class PublicKey(BaseModel):
    public_key: str

app = FastAPI()

# In-memory storage for the key pair (in production, use a database), nested dict of username and key fingerprint
# This is a simple in-memory storage for demonstration purposes. please use a proper database in production.

ALL_KEYS = {} 
# SSHKEYPAIR = {
#     "key_type": None,
#     "username": None,
#     "finger_print": None,
#     "private_key": None,
#     "public_key": None,
#     "source_ip": None,
#     "created_at": None,
#     "valid_until": None,
#     "expiry": None   
# }

USERNAME_HEADER_FIELD = os.environ.get('SLACSSH_USERNAME_HEADER_FIELD', 'REMOTE-USER')


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

# shudl probably refactor this as a decorator...
def auth_okay(request: Request, username: str, user_header: str = USERNAME_HEADER_FIELD):
    """
    Check if the logged in user is expected to be allowed to access this resource
    """
    #logger.debug(f'all headers: {request.headers}')
    # only allow user defined in the request, or if user is admin
    admins = os.getenv('SLACSSH_ADMINS', '').split(',')
    found_username = auth(request, user_header)
    if found_username != username and found_username not in admins:
        logger.error(f"Unauthorized access attempt by user: {found_username}. Expected user: {username}.")
        raise HTTPException(status_code=403, detail=f"Forbidden: User {found_username} is not allowed to access this resource.")
    logger.info(f"User {found_username} is authorized to access the resource.")
    # if we reach here, the user is good
    return found_username


@app.get("/list/{username}")
async def list_user_keypair( request: Request, username: str, jinja_template: str = 'list.html.j2' ):
    """
    List the SSH key pair for the given username.
    """
    logger.info(f"Listing SSH key pair for user: {username}")
    
    found_username = auth_okay(request, username)

    keys = []
    if username in ALL_KEYS:
        keys = [ ALL_KEYS[username][finger_print] for finger_print in ALL_KEYS[username].keys() ]

    return templates.TemplateResponse(
        name=jinja_template,  # Name of your Jinja2 template file
        request=request,    # Pass the request object
        context={
            "title": "list",
            "username": username, 
            "keys": keys
        }
    )


@app.get("/create/{username}")
async def create_user_keypair( request: Request, username: str, key_type: str = "rsa", key_bits: int = 2048, jinja_template: str = 'create.html.j2', source_ip_header_field: str = 'x-real-ip', valid_seconds: int = 90000, expires_seconds: int = 604800 ):
    """
    Generate and return a webpage containing instructions on how to use the keypair.
    Defaults to RSA 2048-bit key.
    Options:
    - key_type: 'rsa', 'dsa', 'ecdsa', 'ed25519'
    - key_bits: Key size (for RSA, typically 2048 or 4096)
    """
    
    found_username = auth_okay(request, username)

    logger.info(f"Rendering SSH key pair for user: {username} with type: {key_type} and bits: {key_bits}")
    
    if key_bits not in [2048, 4096]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Key bits must be 2048 or 4096."
        )

    try:
        bundle = generate_keypair( key_type, key_bits)

        # update timestamps, source_ip and user information
        now = pendulum.now()        
        bundle.update( {
            'username': username,
            'source_ip': request.headers.get(source_ip_header_field, request.client.host),
            'created_at': now,
            'valid_until': now.add(seconds=valid_seconds),
            'expires_at': now.add(seconds=expires_seconds)
        } )

        if not username in ALL_KEYS:
            ALL_KEYS[username] = {}

        # make sure we do not store the private key
        ALL_KEYS[username][bundle['finger_print']] = bundle
        show = ALL_KEYS[username][bundle['finger_print']].copy()
        bundle['private_key'] = None

        return templates.TemplateResponse(
            name=jinja_template,  # Name of your Jinja2 template file
            request=request,    # Pass the request object
            context={
                "title": "ssh hackapp", 
                "username": username, 
                "prefix_path": "~/.ssh/s3df",
                "keys": show,
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def generate_keypair( key_type: str = "rsa", key_bits: int = 2048, valid_seconds: int = 90000, expires_seconds: int = 604800 ):
    """
    Generate a new SSH key pair.
    Defaults to RSA 2048-bit key.
    Options:
    - key_type: 'rsa', 'dsa', 'ecdsa', 'ed25519'
    - key_bits: Key size (for RSA, typically 2048 or 4096)
    - comment: Comment to include in the public key
    """

    logger.info(f"Generating {key_bits} bit {key_type} ssh keypair...")

    key = None
    if key_type == "rsa":
        key = paramiko.RSAKey.generate(bits=key_bits)
    elif key_type == "dsa":
        key = paramiko.DSSKey.generate(bits=key_bits)
    elif key_type == "ecdsa":
        key = paramiko.ECDSAKey.generate()
    elif key_type == "ed25519":
        key = paramiko.ed25519key.Ed25519Key.generate()
    else:
        raise HTTPException(status_code=400, detail="Invalid key type. Choose rsa, dsa, ecdsa, or ed25519")
    
    # Store the keys in memory
    # private
    private_key_string_io = io.StringIO()
    key.write_private_key(private_key_string_io)
    private_key = private_key_string_io.getvalue()
    
    # obtain a fingerprint that should be the same as that reported by sshd when key is used
    public_key = key.get_base64() 
    sha256 = hashlib.sha256()
    sha256.update(base64.b64decode(public_key))
    hash_sha256 = sha256.digest()
    # remove trailing '=' and replace '/' with '.' since we can't have filenames with '/' in them
    finger_print = f"SHA256:{base64.b64encode(hash_sha256).decode('utf-8').rstrip('=').replace('/','.').replace('+','.')}"

    return {
        'key_type': key.get_name(),
        'finger_print': finger_print,
        'private_key': private_key,
        'public_key': public_key,
    }


@app.get("/generate/{username}")
async def generate_user_keypair( request: Request, username: str, key_type: str = "ed25519", key_bits: int = 2048, jinja_template: str = 'generate.html.j2'):
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
            "prefix_path": "~/.ssh/s3df"
        }
    )



@app.post("/upload/{username}")
async def upload_user_public_key( request: Request, username: str, public_key: PublicKey, source_ip_header_field: str = 'x-real-ip', valid_seconds: int = 90000, expires_seconds: int = 604800  ):
    """ Uploads the public key for the given username.
    """
    found_username = auth_okay(request, username)

    logger.info(f"Uploading public key for user: {username}")

    pubkey = paramiko.pkey.PKey(data=public_key.public_key.strip())
    fingerprint = pubkey.fingerprint
    # shoudl check if the public key is already registered

    # update timestamps, source_ip and user information
    now = pendulum.now()
    bundle = {
        'username': username,
        'public_key': public_key.public_key.strip(),
        'key_type': None, # will be calculated later
        'finger_print': fingerprint,
    }

    # determine time ranges
    bundle.update( {
        'source_ip': request.headers.get(source_ip_header_field, request.client.host),
        'created_at': now,
        'valid_until': now.add(seconds=valid_seconds),
        'expires_at': now.add(seconds=expires_seconds)
    } ) 

    # make sure we do not store the private key
    bundle['private_key'] = None

    if not username in ALL_KEYS:
        ALL_KEYS[username] = {}

    ALL_KEYS[username][bundle['finger_print']] = bundle

    return True



@app.get("/authorized_keys/{username}", response_class=PlainTextResponse)
async def get_authorized_keys( request: Request, username: str, jinja_template: str = 'authorized_keys.j2'): 
    """
    Returns the valid public keys in authorized_keys format
    """
    logger.info(f"Fetching authorized keys for user: {username}")
    if not username in ALL_KEYS:
        raise HTTPException(status_code=404, detail=f"No SSH keys found for {username} generated yet. Call /generate-keypair first.")
    
    now = pendulum.now()

    keys = []
    # filter out expired keys or not valid keys
    for finger_print in ALL_KEYS[username].keys():
        if ALL_KEYS[username][finger_print]['valid_until'] > now \
            and ALL_KEYS[username][finger_print]['expires_at'] > now \
            and ALL_KEYS[username][finger_print]['valid_until'] < ALL_KEYS[username][finger_print]['expires_at']:
            keys.append(ALL_KEYS[username][finger_print])

    logger.info(f"Found {len(keys)} valid keys for user: {username}")

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
async def destroy_user_keypair( request: Request, username: str, finger_print: str):
    """
    Destroy the SSH key pair for the given username and fingerprint.
    """

    found_username = auth_okay(request, username)

    logger.info(f"Destroying SSH key pair for user: {username} with fingerprint: {finger_print}")
    
    if not username in ALL_KEYS or finger_print not in ALL_KEYS[username]:
        raise HTTPException(status_code=404, detail=f"No SSH keys found for {username} with fingerprint {finger_print}.")
    
    del ALL_KEYS[username][finger_print]
    return {}
    
@app.patch("/refresh/{username}/{finger_print}")
async def refresh_user_keypair( request: Request, username: str, finger_print: str, extend_seconds: int = 90000):
    """
    Refresh the SSH key pair for the given username and fingerprint.
    """

    found_username = auth_okay(request, username)

    logger.info(f"Refreshing SSH key pair for user: {username} with fingerprint: {finger_print}")
    
    if not username in ALL_KEYS or finger_print not in ALL_KEYS[username]:
        raise HTTPException(status_code=404, detail=f"No SSH keys found for {username} with fingerprint {finger_print}.")
    
    # allow an extra number of hours
    extension = pendulum.now().add(seconds=extend_seconds)
    # okay to extend validity
    if extension < ALL_KEYS[username][finger_print]['expires_at']:
       ALL_KEYS[username][finger_print]['valid_until'] = extension
    # extend upto the expiry
    elif extension > ALL_KEYS[username][finger_print]['expires_at']:
        # extend the expiry date
        ALL_KEYS[username][finger_print]['valid_until'] = ALL_KEYS[username][finger_print]['expires_at'] 
    # nope
    else:
        raise HTTPException(status_code=400, detail="Cannot extend beyond the expiry date.")
    
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

@app.get("/list/", response_class=HTMLResponse)
async def list( request: Request ):
    """
    Redirect to the personal keypair list page.
    """
    found_username = auth(request)
    return RedirectResponse(url=f"/list/{found_username}")


@app.get("/create/", response_class=HTMLResponse)
async def create( request: Request ):
    """
    Redirect to the personal create keypaior page.
    """
    found_username = auth(request)
    return RedirectResponse(url=f"/create/{found_username}")



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)





