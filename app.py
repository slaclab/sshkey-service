from fastapi import FastAPI, HTTPException

import paramiko
from pydantic import BaseModel
from typing import Optional

import os
import io
import binascii
from loguru import logger

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

import pendulum

templates = Jinja2Templates(directory="templates")

app = FastAPI()

# In-memory storage for the key pair (in production, use a database)
SSHKEYPAIR = {
    "key_type": None,
    "username": None,
    "finger_print": None,
    "private_key": None,
    "public_key": None,
    "created_at": None,
    "valid_until": None,
    "expiry": None   
}

# class SSHKeyPair(BaseModel):
#     key_type: str
#     username: str
#     finger_print: str
#     private_key: str
#     public_key: str



@app.get("/list/{username}")
async def list( request: Request, username: str, jinja_template: str = 'list.html.j2' ):
    """
    List the SSH key pair for the given username.
    """
    logger.info(f"Listing SSH key pair for user: {username}")
    
    if not SSHKEYPAIR["username"] == username:
        raise HTTPException(status_code=404, detail=f"No SSH keys found for {username}. Call /create first.")

    return templates.TemplateResponse(
        name=jinja_template,  # Name of your Jinja2 template file
        request=request,    # Pass the request object
        context={
            "title": "list",
            "username": username, 
            "keys": [ SSHKEYPAIR ]
        }
    )


@app.get("/create/{username}")
async def create( request: Request, username: str, key_type: str = "rsa", key_bits: int = 2048, jinja_template: str = 'create.html.j2' ):
    """
    Generate and return a webpage containing instructions on how to use the keypair.
    Defaults to RSA 2048-bit key.
    Options:
    - key_type: 'rsa', 'dsa', 'ecdsa', 'ed25519'
    - key_bits: Key size (for RSA, typically 2048 or 4096)
    """
    
    logger.info(f"Rendering SSH key pair for user: {username} with type: {key_type} and bits: {key_bits}")
    
    if key_bits not in [2048, 4096]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Key bits must be 2048 or 4096."
        )

    try:
        bundle = generate_keypair(username, key_type, key_bits)
        SSHKEYPAIR.update(bundle)
        
        return templates.TemplateResponse(
            name=jinja_template,  # Name of your Jinja2 template file
            request=request,    # Pass the request object
            context={
                "title": "ssh hackapp", 
                "username": username, 
                "prefix_path": "~/.ssh/s3df",
                "keys": SSHKEYPAIR
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def generate_keypair( username: str, key_type: str = "rsa", key_bits: int = 2048 ):
    """
    Generate a new SSH key pair.
    Defaults to RSA 2048-bit key.
    Options:
    - key_type: 'rsa', 'dsa', 'ecdsa', 'ed25519'
    - key_bits: Key size (for RSA, typically 2048 or 4096)
    - comment: Comment to include in the public key
    """

    logger.info(f"Generating SSH key pair for user: {username} with type: {key_type} and bits: {key_bits}")

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
    
    return {
        'key_type': key.get_name(),
        'username': username,
        'finger_print': binascii.hexlify(key.get_fingerprint()).decode('utf-8'),
        'private_key': private_key,
        'public_key': key.get_base64(),
        'created_at': pendulum.now().to_iso8601_string(),
        'valid_until': pendulum.now().add(hours=25).to_iso8601_string(),
        'expires_at': pendulum.now().add(days=30).to_iso8601_string()  
    }   

@app.get("/authorized_keys/{username}", response_class=PlainTextResponse)
async def get_authorized_keys(request: Request, username: str, jinja_template: str = 'authorized_keys.j2'): 
    """
    Returns the public key in authorized_keys format
    """
    logger.info(f"Fetching authorized keys for user: {username}: {SSHKEYPAIR}")
    if not username == SSHKEYPAIR["username"]:
        raise HTTPException(status_code=404, detail=f"No SSH keys found for {username} generated yet. Call /generate-keypair first.")
    
    keys = [ SSHKEYPAIR ]
    
    return templates.TemplateResponse(
        name=jinja_template,  # Name of your Jinja2 template file
        request=request,    # Pass the request object
        context={
            "title": "ssh hackapp", 
            "username": username, 
            "keys": keys
        }
    )
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)





