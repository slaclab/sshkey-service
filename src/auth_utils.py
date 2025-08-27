import os

from fastapi import HTTPException, Request
from loguru import logger

USERNAME_HEADER_FIELD = os.environ.get('SLACSSH_USERNAME_HEADER_FIELD', 'REMOTE-USER')

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

