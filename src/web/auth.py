"""
API key authentication dependency for the web interface.
"""
import os
import secrets

from fastapi import Cookie, Header, HTTPException, Security, status
from fastapi.security import APIKeyHeader

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str = Security(_api_key_header)) -> str:
    """
    FastAPI dependency that validates the X-API-Key header.

    Returns the key on success; raises HTTP 401 on missing or incorrect key.
    """
    expected = os.getenv("WEB_API_KEY")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration: WEB_API_KEY not set.",
        )
    if not api_key or not secrets.compare_digest(api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return None


def require_csrf_token(
    x_csrf_token: str = Header(default=None, alias="X-CSRF-Token"),
    csrftoken: str = Cookie(default=None),
) -> None:
    if not x_csrf_token or not csrftoken:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid",
        )
    if not secrets.compare_digest(x_csrf_token, csrftoken):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid",
        )
