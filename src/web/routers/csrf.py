"""
GET /api/v1/csrf-token — issue a CSRF token as a cookie and in the response body.
"""
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/csrf-token", include_in_schema=False)
def get_csrf_token(request: Request) -> JSONResponse:
    token = secrets.token_hex(32)
    response = JSONResponse(content={"csrfToken": token})
    response.set_cookie(
        key="csrftoken",
        value=token,
        samesite="lax",
        httponly=True,
        path="/",
        secure=request.url.scheme == "https",
    )
    return response
