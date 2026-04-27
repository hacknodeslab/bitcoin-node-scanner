"""
L402 (Lightning HTTP 402) challenge helper.

Until the full L402 capability lands (macaroon issuance, Lightning invoice
generation, status polling, content unlock), protected resources respond with
HTTP 402 + a placeholder `WWW-Authenticate: L402 ...` header. The frontend
detects the challenge and surfaces a non-blocking note. The full payment flow
is tracked in the `l402-payment-flow` change.
"""
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

_PLACEHOLDER_MACAROON = "placeholder-macaroon"
_PLACEHOLDER_INVOICE = "placeholder-invoice"


def l402_challenge_response() -> JSONResponse:
    """Return a 402 response with an L402 WWW-Authenticate challenge header."""
    return JSONResponse(
        status_code=402,
        content={"error": "l402_pending"},
        headers={
            "WWW-Authenticate": (
                f'L402 macaroon="{_PLACEHOLDER_MACAROON}", '
                f'invoice="{_PLACEHOLDER_INVOICE}"'
            )
        },
    )


@router.get("/l402/example", include_in_schema=False)
def l402_example() -> JSONResponse:
    """Example protected resource exercising the L402 challenge helper."""
    return l402_challenge_response()
