"""
FastAPI application entry point for the Bitcoin Node Scanner web interface.
"""
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .routers import nodes, stats, scans, vulnerabilities

_STATIC_DIR = Path(__file__).parent / "static"

# Validate required configuration at import time so the process fails fast
# if misconfigured (e.g., launched by a process manager).
_WEB_API_KEY = os.getenv("WEB_API_KEY")
if not _WEB_API_KEY:
    raise RuntimeError(
        "WEB_API_KEY environment variable is not set. "
        "Set it before starting the web server."
    )

app = FastAPI(
    title="Bitcoin Node Scanner",
    description="Web interface for the Bitcoin Node Security Scanner",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# API routers
app.include_router(nodes.router, prefix="/api/v1")
app.include_router(stats.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(vulnerabilities.router, prefix="/api/v1")

# Serve dashboard
if _STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def dashboard():
    index = _STATIC_DIR / "index.html"
    if index.is_file():
        return FileResponse(str(index))
    return {"message": "Bitcoin Node Scanner API is running. See /docs for API reference."}


def start():
    """Entry point for the `bitcoin-scanner-web` console script."""
    import uvicorn

    host = os.getenv("WEB_HOST", "127.0.0.1")
    port = int(os.getenv("WEB_PORT", "8000"))
    uvicorn.run("src.web.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    start()
