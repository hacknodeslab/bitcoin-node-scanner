"""
FastAPI application entry point for the Bitcoin Node Scanner web interface.
"""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from ..db.connection import init_db
from . import l402
from .routers import nodes, stats, scans, vulnerabilities, csrf

_STATIC_DIR = Path(__file__).parent / "static"

# Validate required configuration at import time so the process fails fast
# if misconfigured (e.g., launched by a process manager).
_WEB_API_KEY = os.getenv("WEB_API_KEY")
if not _WEB_API_KEY:
    raise RuntimeError(
        "WEB_API_KEY environment variable is not set. "
        "Set it before starting the web server."
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


_docs_enabled = os.getenv("ENABLE_API_DOCS", "").lower() in {"1", "true", "yes"}

app = FastAPI(
    title="Bitcoin Node Scanner",
    description="Web interface for the Bitcoin Node Security Scanner",
    version="1.0.0",
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
    lifespan=lifespan,
)

_frontend_origins = [
    o.strip()
    for o in os.getenv("FRONTEND_ORIGIN", "http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_frontend_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["X-API-Key", "X-CSRF-Token", "Content-Type", "Accept"],
)

# API routers
app.include_router(nodes.router, prefix="/api/v1")
app.include_router(stats.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(vulnerabilities.router, prefix="/api/v1")
app.include_router(csrf.router, prefix="/api/v1")
app.include_router(l402.router, prefix="/api/v1")

# Serve dashboard
if _STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def dashboard():
    # Migration: the legacy static dashboard at src/web/static/index.html is being
    # replaced by the Next.js app at frontend/ (change: redesign-dashboard-design-system).
    # While index.html still exists, serve it for backward compatibility. Once it is
    # removed (cutover task 11.1), this endpoint redirects to FRONTEND_ORIGIN.
    # Deprecation reminder: drop this redirect 30 days after cutover.
    index = _STATIC_DIR / "index.html"
    if index.is_file():
        return FileResponse(str(index))
    target = _frontend_origins[0] if _frontend_origins else "http://localhost:3000"
    return RedirectResponse(url=target, status_code=302)


def start():
    """Entry point for the `bitcoin-scanner-web` console script."""
    import uvicorn

    host = os.getenv("WEB_HOST", "127.0.0.1")
    port = int(os.getenv("WEB_PORT", "8000"))
    uvicorn.run("src.web.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    start()
