"""
Unit tests for the web API key authentication dependency.
"""
import os
import pytest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

# Set a dummy key before importing main (main validates at import time)
os.environ.setdefault("WEB_API_KEY", "test-key-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_web_auth.db")

from src.web.auth import require_api_key, require_csrf_token
from src.web.routers.csrf import router as csrf_router
from src.web.routers.nodes import get_db


@pytest.fixture
def simple_app():
    """Minimal FastAPI app with a single protected endpoint."""
    app = FastAPI()

    @app.get("/protected")
    def protected(key: str = __import__("fastapi").Depends(require_api_key)):
        return {"ok": True}

    return app


@pytest.fixture
def client(simple_app):
    return TestClient(simple_app, raise_server_exceptions=True)


class TestRequireApiKey:
    def test_valid_key_is_accepted(self, client):
        with patch.dict(os.environ, {"WEB_API_KEY": "secret"}):
            r = client.get("/protected", headers={"X-API-Key": "secret"})
        assert r.status_code == 200
        assert r.json() == {"ok": True}

    def test_missing_key_returns_401(self, client):
        with patch.dict(os.environ, {"WEB_API_KEY": "secret"}):
            r = client.get("/protected")
        assert r.status_code == 401

    def test_wrong_key_returns_401(self, client):
        with patch.dict(os.environ, {"WEB_API_KEY": "secret"}):
            r = client.get("/protected", headers={"X-API-Key": "wrong"})
        assert r.status_code == 401


@pytest.fixture
def csrf_app():
    """Minimal FastAPI app exposing the CSRF token endpoint and a CSRF-protected POST."""
    from fastapi import Depends

    app = FastAPI()
    app.include_router(csrf_router, prefix="/api/v1")

    @app.post("/csrf-protected")
    def protected(_: None = Depends(require_csrf_token)):
        return {"ok": True}

    return app


@pytest.fixture
def csrf_client(csrf_app):
    return TestClient(csrf_app, raise_server_exceptions=True)


class TestCsrfDoubleSubmit:
    def test_cookie_uses_samesite_lax(self, csrf_client):
        r = csrf_client.get("/api/v1/csrf-token")
        assert r.status_code == 200
        cookie_header = r.headers.get("set-cookie", "")
        assert "samesite=lax" in cookie_header.lower()

    def test_matching_token_passes(self, csrf_client):
        token = csrf_client.get("/api/v1/csrf-token").json()["csrfToken"]
        r = csrf_client.post("/csrf-protected", headers={"X-CSRF-Token": token})
        assert r.status_code == 200

    def test_missing_header_rejected(self, csrf_client):
        csrf_client.get("/api/v1/csrf-token")
        r = csrf_client.post("/csrf-protected")
        assert r.status_code == 403

    def test_mismatched_header_rejected(self, csrf_client):
        csrf_client.get("/api/v1/csrf-token")
        r = csrf_client.post("/csrf-protected", headers={"X-CSRF-Token": "not-the-cookie-value"})
        assert r.status_code == 403

    def test_missing_cookie_rejected(self, csrf_app):
        # Fresh client — no prior /csrf-token call, so no cookie was set.
        client = TestClient(csrf_app, raise_server_exceptions=True)
        r = client.post("/csrf-protected", headers={"X-CSRF-Token": "anything"})
        assert r.status_code == 403
