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

from src.web.auth import require_api_key
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
