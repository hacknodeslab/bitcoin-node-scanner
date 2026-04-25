"""
Tests for the L402 challenge helper and the example protected endpoint.
"""
import os
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("WEB_API_KEY", "test-key-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_web_l402.db")

from src.web.l402 import l402_challenge_response, router as l402_router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(l402_router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=True)


_L402_HEADER_RE = re.compile(r'^L402 macaroon="[^"]+", invoice="[^"]+"$')


class TestL402Helper:
    def test_helper_returns_402(self):
        r = l402_challenge_response()
        assert r.status_code == 402

    def test_helper_body_shape(self):
        r = l402_challenge_response()
        # JSONResponse encodes its body to bytes; decode and parse
        import json
        assert json.loads(r.body) == {"error": "l402_pending"}

    def test_helper_www_authenticate_header(self):
        r = l402_challenge_response()
        header = r.headers.get("www-authenticate")
        assert header is not None
        assert _L402_HEADER_RE.match(header), f"unexpected header: {header!r}"


class TestL402ExampleEndpoint:
    def test_example_returns_402(self, client):
        r = client.get("/api/v1/l402/example")
        assert r.status_code == 402

    def test_example_body(self, client):
        r = client.get("/api/v1/l402/example")
        assert r.json() == {"error": "l402_pending"}

    def test_example_www_authenticate_starts_with_l402(self, client):
        r = client.get("/api/v1/l402/example")
        header = r.headers.get("www-authenticate", "")
        assert header.startswith("L402 ")
        assert _L402_HEADER_RE.match(header), f"unexpected header: {header!r}"
