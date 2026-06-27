"""
Integration tests for /api/v1/nostr/relays and /api/v1/nostr/stats.

Uses FastAPI TestClient with an in-memory SQLite database.
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ["WEB_API_KEY"] = "integration-test-key"
os.environ["DATABASE_URL"] = "sqlite://"

from src.db.models import Base
from src.db.repositories import NostrRepository
from src.web.routers.nodes import get_db

os.environ["WEB_API_KEY"] = "integration-test-key"
os.environ["DATABASE_URL"] = "sqlite://"

API_KEY = "integration-test-key"
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(autouse=True)
def _pin_api_key(monkeypatch):
    """Other test modules can clobber WEB_API_KEY via load_dotenv(override=True)
    at import time. Re-pin it per-test so require_api_key validates at request
    time regardless of suite ordering. Auto-restored by monkeypatch."""
    monkeypatch.setenv("WEB_API_KEY", API_KEY)


@pytest.fixture(scope="function")
def db_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(db_engine):
    factory = sessionmaker(bind=db_engine)
    session = factory()
    yield session
    session.close()


@pytest.fixture(scope="function")
def client(db_session):
    from src.web.main import app

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app, raise_server_exceptions=True)
    app.dependency_overrides.clear()


def _seed(session):
    repo = NostrRepository(session)
    scan = repo.create_scan(source="t.json", total=4, resolved=3, behind_any_cdn=2)
    rows = [
        ("cf.relay", "cloudflare", ["cloudflare"], ["104.16.0.1"], None),
        ("fast.relay", "fastly", ["fastly"], ["151.101.1.1"], None),
        ("plain.relay", "direct", [], ["8.8.8.8"], None),
        ("broken.relay", "dns_error", [], [], "nxdomain"),
    ]
    for host, verdict, providers, ips, error in rows:
        repo.upsert_relay(host=host, verdict=verdict, providers=providers, ips=ips, error=error, scan=scan)
    session.commit()


class TestRelaysEndpoint:
    def test_requires_api_key(self, client):
        assert client.get("/api/v1/nostr/relays").status_code == 401

    def test_paginated_list(self, client, db_session):
        _seed(db_session)
        resp = client.get("/api/v1/nostr/relays", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 4
        assert resp.headers["X-Total-Count"] == "4"
        cf = next(r for r in body if r["host"] == "cf.relay")
        assert cf["verdict"] == "cloudflare"
        assert cf["providers"] == ["cloudflare"]
        assert cf["ips"] == ["104.16.0.1"]

    def test_provider_filter(self, client, db_session):
        _seed(db_session)
        resp = client.get("/api/v1/nostr/relays", params={"provider": "fastly"}, headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert [r["host"] for r in body] == ["fast.relay"]

    def test_behind_cdn_excludes_non_cdn(self, client, db_session):
        _seed(db_session)
        resp = client.get("/api/v1/nostr/relays", params={"behind_cdn": "true"}, headers=HEADERS)
        assert resp.status_code == 200
        hosts = {r["host"] for r in resp.json()}
        assert hosts == {"cf.relay", "fast.relay"}

    def test_pagination_limit(self, client, db_session):
        _seed(db_session)
        resp = client.get("/api/v1/nostr/relays", params={"limit": 2}, headers=HEADERS)
        assert resp.status_code == 200
        assert len(resp.json()) == 2
        assert resp.headers["X-Total-Count"] == "4"

    def test_empty_when_no_scan(self, client):
        resp = client.get("/api/v1/nostr/relays", headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json() == []
        assert resp.headers["X-Total-Count"] == "0"


class TestStatsEndpoint:
    def test_requires_api_key(self, client):
        assert client.get("/api/v1/nostr/stats").status_code == 401

    def test_stats_shape(self, client, db_session):
        _seed(db_session)
        resp = client.get("/api/v1/nostr/stats", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 4
        assert body["resolved"] == 3
        assert body["behind_any_cdn"] == 2
        assert body["behind_cdn_pct"] == pytest.approx(66.7, abs=0.1)
        assert body["counts"]["cloudflare"] == 1
        assert body["providers"] == {"cloudflare": 1, "fastly": 1}

    def test_zeroed_stats_when_no_scan(self, client):
        resp = client.get("/api/v1/nostr/stats", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["counts"] == {}
