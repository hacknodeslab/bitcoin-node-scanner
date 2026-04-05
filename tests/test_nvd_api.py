"""
Integration tests for GET /api/v1/vulnerabilities.

Uses FastAPI TestClient with an in-memory SQLite database.
"""
import json
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Configure env before importing web modules
os.environ["WEB_API_KEY"] = "integration-test-key"
os.environ["DATABASE_URL"] = "sqlite://"

from src.db.models import Base, CVEEntry as CVEEntryModel
from src.nvd.models import NVDAPIError
from src.web.routers.nodes import get_db

# Re-assert after imports: scanner.py calls load_dotenv(override=True)
# which can overwrite env vars set above if a .env file is present.
os.environ["WEB_API_KEY"] = "integration-test-key"
os.environ["DATABASE_URL"] = "sqlite://"

API_KEY = "integration-test-key"
HEADERS = {"X-API-Key": API_KEY}


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


def _cached_cve(cve_id: str, cvss_score: float = 7.5) -> CVEEntryModel:
    return CVEEntryModel(
        cve_id=cve_id,
        published=datetime(2023, 1, 15),
        last_modified=datetime(2023, 6, 1),
        severity="HIGH",
        cvss_score=cvss_score,
        description=f"Test vulnerability {cve_id}",
        affected_versions=json.dumps(["cpe:2.3:a:bitcoin:bitcoin:0.21.0:*"]),
        fetched_at=datetime.utcnow(),
    )


class TestVulnerabilitiesEndpoint:
    def test_returns_200_with_cached_data(self, client, db_session):
        db_session.add(_cached_cve("CVE-2023-0001"))
        db_session.add(_cached_cve("CVE-2023-0002", cvss_score=9.8))
        db_session.commit()

        r = client.get("/api/v1/vulnerabilities", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        # Should be sorted by cvss_score DESC
        assert data["items"][0]["cvss_score"] == 9.8

    def test_accessible_without_api_key(self, client, db_session):
        db_session.add(_cached_cve("CVE-2023-0001"))
        db_session.commit()
        r = client.get("/api/v1/vulnerabilities")
        assert r.status_code == 200

    def test_returns_503_when_nvd_unavailable_and_cache_empty(self, client, db_session):
        with patch("src.nvd.service.NVDClient") as MockClient:
            MockClient.return_value.fetch_bitcoin_cves.side_effect = NVDAPIError(
                "NVD API unreachable", status_code=503
            )
            r = client.get("/api/v1/vulnerabilities", headers=HEADERS)

        assert r.status_code == 503
        assert "NVD API unavailable" in r.json()["detail"]

    def test_response_shape(self, client, db_session):
        db_session.add(_cached_cve("CVE-2023-0001"))
        db_session.commit()

        r = client.get("/api/v1/vulnerabilities", headers=HEADERS)
        assert r.status_code == 200
        item = r.json()["items"][0]
        assert "cve_id" in item
        assert "severity" in item
        assert "cvss_score" in item
        assert "published" in item
        assert "description" in item
        assert "affected_versions" in item
        assert "fetched_at" in item

    def test_affected_versions_deserialized_as_list(self, client, db_session):
        db_session.add(_cached_cve("CVE-2023-0001"))
        db_session.commit()

        r = client.get("/api/v1/vulnerabilities", headers=HEADERS)
        item = r.json()["items"][0]
        assert isinstance(item["affected_versions"], list)

    def test_triggers_fetch_on_empty_cache(self, client, db_session):
        new_entry = MagicMock()
        new_entry.cve_id = "CVE-FRESH-001"
        new_entry.published = datetime(2024, 1, 1)
        new_entry.last_modified = datetime(2024, 1, 2)
        new_entry.severity = "CRITICAL"
        new_entry.cvss_score = 9.8
        new_entry.description = "Fresh CVE"
        new_entry.affected_versions = []

        with patch("src.nvd.service.NVDClient") as MockClient:
            MockClient.return_value.fetch_bitcoin_cves.return_value = [new_entry]
            r = client.get("/api/v1/vulnerabilities", headers=HEADERS)

        assert r.status_code == 200
        MockClient.return_value.fetch_bitcoin_cves.assert_called_once()
