"""
Integration tests for /api/v1/nodes, /api/v1/stats, /api/v1/scans.

Uses FastAPI TestClient with an in-memory SQLite database.
"""
import json
import os
import uuid
from datetime import datetime
from unittest.mock import patch, AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Configure env before importing web modules
os.environ["WEB_API_KEY"] = "integration-test-key"
os.environ["DATABASE_URL"] = "sqlite://"  # in-memory

from src.db.models import Base, Node, ScanJob
from src.web.routers.nodes import get_db

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
    """TestClient with the DB dependency overridden to use the test session."""
    from src.web.main import app

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app, raise_server_exceptions=True)
    app.dependency_overrides.clear()


def _make_node(ip="1.2.3.4", port=8333, risk_level="LOW", version="0.21.0"):
    return Node(
        ip=ip,
        port=port,
        version=version,
        risk_level=risk_level,
        is_vulnerable=False,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )


class TestNodesEndpoint:
    def test_returns_empty_list(self, client):
        r = client.get("/api/v1/nodes", headers=HEADERS)
        assert r.status_code == 200
        assert r.json() == []

    def test_returns_nodes(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", risk_level="HIGH"))
        db_session.add(_make_node("2.2.2.2", risk_level="LOW"))
        db_session.commit()

        r = client.get("/api/v1/nodes", headers=HEADERS)
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_filter_by_risk_level(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", risk_level="CRITICAL"))
        db_session.add(_make_node("2.2.2.2", risk_level="LOW"))
        db_session.commit()

        r = client.get("/api/v1/nodes?risk_level=CRITICAL", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["risk_level"] == "CRITICAL"

    def test_requires_api_key(self, client):
        r = client.get("/api/v1/nodes")
        assert r.status_code == 401


class TestStatsEndpoint:
    def test_returns_zero_counts_for_empty_db(self, client):
        r = client.get("/api/v1/stats", headers=HEADERS)
        assert r.status_code == 200
        d = r.json()
        assert d["total_nodes"] == 0
        assert d["vulnerable_nodes_count"] == 0

    def test_counts_by_risk_level(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", risk_level="CRITICAL"))
        db_session.add(_make_node("2.2.2.2", risk_level="CRITICAL"))
        db_session.add(_make_node("3.3.3.3", risk_level="HIGH"))
        db_session.commit()

        r = client.get("/api/v1/stats", headers=HEADERS)
        assert r.status_code == 200
        d = r.json()
        assert d["total_nodes"] == 3
        assert d["by_risk_level"].get("CRITICAL") == 2
        assert d["by_risk_level"].get("HIGH") == 1

    def test_requires_api_key(self, client):
        r = client.get("/api/v1/stats")
        assert r.status_code == 401


class TestScansEndpoint:
    def test_trigger_scan_returns_202(self, client, db_session):
        with patch("src.web.background.run_scan_job", new_callable=AsyncMock):
            r = client.post("/api/v1/scans", headers=HEADERS)
        assert r.status_code == 202
        d = r.json()
        assert d["status"] == "pending"
        assert "job_id" in d

    def test_concurrent_scan_returns_409(self, client, db_session):
        # Insert an active job directly
        job = ScanJob(id=str(uuid.uuid4()), status="running", created_at=datetime.utcnow())
        db_session.add(job)
        db_session.commit()

        with patch("src.web.background.run_scan_job", new_callable=AsyncMock):
            r = client.post("/api/v1/scans", headers=HEADERS)
        assert r.status_code == 409

    def test_get_job_status_found(self, client, db_session):
        job_id = str(uuid.uuid4())
        job = ScanJob(
            id=job_id,
            status="completed",
            started_at=datetime.utcnow(),
            finished_at=datetime.utcnow(),
            result_summary=json.dumps({"total_nodes": 5}),
            created_at=datetime.utcnow(),
        )
        db_session.add(job)
        db_session.commit()

        r = client.get(f"/api/v1/scans/{job_id}", headers=HEADERS)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "completed"
        assert d["result_summary"]["total_nodes"] == 5

    def test_get_job_status_not_found(self, client):
        r = client.get(f"/api/v1/scans/{uuid.uuid4()}", headers=HEADERS)
        assert r.status_code == 404

    def test_requires_api_key(self, client):
        r = client.post("/api/v1/scans")
        assert r.status_code == 401


class TestNodeGeoEndpoint:
    def test_returns_geo_for_known_node(self, client, db_session):
        node = Node(
            ip="8.8.8.8",
            port=8333,
            country_code="US",
            country_name="United States",
            city="Mountain View",
            latitude=37.386,
            longitude=-122.0838,
            asn="AS15169",
            asn_name="Google LLC",
            is_vulnerable=False,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db_session.add(node)
        db_session.commit()

        r = client.get(f"/api/v1/nodes/{node.id}/geo", headers=HEADERS)
        assert r.status_code == 200
        d = r.json()
        assert d["ip"] == "8.8.8.8"
        assert d["country_code"] == "US"
        assert d["city"] == "Mountain View"
        assert d["latitude"] == pytest.approx(37.386)
        assert d["asn"] == "AS15169"

    def test_returns_404_for_unknown_node(self, client):
        r = client.get("/api/v1/nodes/99999/geo", headers=HEADERS)
        assert r.status_code == 404

    def test_requires_api_key(self, client, db_session):
        r = client.get("/api/v1/nodes/1/geo")
        assert r.status_code == 401


class TestNodeSortingAndFiltering:
    def _add_nodes(self, db_session):
        db_session.add(_make_node("1.1.1.1", risk_level="HIGH", version="0.20.0"))
        db_session.add(Node(
            ip="2.2.2.2", port=8333, risk_level="LOW", version="0.21.0",
            country_name="Germany", is_vulnerable=False,
            first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        ))
        db_session.add(Node(
            ip="3.3.3.3", port=8333, risk_level="LOW", version="0.22.0",
            country_name="France", is_vulnerable=False,
            first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        ))
        db_session.commit()

    def test_sort_by_ip_asc(self, client, db_session):
        self._add_nodes(db_session)
        r = client.get("/api/v1/nodes?sort_by=ip&sort_dir=asc", headers=HEADERS)
        assert r.status_code == 200
        ips = [n["ip"] for n in r.json()]
        assert ips == sorted(ips)

    def test_sort_by_last_seen_desc_default(self, client, db_session):
        self._add_nodes(db_session)
        r = client.get("/api/v1/nodes", headers=HEADERS)
        assert r.status_code == 200
        assert len(r.json()) == 3

    def test_invalid_sort_by_falls_back(self, client, db_session):
        self._add_nodes(db_session)
        r = client.get("/api/v1/nodes?sort_by=nonexistent", headers=HEADERS)
        assert r.status_code == 200
        assert len(r.json()) == 3

    def test_country_filter_returns_matching_nodes(self, client, db_session):
        self._add_nodes(db_session)
        r = client.get("/api/v1/nodes?country=Germany", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["country_name"] == "Germany"

    def test_country_filter_case_insensitive(self, client, db_session):
        self._add_nodes(db_session)
        r = client.get("/api/v1/nodes?country=germany", headers=HEADERS)
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_country_and_risk_level_combined(self, client, db_session):
        self._add_nodes(db_session)
        r = client.get("/api/v1/nodes?country=Germany&risk_level=HIGH", headers=HEADERS)
        assert r.status_code == 200
        assert len(r.json()) == 0  # Germany node is LOW

    def test_country_no_match_returns_empty(self, client, db_session):
        self._add_nodes(db_session)
        r = client.get("/api/v1/nodes?country=Narnia", headers=HEADERS)
        assert r.status_code == 200
        assert r.json() == []


class TestCountriesEndpoint:
    def test_returns_sorted_countries(self, client, db_session):
        db_session.add(Node(
            ip="1.1.1.1", port=8333, country_name="Germany", is_vulnerable=False,
            first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        ))
        db_session.add(Node(
            ip="2.2.2.2", port=8333, country_name="France", is_vulnerable=False,
            first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        ))
        db_session.add(Node(
            ip="3.3.3.3", port=8333, country_name="Germany", is_vulnerable=False,
            first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        ))
        db_session.commit()

        r = client.get("/api/v1/nodes/countries", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data == ["France", "Germany"]  # distinct, sorted

    def test_returns_empty_when_no_nodes(self, client):
        r = client.get("/api/v1/nodes/countries", headers=HEADERS)
        assert r.status_code == 200
        assert r.json() == []

    def test_requires_api_key(self, client):
        r = client.get("/api/v1/nodes/countries")
        assert r.status_code == 401
