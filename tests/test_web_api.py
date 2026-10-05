"""
Integration tests for /api/v1/nodes, /api/v1/stats, /api/v1/scans.

Uses FastAPI TestClient with an in-memory SQLite database.
"""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Configure env before importing web modules
os.environ["WEB_API_KEY"] = "integration-test-key"
os.environ["DATABASE_URL"] = "sqlite://"  # in-memory

from src.db.models import Base, CVEEntry, Node, NodeVulnerability, ScanJob
from src.web.routers.nodes import get_db

# Re-assert after imports: src/__init__.py triggers scanner.py which calls
# load_dotenv(override=True), overwriting env vars set above if .env has them.
os.environ["WEB_API_KEY"] = "integration-test-key"
os.environ["DATABASE_URL"] = "sqlite://"

API_KEY = "integration-test-key"
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(autouse=True)
def _pin_api_key(monkeypatch):
    # Another module's import can re-run load_dotenv(override=True) and clobber
    # WEB_API_KEY before these tests run; pin it per test (as test_web_nostr does).
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
    """TestClient with the DB dependency overridden to use the test session."""
    from src.web.main import app

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app, raise_server_exceptions=True)
    app.dependency_overrides.clear()


def _make_node(
    ip="1.2.3.4",
    port=8333,
    risk_level="LOW",
    version="0.21.0",
    has_exposed_rpc=False,
    last_seen=None,
    tags_json=None,
    hostname=None,
    is_example=False,
):
    return Node(
        ip=ip,
        port=port,
        version=version,
        risk_level=risk_level,
        is_vulnerable=False,
        has_exposed_rpc=has_exposed_rpc,
        is_example=is_example,
        first_seen=datetime.now(timezone.utc).replace(tzinfo=None),
        last_seen=last_seen or datetime.now(timezone.utc).replace(tzinfo=None),
        tags_json=tags_json,
        hostname=hostname,
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

    def test_accessible_without_api_key(self, client):
        r = client.get("/api/v1/nodes")
        assert r.status_code == 200

    def test_filter_by_exposed_true(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", has_exposed_rpc=True))
        db_session.add(_make_node("2.2.2.2", has_exposed_rpc=False))
        db_session.commit()

        r = client.get("/api/v1/nodes?exposed=true", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["ip"] == "1.1.1.1"

    def test_filter_by_exposed_false(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", has_exposed_rpc=True))
        db_session.add(_make_node("2.2.2.2", has_exposed_rpc=False))
        db_session.commit()

        r = client.get("/api/v1/nodes?exposed=false", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["ip"] == "2.2.2.2"

    def test_filter_by_ip(self, client, db_session):
        db_session.add(_make_node("9.9.9.9", port=8333))
        db_session.add(_make_node("10.10.10.10", port=8333))
        db_session.commit()

        r = client.get("/api/v1/nodes?ip=9.9.9.9", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["ip"] == "9.9.9.9"

    def test_filter_by_port(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", port=8333))
        db_session.add(_make_node("2.2.2.2", port=8332))
        db_session.commit()

        r = client.get("/api/v1/nodes?port=8332", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["ip"] == "2.2.2.2"
        assert data[0]["port"] == 8332

    def test_filter_by_tor_true_matches_tag_or_onion(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", tags_json='["tor","other"]'))
        db_session.add(_make_node("2.2.2.2", hostname="abc.onion"))
        db_session.add(_make_node("3.3.3.3"))
        db_session.commit()

        r = client.get("/api/v1/nodes?tor=true", headers=HEADERS)
        assert r.status_code == 200
        ips = sorted(n["ip"] for n in r.json())
        assert ips == ["1.1.1.1", "2.2.2.2"]

    def test_filter_by_tor_false_returns_400(self, client):
        r = client.get("/api/v1/nodes?tor=false", headers=HEADERS)
        assert r.status_code == 400

    def test_x_total_count_unfiltered(self, client, db_session):
        for i in range(3):
            db_session.add(_make_node(f"10.0.0.{i}"))
        db_session.commit()

        r = client.get("/api/v1/nodes?limit=2", headers=HEADERS)
        assert r.status_code == 200
        assert r.headers["X-Total-Count"] == "3"
        assert len(r.json()) == 2

    def test_x_total_count_filtered(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", risk_level="CRITICAL"))
        db_session.add(_make_node("2.2.2.2", risk_level="CRITICAL"))
        db_session.add(_make_node("3.3.3.3", risk_level="LOW"))
        db_session.commit()

        r = client.get("/api/v1/nodes?risk_level=CRITICAL&limit=1", headers=HEADERS)
        assert r.status_code == 200
        assert r.headers["X-Total-Count"] == "2"
        assert len(r.json()) == 1

    def test_x_total_count_zero(self, client):
        r = client.get("/api/v1/nodes?country=Narnia", headers=HEADERS)
        assert r.status_code == 200
        assert r.headers["X-Total-Count"] == "0"
        assert r.json() == []

    def test_x_total_count_is_string_integer(self, client, db_session):
        db_session.add(_make_node("1.1.1.1"))
        db_session.commit()

        r = client.get("/api/v1/nodes", headers=HEADERS)
        assert r.headers["X-Total-Count"].isdigit()

    def test_response_includes_is_example_field(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", is_example=False))
        db_session.add(_make_node("192.0.2.7", is_example=True))
        db_session.commit()

        r = client.get("/api/v1/nodes", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        by_ip = {n["ip"]: n for n in data}
        assert by_ip["1.1.1.1"]["is_example"] is False
        assert by_ip["192.0.2.7"]["is_example"] is True

    def test_filter_is_example_false_excludes_examples(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", is_example=False))
        db_session.add(_make_node("192.0.2.7", is_example=True))
        db_session.commit()

        r = client.get("/api/v1/nodes?is_example=false", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["ip"] == "1.1.1.1"

    def test_filter_is_example_true_returns_only_examples(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", is_example=False))
        db_session.add(_make_node("192.0.2.7", is_example=True))
        db_session.commit()

        r = client.get("/api/v1/nodes?is_example=true", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["ip"] == "192.0.2.7"

    def test_filter_is_example_invalid_returns_422(self, client):
        r = client.get("/api/v1/nodes?is_example=maybe", headers=HEADERS)
        assert r.status_code == 422

    def test_filter_combines_risk_level_and_is_example(self, client, db_session):
        db_session.add(_make_node("1.1.1.1", risk_level="CRITICAL", is_example=False))
        db_session.add(_make_node("192.0.2.7", risk_level="CRITICAL", is_example=True))
        db_session.add(_make_node("2.2.2.2", risk_level="LOW", is_example=False))
        db_session.commit()

        r = client.get(
            "/api/v1/nodes?risk_level=CRITICAL&is_example=false",
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert [n["ip"] for n in data] == ["1.1.1.1"]


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

    def test_strip_token_counts(self, client, db_session):
        # 11 days ago: stale by the default 7-day threshold.
        old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=11)
        # 1 fresh, exposed, LOW → EXPOSED, not OK (exposed disqualifies)
        db_session.add(_make_node("1.1.1.1", risk_level="LOW", has_exposed_rpc=True))
        # 1 stale, LOW, not exposed → STALE, not OK (last_seen too old)
        db_session.add(_make_node("2.2.2.2", risk_level="LOW", last_seen=old))
        # 1 fresh, LOW, .onion hostname → TOR + OK (no exposed, fresh)
        db_session.add(_make_node("3.3.3.3", risk_level="LOW", hostname="abc.onion"))
        # 1 fresh, MEDIUM, tor in tags → TOR, not OK (LOW required)
        db_session.add(_make_node("4.4.4.4", risk_level="MEDIUM", tags_json='["tor"]'))
        # 1 fresh, LOW, clean → OK
        db_session.add(_make_node("5.5.5.5", risk_level="LOW"))
        db_session.commit()

        r = client.get("/api/v1/stats", headers=HEADERS)
        assert r.status_code == 200
        d = r.json()
        assert d["total_nodes"] == 5
        assert d["exposed_count"] == 1
        assert d["stale_count"] == 1
        assert d["tor_count"] == 2
        assert d["ok_count"] == 2
        assert d["stale_threshold_days"] == 7


def _csrf_headers(client):
    token = client.get("/api/v1/csrf-token").json()["csrfToken"]
    return {**HEADERS, "X-CSRF-Token": token}


class TestScansEndpoint:
    def test_trigger_scan_returns_202(self, client, db_session):
        headers = _csrf_headers(client)
        with patch("src.web.background.run_scan_job", new_callable=AsyncMock):
            r = client.post("/api/v1/scans", headers=headers)
        assert r.status_code == 202
        d = r.json()
        assert d["status"] == "pending"
        assert "job_id" in d

    def test_concurrent_scan_returns_409(self, client, db_session):
        # Insert an active job directly
        job = ScanJob(id=str(uuid.uuid4()), status="running", created_at=datetime.now(timezone.utc).replace(tzinfo=None))
        db_session.add(job)
        db_session.commit()

        headers = _csrf_headers(client)
        with patch("src.web.background.run_scan_job", new_callable=AsyncMock):
            r = client.post("/api/v1/scans", headers=headers)
        assert r.status_code == 409

    def test_get_job_status_found(self, client, db_session):
        job_id = str(uuid.uuid4())
        job = ScanJob(
            id=job_id,
            status="completed",
            started_at=datetime.now(timezone.utc).replace(tzinfo=None),
            finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
            result_summary=json.dumps({"total_nodes": 5}),
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
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
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None),
            last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
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

    def test_accessible_without_api_key_returns_404(self, client, db_session):
        r = client.get("/api/v1/nodes/99999/geo")
        assert r.status_code == 404  # public endpoint, no such node


class TestNodeSortingAndFiltering:
    def _add_nodes(self, db_session):
        db_session.add(_make_node("1.1.1.1", risk_level="HIGH", version="0.20.0"))
        db_session.add(Node(
            ip="2.2.2.2", port=8333, risk_level="LOW", version="0.21.0",
            country_name="Germany", is_vulnerable=False,
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None), last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
        ))
        db_session.add(Node(
            ip="3.3.3.3", port=8333, risk_level="LOW", version="0.22.0",
            country_name="France", is_vulnerable=False,
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None), last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
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
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None), last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
        ))
        db_session.add(Node(
            ip="2.2.2.2", port=8333, country_name="France", is_vulnerable=False,
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None), last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
        ))
        db_session.add(Node(
            ip="3.3.3.3", port=8333, country_name="Germany", is_vulnerable=False,
            first_seen=datetime.now(timezone.utc).replace(tzinfo=None), last_seen=datetime.now(timezone.utc).replace(tzinfo=None),
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

    def test_accessible_without_api_key(self, client):
        r = client.get("/api/v1/nodes/countries")
        assert r.status_code == 200


class TestRootRedirect:
    def test_root_redirects_to_frontend_origin(self, client):
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 302
        # FRONTEND_ORIGIN defaults to http://localhost:3000 when unset.
        assert r.headers["location"].startswith("http://localhost:3000")


class TestNodeDetailEndpoint:
    def _seed(self, db_session):
        node_a = _make_node("10.0.0.1", risk_level="HIGH")
        node_b = _make_node("10.0.0.2", risk_level="LOW")
        db_session.add_all([node_a, node_b])
        db_session.add(CVEEntry(
            cve_id="CVE-2023-AAAA",
            severity="CRITICAL",
            cvss_score=9.8,
            description="Critical bug",
            affected_versions="[]",
        ))
        db_session.add(CVEEntry(
            cve_id="CVE-2023-BBBB",
            severity="MEDIUM",
            cvss_score=5.5,
            affected_versions="[]",
        ))
        db_session.commit()
        return node_a, node_b

    def test_returns_node_with_cves(self, client, db_session):
        node_a, _ = self._seed(db_session)
        db_session.add(NodeVulnerability(node_id=node_a.id, cve_id="CVE-2023-AAAA"))
        db_session.add(NodeVulnerability(node_id=node_a.id, cve_id="CVE-2023-BBBB"))
        db_session.commit()

        r = client.get(f"/api/v1/nodes/{node_a.id}", headers=HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == node_a.id
        assert body["cve_count"] == 2
        assert body["top_cve"]["cve_id"] == "CVE-2023-AAAA"
        cves = body["cves"]
        assert [c["cve_id"] for c in cves] == ["CVE-2023-AAAA", "CVE-2023-BBBB"]

    def test_returns_node_without_cves(self, client, db_session):
        _, node_b = self._seed(db_session)

        r = client.get(f"/api/v1/nodes/{node_b.id}", headers=HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert body["cve_count"] == 0
        assert body["top_cve"] is None
        assert body["cves"] == []

    def test_404_when_unknown_node(self, client, db_session):
        r = client.get("/api/v1/nodes/9999", headers=HEADERS)
        assert r.status_code == 404

    def test_include_resolved(self, client, db_session):
        node_a, _ = self._seed(db_session)
        active = NodeVulnerability(node_id=node_a.id, cve_id="CVE-2023-AAAA")
        resolved = NodeVulnerability(
            node_id=node_a.id,
            cve_id="CVE-2023-BBBB",
            resolved_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        db_session.add_all([active, resolved])
        db_session.commit()

        r = client.get(f"/api/v1/nodes/{node_a.id}", headers=HEADERS)
        assert r.status_code == 200
        assert r.json()["cve_count"] == 1
        assert len(r.json()["cves"]) == 1

        r = client.get(
            f"/api/v1/nodes/{node_a.id}?include_resolved=true",
            headers=HEADERS,
        )
        body = r.json()
        assert body["cve_count"] == 1
        cves = body["cves"]
        assert len(cves) == 2
        assert cves[0]["resolved_at"] is None
        assert cves[1]["resolved_at"] is not None


class TestNodesListCVESummary:
    def test_list_includes_cve_count_and_top_cve(self, client, db_session):
        node_a = _make_node("10.0.0.1", risk_level="HIGH")
        node_b = _make_node("10.0.0.2", risk_level="LOW")
        db_session.add_all([node_a, node_b])
        db_session.add(CVEEntry(
            cve_id="CVE-X1", severity="HIGH", cvss_score=7.0, affected_versions="[]",
        ))
        db_session.add(CVEEntry(
            cve_id="CVE-X2", severity="CRITICAL", cvss_score=9.5, affected_versions="[]",
        ))
        db_session.commit()
        db_session.add(NodeVulnerability(node_id=node_a.id, cve_id="CVE-X1"))
        db_session.add(NodeVulnerability(node_id=node_a.id, cve_id="CVE-X2"))
        db_session.commit()

        r = client.get("/api/v1/nodes", headers=HEADERS)
        assert r.status_code == 200
        items = {n["ip"]: n for n in r.json()}
        assert items["10.0.0.1"]["cve_count"] == 2
        assert items["10.0.0.1"]["top_cve"]["cve_id"] == "CVE-X2"
        assert items["10.0.0.2"]["cve_count"] == 0
        assert items["10.0.0.2"]["top_cve"] is None


class TestVulnerabilitiesAffectedNodes:
    def test_returns_affected_nodes(self, client, db_session):
        node = _make_node("10.0.0.5", risk_level="HIGH")
        db_session.add(node)
        db_session.add(CVEEntry(
            cve_id="CVE-FOO", severity="HIGH", affected_versions="[]",
        ))
        db_session.commit()
        db_session.add(NodeVulnerability(node_id=node.id, cve_id="CVE-FOO"))
        db_session.commit()

        r = client.get("/api/v1/vulnerabilities/CVE-FOO/nodes", headers=HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert body["cve_id"] == "CVE-FOO"
        assert body["total"] == 1
        assert body["nodes"][0]["ip"] == "10.0.0.5"

    def test_404_for_unknown_cve(self, client, db_session):
        r = client.get("/api/v1/vulnerabilities/CVE-NOPE/nodes", headers=HEADERS)
        assert r.status_code == 404


class TestVulnerabilitiesCatalog:
    def test_catalog_includes_affected_node_count(self, client, db_session):
        node_a = _make_node("10.1.0.1")
        node_b = _make_node("10.1.0.2")
        db_session.add_all([node_a, node_b])
        db_session.add(CVEEntry(cve_id="CVE-LINKED", severity="HIGH", affected_versions="[]"))
        db_session.add(CVEEntry(cve_id="CVE-UNLINKED", severity="LOW", affected_versions="[]"))
        db_session.commit()
        db_session.add(NodeVulnerability(node_id=node_a.id, cve_id="CVE-LINKED"))
        db_session.add(NodeVulnerability(node_id=node_b.id, cve_id="CVE-LINKED"))
        db_session.commit()

        r = client.get("/api/v1/vulnerabilities", headers=HEADERS)
        assert r.status_code == 200
        items = {i["cve_id"]: i for i in r.json()["items"]}
        assert items["CVE-LINKED"]["affected_node_count"] == 2
        assert items["CVE-UNLINKED"]["affected_node_count"] == 0


class TestNodeDetailReputation:
    def test_reputation_null_when_never_enriched(self, client, db_session):
        node = _make_node(ip="10.1.1.1")
        db_session.add(node)
        db_session.commit()
        r = client.get(f"/api/v1/nodes/{node.id}", headers=HEADERS)
        assert r.status_code == 200
        assert r.json()["reputation"] is None
        assert r.json()["ip"] == "10.1.1.1"

    def test_reputation_populated_and_shared_across_ports(self, client, db_session):
        from src.db.models import IpReputation
        a = _make_node(ip="10.1.1.2", port=8333)
        b = _make_node(ip="10.1.1.2", port=8332)
        db_session.add_all([a, b])
        db_session.add(IpReputation(
            ip="10.1.1.2",
            abuse_confidence_score=82,
            abuse_total_reports=41,
            blocklists_json=json.dumps(["feodo"]),
            sources_json=json.dumps({
                "abuseipdb": {"status": "ok", "data": {"isp": "secret-ish"}},
                "blocklists": {"status": "ok"},
            }),
            reputation_enriched_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=10),
        ))
        db_session.commit()
        for node in (a, b):
            rep = client.get(f"/api/v1/nodes/{node.id}", headers=HEADERS).json()["reputation"]
            assert rep["abuse_confidence_score"] == 82
            assert rep["blocklists"] == ["feodo"]
            assert rep["stale"] is True
            assert rep["sources"] == {"abuseipdb": "ok", "blocklists": "ok"}
            assert "data" not in json.dumps(rep)

    def test_list_endpoint_has_no_reputation(self, client, db_session):
        db_session.add(_make_node(ip="10.1.1.3"))
        db_session.commit()
        rows = client.get("/api/v1/nodes", headers=HEADERS).json()
        assert "reputation" not in rows[0]


class TestEnrichmentEndpoint:
    def test_trigger_returns_202_with_job_type(self, client):
        headers = _csrf_headers(client)
        with patch("src.web.background.run_enrichment_job", new_callable=AsyncMock) as run:
            r = client.post("/api/v1/enrichment/run", headers=headers, json={"limit": 10})
        assert r.status_code == 202
        assert r.json()["job_type"] == "enrichment"
        assert run.await_args.args[1:] == (10, None)

    def test_default_body(self, client):
        headers = _csrf_headers(client)
        with patch("src.web.background.run_enrichment_job", new_callable=AsyncMock) as run:
            r = client.post("/api/v1/enrichment/run", headers=headers)
        assert r.status_code == 202
        assert run.await_args.args[1:] == (100, None)

    def test_requires_csrf(self, client, db_session):
        r = client.post("/api/v1/enrichment/run", headers=HEADERS)
        assert r.status_code == 403
        assert db_session.query(ScanJob).count() == 0

    def test_409_when_enrichment_active(self, client, db_session):
        db_session.add(ScanJob(id=str(uuid.uuid4()), job_type="enrichment", status="running",
                               created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        db_session.commit()
        headers = _csrf_headers(client)
        with patch("src.web.background.run_enrichment_job", new_callable=AsyncMock):
            r = client.post("/api/v1/enrichment/run", headers=headers)
        assert r.status_code == 409

    @pytest.mark.parametrize("body", [{"limit": 5000}, {"limit": 0}, {"source": "greynoise"}])
    def test_invalid_body_422(self, client, body):
        headers = _csrf_headers(client)
        r = client.post("/api/v1/enrichment/run", headers=headers, json=body)
        assert r.status_code == 422

    def test_running_enrichment_does_not_block_scan(self, client, db_session):
        db_session.add(ScanJob(id=str(uuid.uuid4()), job_type="enrichment", status="running",
                               created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        db_session.commit()
        headers = _csrf_headers(client)
        with patch("src.web.background.run_scan_job", new_callable=AsyncMock):
            r = client.post("/api/v1/scans", headers=headers)
        assert r.status_code == 202
        assert r.json()["job_type"] == "scan"

    def test_job_status_exposes_job_type(self, client, db_session):
        job_id = str(uuid.uuid4())
        db_session.add(ScanJob(id=job_id, job_type="enrichment", status="completed",
                               created_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        db_session.commit()
        r = client.get(f"/api/v1/scans/{job_id}", headers=HEADERS)
        assert r.json()["job_type"] == "enrichment"


class TestNodeBlocklistFilters:
    def _seed(self, db_session):
        from src.db.models import IpReputation
        db_session.add_all([
            _make_node(ip="10.2.0.1", port=8333),
            _make_node(ip="10.2.0.1", port=8332),  # same IP, second port
            _make_node(ip="10.2.0.2"),
            _make_node(ip="10.2.0.3"),
            _make_node(ip="10.2.0.4"),  # never enriched
        ])
        db_session.add_all([
            IpReputation(ip="10.2.0.1", blocklists_json=json.dumps(["firehol_level1", "spamhaus_drop"])),
            IpReputation(ip="10.2.0.2", blocklists_json=json.dumps(["tor_exit"])),
            IpReputation(ip="10.2.0.3", blocklists_json="[]"),
        ])
        db_session.commit()

    def _ips(self, r):
        return sorted({n["ip"] for n in r.json()})

    def test_blocklisted_true(self, client, db_session):
        self._seed(db_session)
        r = client.get("/api/v1/nodes?blocklisted=true", headers=HEADERS)
        assert r.status_code == 200
        assert self._ips(r) == ["10.2.0.1", "10.2.0.2"]
        assert r.headers["X-Total-Count"] == "3"  # both ports of 10.2.0.1

    def test_blocklist_by_id(self, client, db_session):
        self._seed(db_session)
        r = client.get("/api/v1/nodes?blocklist=spamhaus_drop", headers=HEADERS)
        assert self._ips(r) == ["10.2.0.1"]
        r = client.get("/api/v1/nodes?blocklist=tor_exit", headers=HEADERS)
        assert self._ips(r) == ["10.2.0.2"]
        r = client.get("/api/v1/nodes?blocklist=feodo", headers=HEADERS)
        assert r.json() == []

    def test_unknown_blocklist_422(self, client, db_session):
        r = client.get("/api/v1/nodes?blocklist=%25", headers=HEADERS)
        assert r.status_code == 422

    def test_blocklisted_false_400(self, client):
        r = client.get("/api/v1/nodes?blocklisted=false", headers=HEADERS)
        assert r.status_code == 400

    def test_combines_with_other_filters(self, client, db_session):
        self._seed(db_session)
        r = client.get("/api/v1/nodes?blocklisted=true&port=8332", headers=HEADERS)
        assert [(n["ip"], n["port"]) for n in r.json()] == [("10.2.0.1", 8332)]


class TestNodeAbuseFilters:
    def _seed(self, db_session):
        from src.db.models import IpReputation
        db_session.add_all([
            _make_node(ip="10.3.0.1"),
            _make_node(ip="10.3.0.2"),
            _make_node(ip="10.3.0.3"),
            _make_node(ip="10.3.0.4"),  # never checked by AbuseIPDB
        ])
        db_session.add_all([
            IpReputation(ip="10.3.0.1", abuse_confidence_score=90, abuse_total_reports=40),
            IpReputation(ip="10.3.0.2", abuse_confidence_score=30, abuse_total_reports=2),
            IpReputation(ip="10.3.0.3", abuse_confidence_score=0, abuse_total_reports=0),
        ])
        db_session.commit()

    def _ips(self, r):
        return sorted(n["ip"] for n in r.json())

    def test_abuse_min(self, client, db_session):
        self._seed(db_session)
        assert self._ips(client.get("/api/v1/nodes?abuse_min=75", headers=HEADERS)) == ["10.3.0.1"]
        assert self._ips(client.get("/api/v1/nodes?abuse_min=25", headers=HEADERS)) == ["10.3.0.1", "10.3.0.2"]
        r = client.get("/api/v1/nodes?abuse_min=0", headers=HEADERS)
        assert self._ips(r) == ["10.3.0.1", "10.3.0.2", "10.3.0.3"]  # unchecked IP excluded

    def test_abuse_min_out_of_range(self, client):
        assert client.get("/api/v1/nodes?abuse_min=101", headers=HEADERS).status_code == 422

    def test_reported(self, client, db_session):
        self._seed(db_session)
        r = client.get("/api/v1/nodes?reported=true", headers=HEADERS)
        assert self._ips(r) == ["10.3.0.1", "10.3.0.2"]
        assert r.headers["X-Total-Count"] == "2"

    def test_reported_false_400(self, client):
        assert client.get("/api/v1/nodes?reported=false", headers=HEADERS).status_code == 400

    def test_ip_exact_match_returns_all_ports(self, client, db_session):
        db_session.add_all([_make_node(ip="10.3.1.1", port=8333), _make_node(ip="10.3.1.1", port=8332),
                            _make_node(ip="10.3.1.10")])
        db_session.commit()
        r = client.get("/api/v1/nodes?ip=10.3.1.1", headers=HEADERS)
        assert sorted(n["port"] for n in r.json()) == [8332, 8333]
