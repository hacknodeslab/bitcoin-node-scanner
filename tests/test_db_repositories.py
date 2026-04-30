"""
Tests for database repositories.
"""
import pytest
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.db.models import Base, Node, Scan, CVEEntry
from src.db.repositories import NodeRepository, ScanRepository, VulnerabilityRepository


@pytest.fixture
def engine():
    """Create in-memory SQLite engine for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session(engine):
    """Create a new session for each test."""
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestNodeRepository:
    """Tests for NodeRepository."""

    def test_upsert_new_node(self, session):
        """Test upserting a new node."""
        repo = NodeRepository(session)
        node_data = {
            "ip": "10.0.0.1",
            "port": 8333,
            "country_code": "US",
            "version": "0.21.0",
        }

        node = repo.upsert(node_data)
        session.commit()

        assert node.id is not None
        assert node.ip == "10.0.0.1"
        assert node.first_seen is not None

    def test_upsert_existing_node(self, session):
        """Test upserting an existing node updates it."""
        repo = NodeRepository(session)

        # Create initial node
        node_data = {
            "ip": "10.0.0.2",
            "port": 8333,
            "version": "0.20.0",
        }
        node1 = repo.upsert(node_data)
        session.commit()
        first_seen = node1.first_seen

        # Update the node
        node_data["version"] = "0.21.0"
        node2 = repo.upsert(node_data)
        session.commit()

        assert node1.id == node2.id
        assert node2.version == "0.21.0"
        assert node2.first_seen == first_seen  # Preserved

    def test_find_by_ip(self, session):
        """Test finding nodes by IP."""
        repo = NodeRepository(session)

        # Create nodes with same IP, different ports
        repo.upsert({"ip": "10.0.0.3", "port": 8333})
        repo.upsert({"ip": "10.0.0.3", "port": 8332})
        session.commit()

        nodes = repo.find_by_ip("10.0.0.3")
        assert len(nodes) == 2

    def test_find_by_ip_port(self, session):
        """Test finding specific node by IP and port."""
        repo = NodeRepository(session)
        repo.upsert({"ip": "10.0.0.4", "port": 8333})
        session.commit()

        node = repo.find_by_ip_port("10.0.0.4", 8333)
        assert node is not None
        assert node.ip == "10.0.0.4"

        missing = repo.find_by_ip_port("10.0.0.4", 9999)
        assert missing is None

    def test_find_vulnerable(self, session):
        """Test finding vulnerable nodes."""
        repo = NodeRepository(session)

        repo.upsert({"ip": "10.0.0.5", "port": 8333, "is_vulnerable": True})
        repo.upsert({"ip": "10.0.0.6", "port": 8333, "is_vulnerable": False})
        session.commit()

        vulnerable = repo.find_vulnerable()
        assert len(vulnerable) == 1
        assert vulnerable[0].ip == "10.0.0.5"

    def test_find_by_country(self, session):
        """Test finding nodes by country."""
        repo = NodeRepository(session)

        repo.upsert({"ip": "10.0.0.7", "port": 8333, "country_code": "US"})
        repo.upsert({"ip": "10.0.0.8", "port": 8333, "country_code": "DE"})
        session.commit()

        us_nodes = repo.find_by_country("US")
        assert len(us_nodes) == 1
        assert us_nodes[0].ip == "10.0.0.7"

    def test_bulk_upsert(self, session):
        """Test bulk upsert of nodes."""
        repo = NodeRepository(session)

        nodes_data = [
            {"ip": f"10.0.1.{i}", "port": 8333, "version": "0.21.0"}
            for i in range(150)
        ]

        count = repo.bulk_upsert(nodes_data)
        session.commit()

        assert count == 150
        assert repo.count_all() == 150

    def test_count_by_country(self, session):
        """Test counting nodes by country."""
        repo = NodeRepository(session)

        repo.upsert({"ip": "10.0.0.10", "port": 8333, "country_code": "US"})
        repo.upsert({"ip": "10.0.0.11", "port": 8333, "country_code": "US"})
        repo.upsert({"ip": "10.0.0.12", "port": 8333, "country_code": "DE"})
        session.commit()

        counts = repo.count_by_country()
        assert counts["US"] == 2
        assert counts["DE"] == 1

    def test_count_by_risk_level(self, session):
        """Test counting nodes by risk level."""
        repo = NodeRepository(session)

        repo.upsert({"ip": "10.0.0.13", "port": 8333, "risk_level": "CRITICAL"})
        repo.upsert({"ip": "10.0.0.14", "port": 8333, "risk_level": "HIGH"})
        repo.upsert({"ip": "10.0.0.15", "port": 8333, "risk_level": "HIGH"})
        session.commit()

        counts = repo.count_by_risk_level()
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 2


class TestScanRepository:
    """Tests for ScanRepository."""

    def test_create_scan(self, session):
        """Test creating a scan."""
        repo = ScanRepository(session)

        scan = repo.create(queries_executed=["query1", "query2"])
        session.commit()

        assert scan.id is not None
        assert scan.status == "running"
        assert "query1" in scan.queries_executed

    def test_complete_scan(self, session):
        """Test completing a scan."""
        repo = ScanRepository(session)

        scan = repo.create()
        session.commit()

        repo.complete(
            scan,
            total_nodes=100,
            critical_nodes=5,
            vulnerable_nodes=20,
            credits_used=10,
            duration_seconds=120.5,
        )
        session.commit()

        assert scan.status == "completed"
        assert scan.total_nodes == 100
        assert scan.duration_seconds == 120.5

    def test_fail_scan(self, session):
        """Test failing a scan."""
        repo = ScanRepository(session)

        scan = repo.create()
        session.commit()

        repo.fail(scan, "Connection error")
        session.commit()

        assert scan.status == "failed"
        assert scan.error_message == "Connection error"

    def test_add_node_to_scan(self, session):
        """Test adding nodes to a scan."""
        scan_repo = ScanRepository(session)
        node_repo = NodeRepository(session)

        scan = scan_repo.create()
        node = node_repo.upsert({"ip": "10.0.2.1", "port": 8333})
        session.commit()

        scan_repo.add_node(scan, node)
        session.commit()

        assert node in scan.nodes

    def test_get_by_date_range(self, session):
        """Test getting scans by date range."""
        repo = ScanRepository(session)

        # Create scans at different times
        now = datetime.utcnow()
        scan1 = Scan(timestamp=now - timedelta(days=5), status="completed")
        scan2 = Scan(timestamp=now - timedelta(days=2), status="completed")
        scan3 = Scan(timestamp=now + timedelta(days=1), status="completed")
        session.add_all([scan1, scan2, scan3])
        session.commit()

        scans = repo.get_by_date_range(now - timedelta(days=3), now)
        assert len(scans) == 1
        assert scan2 in scans

    def test_get_statistics(self, session):
        """Test getting scan statistics."""
        repo = ScanRepository(session)

        # Create completed scans
        now = datetime.utcnow()
        scan1 = Scan(
            timestamp=now - timedelta(days=1),
            status="completed",
            total_nodes=100,
            vulnerable_nodes=10,
            credits_used=5,
            duration_seconds=60,
        )
        scan2 = Scan(
            timestamp=now - timedelta(hours=1),
            status="completed",
            total_nodes=150,
            vulnerable_nodes=15,
            credits_used=7,
            duration_seconds=90,
        )
        session.add_all([scan1, scan2])
        session.commit()

        stats = repo.get_statistics(now - timedelta(days=2))

        assert stats["total_scans"] == 2
        assert stats["total_nodes"] == 250
        assert stats["total_vulnerable"] == 25
        assert stats["total_credits"] == 12


def _make_cve(session, cve_id: str, severity: str = "HIGH", cvss: float = 7.5) -> CVEEntry:
    cve = CVEEntry(cve_id=cve_id, severity=severity, cvss_score=cvss, affected_versions="[]")
    session.add(cve)
    session.commit()
    return cve


class TestVulnerabilityRepository:
    """Tests for VulnerabilityRepository (CVEEntry-backed)."""

    def test_find_by_cve_id(self, session):
        repo = VulnerabilityRepository(session)
        _make_cve(session, "CVE-2023-12345", severity="CRITICAL")

        found = repo.find_by_cve_id("CVE-2023-12345")
        assert found is not None
        assert found.severity == "CRITICAL"
        assert repo.find_by_cve_id("CVE-NOPE") is None

    def test_link_to_node(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node = node_repo.upsert({"ip": "10.0.3.1", "port": 8333, "version": "0.19.0"})
        cve = _make_cve(session, "CVE-2023-22222")

        link = vuln_repo.link_to_node(node, cve)
        session.commit()

        assert link.node_id == node.id
        assert link.cve_id == cve.cve_id
        assert link.detected_at is not None

    def test_resolve_for_node(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node = node_repo.upsert({"ip": "10.0.3.2", "port": 8333})
        cve = _make_cve(session, "CVE-2023-33333", severity="CRITICAL")

        vuln_repo.link_to_node(node, cve)
        session.commit()

        result = vuln_repo.resolve_for_node(node, cve)
        session.commit()

        assert result is True
        active = vuln_repo.get_active_for_node(node)
        assert len(active) == 0

    def test_sync_node_links_adds_and_resolves(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node = node_repo.upsert({"ip": "10.0.3.3", "port": 8333, "version": "0.20.0"})
        cve_a = _make_cve(session, "CVE-A")
        cve_b = _make_cve(session, "CVE-B")
        cve_c = _make_cve(session, "CVE-C")

        # Initial: no links → expected {A, B}
        added, resolved = vuln_repo.sync_node_links(node, {"CVE-A", "CVE-B"})
        session.commit()
        assert (added, resolved) == (2, 0)

        # Same expected set → no-op
        added, resolved = vuln_repo.sync_node_links(node, {"CVE-A", "CVE-B"})
        session.commit()
        assert (added, resolved) == (0, 0)

        # Now expected {B, C} → A resolved, C added
        added, resolved = vuln_repo.sync_node_links(node, {"CVE-B", "CVE-C"})
        session.commit()
        assert (added, resolved) == (1, 1)
        active_ids = {c.cve_id for c in vuln_repo.get_active_for_node(node)}
        assert active_ids == {"CVE-B", "CVE-C"}

    def test_get_top_vulnerabilities(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        cve1 = _make_cve(session, "CVE-2023-TOP1")
        cve2 = _make_cve(session, "CVE-2023-TOP2", severity="CRITICAL", cvss=9.8)

        for i in range(5):
            node = node_repo.upsert({"ip": f"10.0.4.{i}", "port": 8333})
            session.commit()
            vuln_repo.link_to_node(node, cve1)

        for i in range(10):
            node = node_repo.upsert({"ip": f"10.0.5.{i}", "port": 8333})
            session.commit()
            vuln_repo.link_to_node(node, cve2)

        session.commit()

        top = vuln_repo.get_top_vulnerabilities(limit=2)

        assert len(top) == 2
        assert top[0]["cve_id"] == "CVE-2023-TOP2"
        assert top[0]["affected_nodes"] == 10
