"""
Tests for database models.
"""
import pytest
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.db.models import Base, Node, Scan, CVEEntry, NodeVulnerability, ScanNode


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


class TestNodeModel:
    """Tests for Node model."""

    def test_create_node(self, session):
        """Test creating a basic node."""
        node = Node(
            ip="192.168.1.1",
            port=8333,
            country_code="US",
            version="Satoshi:0.21.0",
        )
        session.add(node)
        session.commit()

        assert node.id is not None
        assert node.ip == "192.168.1.1"
        assert node.port == 8333

    def test_node_defaults(self, session):
        """Test node default values."""
        node = Node(ip="192.168.1.2", port=8333)
        session.add(node)
        session.commit()

        assert node.is_vulnerable is False
        assert node.has_exposed_rpc is False
        assert node.is_dev_version is False
        assert node.first_seen is not None
        assert node.last_seen is not None

    def test_node_unique_ip_port(self, session):
        """Test that IP+port combination is unique."""
        node1 = Node(ip="192.168.1.3", port=8333)
        session.add(node1)
        session.commit()

        node2 = Node(ip="192.168.1.3", port=8333)
        session.add(node2)

        with pytest.raises(Exception):  # IntegrityError
            session.commit()

    def test_node_same_ip_different_port(self, session):
        """Test that same IP with different port is allowed."""
        node1 = Node(ip="192.168.1.4", port=8333)
        node2 = Node(ip="192.168.1.4", port=8332)
        session.add_all([node1, node2])
        session.commit()

        assert node1.id != node2.id

    def test_node_repr(self, session):
        """Test node string representation."""
        node = Node(ip="192.168.1.5", port=8333, version="0.21.0")
        assert "192.168.1.5" in repr(node)
        assert "8333" in repr(node)


class TestScanModel:
    """Tests for Scan model."""

    def test_create_scan(self, session):
        """Test creating a scan."""
        scan = Scan(
            timestamp=datetime.utcnow(),
            total_nodes=100,
            status="completed",
        )
        session.add(scan)
        session.commit()

        assert scan.id is not None
        assert scan.total_nodes == 100

    def test_scan_defaults(self, session):
        """Test scan default values."""
        scan = Scan()
        session.add(scan)
        session.commit()

        assert scan.status == "running"
        assert scan.total_nodes == 0

    def test_scan_node_relationship(self, session):
        """Test many-to-many relationship between Scan and Node."""
        node = Node(ip="192.168.1.6", port=8333)
        scan = Scan(total_nodes=1)

        session.add_all([node, scan])
        session.commit()

        scan.nodes.append(node)
        session.commit()

        assert node in scan.nodes
        assert scan in node.scans


class TestCVEEntryModel:
    """Tests for CVEEntry model."""

    def test_create_cve_entry(self, session):
        cve = CVEEntry(
            cve_id="CVE-2018-17144",
            severity="CRITICAL",
            cvss_score=9.8,
            description="Inflation bug",
            affected_versions='[]',
        )
        session.add(cve)
        session.commit()

        assert cve.cve_id == "CVE-2018-17144"
        assert cve.fetched_at is not None

    def test_cve_id_is_primary_key_unique(self, session):
        session.add(CVEEntry(cve_id="CVE-2020-14198", severity="HIGH", affected_versions="[]"))
        session.commit()

        session.add(CVEEntry(cve_id="CVE-2020-14198", severity="HIGH", affected_versions="[]"))
        with pytest.raises(Exception):  # IntegrityError
            session.commit()


class TestNodeVulnerabilityModel:
    """Tests for NodeVulnerability association."""

    def test_link_cve_to_node(self, session):
        node = Node(ip="192.168.1.7", port=8333)
        cve = CVEEntry(cve_id="CVE-2021-12345", severity="HIGH", affected_versions="[]")
        session.add_all([node, cve])
        session.commit()

        node_vuln = NodeVulnerability(
            node_id=node.id,
            cve_id=cve.cve_id,
            detected_version="0.19.0",
        )
        session.add(node_vuln)
        session.commit()

        assert node_vuln.id is not None
        assert node_vuln.detected_at is not None
        assert node_vuln.resolved_at is None

    def test_resolve_vulnerability(self, session):
        node = Node(ip="192.168.1.8", port=8333)
        cve = CVEEntry(cve_id="CVE-2021-54321", severity="MEDIUM", affected_versions="[]")
        session.add_all([node, cve])
        session.commit()

        node_vuln = NodeVulnerability(node_id=node.id, cve_id=cve.cve_id)
        session.add(node_vuln)
        session.commit()

        node_vuln.resolved_at = datetime.utcnow()
        session.commit()

        assert node_vuln.resolved_at is not None

    def test_cascade_delete_node(self, session):
        node = Node(ip="192.168.1.9", port=8333)
        cve = CVEEntry(cve_id="CVE-2022-11111", severity="LOW", affected_versions="[]")
        session.add_all([node, cve])
        session.commit()

        node_vuln = NodeVulnerability(node_id=node.id, cve_id=cve.cve_id)
        session.add(node_vuln)
        session.commit()

        node_vuln_id = node_vuln.id

        session.delete(node)
        session.commit()

        assert session.get(NodeVulnerability, node_vuln_id) is None
