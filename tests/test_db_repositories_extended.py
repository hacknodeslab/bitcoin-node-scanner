"""
Extended tests for database repositories — covering methods not tested in test_db_repositories.py.
"""
import pytest
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.db.models import Base, Node, Scan, CVEEntry, NodeVulnerability
from src.db.repositories import NodeRepository, ScanRepository, VulnerabilityRepository


def _mk_cve(session, cve_id: str, severity: str = "HIGH", **kwargs) -> CVEEntry:
    cve = CVEEntry(
        cve_id=cve_id,
        severity=severity,
        cvss_score=kwargs.get("cvss_score"),
        description=kwargs.get("description"),
        affected_versions=kwargs.get("affected_versions", "[]"),
    )
    session.add(cve)
    session.commit()
    return cve


@pytest.fixture
def engine():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session(engine):
    Session = sessionmaker(bind=engine)
    s = Session()
    yield s
    s.close()


class TestNodeRepositoryExtended:
    """Tests for NodeRepository methods not covered in the base test file."""

    def test_find_vulnerable_with_since_filter(self, session):
        repo = NodeRepository(session)
        now = datetime.utcnow()

        node_old = Node(
            ip="10.1.0.1", port=8333, is_vulnerable=True,
            first_seen=now - timedelta(days=10),
            last_seen=now - timedelta(days=10),
        )
        node_recent = Node(
            ip="10.1.0.2", port=8333, is_vulnerable=True,
            first_seen=now - timedelta(days=1),
            last_seen=now - timedelta(days=1),
        )
        session.add_all([node_old, node_recent])
        session.commit()

        results = repo.find_vulnerable(since=now - timedelta(days=5))
        assert len(results) == 1
        assert results[0].ip == "10.1.0.2"

    def test_find_by_risk_level(self, session):
        repo = NodeRepository(session)
        node1 = Node(ip="10.2.0.1", port=8333, risk_level="CRITICAL",
                     first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
        node2 = Node(ip="10.2.0.2", port=8333, risk_level="HIGH",
                     first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
        session.add_all([node1, node2])
        session.commit()

        critical = repo.find_by_risk_level("CRITICAL")
        assert len(critical) == 1
        assert critical[0].ip == "10.2.0.1"

    def test_find_critical_and_high(self, session):
        repo = NodeRepository(session)
        session.add_all([
            Node(ip="10.3.0.1", port=8333, risk_level="CRITICAL",
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow()),
            Node(ip="10.3.0.2", port=8333, risk_level="HIGH",
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow()),
            Node(ip="10.3.0.3", port=8333, risk_level="LOW",
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow()),
        ])
        session.commit()

        results = repo.find_critical_and_high()
        ips = [r.ip for r in results]
        assert "10.3.0.1" in ips
        assert "10.3.0.2" in ips
        assert "10.3.0.3" not in ips

    def test_find_not_seen_since(self, session):
        repo = NodeRepository(session)
        now = datetime.utcnow()
        old_node = Node(ip="10.4.0.1", port=8333,
                        first_seen=now - timedelta(days=20),
                        last_seen=now - timedelta(days=20))
        new_node = Node(ip="10.4.0.2", port=8333,
                        first_seen=now, last_seen=now)
        session.add_all([old_node, new_node])
        session.commit()

        stale = repo.find_not_seen_since(since=now - timedelta(days=10))
        assert len(stale) == 1
        assert stale[0].ip == "10.4.0.1"

    def test_count_all(self, session):
        repo = NodeRepository(session)
        session.add_all([
            Node(ip=f"10.5.0.{i}", port=8333,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
            for i in range(5)
        ])
        session.commit()
        assert repo.count_all() == 5

    def test_count_vulnerable(self, session):
        repo = NodeRepository(session)
        session.add_all([
            Node(ip="10.6.0.1", port=8333, is_vulnerable=True,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow()),
            Node(ip="10.6.0.2", port=8333, is_vulnerable=False,
                 first_seen=datetime.utcnow(), last_seen=datetime.utcnow()),
        ])
        session.commit()
        assert repo.count_vulnerable() == 1

    def test_get_by_id(self, session):
        repo = NodeRepository(session)
        node = repo.upsert({"ip": "10.7.0.1", "port": 8333})
        session.commit()

        fetched = repo.get_by_id(node.id)
        assert fetched is not None
        assert fetched.ip == "10.7.0.1"

    def test_get_by_id_not_found(self, session):
        repo = NodeRepository(session)
        assert repo.get_by_id(99999) is None

    def test_delete(self, session):
        repo = NodeRepository(session)
        node = repo.upsert({"ip": "10.8.0.1", "port": 8333})
        session.commit()
        assert repo.count_all() == 1

        repo.delete(node)
        session.commit()
        assert repo.count_all() == 0

    def test_upsert_with_all_fields(self, session):
        repo = NodeRepository(session)
        node_data = {
            "ip": "10.9.0.1",
            "port": 8333,
            "country_code": "US",
            "country_name": "United States",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060,
            "asn": "AS1234",
            "asn_name": "Test ISP",
            "version": "Satoshi:0.21.0",
            "user_agent": "Bitcoin Core",
            "banner": "/Satoshi:0.21.0/",
            "protocol_version": "70015",
            "services": "1033",
            "risk_level": "LOW",
            "is_vulnerable": False,
            "has_exposed_rpc": False,
            "is_dev_version": False,
        }
        node = repo.upsert(node_data)
        session.commit()
        assert node.country_name == "United States"
        assert node.latitude == 40.7128


class TestScanRepositoryExtended:
    """Tests for ScanRepository methods not covered in the base test file."""

    def test_get_by_id(self, session):
        repo = ScanRepository(session)
        scan = repo.create()
        session.commit()

        fetched = repo.get_by_id(scan.id)
        assert fetched is not None

    def test_get_by_id_not_found(self, session):
        repo = ScanRepository(session)
        assert repo.get_by_id(99999) is None

    def test_get_latest(self, session):
        repo = ScanRepository(session)
        now = datetime.utcnow()
        scan1 = Scan(timestamp=now - timedelta(days=5), status="completed")
        scan2 = Scan(timestamp=now - timedelta(days=1), status="completed")
        session.add_all([scan1, scan2])
        session.commit()

        latest = repo.get_latest()
        assert latest is not None
        assert latest.id == scan2.id

    def test_get_by_date_range_with_status_filter(self, session):
        repo = ScanRepository(session)
        now = datetime.utcnow()
        scan_ok = Scan(timestamp=now - timedelta(days=1), status="completed")
        scan_fail = Scan(timestamp=now - timedelta(days=1), status="failed")
        session.add_all([scan_ok, scan_fail])
        session.commit()

        results = repo.get_by_date_range(now - timedelta(days=2), status="completed")
        assert len(results) == 1
        assert results[0].status == "completed"

    def test_get_statistics_no_scans(self, session):
        repo = ScanRepository(session)
        stats = repo.get_statistics(datetime.utcnow() - timedelta(days=7))
        assert stats["total_scans"] == 0
        assert stats["total_nodes"] == 0

    def test_get_statistics_with_no_durations(self, session):
        repo = ScanRepository(session)
        now = datetime.utcnow()
        scan = Scan(
            timestamp=now - timedelta(hours=1),
            status="completed",
            total_nodes=50,
            critical_nodes=2,
            high_risk_nodes=5,
            vulnerable_nodes=7,
            credits_used=3,
            duration_seconds=None,
        )
        session.add(scan)
        session.commit()

        stats = repo.get_statistics(now - timedelta(days=1))
        assert stats["avg_duration"] == 0

    def test_count_all(self, session):
        repo = ScanRepository(session)
        repo.create()
        repo.create()
        session.commit()
        assert repo.count_all() == 2

    def test_count_by_status(self, session):
        repo = ScanRepository(session)
        scan1 = repo.create(status="completed")
        scan1.status = "completed"
        scan2 = repo.create(status="failed")
        scan2.status = "failed"
        session.commit()

        counts = repo.count_by_status()
        assert "running" in counts or "completed" in counts or "failed" in counts

    def test_add_nodes_bulk(self, session):
        scan_repo = ScanRepository(session)
        node_repo = NodeRepository(session)

        scan = scan_repo.create()
        nodes = [node_repo.upsert({"ip": f"10.10.0.{i}", "port": 8333}) for i in range(3)]
        session.commit()

        scan_repo.add_nodes(scan, nodes)
        session.commit()

        assert len(scan.nodes) == 3

    def test_delete(self, session):
        repo = ScanRepository(session)
        scan = repo.create()
        session.commit()
        assert repo.count_all() == 1

        repo.delete(scan)
        session.commit()
        assert repo.count_all() == 0

    def test_create_scan_no_queries(self, session):
        repo = ScanRepository(session)
        scan = repo.create(queries_executed=None)
        session.commit()
        assert scan.queries_executed is None

    def test_complete_scan_all_fields(self, session):
        repo = ScanRepository(session)
        scan = repo.create()
        session.commit()

        repo.complete(
            scan,
            total_nodes=500,
            critical_nodes=10,
            high_risk_nodes=50,
            vulnerable_nodes=100,
            credits_used=25,
            duration_seconds=300.5,
        )
        session.commit()

        assert scan.status == "completed"
        assert scan.high_risk_nodes == 50
        assert scan.duration_seconds == 300.5


class TestVulnerabilityRepositoryExtended:
    """Tests for VulnerabilityRepository (CVEEntry-backed) — extended coverage."""

    def test_find_by_severity(self, session):
        repo = VulnerabilityRepository(session)
        _mk_cve(session, "CVE-CRIT", severity="CRITICAL")
        _mk_cve(session, "CVE-HIGH", severity="HIGH")

        crits = repo.find_by_severity("CRITICAL")
        assert len(crits) == 1
        assert crits[0].cve_id == "CVE-CRIT"

    def test_get_all(self, session):
        repo = VulnerabilityRepository(session)
        _mk_cve(session, "CVE-A")
        _mk_cve(session, "CVE-B", severity="LOW")

        all_cves = repo.get_all()
        assert len(all_cves) == 2

    def test_link_to_node_idempotent(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node = node_repo.upsert({"ip": "10.20.0.1", "port": 8333})
        cve = _mk_cve(session, "CVE-DUP")

        nv1 = vuln_repo.link_to_node(node, cve)
        session.commit()
        nv2 = vuln_repo.link_to_node(node, cve)
        session.commit()

        assert nv1.id == nv2.id

    def test_link_to_node_with_detected_version(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node = node_repo.upsert({"ip": "10.21.0.1", "port": 8333, "version": "0.19.0"})
        cve = _mk_cve(session, "CVE-VER", severity="MEDIUM")

        nv = vuln_repo.link_to_node(node, cve, detected_version="0.19.0")
        session.commit()
        assert nv.detected_version == "0.19.0"

    def test_resolve_for_node_returns_false_when_not_found(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node = node_repo.upsert({"ip": "10.22.0.1", "port": 8333})
        cve = _mk_cve(session, "CVE-NONE", severity="LOW")

        result = vuln_repo.resolve_for_node(node, cve)
        assert result is False

    def test_resolve_all_for_node(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node = node_repo.upsert({"ip": "10.23.0.1", "port": 8333})
        cve1 = _mk_cve(session, "CVE-R1")
        cve2 = _mk_cve(session, "CVE-R2", severity="CRITICAL")

        vuln_repo.link_to_node(node, cve1)
        vuln_repo.link_to_node(node, cve2)
        session.commit()

        count = vuln_repo.resolve_all_for_node(node)
        session.commit()

        assert count == 2
        assert len(vuln_repo.get_active_for_node(node)) == 0

    def test_get_nodes_by_cve(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node1 = node_repo.upsert({"ip": "10.24.0.1", "port": 8333})
        node2 = node_repo.upsert({"ip": "10.24.0.2", "port": 8333})
        cve = _mk_cve(session, "CVE-NODES")

        vuln_repo.link_to_node(node1, cve)
        vuln_repo.link_to_node(node2, cve)
        session.commit()

        affected = vuln_repo.get_nodes_by_cve(cve)
        assert len(affected) == 2

    def test_count_affected_nodes(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node = node_repo.upsert({"ip": "10.25.0.1", "port": 8333})
        cve = _mk_cve(session, "CVE-COUNT")

        vuln_repo.link_to_node(node, cve)
        session.commit()

        assert vuln_repo.count_affected_nodes(cve) == 1

    def test_count_all(self, session):
        repo = VulnerabilityRepository(session)
        _mk_cve(session, "CVE-C1")
        _mk_cve(session, "CVE-C2", severity="LOW")
        assert repo.count_all() == 2

    def test_count_by_severity(self, session):
        repo = VulnerabilityRepository(session)
        _mk_cve(session, "CVE-S1", severity="HIGH")
        _mk_cve(session, "CVE-S2", severity="HIGH")
        _mk_cve(session, "CVE-S3", severity="CRITICAL")

        counts = repo.count_by_severity()
        assert counts["HIGH"] == 2
        assert counts["CRITICAL"] == 1

    def test_delete(self, session):
        repo = VulnerabilityRepository(session)
        cve = _mk_cve(session, "CVE-DEL", severity="LOW")
        assert repo.count_all() == 1

        repo.delete(cve)
        session.commit()
        assert repo.count_all() == 0

    def test_sync_node_links_no_op_when_unchanged(self, session):
        vuln_repo = VulnerabilityRepository(session)
        node_repo = NodeRepository(session)

        node = node_repo.upsert({"ip": "10.30.0.1", "port": 8333})
        _mk_cve(session, "CVE-X1")
        _mk_cve(session, "CVE-X2")

        vuln_repo.sync_node_links(node, {"CVE-X1", "CVE-X2"})
        session.commit()

        added, resolved = vuln_repo.sync_node_links(node, {"CVE-X1", "CVE-X2"})
        session.commit()
        assert (added, resolved) == (0, 0)
