"""
Integration tests for the CVE-linking hook in DatabaseScannerMixin.
"""
import json
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from src.db.models import Base, CVEEntry, Node, NodeVulnerability
from src.db.scanner_integration import DatabaseScannerMixin


class _MockBaseScanner:
    QUERIES: list[str] = []

    def __init__(self, *args, **kwargs):
        self.results = []
        self.unique_ips = set()

    def log(self, message, level="INFO"):
        pass

    def analyze_risk_level(self, node_data):
        return "LOW"

    def is_vulnerable_version(self, version):
        return False

    def generate_statistics(self):
        return {"total_results": 0, "risk_distribution": {}, "vulnerable_nodes": 0}


class _DBScanner(DatabaseScannerMixin, _MockBaseScanner):
    pass


@pytest.fixture
def db_engine():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def session_factory(db_engine):
    return sessionmaker(bind=db_engine)


@pytest.fixture
def seeded_engine(db_engine, session_factory):
    """Seed the catalog with one CVE that affects 0.20.0–0.21.x."""
    s = session_factory()
    s.add(CVEEntry(
        cve_id="CVE-RANGE-001",
        severity="CRITICAL",
        cvss_score=9.8,
        affected_versions=json.dumps([
            {"cpe": "cpe:2.3:a:bitcoin:bitcoin:*", "start_inc": "0.20.0", "end_exc": "0.22.0"},
        ]),
    ))
    s.commit()
    s.close()
    return db_engine


def _patched_session(session_factory):
    @contextmanager
    def fake_session():
        s = session_factory()
        try:
            yield s
            s.commit()
        finally:
            s.close()
    return fake_session


def _make_scanner():
    with patch("src.db.scanner_integration.is_database_configured", return_value=True), \
         patch("src.db.scanner_integration.init_db"):
        return _DBScanner()


def test_save_node_links_matching_cve(seeded_engine, session_factory):
    scanner = _make_scanner()

    node_data = {
        "ip": "10.0.0.5",
        "port": 8333,
        "version": "Satoshi:0.21.0",
        "country_code": "US",
    }
    with patch("src.db.scanner_integration.get_db_session", _patched_session(session_factory)):
        scanner._save_node_to_db(node_data)

    with session_factory() as s:
        node = s.scalar(select(Node).where(Node.ip == "10.0.0.5"))
        assert node is not None
        active = s.scalars(
            select(NodeVulnerability).where(
                NodeVulnerability.node_id == node.id,
                NodeVulnerability.resolved_at.is_(None),
            )
        ).all()
        assert {nv.cve_id for nv in active} == {"CVE-RANGE-001"}


def test_save_node_resolves_cve_when_version_no_longer_affected(seeded_engine, session_factory):
    scanner = _make_scanner()

    sess = _patched_session(session_factory)

    # First scan: vulnerable
    with patch("src.db.scanner_integration.get_db_session", sess):
        scanner._save_node_to_db({
            "ip": "10.0.0.6", "port": 8333, "version": "Satoshi:0.20.5",
        })

    # Reset matcher cache between scans (simulates a new scan session)
    scanner._cve_matcher = None

    # Second scan: same node upgraded
    with patch("src.db.scanner_integration.get_db_session", sess):
        scanner._save_node_to_db({
            "ip": "10.0.0.6", "port": 8333, "version": "Satoshi:25.0.0",
        })

    with session_factory() as s:
        node = s.scalar(select(Node).where(Node.ip == "10.0.0.6"))
        rows = s.scalars(
            select(NodeVulnerability).where(NodeVulnerability.node_id == node.id)
        ).all()
        assert len(rows) == 1
        assert rows[0].cve_id == "CVE-RANGE-001"
        assert rows[0].resolved_at is not None


def test_save_node_no_link_when_version_outside_range(seeded_engine, session_factory):
    scanner = _make_scanner()

    with patch("src.db.scanner_integration.get_db_session", _patched_session(session_factory)):
        scanner._save_node_to_db({
            "ip": "10.0.0.7", "port": 8333, "version": "Satoshi:25.0.0",
        })

    with session_factory() as s:
        node = s.scalar(select(Node).where(Node.ip == "10.0.0.7"))
        rows = s.scalars(
            select(NodeVulnerability).where(NodeVulnerability.node_id == node.id)
        ).all()
        assert rows == []


def test_save_nodes_bulk_creates_links_per_node(seeded_engine, session_factory):
    scanner = _make_scanner()

    nodes = [
        {"ip": "10.1.0.1", "port": 8333, "version": "Satoshi:0.21.0"},
        {"ip": "10.1.0.2", "port": 8333, "version": "Satoshi:25.0.0"},  # not affected
        {"ip": "10.1.0.3", "port": 8333, "version": "Satoshi:0.20.0"},
    ]

    with patch("src.db.scanner_integration.get_db_session", _patched_session(session_factory)):
        scanner._save_nodes_bulk(nodes)

    with session_factory() as s:
        active = s.scalars(
            select(NodeVulnerability).where(NodeVulnerability.resolved_at.is_(None))
        ).all()
        affected_ips = {
            s.get(Node, nv.node_id).ip for nv in active
        }
        assert affected_ips == {"10.1.0.1", "10.1.0.3"}
