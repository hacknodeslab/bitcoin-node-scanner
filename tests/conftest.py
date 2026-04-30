"""
Shared pytest fixtures for Bitcoin Node Scanner tests.
"""
import os
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


# Database fixtures for DB tests
@pytest.fixture(scope="function")
def db_engine():
    """Create in-memory SQLite engine for testing."""
    from src.db.models import Base

    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(db_engine):
    """Create a new database session for each test."""
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def sample_node_data():
    """Sample node data for testing."""
    return {
        "ip": "192.168.1.1",
        "port": 8333,
        "country_code": "US",
        "country": "United States",
        "city": "New York",
        "asn": "AS12345",
        "organization": "Test ISP",
        "version": "Satoshi:0.21.0/",
        "product": "Bitcoin Core",
        "banner": "/Satoshi:0.21.0/",
        "transport": "tcp",
        "timestamp": datetime.now().strftime('%Y%m%d_%H%M%S'),
        "query": "Bitcoin",
    }


@pytest.fixture
def sample_nodes_batch():
    """Batch of sample nodes for bulk testing."""
    return [
        {
            "ip": f"10.0.0.{i}",
            "port": 8333,
            "country_code": "US" if i % 2 == 0 else "DE",
            "version": f"Satoshi:0.{20 + i % 5}.0/",
            "is_vulnerable": i % 3 == 0,
            "risk_level": "CRITICAL" if i % 4 == 0 else "LOW",
        }
        for i in range(20)
    ]


@pytest.fixture
def mock_shodan_api():
    """Mock Shodan API for testing scanner without real API calls."""
    mock_api = Mock()

    # Mock info() to return credits
    mock_api.info.return_value = {
        "query_credits": 100,
        "scan_credits": 100,
    }

    # Mock search() to return sample results
    mock_api.search.return_value = {
        "total": 5,
        "matches": [
            {
                "ip_str": f"10.0.0.{i}",
                "port": 8333,
                "transport": "tcp",
                "product": "Bitcoin Core",
                "version": "0.21.0",
                "data": "/Satoshi:0.21.0/",
                "org": "Test Org",
                "isp": "Test ISP",
                "asn": "AS12345",
                "location": {
                    "country_name": "United States",
                    "country_code": "US",
                    "city": "New York",
                },
                "hostnames": [],
                "domains": [],
                "timestamp": "2024-01-01T00:00:00",
            }
            for i in range(5)
        ],
    }

    # Mock host() for enrichment
    mock_api.host.return_value = {
        "data": [
            {"port": 8333, "product": "Bitcoin Core", "version": "0.21.0"},
            {"port": 22, "product": "OpenSSH", "version": "8.0"},
        ],
        "tags": [],
        "vulns": [],
        "os": "Linux",
        "last_update": "2024-01-01",
    }

    return mock_api


@pytest.fixture
def mock_db_configured():
    """Mock database as configured."""
    with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///:memory:"}):
        yield


@pytest.fixture
def mock_db_not_configured():
    """Mock database as not configured."""
    env = os.environ.copy()
    if "DATABASE_URL" in env:
        del env["DATABASE_URL"]
    with patch.dict(os.environ, env, clear=True):
        yield


@pytest.fixture
def populated_db_session(db_session):
    """Database session with pre-populated test data."""
    from src.db.models import Node, Scan, CVEEntry, NodeVulnerability

    now = datetime.utcnow()

    # Create nodes
    nodes = []
    for i in range(10):
        node = Node(
            ip=f"10.0.0.{i}",
            port=8333,
            country_code="US" if i % 2 == 0 else "DE",
            version=f"Satoshi:0.{20 + i % 3}.0",
            is_vulnerable=i % 3 == 0,
            risk_level="CRITICAL" if i == 0 else "HIGH" if i == 1 else "LOW",
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(days=i),
        )
        nodes.append(node)
        db_session.add(node)

    # Create scans
    for i in range(3):
        scan = Scan(
            timestamp=now - timedelta(days=i * 2),
            status="completed",
            total_nodes=100,
            vulnerable_nodes=10,
        )
        db_session.add(scan)

    # Create CVE entry
    cve = CVEEntry(
        cve_id="CVE-2018-17144",
        severity="CRITICAL",
        cvss_score=9.8,
        affected_versions='[{"cpe": "cpe:2.3:a:bitcoin:bitcoin:0.20.0:*:*:*:*:*:*:*", "version": "0.20.0"}]',
    )
    db_session.add(cve)
    db_session.commit()

    # Link CVE to first node
    nv = NodeVulnerability(
        node_id=nodes[0].id,
        cve_id=cve.cve_id,
    )
    db_session.add(nv)
    db_session.commit()

    yield db_session
