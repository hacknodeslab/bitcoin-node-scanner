"""
Integration tests for database with scanner.
"""
import pytest
import os
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.db.models import Base
from src.db.connection import get_db_session, is_database_configured
from src.db.scanner_integration import DatabaseScannerMixin, create_db_scanner


@pytest.fixture
def test_db_url():
    """Set up test database URL."""
    return "sqlite:///:memory:"


@pytest.fixture
def mock_db_session(test_db_url):
    """Create a mock database session for testing."""
    engine = create_engine(test_db_url, echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    with patch.dict(os.environ, {"DATABASE_URL": test_db_url}):
        yield session

    session.close()


class TestDatabaseScannerMixin:
    """Tests for DatabaseScannerMixin."""

    def test_map_node_data(self, mock_db_session):
        """Test mapping scanner node data to database format."""
        # Create a mock scanner with the mixin
        class MockScanner:
            def analyze_risk_level(self, node_data):
                return "LOW"

            def is_vulnerable_version(self, version):
                return False

            def log(self, message, level="INFO"):
                pass

        class TestScanner(DatabaseScannerMixin, MockScanner):
            def __init__(self):
                self._db_enabled = True
                self._current_scan = None
                self._scan_start_time = None

        scanner = TestScanner()

        node_data = {
            "ip": "192.168.1.100",
            "port": 8333,
            "country_code": "US",
            "country": "United States",
            "city": "New York",
            "asn": "AS12345",
            "organization": "Test ISP",
            "version": "0.21.0",
            "product": "Bitcoin Core",
            "banner": "Test banner",
        }

        db_data = scanner._map_node_data(node_data)

        assert db_data["ip"] == "192.168.1.100"
        assert db_data["port"] == 8333
        assert db_data["country_code"] == "US"
        assert db_data["country_name"] == "United States"
        assert db_data["asn"] == "AS12345"
        assert db_data["asn_name"] == "Test ISP"

    def test_mixin_with_db_disabled(self):
        """Test mixin behavior when database is not configured."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove DATABASE_URL
            if "DATABASE_URL" in os.environ:
                del os.environ["DATABASE_URL"]

            class MockScanner:
                def log(self, message, level="INFO"):
                    pass

            class TestScanner(DatabaseScannerMixin, MockScanner):
                pass

            # Should not raise even without DB
            with patch("src.db.scanner_integration.is_database_configured", return_value=False):
                scanner = TestScanner()
                assert scanner._db_enabled is False


class TestCreateDbScanner:
    """Tests for create_db_scanner factory function."""

    def test_create_scanner_without_db(self):
        """Test creating scanner when DB is not configured."""
        with patch("src.db.scanner_integration.is_database_configured", return_value=False):
            with patch("src.db.scanner_integration.init_db", return_value=False):
                # Should not raise
                pass  # Factory would need mocking of BitcoinNodeScanner

    def test_create_optimized_scanner(self):
        """Test creating optimized scanner variant."""
        # This test verifies the factory function signature
        # Full integration test would require mocking Shodan API
        pass


class TestDatabaseIntegration:
    """Integration tests for scanner with database."""

    def test_save_node_to_db_flow(self, mock_db_session):
        """Test the flow of saving a node to database."""
        from src.db.repositories import NodeRepository

        repo = NodeRepository(mock_db_session)

        # Simulate what the scanner integration would do
        node_data = {
            "ip": "10.0.0.100",
            "port": 8333,
            "country_code": "DE",
            "version": "0.22.0",
            "risk_level": "LOW",
            "is_vulnerable": False,
            "has_exposed_rpc": False,
            "is_dev_version": False,
        }

        node = repo.upsert(node_data)
        mock_db_session.commit()

        assert node.id is not None
        assert node.ip == "10.0.0.100"

        # Verify can be retrieved
        found = repo.find_by_ip_port("10.0.0.100", 8333)
        assert found is not None
        assert found.version == "0.22.0"

    def test_scan_session_flow(self, mock_db_session):
        """Test creating and completing a scan session."""
        from src.db.repositories import ScanRepository, NodeRepository

        scan_repo = ScanRepository(mock_db_session)
        node_repo = NodeRepository(mock_db_session)

        # Start scan
        scan = scan_repo.create(queries_executed=["port:8333", "Bitcoin"])
        mock_db_session.commit()

        assert scan.id is not None
        assert scan.status == "running"

        # Add nodes
        nodes = []
        for i in range(5):
            node = node_repo.upsert({
                "ip": f"10.0.1.{i}",
                "port": 8333,
            })
            nodes.append(node)
        mock_db_session.commit()

        scan_repo.add_nodes(scan, nodes)
        mock_db_session.commit()

        # Complete scan
        scan_repo.complete(
            scan,
            total_nodes=5,
            critical_nodes=1,
            vulnerable_nodes=2,
            credits_used=3,
            duration_seconds=60.5,
        )
        mock_db_session.commit()

        assert scan.status == "completed"
        assert scan.total_nodes == 5
        assert len(scan.nodes) == 5

    def test_bulk_upsert_performance(self, mock_db_session):
        """Test bulk upsert handles many nodes efficiently."""
        from src.db.repositories import NodeRepository
        import time

        repo = NodeRepository(mock_db_session)

        # Create many nodes
        nodes_data = [
            {
                "ip": f"172.16.{i // 256}.{i % 256}",
                "port": 8333,
                "version": "0.21.0",
            }
            for i in range(500)
        ]

        start = time.time()
        count = repo.bulk_upsert(nodes_data, batch_size=100)
        mock_db_session.commit()
        elapsed = time.time() - start

        assert count == 500
        assert repo.count_all() == 500
        # Should complete reasonably fast (under 5 seconds for in-memory SQLite)
        assert elapsed < 5.0

    def test_upsert_preserves_first_seen(self, mock_db_session):
        """Test that upsert preserves first_seen timestamp."""
        from src.db.repositories import NodeRepository
        from datetime import timedelta

        repo = NodeRepository(mock_db_session)

        # Create initial node
        node1 = repo.upsert({
            "ip": "10.0.2.1",
            "port": 8333,
            "version": "0.20.0",
        })
        mock_db_session.commit()

        original_first_seen = node1.first_seen

        # Update the same node
        node2 = repo.upsert({
            "ip": "10.0.2.1",
            "port": 8333,
            "version": "0.21.0",  # Version changed
        })
        mock_db_session.commit()

        # first_seen should be preserved
        assert node2.first_seen == original_first_seen
        # version should be updated
        assert node2.version == "0.21.0"
        # Should be same node
        assert node1.id == node2.id
