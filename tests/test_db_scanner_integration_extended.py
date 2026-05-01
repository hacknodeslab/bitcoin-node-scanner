"""
Tests for DatabaseScannerMixin and scanner integration.
"""
import os
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, call

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.db.models import Base, Node, Scan
from src.db.scanner_integration import DatabaseScannerMixin, create_db_scanner


@pytest.fixture
def sqlite_url():
    return "sqlite:///:memory:"


@pytest.fixture
def db_engine(sqlite_url):
    engine = create_engine(sqlite_url, echo=False)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.close()


class MockBaseScanner:
    """Minimal base scanner for mixin testing."""

    QUERIES = ["Bitcoin", "port:8332"]

    def __init__(self, *args, **kwargs):
        self.results = []
        self.unique_ips = set()
        self._log = []

    def log(self, message, level="INFO"):
        self._log.append(message)

    def analyze_risk_level(self, node_data):
        if node_data.get("port") == 8332:
            return "CRITICAL"
        return "LOW"

    def is_vulnerable_version(self, version):
        return "0.15" in (version or "")

    def generate_statistics(self):
        return {
            "total_results": len(self.results),
            "risk_distribution": {"CRITICAL": 0, "LOW": len(self.results)},
            "vulnerable_nodes": 0,
        }

    def run_full_scan(self):
        return self.results


class DBScanner(DatabaseScannerMixin, MockBaseScanner):
    """Combined scanner with DB mixin."""
    pass


class TestDatabaseScannerMixinMapNodeData:
    """Test _map_node_data method."""

    def test_maps_all_fields(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=False):
            scanner = DBScanner()

        node_data = {
            "ip": "1.2.3.4",
            "port": 8333,
            "country_code": "US",
            "country": "United States",
            "city": "NYC",
            "asn": "AS1234",
            "organization": "Test ISP",
            "version": "Satoshi:0.21.0",
            "product": "Bitcoin Core",
            "banner": "/Satoshi:0.21.0/",
        }
        mapped = scanner._map_node_data(node_data)

        assert mapped["ip"] == "1.2.3.4"
        assert mapped["port"] == 8333
        assert mapped["country_code"] == "US"
        assert mapped["country_name"] == "United States"
        assert mapped["city"] == "NYC"
        assert mapped["asn"] == "AS1234"
        assert mapped["asn_name"] == "Test ISP"
        assert mapped["version"] == "Satoshi:0.21.0"
        assert mapped["user_agent"] == "Bitcoin Core"
        assert mapped["banner"] == "/Satoshi:0.21.0/"

    def test_maps_missing_fields_as_none(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=False):
            scanner = DBScanner()

        mapped = scanner._map_node_data({"ip": "1.2.3.4"})
        assert mapped["country_code"] is None
        assert mapped["version"] is None

    def test_maps_example_ip_flag(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=False):
            scanner = DBScanner()

        for ip in ("192.0.2.7", "198.51.100.13", "203.0.113.42", "203.0.113.99"):
            assert scanner._map_node_data({"ip": ip})["is_example"] is True

        assert scanner._map_node_data({"ip": "8.8.8.8"})["is_example"] is False
        assert scanner._map_node_data({"ip": "1.2.3.4"})["is_example"] is False
        assert scanner._map_node_data({"ip": None})["is_example"] is False


class TestDatabaseScannerMixinInit:
    """Test DatabaseScannerMixin __init__."""

    def test_init_db_disabled_when_not_configured(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=False):
            scanner = DBScanner()
        assert scanner._db_enabled is False
        assert scanner._current_scan is None

    def test_init_db_enabled_when_configured(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()
        assert scanner._db_enabled is True


class TestDatabaseScannerMixinSaveNodeToDb:
    """Test _save_node_to_db method."""

    def test_returns_none_when_db_disabled(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=False):
            scanner = DBScanner()

        result = scanner._save_node_to_db({"ip": "1.2.3.4", "port": 8333})
        assert result is None

    def test_saves_node_to_db(self, sqlite_url, db_engine):
        from contextlib import contextmanager

        Session = sessionmaker(bind=db_engine)
        saved_ip = []

        @contextmanager
        def mock_session():
            s = Session()
            try:
                yield s
                s.commit()
                # Capture data before session closes
                for node in s.query(Node).all():
                    saved_ip.append(node.ip)
            finally:
                s.close()

        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()

        with patch("src.db.scanner_integration.get_db_session", mock_session):
            node_data = {
                "ip": "10.0.0.1",
                "port": 8333,
                "version": "Satoshi:0.21.0",
                "country_code": "US",
            }
            result = scanner._save_node_to_db(node_data)
        # result may be detached, verify via DB instead
        assert "10.0.0.1" in saved_ip

    def test_returns_none_when_session_is_none(self):
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()

        with patch("src.db.scanner_integration.get_db_session", null_session):
            result = scanner._save_node_to_db({"ip": "1.2.3.4", "port": 8333})
        assert result is None

    def test_new_example_node_is_flagged(self, sqlite_url, db_engine):
        from contextlib import contextmanager

        Session = sessionmaker(bind=db_engine)
        captured = {}

        @contextmanager
        def mock_session():
            s = Session()
            try:
                yield s
                s.commit()
                for n in s.query(Node).all():
                    captured[n.ip] = n.is_example
            finally:
                s.close()

        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()

        with patch("src.db.scanner_integration.get_db_session", mock_session):
            scanner._save_node_to_db({"ip": "192.0.2.7", "port": 8333})
            scanner._save_node_to_db({"ip": "8.8.8.8", "port": 8333})

        assert captured["192.0.2.7"] is True
        assert captured["8.8.8.8"] is False

    def test_stale_flag_is_corrected_on_upsert(self, sqlite_url, db_engine):
        from contextlib import contextmanager

        Session = sessionmaker(bind=db_engine)

        # Pre-seed an example IP with the wrong flag
        seed = Session()
        seed.add(Node(ip="192.0.2.7", port=8333, is_example=False))
        seed.commit()
        seed.close()

        @contextmanager
        def mock_session():
            s = Session()
            try:
                yield s
                s.commit()
            finally:
                s.close()

        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()

        with patch("src.db.scanner_integration.get_db_session", mock_session):
            scanner._save_node_to_db({"ip": "192.0.2.7", "port": 8333})

        verify = Session()
        node = verify.query(Node).filter_by(ip="192.0.2.7", port=8333).one()
        assert node.is_example is True
        verify.close()


class TestDatabaseScannerMixinStartScanSession:
    """Test _start_scan_session method."""

    def test_returns_none_when_db_disabled(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=False):
            scanner = DBScanner()

        result = scanner._start_scan_session(["query1"])
        assert result is None

    def test_creates_scan_session(self, sqlite_url, db_engine):
        from contextlib import contextmanager

        Session = sessionmaker(bind=db_engine)
        scan_ids = []

        @contextmanager
        def mock_session():
            s = Session()
            try:
                yield s
                s.commit()
                for scan in s.query(Scan).all():
                    scan_ids.append(scan.id)
            finally:
                s.close()

        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()

        with patch("src.db.scanner_integration.get_db_session", mock_session):
            scanner._start_scan_session(["Bitcoin", "port:8332"])
        assert len(scan_ids) >= 1

    def test_returns_none_when_session_is_none(self):
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()

        with patch("src.db.scanner_integration.get_db_session", null_session):
            result = scanner._start_scan_session(["Bitcoin"])
        assert result is None


class TestDatabaseScannerMixinCompleteScanSession:
    """Test _complete_scan_session method."""

    def test_no_op_when_db_disabled(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=False):
            scanner = DBScanner()
        # Should not raise
        scanner._complete_scan_session({"total_results": 0})

    def test_no_op_when_no_current_scan(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()
        scanner._current_scan = None
        scanner._complete_scan_session({"total_results": 0})

    def test_completes_scan(self, sqlite_url, db_engine):
        from contextlib import contextmanager

        Session = sessionmaker(bind=db_engine)

        @contextmanager
        def mock_session():
            s = Session()
            try:
                yield s
                s.commit()
            finally:
                s.close()

        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()

        # Create a scan first
        with patch("src.db.scanner_integration.get_db_session", mock_session):
            scanner._start_scan_session(["Bitcoin"])
            scanner._scan_start_time = 0

        # Complete the scan (current_scan is detached, so mock the repo lookup)
        stats = {
            "total_results": 100,
            "risk_distribution": {"CRITICAL": 5, "HIGH": 10},
            "vulnerable_nodes": 15,
        }

        mock_scan = MagicMock()
        mock_scan.id = 1

        # Patch _current_scan directly so complete_scan can find it
        scanner._current_scan = mock_scan

        with patch("src.db.scanner_integration.get_db_session", mock_session):
            with patch("src.db.scanner_integration.time") as mock_time:
                mock_time.time.return_value = 120
                with patch("src.db.repositories.scan_repository.ScanRepository.get_by_id", return_value=mock_scan):
                    scanner._complete_scan_session(stats)

        assert scanner._current_scan is None


class TestDatabaseScannerMixinSaveNodesBulk:
    """Test _save_nodes_bulk method."""

    def test_returns_zero_when_db_disabled(self):
        with patch("src.db.scanner_integration.is_database_configured", return_value=False):
            scanner = DBScanner()

        count = scanner._save_nodes_bulk([{"ip": "1.2.3.4", "port": 8333}])
        assert count == 0

    def test_saves_multiple_nodes(self, sqlite_url, db_engine):
        from contextlib import contextmanager

        Session = sessionmaker(bind=db_engine)

        @contextmanager
        def mock_session():
            s = Session()
            try:
                yield s
                s.commit()
            finally:
                s.close()

        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()

        nodes_data = [
            {"ip": f"10.0.0.{i}", "port": 8333, "version": "0.21.0"}
            for i in range(5)
        ]
        with patch("src.db.scanner_integration.get_db_session", mock_session):
            count = scanner._save_nodes_bulk(nodes_data)
        assert count == 5

    def test_returns_zero_when_session_is_none(self):
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        with patch("src.db.scanner_integration.is_database_configured", return_value=True):
            with patch("src.db.scanner_integration.init_db"):
                scanner = DBScanner()

        with patch("src.db.scanner_integration.get_db_session", null_session):
            count = scanner._save_nodes_bulk([{"ip": "1.2.3.4", "port": 8333}])
        assert count == 0


class TestAnalysisNoDB:
    """Test HistoricalAnalyzer methods when DB is not configured."""

    def test_get_vulnerability_trends_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_vulnerability_trends(datetime.utcnow())
        assert result == {"error": "Database not configured"}

    def test_compare_periods_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        now = datetime.utcnow()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.compare_periods(now, now, now, now)
        assert result == {"error": "Database not configured"}

    def test_get_top_vulnerabilities_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_top_vulnerabilities()
        assert result == []

    def test_get_version_distribution_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_version_distribution()
        assert result == {}

    def test_get_version_evolution_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_version_evolution("0.21")
        assert result == {}

    def test_get_geographic_distribution_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_geographic_distribution(datetime.utcnow())
        assert result == {}

    def test_get_asn_concentration_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_asn_concentration(datetime.utcnow())
        assert result == []

    def test_get_node_lifecycle_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_node_lifecycle("1.2.3.4")
        assert result == {}

    def test_get_nodes_not_seen_since_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_nodes_not_seen_since(days=30)
        assert result == []

    def test_get_churn_rate_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_churn_rate(datetime.utcnow())
        assert result == {}

    def test_get_summary_statistics_no_db(self):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", null_session):
            result = analyzer.get_summary_statistics(datetime.utcnow())
        assert result == {}

    def test_normalize_version_edge_cases(self):
        from src.db.analysis import HistoricalAnalyzer
        analyzer = HistoricalAnalyzer()

        # Single part version (no dot)
        assert analyzer._normalize_version("25") == "25"
        # None
        assert analyzer._normalize_version(None) == "Unknown"
        # Satoshi with proper format
        assert analyzer._normalize_version("Satoshi:0.21.0/") == "0.21.x"
        # Standard version
        assert analyzer._normalize_version("22.0") == "22.0.x"

    def test_get_vulnerability_trends_month_granularity(self, db_engine):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager

        Session = sessionmaker(bind=db_engine)

        @contextmanager
        def mock_session():
            s = Session()
            try:
                yield s
            finally:
                s.close()

        now = datetime.utcnow()
        s = Session()
        node = Node(
            ip="10.0.0.1", port=8333,
            is_vulnerable=True, risk_level="HIGH",
            first_seen=now, last_seen=now,
        )
        s.add(node)
        s.commit()
        s.close()

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", mock_session):
            result = analyzer.get_vulnerability_trends(
                now, granularity="month"
            )
        assert result["granularity"] == "month"

    def test_get_version_evolution_with_data(self, db_engine):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager
        from src.db.models import Scan

        Session = sessionmaker(bind=db_engine)

        @contextmanager
        def mock_session():
            s = Session()
            try:
                yield s
            finally:
                s.close()

        now = datetime.utcnow()
        s = Session()
        scan = Scan(timestamp=now, status="completed", total_nodes=1)
        node = Node(ip="10.0.0.1", port=8333, version="0.21.0",
                    first_seen=now, last_seen=now)
        s.add_all([scan, node])
        s.commit()
        s.close()

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", mock_session):
            result = analyzer.get_version_evolution("0.21")
        assert isinstance(result, dict)

    def test_get_nodes_not_seen_since_with_data(self, db_engine):
        from src.db.analysis import HistoricalAnalyzer
        from contextlib import contextmanager
        from datetime import timedelta

        Session = sessionmaker(bind=db_engine)

        @contextmanager
        def mock_session():
            s = Session()
            try:
                yield s
            finally:
                s.close()

        now = datetime.utcnow()
        s = Session()
        old_node = Node(
            ip="10.0.0.99", port=8333, version="0.19.0",
            country_code="US",
            first_seen=now - timedelta(days=60),
            last_seen=now - timedelta(days=60),
        )
        s.add(old_node)
        s.commit()
        s.close()

        analyzer = HistoricalAnalyzer()
        with patch("src.db.analysis.get_db_session", mock_session):
            result = analyzer.get_nodes_not_seen_since(days=30)
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.99"
