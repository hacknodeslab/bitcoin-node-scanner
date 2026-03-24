"""
Tests for historical analysis module.
"""
import pytest
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.db.models import Base, Node, Scan, Vulnerability, NodeVulnerability
from src.db.analysis import HistoricalAnalyzer


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


@pytest.fixture
def populated_db(session):
    """Populate database with test data."""
    now = datetime.utcnow()

    # Create nodes with various attributes
    nodes = [
        Node(
            ip=f"10.0.0.{i}",
            port=8333,
            country_code="US" if i % 2 == 0 else "DE",
            version=f"Satoshi:0.{20 + i % 5}.0",
            is_vulnerable=i % 3 == 0,
            risk_level="CRITICAL" if i % 4 == 0 else "HIGH" if i % 3 == 0 else "LOW",
            has_exposed_rpc=i % 5 == 0,
            is_dev_version=i % 7 == 0,
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(days=i % 10),
        )
        for i in range(20)
    ]
    session.add_all(nodes)

    # Create scans
    scans = [
        Scan(
            timestamp=now - timedelta(days=i),
            status="completed",
            total_nodes=100 + i * 5,
            vulnerable_nodes=10 + i,
        )
        for i in range(10)
    ]
    session.add_all(scans)

    # Create vulnerability
    vuln = Vulnerability(
        cve_id="CVE-2018-17144",
        affected_versions='["0.20.0", "0.21.0"]',
        severity="CRITICAL",
    )
    session.add(vuln)
    session.commit()

    # Link some nodes to vulnerability
    for i in range(5):
        nv = NodeVulnerability(
            node_id=nodes[i].id,
            vulnerability_id=vuln.id,
            detected_at=now - timedelta(days=5),
        )
        session.add(nv)

    session.commit()
    return session


class TestHistoricalAnalyzer:
    """Tests for HistoricalAnalyzer."""

    def test_get_vulnerability_trends_day(self, populated_db):
        """Test vulnerability trends with daily granularity."""
        analyzer = HistoricalAnalyzer()
        start_date = datetime.utcnow() - timedelta(days=15)

        # Mock session by patching get_db_session
        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            trends = analyzer.get_vulnerability_trends(start_date, granularity="day")

        assert "data" in trends
        assert "summary" in trends
        assert trends["granularity"] == "day"

    def test_get_vulnerability_trends_week(self, populated_db):
        """Test vulnerability trends with weekly granularity."""
        analyzer = HistoricalAnalyzer()
        start_date = datetime.utcnow() - timedelta(days=30)

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            trends = analyzer.get_vulnerability_trends(start_date, granularity="week")

        assert trends["granularity"] == "week"

    def test_get_version_distribution(self, populated_db):
        """Test version distribution analysis."""
        analyzer = HistoricalAnalyzer()

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            distribution = analyzer.get_version_distribution()

        assert len(distribution) > 0
        # All versions should be normalized
        for version in distribution.keys():
            assert version == "Unknown" or ".x" in version or version != ""

    def test_normalize_version(self, session):
        """Test version string normalization."""
        analyzer = HistoricalAnalyzer()

        assert analyzer._normalize_version("Satoshi:0.21.0/") == "0.21.x"
        assert analyzer._normalize_version("0.22.1") == "0.22.x"
        assert analyzer._normalize_version("") == "Unknown"
        assert analyzer._normalize_version(None) == "Unknown"

    def test_get_geographic_distribution(self, populated_db):
        """Test geographic distribution analysis."""
        analyzer = HistoricalAnalyzer()
        start_date = datetime.utcnow() - timedelta(days=15)

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            geo = analyzer.get_geographic_distribution(start_date)

        assert "distribution" in geo
        assert "total_countries" in geo

    def test_get_node_lifecycle(self, populated_db):
        """Test node lifecycle analysis."""
        analyzer = HistoricalAnalyzer()

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            lifecycle = analyzer.get_node_lifecycle("10.0.0.1")

        assert lifecycle["ip"] == "10.0.0.1"
        assert "ports" in lifecycle
        assert "first_seen" in lifecycle
        assert "last_seen" in lifecycle

    def test_get_node_lifecycle_not_found(self, populated_db):
        """Test node lifecycle for non-existent node."""
        analyzer = HistoricalAnalyzer()

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            lifecycle = analyzer.get_node_lifecycle("192.168.255.255")

        assert "error" in lifecycle

    def test_get_summary_statistics(self, populated_db):
        """Test summary statistics generation."""
        analyzer = HistoricalAnalyzer()
        start_date = datetime.utcnow() - timedelta(days=15)

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            stats = analyzer.get_summary_statistics(start_date)

        assert "total_nodes" in stats
        assert "vulnerable_nodes" in stats
        assert "critical_nodes" in stats
        assert "vulnerability_rate" in stats
        assert "top_asns" in stats

    def test_get_asn_concentration(self, populated_db):
        """Test ASN concentration analysis."""
        analyzer = HistoricalAnalyzer()
        start_date = datetime.utcnow() - timedelta(days=15)

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            asns = analyzer.get_asn_concentration(start_date)

        # Should return list of ASN info
        assert isinstance(asns, list)

    def test_get_churn_rate(self, populated_db):
        """Test churn rate calculation."""
        analyzer = HistoricalAnalyzer()
        start_date = datetime.utcnow() - timedelta(days=15)

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            churn = analyzer.get_churn_rate(start_date)

        assert "new_nodes" in churn
        assert "disappeared_nodes" in churn
        assert "active_nodes" in churn
        assert "churn_rate" in churn

    def test_compare_periods(self, populated_db):
        """Test period comparison."""
        analyzer = HistoricalAnalyzer()
        now = datetime.utcnow()

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            comparison = analyzer.compare_periods(
                now - timedelta(days=30),
                now - timedelta(days=15),
                now - timedelta(days=15),
                now,
            )

        assert "period1" in comparison
        assert "period2" in comparison
        assert "changes" in comparison

    def test_get_top_vulnerabilities(self, populated_db):
        """Test getting top vulnerabilities."""
        analyzer = HistoricalAnalyzer()

        with pytest.MonkeyPatch().context() as m:
            def mock_session():
                class MockContext:
                    def __enter__(self):
                        return populated_db
                    def __exit__(self, *args):
                        pass
                return MockContext()

            m.setattr("src.db.analysis.get_db_session", mock_session)
            top_vulns = analyzer.get_top_vulnerabilities(limit=5)

        assert isinstance(top_vulns, list)
        if len(top_vulns) > 0:
            assert "cve_id" in top_vulns[0]
            assert "affected_nodes" in top_vulns[0]
