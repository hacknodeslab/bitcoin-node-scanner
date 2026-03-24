"""
Tests for database CLI commands.
"""
import argparse
import json
import os
import pytest
import tempfile
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, mock_open

from src.db.cli import cmd_stats, cmd_trends, cmd_export, cmd_import, cmd_node, main


def _make_args(**kwargs):
    """Create a mock args namespace."""
    defaults = {
        "days": 30,
        "granularity": "day",
        "output": None,
        "file": None,
        "ip": None,
        "command": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestCmdStats:
    def test_returns_1_when_db_not_configured(self, capsys):
        with patch("src.db.cli.is_database_configured", return_value=False):
            result = cmd_stats(_make_args())
        assert result == 1
        captured = capsys.readouterr()
        assert "DATABASE_URL not configured" in captured.out

    def test_returns_1_on_db_error(self, capsys):
        with patch("src.db.cli.is_database_configured", return_value=True):
            with patch("src.db.cli.init_db"):
                with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                    instance = MockAnalyzer.return_value
                    instance.get_summary_statistics.return_value = {"error": "DB error"}
                    result = cmd_stats(_make_args())
        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out

    def test_prints_stats_and_returns_0(self, capsys):
        stats = {
            "period": "2024-01-01 to 2024-01-31",
            "total_nodes": 100,
            "vulnerable_nodes": 10,
            "vulnerability_rate": 10.0,
            "critical_nodes": 5,
            "new_nodes": 20,
            "exposed_rpc": 2,
            "exposed_rpc_rate": 2.0,
            "dev_versions": 3,
            "dev_version_rate": 3.0,
            "unique_countries": 15,
            "top_asns": [{"asn": "AS1234", "count": 30}],
        }
        with patch("src.db.cli.is_database_configured", return_value=True):
            with patch("src.db.cli.init_db"):
                with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                    MockAnalyzer.return_value.get_summary_statistics.return_value = stats
                    result = cmd_stats(_make_args())
        assert result == 0
        captured = capsys.readouterr()
        assert "100" in captured.out
        assert "AS1234" in captured.out


class TestCmdTrends:
    def test_returns_1_when_db_not_configured(self, capsys):
        with patch("src.db.cli.is_database_configured", return_value=False):
            result = cmd_trends(_make_args())
        assert result == 1

    def test_returns_1_on_db_error(self, capsys):
        with patch("src.db.cli.is_database_configured", return_value=True):
            with patch("src.db.cli.init_db"):
                with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                    MockAnalyzer.return_value.get_vulnerability_trends.return_value = {"error": "fail"}
                    result = cmd_trends(_make_args())
        assert result == 1

    def test_prints_trends_and_returns_0(self, capsys):
        trends = {
            "period": "2024-01-01 to 2024-01-31",
            "granularity": "day",
            "data": {
                "2024-01-01": {"total": 10, "vulnerable": 2, "critical": 1, "high": 1},
            },
            "summary": {
                "total_nodes": 10,
                "total_vulnerable": 2,
                "vulnerability_rate": 20.0,
            },
        }
        with patch("src.db.cli.is_database_configured", return_value=True):
            with patch("src.db.cli.init_db"):
                with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                    MockAnalyzer.return_value.get_vulnerability_trends.return_value = trends
                    result = cmd_trends(_make_args(days=30, granularity="day"))
        assert result == 0
        captured = capsys.readouterr()
        assert "VULNERABILITY TRENDS" in captured.out
        assert "2024-01-01" in captured.out


class TestCmdExport:
    def test_returns_1_when_db_not_configured(self, capsys):
        with patch("src.db.cli.is_database_configured", return_value=False):
            result = cmd_export(_make_args())
        assert result == 1

    def test_returns_1_when_session_none(self, capsys):
        from contextlib import contextmanager

        @contextmanager
        def null_session():
            yield None

        with patch("src.db.cli.is_database_configured", return_value=True):
            with patch("src.db.cli.init_db"):
                with patch("src.db.cli.get_db_session", null_session):
                    result = cmd_export(_make_args())
        assert result == 1

    def test_exports_data_to_file(self, capsys, tmp_path):
        output_file = str(tmp_path / "export.json")

        mock_node = MagicMock()
        mock_node.ip = "1.2.3.4"
        mock_node.port = 8333
        mock_node.country_code = "US"
        mock_node.country_name = "United States"
        mock_node.city = "NYC"
        mock_node.asn = "AS1234"
        mock_node.asn_name = "Test ASN"
        mock_node.version = "0.21.0"
        mock_node.risk_level = "LOW"
        mock_node.is_vulnerable = False
        mock_node.has_exposed_rpc = False
        mock_node.first_seen = datetime(2024, 1, 1)
        mock_node.last_seen = datetime(2024, 1, 15)

        mock_scan = MagicMock()
        mock_scan.id = 1
        mock_scan.timestamp = datetime(2024, 1, 10)
        mock_scan.total_nodes = 100
        mock_scan.critical_nodes = 5
        mock_scan.vulnerable_nodes = 10
        mock_scan.status = "completed"

        from contextlib import contextmanager

        @contextmanager
        def mock_session_ctx():
            mock_session = MagicMock()
            mock_session.query.return_value.filter.return_value.all.return_value = [mock_node]
            yield mock_session

        with patch("src.db.cli.is_database_configured", return_value=True):
            with patch("src.db.cli.init_db"):
                with patch("src.db.cli.get_db_session", mock_session_ctx):
                    with patch("src.db.cli.ScanRepository") as MockScanRepo:
                        MockScanRepo.return_value.get_by_date_range.return_value = [mock_scan]
                        result = cmd_export(_make_args(output=output_file, days=30))

        assert result == 0
        assert os.path.exists(output_file)
        with open(output_file) as f:
            data = json.load(f)
        assert data["summary"]["total_nodes"] == 1


class TestCmdImport:
    def test_returns_1_when_no_file(self, capsys):
        result = cmd_import(_make_args(file=None))
        assert result == 1
        captured = capsys.readouterr()
        assert "No file specified" in captured.out

    def test_delegates_to_subprocess(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = cmd_import(_make_args(file="test.json"))
        assert result == 0
        mock_run.assert_called_once()


class TestCmdNode:
    def test_returns_1_when_no_ip(self, capsys):
        result = cmd_node(_make_args(ip=None))
        assert result == 1
        captured = capsys.readouterr()
        assert "No IP specified" in captured.out

    def test_returns_1_when_db_not_configured(self, capsys):
        with patch("src.db.cli.is_database_configured", return_value=False):
            result = cmd_node(_make_args(ip="1.2.3.4"))
        assert result == 1

    def test_returns_1_when_node_not_found(self, capsys):
        with patch("src.db.cli.is_database_configured", return_value=True):
            with patch("src.db.cli.init_db"):
                with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                    MockAnalyzer.return_value.get_node_lifecycle.return_value = {"error": "Node not found"}
                    result = cmd_node(_make_args(ip="9.9.9.9"))
        assert result == 1

    def test_prints_node_lifecycle(self, capsys):
        lifecycle = {
            "ip": "1.2.3.4",
            "first_seen": "2024-01-01T00:00:00",
            "last_seen": "2024-01-15T00:00:00",
            "ports": [{"port": 8333, "version": "0.21.0", "risk_level": "LOW"}],
            "versions_seen": ["0.21.0"],
            "risk_levels": ["LOW"],
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2018-17144",
                    "severity": "CRITICAL",
                    "resolved_at": None,
                }
            ],
        }
        with patch("src.db.cli.is_database_configured", return_value=True):
            with patch("src.db.cli.init_db"):
                with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                    MockAnalyzer.return_value.get_node_lifecycle.return_value = lifecycle
                    result = cmd_node(_make_args(ip="1.2.3.4"))
        assert result == 0
        captured = capsys.readouterr()
        assert "1.2.3.4" in captured.out
        assert "CVE-2018-17144" in captured.out

    def test_prints_node_lifecycle_with_resolved_vuln(self, capsys):
        lifecycle = {
            "ip": "1.2.3.4",
            "first_seen": "2024-01-01T00:00:00",
            "last_seen": "2024-01-15T00:00:00",
            "ports": [{"port": 8333, "version": "0.21.0", "risk_level": "LOW"}],
            "versions_seen": ["0.21.0"],
            "risk_levels": ["LOW"],
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2018-17144",
                    "severity": "CRITICAL",
                    "resolved_at": "2024-01-10T00:00:00",
                }
            ],
        }
        with patch("src.db.cli.is_database_configured", return_value=True):
            with patch("src.db.cli.init_db"):
                with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                    MockAnalyzer.return_value.get_node_lifecycle.return_value = lifecycle
                    result = cmd_node(_make_args(ip="1.2.3.4"))
        assert result == 0


class TestMain:
    def test_no_command_prints_help(self, capsys):
        with patch("sys.argv", ["cli"]):
            result = main()
        assert result == 1

    def test_db_stats_command(self, capsys):
        stats = {
            "period": "...",
            "total_nodes": 0,
            "vulnerable_nodes": 0,
            "vulnerability_rate": 0,
            "critical_nodes": 0,
            "new_nodes": 0,
            "exposed_rpc": 0,
            "exposed_rpc_rate": 0,
            "dev_versions": 0,
            "dev_version_rate": 0,
            "unique_countries": 0,
            "top_asns": [],
        }
        with patch("sys.argv", ["cli", "db-stats", "--days", "7"]):
            with patch("src.db.cli.is_database_configured", return_value=True):
                with patch("src.db.cli.init_db"):
                    with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                        MockAnalyzer.return_value.get_summary_statistics.return_value = stats
                        result = main()
        assert result == 0

    def test_db_trends_command(self, capsys):
        trends = {
            "period": "...",
            "granularity": "week",
            "data": {},
            "summary": {"total_nodes": 0, "total_vulnerable": 0, "vulnerability_rate": 0.0},
        }
        with patch("sys.argv", ["cli", "db-trends", "--granularity", "week"]):
            with patch("src.db.cli.is_database_configured", return_value=True):
                with patch("src.db.cli.init_db"):
                    with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                        MockAnalyzer.return_value.get_vulnerability_trends.return_value = trends
                        result = main()
        assert result == 0

    def test_db_import_command(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("sys.argv", ["cli", "db-import", "test.json"]):
            with patch("subprocess.run", return_value=mock_result):
                result = main()
        assert result == 0

    def test_db_node_command(self, capsys):
        lifecycle = {
            "ip": "1.2.3.4",
            "first_seen": "2024-01-01",
            "last_seen": "2024-01-15",
            "ports": [],
            "versions_seen": [],
            "risk_levels": [],
            "vulnerabilities": [],
        }
        with patch("sys.argv", ["cli", "db-node", "1.2.3.4"]):
            with patch("src.db.cli.is_database_configured", return_value=True):
                with patch("src.db.cli.init_db"):
                    with patch("src.db.cli.HistoricalAnalyzer") as MockAnalyzer:
                        MockAnalyzer.return_value.get_node_lifecycle.return_value = lifecycle
                        result = main()
        assert result == 0
