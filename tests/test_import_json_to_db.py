"""
Tests for scripts/import_json_to_db.py

Covers: ProgressBar, JSONImporter (file/dir import, node logic, risk analysis,
version detection, timestamp extraction) and the main() CLI entry point.
Target: ≥80% line coverage on the script.
"""
import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# ---------------------------------------------------------------------------
# Load the script module (it lives outside a package, so use importlib)
# ---------------------------------------------------------------------------

def _load_script():
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "import_json_to_db.py"
    spec = importlib.util.spec_from_file_location(
        "import_json_to_db",
        script_path,
        submodule_search_locations=[],
    )
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules so coverage.py can track it
    sys.modules.setdefault("import_json_to_db", mod)
    spec.loader.exec_module(mod)
    return mod


_script = _load_script()
ProgressBar = _script.ProgressBar
JSONImporter = _script.JSONImporter

# ---------------------------------------------------------------------------
# DB fixture — injects a shared in-memory SQLite engine into the connection
# globals so that get_db_session() uses it transparently.
# ---------------------------------------------------------------------------

import src.db.connection as _db_conn
from src.db.models import Base
from src.db.repositories import NodeRepository


@pytest.fixture()
def db_setup(monkeypatch):
    """Inject an in-memory SQLite engine into the db connection globals."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    monkeypatch.setattr(_db_conn, "_engine", engine)
    monkeypatch.setattr(_db_conn, "_SessionLocal", session_factory)
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")

    yield engine

    engine.dispose()


# ---------------------------------------------------------------------------
# Helper factory
# ---------------------------------------------------------------------------

def make_node_dict(ip, port=8333, version="/Satoshi:30.0.0/", **kwargs):
    data = {
        "ip": ip,
        "port": port,
        "version": version,
        "country_code": "US",
        "country": "United States",
        "city": "New York",
        "asn": "AS12345",
        "organization": "Example Corp",
        "banner": "Bitcoin v25",
    }
    data.update(kwargs)
    return data


# ===========================================================================
# Section 2 — ProgressBar
# ===========================================================================

class TestProgressBar:
    def test_update_no_arg_increments_current(self, capsys):
        pb = ProgressBar(total=10)
        pb.update()
        assert pb.current == 1

    def test_update_explicit_current(self, capsys):
        pb = ProgressBar(total=10)
        pb.update(current=5)
        assert pb.current == 5

    def test_update_zero_total_no_division_error(self):
        pb = ProgressBar(total=0)
        pb.update()  # must not raise ZeroDivisionError

    def test_finish_prints_newline(self, capsys):
        pb = ProgressBar(total=5)
        pb.finish()
        captured = capsys.readouterr()
        assert "\n" in captured.out


# ===========================================================================
# Section 3 — JSONImporter file parsing
# ===========================================================================

class TestImportFile:
    def test_list_format_three_nodes_imported(self, db_setup, tmp_path):
        nodes = [make_node_dict(f"1.2.3.{i}") for i in range(3)]
        f = tmp_path / "nodes.json"
        f.write_text(json.dumps(nodes))

        importer = JSONImporter(verbose=False)
        stats = importer.import_file(str(f))

        assert stats["imported"] == 3
        assert stats["errors"] == 0

    def test_second_import_updates_not_re_inserts(self, db_setup, tmp_path):
        nodes = [make_node_dict(f"1.2.3.{i}") for i in range(3)]
        f = tmp_path / "nodes.json"
        f.write_text(json.dumps(nodes))

        importer = JSONImporter(verbose=False)
        importer.import_file(str(f))
        stats2 = importer.import_file(str(f))

        assert stats2["updated"] == 3
        assert stats2["imported"] == 0

    def test_dict_nodes_key_envelope(self, db_setup, tmp_path):
        payload = {"nodes": [make_node_dict("10.0.0.1"), make_node_dict("10.0.0.2")]}
        f = tmp_path / "wrapped.json"
        f.write_text(json.dumps(payload))

        importer = JSONImporter(verbose=False)
        stats = importer.import_file(str(f))

        assert stats["imported"] == 2

    def test_single_node_dict_with_ip_key(self, db_setup, tmp_path):
        node = make_node_dict("192.168.1.1")
        f = tmp_path / "single.json"
        f.write_text(json.dumps(node))

        importer = JSONImporter(verbose=False)
        stats = importer.import_file(str(f))

        assert stats["imported"] == 1

    def test_arbitrary_key_dict_envelope(self, db_setup, tmp_path):
        payload = {"a": make_node_dict("5.5.5.5"), "b": make_node_dict("6.6.6.6")}
        f = tmp_path / "bykey.json"
        f.write_text(json.dumps(payload))

        importer = JSONImporter(verbose=False)
        stats = importer.import_file(str(f))

        assert stats["imported"] == 2

    def test_nonexistent_file_returns_zero_stats(self, db_setup):
        importer = JSONImporter(verbose=False)
        stats = importer.import_file("/does/not/exist.json")

        assert stats == {"imported": 0, "updated": 0, "skipped": 0, "errors": 0}

    def test_invalid_json_returns_error_count_one(self, db_setup, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{ not valid json }")

        importer = JSONImporter(verbose=False)
        stats = importer.import_file(str(f))

        assert stats["errors"] == 1

    def test_empty_list_returns_zero_stats(self, db_setup, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("[]")

        importer = JSONImporter(verbose=False)
        stats = importer.import_file(str(f))

        assert stats == {"imported": 0, "updated": 0, "skipped": 0, "errors": 0}

    def test_session_none_returns_zero_stats(self, tmp_path, monkeypatch):
        """When get_db_session yields None the importer exits gracefully."""
        from contextlib import contextmanager

        @contextmanager
        def _null_session():
            yield None

        monkeypatch.setattr(_script, "get_db_session", _null_session)

        nodes = [make_node_dict("9.9.9.9")]
        f = tmp_path / "nodes.json"
        f.write_text(json.dumps(nodes))

        importer = JSONImporter(verbose=False)
        stats = importer.import_file(str(f))

        assert stats == {"imported": 0, "updated": 0, "skipped": 0, "errors": 0}


# ===========================================================================
# Section 4 — _import_node and _analyze_risk_level
# ===========================================================================

class TestImportNode:
    def test_skip_when_ip_missing(self, db_setup):
        importer = JSONImporter(verbose=False)
        from src.db.connection import get_db_session
        with get_db_session() as session:
            repo = NodeRepository(session)
            result = importer._import_node(repo, {"port": 8333})
        assert result == "skipped"

    def test_rpc_port_sets_critical_and_exposed(self, db_setup):
        importer = JSONImporter(verbose=False)
        from src.db.connection import get_db_session
        node_data = make_node_dict("7.7.7.7", port=8332)
        with get_db_session() as session:
            repo = NodeRepository(session)
            result = importer._import_node(repo, node_data)
        assert result == "imported"
        # Verify stored values via a fresh session
        with get_db_session() as session:
            repo = NodeRepository(session)
            node = repo.find_by_ip_port("7.7.7.7", 8332)
            assert node is not None
            assert node.has_exposed_rpc is True
            assert node.risk_level == "CRITICAL"

    def test_analyze_risk_level_critical_for_rpc_port(self):
        importer = JSONImporter(verbose=False)
        assert importer._analyze_risk_level({"port": 8332}) == "CRITICAL"

    def test_analyze_risk_level_medium_vulnerable_only(self):
        importer = JSONImporter(verbose=False)
        # /Satoshi:0.18.1/ is vulnerable but no dev flag
        result = importer._analyze_risk_level(
            {"port": 8333, "version": "/Satoshi:0.18.1/"}
        )
        assert result == "MEDIUM"

    def test_analyze_risk_level_high_vulnerable_plus_dev(self):
        importer = JSONImporter(verbose=False)
        result = importer._analyze_risk_level(
            {"port": 8333, "version": "/Satoshi:0.18.99.0/"}
        )
        assert result == "HIGH"

    def test_analyze_risk_level_low_safe_node(self):
        importer = JSONImporter(verbose=False)
        result = importer._analyze_risk_level(
            {"port": 8333, "version": "/Satoshi:30.0.0/"}
        )
        assert result == "LOW"


# ===========================================================================
# Section 5 — _is_vulnerable_version
# ===========================================================================

class TestIsVulnerableVersion:
    def test_old_version_is_vulnerable(self):
        importer = JSONImporter(verbose=False)
        assert importer._is_vulnerable_version("/Satoshi:0.18.1/") is True

    def test_modern_version_not_vulnerable(self):
        importer = JSONImporter(verbose=False)
        assert importer._is_vulnerable_version("/Satoshi:30.0.0/") is False

    def test_garbage_string_not_vulnerable(self):
        importer = JSONImporter(verbose=False)
        assert importer._is_vulnerable_version("garbage") is False

    def test_empty_string_not_vulnerable(self):
        importer = JSONImporter(verbose=False)
        assert importer._is_vulnerable_version("") is False

    def test_malformed_satoshi_version_no_raise(self):
        importer = JSONImporter(verbose=False)
        # Triggers the except branch in the version parsing
        assert importer._is_vulnerable_version("/Satoshi:0.abc/") is False


# ===========================================================================
# Section 6 — _extract_timestamp
# ===========================================================================

class TestExtractTimestamp:
    def test_full_datetime_filename(self):
        importer = JSONImporter(verbose=False)
        result = importer._extract_timestamp("nodes_20240115_120000.json")
        assert result == datetime(2024, 1, 15, 12, 0, 0)

    def test_date_only_filename(self):
        importer = JSONImporter(verbose=False)
        result = importer._extract_timestamp("nodes_20240115.json")
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_no_date_returns_recent_time(self):
        importer = JSONImporter(verbose=False)
        before = datetime.utcnow()
        result = importer._extract_timestamp("nodes.json")
        after = datetime.utcnow()
        assert before - timedelta(seconds=5) <= result <= after + timedelta(seconds=5)


# ===========================================================================
# Section 7 — import_directory
# ===========================================================================

class TestImportDirectory:
    def test_two_files_imports_all_nodes(self, db_setup, tmp_path):
        for idx in range(2):
            nodes = [make_node_dict(f"{idx}.0.0.{i}") for i in range(3)]
            (tmp_path / f"file{idx}.json").write_text(json.dumps(nodes))

        importer = JSONImporter(verbose=False)
        stats = importer.import_directory(str(tmp_path))

        assert stats["files_processed"] == 2
        assert stats["nodes_imported"] == 6

    def test_nonexistent_directory_returns_empty_stats(self, db_setup):
        importer = JSONImporter(verbose=False)
        stats = importer.import_directory("/nonexistent/dir/path")
        assert stats["files_processed"] == 0


# ===========================================================================
# Section 8 — main() CLI entry point
# ===========================================================================

class TestMain:
    """All main() tests mock DB functions to avoid real DB access."""

    def _patch_db(self, monkeypatch, configured=True, init_ok=True):
        monkeypatch.setattr(_script, "is_database_configured", lambda: configured)
        monkeypatch.setattr(_script, "init_db", lambda: init_ok)

    def test_no_argv_raises_exit_1(self, monkeypatch):
        self._patch_db(monkeypatch)
        monkeypatch.setattr(sys, "argv", ["import_json_to_db.py"])
        with pytest.raises(SystemExit) as exc:
            _script.main()
        assert exc.value.code == 1

    def test_database_not_configured_exits_1(self, monkeypatch, tmp_path):
        self._patch_db(monkeypatch, configured=False)
        monkeypatch.setattr(sys, "argv", ["prog", str(tmp_path / "f.json")])
        with pytest.raises(SystemExit) as exc:
            _script.main()
        assert exc.value.code == 1

    def test_init_db_failure_exits_1(self, monkeypatch, tmp_path):
        self._patch_db(monkeypatch, configured=True, init_ok=False)
        monkeypatch.setattr(sys, "argv", ["prog", str(tmp_path / "f.json")])
        with pytest.raises(SystemExit) as exc:
            _script.main()
        assert exc.value.code == 1

    def test_all_flag_calls_import_directory(self, monkeypatch):
        self._patch_db(monkeypatch)
        monkeypatch.setattr(sys, "argv", ["prog", "--all"])

        mock_importer = MagicMock()
        mock_importer.stats = {"files_processed": 0, "nodes_imported": 0,
                               "nodes_updated": 0, "nodes_skipped": 0, "errors": 0}
        with patch.object(_script, "JSONImporter", return_value=mock_importer):
            _script.main()

        mock_importer.import_directory.assert_called_once_with("output/raw_data")

    def test_dir_flag_calls_import_directory_with_path(self, monkeypatch):
        self._patch_db(monkeypatch)
        monkeypatch.setattr(sys, "argv", ["prog", "--dir", "/tmp/testdir"])

        mock_importer = MagicMock()
        mock_importer.stats = {"files_processed": 0, "nodes_imported": 0,
                               "nodes_updated": 0, "nodes_skipped": 0, "errors": 0}
        with patch.object(_script, "JSONImporter", return_value=mock_importer):
            _script.main()

        mock_importer.import_directory.assert_called_once_with("/tmp/testdir")

    def test_file_arg_calls_import_file(self, monkeypatch):
        self._patch_db(monkeypatch)
        monkeypatch.setattr(sys, "argv", ["prog", "/tmp/nodes.json"])

        mock_importer = MagicMock()
        mock_importer.stats = {"files_processed": 0, "nodes_imported": 0,
                               "nodes_updated": 0, "nodes_skipped": 0, "errors": 0}
        with patch.object(_script, "JSONImporter", return_value=mock_importer):
            _script.main()

        mock_importer.import_file.assert_called_once_with("/tmp/nodes.json")
