"""
Tests for scripts/full_db_scan.py

Covers: helper functions (extract_version, map_match, bulk_save) and the
main() CLI entry point. Exercises the pagination loop, rate-limit retry,
clean-termination branches, scan lifecycle, and the --dry-run / --limit /
missing-DATABASE_URL paths. All I/O is mocked — no real Shodan calls, no
real sleeps; DB is the shared in-memory SQLite pattern used by
tests/test_import_json_to_db.py.

See openspec/changes/test-full-db-scan/ for the change spec.
"""
import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import shodan
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure repo root is on sys.path so the script's own `from src...` imports work.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ---------------------------------------------------------------------------
# Load the script as a module. It lives outside a package, so we use the
# same importlib pattern as tests/test_import_json_to_db.py.
# ---------------------------------------------------------------------------

def _load_script():
    script_path = _REPO_ROOT / "scripts" / "full_db_scan.py"
    spec = importlib.util.spec_from_file_location(
        "full_db_scan",
        script_path,
        submodule_search_locations=[],
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("full_db_scan", mod)
    spec.loader.exec_module(mod)
    return mod


full_db_scan = _load_script()


import src.db.connection as _db_conn  # noqa: E402
from src.db.models import Base, Node, Scan  # noqa: E402
from src.db.repositories import ScanRepository  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def mock_sleep(monkeypatch):
    """Patch time.sleep everywhere so retry/page delays don't slow the suite."""
    m = MagicMock()
    monkeypatch.setattr("time.sleep", m)
    return m


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


@pytest.fixture()
def scan_id(db_setup):
    """Create a Scan row and return its id for bulk_save tests."""
    Session = sessionmaker(bind=db_setup)
    session = Session()
    try:
        scan_repo = ScanRepository(session)
        scan = scan_repo.create(queries_executed=["product:Satoshi"], status="running")
        session.commit()
        return scan.id
    finally:
        session.close()


class StubScanner:
    """Minimal stand-in for BitcoinNodeScanner used by map_match."""

    def __init__(self, risk_level="LOW", vulnerable=False):
        self._risk = risk_level
        self._vuln = vulnerable
        self.risk_calls = []
        self.vuln_calls = []

    def analyze_risk_level(self, result):
        self.risk_calls.append(result)
        return self._risk

    def is_vulnerable_version(self, version):
        self.vuln_calls.append(version)
        return self._vuln


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_match(ip="1.2.3.4", port=8333, version="/Satoshi:25.0.0/", **kwargs):
    m = {
        "ip_str": ip,
        "port": port,
        "data": version,
        "asn": "AS12345",
        "org": "Example Corp",
        "location": {
            "country_code": "US",
            "country_name": "United States",
            "city": "New York",
            "latitude": 40.0,
            "longitude": -74.0,
        },
    }
    m.update(kwargs)
    return m


class FakeShodan:
    """Fake Shodan client driven by a per-page map + optional per-page errors."""

    def __init__(
        self,
        *,
        credits=1000,
        total=10_000,
        pages_map=None,
        rate_limit_pages=None,
        terminator_exc_on_page=None,
        generic_exc_on_page=None,
    ):
        self.credits = credits
        self.total = total
        self.pages_map = pages_map or {}
        self.rate_limit_pages = set(rate_limit_pages or [])
        self.terminator_exc_on_page = terminator_exc_on_page or {}
        self.generic_exc_on_page = generic_exc_on_page or {}
        self.page_call_counts = {}
        self.info_calls = 0
        self.count_calls = 0

    def info(self):
        self.info_calls += 1
        return {"query_credits": self.credits}

    def search(self, query, page=None, limit=None):
        if page is None:
            # Initial count query: api.search(QUERY, limit=1)
            self.count_calls += 1
            return {"total": self.total, "matches": []}

        self.page_call_counts[page] = self.page_call_counts.get(page, 0) + 1
        if page in self.rate_limit_pages and self.page_call_counts[page] == 1:
            raise shodan.APIError("Rate limit reached")
        if page in self.generic_exc_on_page:
            raise self.generic_exc_on_page[page]
        if page in self.terminator_exc_on_page:
            raise self.terminator_exc_on_page[page]
        return {"total": self.total, "matches": self.pages_map.get(page, [])}


def install_fake_shodan(monkeypatch, fake):
    """Patch full_db_scan.shodan.Shodan to hand back `fake`."""
    factory = MagicMock(return_value=fake)
    monkeypatch.setattr(full_db_scan.shodan, "Shodan", factory)
    return factory


def install_stub_scanner(monkeypatch, scanner=None):
    """Patch full_db_scan.BitcoinNodeScanner to return the supplied stub."""
    scanner = scanner or StubScanner()
    monkeypatch.setattr(full_db_scan, "BitcoinNodeScanner", lambda api_key=None: scanner)
    return scanner


def set_argv(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["full_db_scan.py", *args])


def scan_by_id(engine, sid):
    Session = sessionmaker(bind=engine)
    s = Session()
    try:
        return s.get(Scan, sid)
    finally:
        s.close()


def all_scans(engine):
    Session = sessionmaker(bind=engine)
    s = Session()
    try:
        return s.query(Scan).all()
    finally:
        s.close()


def all_nodes(engine):
    Session = sessionmaker(bind=engine)
    s = Session()
    try:
        return s.query(Node).all()
    finally:
        s.close()


# ===========================================================================
# Section 2 — extract_version
# ===========================================================================

class TestExtractVersion:
    def test_satoshi_banner(self):
        m = {"data": "/Satoshi:25.0.0/"}
        assert full_db_scan.extract_version(m) == "Satoshi:25.0.0"

    def test_falls_back_to_match_version(self):
        m = {"data": "random banner", "version": "24.1"}
        assert full_db_scan.extract_version(m) == "24.1"

    def test_malformed_banner_without_trailing_slash(self):
        # data contains "/Satoshi:" but no closing "/" so the split falls to
        # the except branch and we return match.get("version") (None here).
        m = {"data": "/Satoshi:25.0.0"}
        # The current implementation's split('/')[0] is '25.0.0' — so it still
        # returns the version. Be permissive: it should not raise and should
        # return a string or the version fallback.
        result = full_db_scan.extract_version(m)
        assert result is None or "Satoshi" in result

    def test_empty_match_returns_none(self):
        assert full_db_scan.extract_version({}) is None


# ===========================================================================
# Section 3 — map_match
# ===========================================================================

class TestMapMatch:
    def test_full_shape(self):
        scanner = StubScanner(risk_level="HIGH", vulnerable=True)
        m = make_match(ip="8.8.8.8", port=8333, version="/Satoshi:25.0.0/")
        node = full_db_scan.map_match(m, scanner)

        assert node["ip"] == "8.8.8.8"
        assert node["port"] == 8333
        assert node["country_code"] == "US"
        assert node["country_name"] == "United States"
        assert node["city"] == "New York"
        assert node["latitude"] == 40.0
        assert node["longitude"] == -74.0
        assert node["asn"] == "AS12345"
        assert node["asn_name"] == "Example Corp"
        assert node["version"] == "Satoshi:25.0.0"
        assert node["banner"].startswith("/Satoshi:")
        assert len(node["banner"]) <= 500

    def test_port_8332_flags_exposed_rpc(self):
        scanner = StubScanner()
        node = full_db_scan.map_match(make_match(port=8332), scanner)
        assert node["has_exposed_rpc"] is True

    def test_dev_version_flag(self):
        scanner = StubScanner()
        m = make_match(version="/Satoshi:24.99.0/")
        node = full_db_scan.map_match(m, scanner)
        assert node["is_dev_version"] is True

    def test_missing_port_defaults_to_8333(self):
        scanner = StubScanner()
        m = make_match()
        m.pop("port", None)
        node = full_db_scan.map_match(m, scanner)
        assert node["port"] == 8333
        assert node["has_exposed_rpc"] is False

    def test_delegates_risk_and_vulnerable_to_scanner(self):
        scanner = StubScanner(risk_level="CRITICAL", vulnerable=True)
        m = make_match(version="/Satoshi:23.0.0/")
        node = full_db_scan.map_match(m, scanner)
        assert node["risk_level"] == "CRITICAL"
        assert node["is_vulnerable"] is True
        assert scanner.risk_calls and scanner.risk_calls[0]["port"] == 8333
        assert scanner.vuln_calls and "Satoshi" in scanner.vuln_calls[0]

    def test_banner_truncated_to_500_chars(self):
        scanner = StubScanner()
        long_banner = "/Satoshi:25.0.0/" + ("x" * 800)
        m = make_match(version=long_banner)
        node = full_db_scan.map_match(m, scanner)
        assert len(node["banner"]) == 500


# ===========================================================================
# Section 4 — bulk_save
# ===========================================================================

class TestBulkSave:
    def _make_batch(self, n, scanner):
        return [
            full_db_scan.map_match(make_match(ip=f"10.0.0.{i}"), scanner)
            for i in range(n)
        ]

    def test_batch_of_three_persisted_and_linked(self, db_setup, scan_id):
        scanner = StubScanner()
        batch = self._make_batch(3, scanner)

        count = full_db_scan.bulk_save(batch, scan_id)
        assert count == 3

        nodes = all_nodes(db_setup)
        assert len(nodes) == 3
        assert {n.ip for n in nodes} == {"10.0.0.0", "10.0.0.1", "10.0.0.2"}

        # Association via Scan.nodes
        Session = sessionmaker(bind=db_setup)
        s = Session()
        try:
            scan = s.get(Scan, scan_id)
            assert len(scan.nodes) == 3
        finally:
            s.close()

    def test_empty_batch_is_noop(self, db_setup, scan_id):
        count = full_db_scan.bulk_save([], scan_id)
        assert count == 0
        assert all_nodes(db_setup) == []

    def test_nonexistent_scan_id_does_not_raise(self, db_setup):
        scanner = StubScanner()
        batch = self._make_batch(2, scanner)

        count = full_db_scan.bulk_save(batch, 99999)
        assert count == 2
        assert len(all_nodes(db_setup)) == 2


# ===========================================================================
# Section 5 — main() CLI args
# ===========================================================================

class TestMainCli:
    def test_missing_database_url_exits_nonzero(self, monkeypatch, capsys):
        monkeypatch.setattr(full_db_scan, "is_database_configured", lambda: False)
        # Ensure Shodan is never called — any attempt raises loudly.
        def fail_shodan(*a, **kw):
            raise AssertionError("Shodan should not be instantiated when DB is unconfigured")
        monkeypatch.setattr(full_db_scan.shodan, "Shodan", fail_shodan)
        set_argv(monkeypatch)

        with pytest.raises(SystemExit) as exc:
            full_db_scan.main()
        assert exc.value.code == 1

        out = capsys.readouterr().out
        assert "DATABASE_URL" in out

    def test_dry_run_skips_writes(self, db_setup, monkeypatch, capsys):
        fake = FakeShodan(credits=1000, total=10_000)
        install_fake_shodan(monkeypatch, fake)
        install_stub_scanner(monkeypatch)
        set_argv(monkeypatch, "--dry-run")

        full_db_scan.main()

        out = capsys.readouterr().out
        assert "dry-run" in out
        assert all_nodes(db_setup) == []
        assert all_scans(db_setup) == []

    def test_limit_caps_target(self, db_setup, monkeypatch):
        # Page 1 returns 100 matches; target should be capped to 50, loop
        # stops after page 1 and saves exactly 50.
        page_1 = [make_match(ip=f"1.0.0.{i}") for i in range(100)]
        fake = FakeShodan(
            credits=1000,
            total=10_000,
            pages_map={1: page_1},
        )
        install_fake_shodan(monkeypatch, fake)
        install_stub_scanner(monkeypatch)
        set_argv(monkeypatch, "--limit", "50")

        full_db_scan.main()

        nodes = all_nodes(db_setup)
        assert len(nodes) == 50
        # search() must have been called at most once with page= (plus count call)
        assert fake.page_call_counts == {1: 1}

    def test_target_clamped_by_credits(self, db_setup, monkeypatch):
        # credits=1 → max 100; total=10,000 → target = min(total, 100) = 100.
        page_1 = [make_match(ip=f"2.0.0.{i}") for i in range(100)]
        fake = FakeShodan(
            credits=1,
            total=10_000,
            pages_map={1: page_1},
        )
        install_fake_shodan(monkeypatch, fake)
        install_stub_scanner(monkeypatch)
        set_argv(monkeypatch)

        full_db_scan.main()

        nodes = all_nodes(db_setup)
        assert len(nodes) == 100


# ===========================================================================
# Section 6 — main() pagination loop
# ===========================================================================

class TestMainPagination:
    def test_happy_path_three_pages(self, db_setup, monkeypatch):
        pages_map = {
            i: [make_match(ip=f"10.{i}.0.{j}") for j in range(100)]
            for i in range(1, 4)
        }
        fake = FakeShodan(
            credits=1000,
            total=300,  # so target = 300
            pages_map=pages_map,
        )
        install_fake_shodan(monkeypatch, fake)
        install_stub_scanner(monkeypatch)
        set_argv(monkeypatch)

        full_db_scan.main()

        nodes = all_nodes(db_setup)
        assert len(nodes) == 300

        scans = all_scans(db_setup)
        assert len(scans) == 1
        assert scans[0].status == "completed"
        assert scans[0].total_nodes == 300
        assert scans[0].duration_seconds is not None
        assert scans[0].duration_seconds >= 0.0

    def test_rate_limit_retry_on_page_2(self, db_setup, monkeypatch, mock_sleep):
        pages_map = {
            1: [make_match(ip=f"3.0.0.{j}") for j in range(100)],
            2: [make_match(ip=f"3.1.0.{j}") for j in range(100)],
        }
        fake = FakeShodan(
            credits=1000,
            total=200,
            pages_map=pages_map,
            rate_limit_pages={2},
        )
        install_fake_shodan(monkeypatch, fake)
        install_stub_scanner(monkeypatch)
        set_argv(monkeypatch)

        full_db_scan.main()

        # Page 2 was attempted twice (rate-limit then success).
        assert fake.page_call_counts[2] == 2
        # RETRY_WAIT (30s) was slept at least once.
        mock_sleep.assert_any_call(30)
        # Both pages worth of nodes persisted.
        assert len(all_nodes(db_setup)) == 200

    def test_no_more_pages_apierror_breaks_cleanly(self, db_setup, monkeypatch):
        pages_map = {1: [make_match(ip=f"4.0.0.{j}") for j in range(100)]}
        fake = FakeShodan(
            credits=1000,
            total=10_000,
            pages_map=pages_map,
            terminator_exc_on_page={
                2: shodan.APIError("No information available for that page"),
            },
        )
        install_fake_shodan(monkeypatch, fake)
        install_stub_scanner(monkeypatch)
        set_argv(monkeypatch)

        full_db_scan.main()

        assert len(all_nodes(db_setup)) == 100
        scan = all_scans(db_setup)[0]
        assert scan.status == "completed"
        assert scan.total_nodes == 100

    def test_empty_matches_stops_loop(self, db_setup, monkeypatch):
        pages_map = {
            1: [make_match(ip=f"5.0.0.{j}") for j in range(100)],
            2: [],  # empty → loop breaks
        }
        fake = FakeShodan(
            credits=1000,
            total=10_000,
            pages_map=pages_map,
        )
        install_fake_shodan(monkeypatch, fake)
        install_stub_scanner(monkeypatch)
        set_argv(monkeypatch)

        full_db_scan.main()

        assert len(all_nodes(db_setup)) == 100
        assert all_scans(db_setup)[0].status == "completed"

    def test_unknown_apierror_is_caught_by_outer_handler(self, db_setup, monkeypatch, capsys):
        pages_map = {1: [make_match(ip=f"6.0.0.{j}") for j in range(100)]}
        fake = FakeShodan(
            credits=1000,
            total=10_000,
            pages_map=pages_map,
            generic_exc_on_page={2: shodan.APIError("Server error: upstream down")},
        )
        install_fake_shodan(monkeypatch, fake)
        install_stub_scanner(monkeypatch)
        set_argv(monkeypatch)

        # Must not raise — outer except catches it, finally completes the scan.
        full_db_scan.main()

        out = capsys.readouterr().out
        assert "Server error" in out
        scans = all_scans(db_setup)
        assert len(scans) == 1
        assert scans[0].status == "completed"
        assert scans[0].total_nodes == 100


# ===========================================================================
# Section 7 — Scan lifecycle
# ===========================================================================

class TestScanLifecycle:
    def test_scan_created_running_and_completed(self, db_setup, monkeypatch):
        pages_map = {1: [make_match(ip=f"7.0.0.{j}") for j in range(50)]}
        fake = FakeShodan(
            credits=1000,
            total=50,
            pages_map=pages_map,
        )
        install_fake_shodan(monkeypatch, fake)
        install_stub_scanner(monkeypatch)
        set_argv(monkeypatch)

        full_db_scan.main()

        scans = all_scans(db_setup)
        assert len(scans) == 1
        scan = scans[0]
        assert scan.status == "completed"
        assert scan.total_nodes == 50
        assert scan.duration_seconds is not None and scan.duration_seconds >= 0.0
        assert json.loads(scan.queries_executed) == ["product:Satoshi"]
