"""
Regression tests for the state-machine fixes documented in docs/state-machines.md.

Covers:
- ScanJob lifecycle: transition-table enforcement, stale-job reaping (§1)
- _run_job hardening: jobs must reach a terminal state even when the
  'running' mark fails (§1)
- NodeVulnerability: partial unique index + conflict-tolerant inserts
  prevent duplicate active links from the concurrent-relink race (§3)
- NVD refresh upsert remains idempotent/update-capable on the ORM path (§4)
- Geo enrichment keyset cursor survives a mid-run delete (§7)
"""
import asyncio
import contextlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, select, text as sa_text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.db.geo_enrichment import enrich_nodes_geo
from src.db.models import Base, CVEEntry, Node, NodeVulnerability, ScanJob
from src.db.repositories.scan_job_repository import ScanJobRepository
from src.db.repositories.vulnerability_repository import VulnerabilityRepository
from src.nvd.models import CVEEntry as NVDEntry
from src.nvd.service import NVDService


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _file_session(tmp_path):
    """A file-backed SQLite session (two concurrent sessions need a real file)."""
    engine = create_engine(f"sqlite:///{tmp_path}/state_machine.db")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


# ---------------------------------------------------------------------------
# §1 — ScanJob lifecycle
# ---------------------------------------------------------------------------

class TestScanJobTransitions:
    def test_happy_path_pending_running_completed(self, db_session):
        repo = ScanJobRepository(db_session)
        job = repo.create(job_type="scan")
        db_session.commit()

        repo.update_status(job, "running")
        assert job.started_at is not None and job.finished_at is None

        repo.update_status(job, "completed", {"total_nodes": 3})
        assert job.finished_at is not None
        assert json.loads(job.result_summary) == {"total_nodes": 3}

    def test_terminal_states_are_final(self, db_session):
        repo = ScanJobRepository(db_session)
        job = repo.create()
        db_session.commit()
        repo.update_status(job, "running")
        repo.update_status(job, "completed")
        finished_at = job.finished_at

        with pytest.raises(ValueError):
            repo.update_status(job, "running")
        with pytest.raises(ValueError):
            repo.update_status(job, "failed")
        # Unchanged after the rejected transitions.
        assert job.status == "completed"
        assert job.finished_at == finished_at

    def test_failed_is_final(self, db_session):
        repo = ScanJobRepository(db_session)
        job = repo.create()
        db_session.commit()
        repo.update_status(job, "running")
        repo.update_status(job, "failed", {"error": "boom"})

        with pytest.raises(ValueError):
            repo.update_status(job, "completed")

    def test_running_remark_is_idempotent(self, db_session):
        repo = ScanJobRepository(db_session)
        job = repo.create()
        db_session.commit()
        repo.update_status(job, "running")
        started_at = job.started_at

        repo.update_status(job, "running")
        assert job.started_at == started_at

    def test_pending_to_failed_allowed_for_reaper(self, db_session):
        repo = ScanJobRepository(db_session)
        job = repo.create()
        db_session.commit()
        repo.update_status(job, "failed", {"error": "reaped"})
        assert job.status == "failed"


class TestStaleJobReaping:
    def test_stale_pending_job_is_reaped_and_unblocks_single_flight(self, db_session, monkeypatch):
        monkeypatch.setenv("SCAN_JOB_STALE_PENDING_MINUTES", "30")
        monkeypatch.setenv("SCAN_JOB_STALE_RUNNING_MINUTES", "720")
        repo = ScanJobRepository(db_session)

        orphan = repo.create(job_type="scan")
        orphan.created_at = _utcnow() - timedelta(hours=2)  # crashed before starting
        db_session.commit()

        # The orphaned job no longer blocks: a new POST could proceed.
        assert repo.get_active_job("scan") is None

        # ...and the orphan itself is marked failed with a terminal timestamp.
        db_session.commit()
        orphan = repo.get_by_id(orphan.id)
        assert orphan.status == "failed"
        assert orphan.finished_at is not None

        # A fresh job can now be created for the same type.
        fresh = repo.create(job_type="scan")
        db_session.commit()
        assert repo.get_active_job("scan").id == fresh.id

    def test_stale_running_job_is_reaped(self, db_session, monkeypatch):
        monkeypatch.setenv("SCAN_JOB_STALE_PENDING_MINUTES", "30")
        monkeypatch.setenv("SCAN_JOB_STALE_RUNNING_MINUTES", "720")
        repo = ScanJobRepository(db_session)

        stuck = repo.create(job_type="enrichment")
        db_session.commit()
        repo.update_status(stuck, "running")
        stuck.started_at = _utcnow() - timedelta(days=2)  # runner died mid-work
        db_session.commit()

        assert repo.get_active_job("enrichment") is None
        db_session.commit()
        assert repo.get_by_id(stuck.id).status == "failed"

    def test_fresh_active_job_still_blocks(self, db_session, monkeypatch):
        monkeypatch.setenv("SCAN_JOB_STALE_PENDING_MINUTES", "30")
        repo = ScanJobRepository(db_session)
        active = repo.create(job_type="scan")
        db_session.commit()

        assert repo.get_active_job("scan").id == active.id
        db_session.commit()
        assert repo.get_by_id(active.id).status == "pending"  # untouched

    def test_reap_does_not_overwrite_concurrent_terminal_transition(self, tmp_path, monkeypatch):
        """Session B selects a stale candidate; session A completes the job
        before B reaps. B's conditional update must match zero rows."""
        monkeypatch.setenv("SCAN_JOB_STALE_PENDING_MINUTES", "30")
        Session = _file_session(tmp_path)

        sA = Session()
        repoA = ScanJobRepository(sA)
        job = repoA.create(job_type="scan")
        job.created_at = _utcnow() - timedelta(hours=2)
        sA.commit()
        job_id = job.id

        # B looks first and sees the stale pending job.
        sB = Session()
        repoB = ScanJobRepository(sB)
        candidates = repoB._stale_candidates()
        assert len(candidates) == 1

        # A wins the race: starts and completes the job.
        repoA.update_status(job, "running")
        repoA.update_status(job, "completed", {"total_nodes": 42})
        sA.commit()

        # B's reap must not overwrite A's completed state or result.
        assert repoB._reap_one(candidates[0]) is False
        sB.rollback()

        with Session() as s:
            final = ScanJobRepository(s).get_by_id(job_id)
            assert final.status == "completed"
            assert json.loads(final.result_summary) == {"total_nodes": 42}

    def test_reap_does_not_overwrite_concurrent_start(self, tmp_path, monkeypatch):
        """A stale pending job another session just started must keep its
        active slot — reaping it would admit a second concurrent job."""
        monkeypatch.setenv("SCAN_JOB_STALE_PENDING_MINUTES", "30")
        Session = _file_session(tmp_path)

        sA = Session()
        repoA = ScanJobRepository(sA)
        job = repoA.create(job_type="scan")
        job.created_at = _utcnow() - timedelta(hours=2)
        sA.commit()
        job_id = job.id

        sB = Session()
        repoB = ScanJobRepository(sB)
        candidates = repoB._stale_candidates()

        repoA.update_status(job, "running")  # worker picked it up meanwhile
        sA.commit()

        assert repoB._reap_one(candidates[0]) is False
        sB.rollback()
        with Session() as s:
            assert ScanJobRepository(s).get_by_id(job_id).status == "running"


# ---------------------------------------------------------------------------
# §1 — _run_job hardening
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestRunJobTerminalStates:
    def _make_factory(self, tmp_path):
        # get_session_factory() returns a sessionmaker; background code calls
        # factory() to obtain sessions.
        return _file_session(tmp_path)

    def test_work_failure_marks_job_failed(self, tmp_path):
        Session = self._make_factory(tmp_path)
        with patch("src.web.background.get_session_factory", return_value=Session):
            from src.web import background

            with Session() as s:
                job = ScanJobRepository(s).create(job_type="scan")
                s.commit()
                job_id = job.id

            def boom():
                raise RuntimeError("shodan exploded")

            _run(background._run_job(job_id, "scan", boom))

            with Session() as s:
                job = ScanJobRepository(s).get_by_id(job_id)
                assert job.status == "failed"
                assert "shodan exploded" in job.result_summary
                assert job.finished_at is not None

    def test_work_success_marks_job_completed(self, tmp_path):
        Session = self._make_factory(tmp_path)
        with patch("src.web.background.get_session_factory", return_value=Session):
            from src.web import background

            with Session() as s:
                job = ScanJobRepository(s).create(job_type="scan")
                s.commit()
                job_id = job.id

            _run(background._run_job(job_id, "scan", lambda: {"total_nodes": 7}))

            with Session() as s:
                job = ScanJobRepository(s).get_by_id(job_id)
                assert job.status == "completed"
                assert json.loads(job.result_summary) == {"total_nodes": 7}

    def test_failed_running_mark_still_reaches_terminal_state(self, tmp_path):
        """If marking 'running' fails, the job must not stay 'pending' forever."""
        Session = self._make_factory(tmp_path)
        with patch("src.web.background.get_session_factory", return_value=Session):
            from src.web import background

            with Session() as s:
                job = ScanJobRepository(s).create(job_type="scan")
                s.commit()
                job_id = job.id

            real_update = background._update_job_status

            def flaky_update(jid, status, summary):
                if status == "running":
                    raise RuntimeError("database is locked")
                return real_update(jid, status, summary)

            with patch("src.web.background._update_job_status", side_effect=flaky_update):
                # Must not raise — the failure is contained.
                _run(background._run_job(job_id, "scan", lambda: {}))

            with Session() as s:
                job = ScanJobRepository(s).get_by_id(job_id)
                assert job.status == "failed"
                assert "could not mark job running" in job.result_summary


# ---------------------------------------------------------------------------
# §3 — NodeVulnerability active-link uniqueness
# ---------------------------------------------------------------------------

class TestNodeVulnerabilityUniqueness:
    def _seed(self, session):
        node = Node(ip="10.1.2.3", port=8333, version="0.20.0")
        session.add(node)
        session.add(CVEEntry(
            cve_id="CVE-RACE-1", severity="HIGH", cvss_score=7.0,
            affected_versions=json.dumps([{"version": "0.20.0"}]),
        ))
        session.commit()
        return node

    def test_partial_unique_index_rejects_second_active_link(self, db_session):
        node = self._seed(db_session)
        db_session.add(NodeVulnerability(node_id=node.id, cve_id="CVE-RACE-1"))
        db_session.flush()
        db_session.add(NodeVulnerability(node_id=node.id, cve_id="CVE-RACE-1"))
        with pytest.raises(IntegrityError):
            db_session.flush()

    def test_resolved_history_rows_may_repeat_the_pair(self, db_session):
        node = self._seed(db_session)
        old = NodeVulnerability(node_id=node.id, cve_id="CVE-RACE-1",
                                resolved_at=_utcnow() - timedelta(days=3))
        db_session.add(old)
        db_session.add(NodeVulnerability(node_id=node.id, cve_id="CVE-RACE-1"))
        db_session.flush()  # one resolved + one active: valid

    def test_concurrent_relink_loser_is_no_op_not_duplicate(self, tmp_path):
        """The race from docs/state-machines.md §3: session B computed its diff
        before session A committed the same link. B's insert must be skipped."""
        Session = _file_session(tmp_path)
        with Session() as s:
            node = self._seed(s)
            node_id = node.id

        # A wins the race: syncs and commits first.
        sA = Session()
        VulnerabilityRepository(sA).sync_node_links(sA.get(Node, node_id), {"CVE-RACE-1"})
        sA.commit()

        # B already ran its SELECT (empty active set) before A committed; it
        # now applies its stale diff through the conflict-tolerant insert.
        sB = Session()
        repoB = VulnerabilityRepository(sB)
        loser_node = sB.get(Node, node_id)
        assert repoB._insert_active_link(loser_node.id, "CVE-RACE-1", _utcnow(),
                                         loser_node.version) == 0
        sB.commit()

        with Session() as s:
            active = s.scalars(
                select(NodeVulnerability).where(
                    NodeVulnerability.node_id == node_id,
                    NodeVulnerability.resolved_at.is_(None),
                )
            ).all()
            assert len(active) == 1

    def test_link_to_node_returns_existing_row_after_conflict(self, tmp_path):
        Session = _file_session(tmp_path)
        with Session() as s:
            node = self._seed(s)
            cve = s.get(CVEEntry, "CVE-RACE-1")
            node_id, cve_id = node.id, cve.cve_id

        sA = Session()
        VulnerabilityRepository(sA).sync_node_links(sA.get(Node, node_id), {cve_id})
        sA.commit()

        sB = Session()
        link = VulnerabilityRepository(sB).link_to_node(sB.get(Node, node_id),
                                                         sB.get(CVEEntry, cve_id))
        sB.commit()
        assert link is not None and link.cve_id == cve_id
        with Session() as s:
            assert s.query(NodeVulnerability).filter_by(
                node_id=node_id, cve_id=cve_id, resolved_at=None).count() == 1


# ---------------------------------------------------------------------------
# §4 — NVD refresh upsert (dialect-portable merge)
# ---------------------------------------------------------------------------

class TestNVDRefreshUpsert:
    @pytest.fixture
    def session(self):
        engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        Base.metadata.create_all(engine)
        s = sessionmaker(bind=engine)()
        yield s
        s.close()

    @contextlib.contextmanager
    def _fetched(self, entries):
        with patch("src.nvd.service.NVDClient") as MockClient:
            MockClient.return_value.fetch_bitcoin_cves.return_value = entries
            yield MockClient

    def test_refresh_updates_existing_and_inserts_new(self, session, monkeypatch):
        monkeypatch.setenv("NVD_AUTO_RELINK", "false")
        session.add(CVEEntry(
            cve_id="CVE-OLD-1",
            severity="LOW", cvss_score=2.0,
            affected_versions=json.dumps([{"version": "0.19.0"}]),
            fetched_at=_utcnow() - timedelta(hours=48),
        ))
        session.commit()

        entries = [
            NVDEntry(  # same id, changed fields → update
                cve_id="CVE-OLD-1", published=None, last_modified=None,
                severity="CRITICAL", cvss_score=9.9, description="upgraded",
                affected_versions=[{"version": "0.19.0"}],
            ),
            NVDEntry(  # new id → insert
                cve_id="CVE-NEW-1", published=None, last_modified=None,
                severity="HIGH", cvss_score=7.0, description="fresh",
                affected_versions=[{"version": "0.21.0"}],
            ),
        ]
        with self._fetched(entries):
            NVDService(session).get_vulnerabilities()

        rows = {e.cve_id: e for e in session.query(CVEEntry).all()}
        assert set(rows) == {"CVE-OLD-1", "CVE-NEW-1"}
        assert rows["CVE-OLD-1"].severity == "CRITICAL"
        assert rows["CVE-OLD-1"].cvss_score == 9.9

    def test_refresh_upsert_is_dialect_aware(self):
        """Guard: the refresh upsert must dispatch per dialect (atomic ON
        CONFLICT on SQLite/PostgreSQL) rather than a single-dialect statement
        or the non-atomic merge() path."""
        import inspect
        import src.nvd.service as service_mod

        source = inspect.getsource(service_mod)
        assert "dialects.sqlite" in source
        assert "dialects.postgresql" in source
        assert "on_conflict_do_update" in source
        assert "get_bind().dialect" in source

    def test_refresh_twice_is_idempotent_update(self, session, monkeypatch):
        """Two refreshes writing the same cve_id complete: the second updates
        instead of raising (the concurrent-refresh race)."""
        monkeypatch.setenv("NVD_AUTO_RELINK", "false")
        entry = NVDEntry(
            cve_id="CVE-TWICE-1", published=None, last_modified=None,
            severity="LOW", cvss_score=2.0, description="first",
            affected_versions=[{"version": "0.19.0"}],
        )
        with self._fetched([entry]):
            NVDService(session).get_vulnerabilities()

        # Force staleness, then refresh the same cve with changed fields.
        session.query(CVEEntry).update(
            {"fetched_at": _utcnow() - timedelta(hours=48)}
        )
        session.commit()
        entry2 = NVDEntry(
            cve_id="CVE-TWICE-1", published=None, last_modified=None,
            severity="HIGH", cvss_score=8.0, description="second",
            affected_versions=[{"version": "0.19.0"}],
        )
        with self._fetched([entry2]):
            NVDService(session).get_vulnerabilities()

        rows = session.query(CVEEntry).filter_by(cve_id="CVE-TWICE-1").all()
        assert len(rows) == 1
        assert rows[0].severity == "HIGH"


# ---------------------------------------------------------------------------
# §7 — Geo enrichment keyset cursor
# ---------------------------------------------------------------------------

class _FakeGeo:
    country_code = "DE"
    country_name = "Germany"
    city = "Berlin"
    asn = "AS64500"
    asn_name = "FakeNet"
    subdivision = "BE"
    latitude = 52.5
    longitude = 13.4


class _FakeGeoIPService:
    def lookup(self, ip):
        return _FakeGeo()


class TestGeoEnrichmentCursor:
    def test_mid_run_delete_does_not_skip_rows(self, db_session):
        nodes = [Node(ip=f"10.9.0.{i}", port=8333) for i in range(10)]
        for n in nodes:
            db_session.add(n)
        db_session.commit()

        deleted = nodes[0]

        def progress(done, total):
            # After the first batch, delete an already-processed row. An
            # OFFSET cursor then shifts and silently skips node #5; a keyset
            # cursor on Node.id keeps full coverage of the survivors.
            if done == 4:
                db_session.delete(deleted)
                db_session.flush()

        result = enrich_nodes_geo(db_session, _FakeGeoIPService(),
                                  batch_size=4, progress=progress)

        assert result["no_match"] == 0
        survivors = (
            db_session.query(Node)
            .filter(Node.ip != deleted.ip)
            .all()
        )
        assert len(survivors) == 9
        for node in survivors:
            assert node.subdivision == "BE", f"{node.ip} was skipped by the cursor"
            assert node.geo_country_code == "DE"

    def test_single_pass_processes_every_node_once(self, db_session):
        for i in range(7):
            db_session.add(Node(ip=f"10.8.0.{i}", port=8333))
        db_session.commit()

        result = enrich_nodes_geo(db_session, _FakeGeoIPService(), batch_size=3)
        assert result["updated"] == 7
        assert result["total"] == 7


class TestTerminalWriteRetry:
    def test_transient_failure_retried_until_success(self, tmp_path):
        """A transient 'database is locked' on the terminal write is retried
        instead of leaving the job 'running' for the staleness cutoff."""
        Session = _file_session(tmp_path)
        with patch("src.web.background.get_session_factory", return_value=Session):
            from src.web import background

            with Session() as s:
                job = ScanJobRepository(s).create(job_type="scan")
                s.commit()
                job_id = job.id

            real_update = background._update_job_status
            attempts = {"completed": 0}

            def flaky(jid, status, summary):
                if status == "completed" and attempts["completed"] < 2:
                    attempts["completed"] += 1
                    raise RuntimeError("database is locked")
                return real_update(jid, status, summary)

            with patch("src.web.background._update_job_status", side_effect=flaky):
                _run(background._run_job(job_id, "scan", lambda: {"total_nodes": 1}))

            with Session() as s:
                job = ScanJobRepository(s).get_by_id(job_id)
                assert job.status == "completed"
            assert attempts["completed"] == 2  # two transient failures, third succeeded


class TestNewNodeFlushGuard:
    def test_sync_links_with_unflushed_new_node(self, db_session):
        """sync_node_links must flush a brand-new node first (sessions are
        autoflush=False; NodeRepository.upsert does not flush)."""
        db_session.add(CVEEntry(
            cve_id="CVE-NEW-9", severity="HIGH", cvss_score=7.0,
            affected_versions=json.dumps([{"version": "0.20.0"}]),
        ))
        db_session.commit()
        new_node = Node(ip="10.5.5.5", port=8333, version="0.20.0")
        db_session.add(new_node)  # NOT flushed: id is None
        assert new_node.id is None

        added, resolved = VulnerabilityRepository(db_session).sync_node_links(
            new_node, {"CVE-NEW-9"}
        )
        assert (added, resolved) == (1, 0)
        assert new_node.id is not None
        links = db_session.query(NodeVulnerability).filter_by(
            node_id=new_node.id, cve_id="CVE-NEW-9", resolved_at=None
        ).all()
        assert len(links) == 1


class TestMigrationDuplicateRepair:
    def test_init_db_repairs_duplicate_active_links_before_indexing(self, tmp_path, monkeypatch):
        """A DB already hit by the pre-fix race has duplicate ACTIVE rows;
        init_db must resolve the surplus (keeping the oldest) and then create
        the unique index, instead of failing on it."""
        db_url = f"sqlite:///{tmp_path}/legacy.db"
        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        with engine.begin() as conn:
            conn.execute(sa_text("DROP INDEX IF EXISTS uq_node_vuln_active"))
            # Legacy state: two ACTIVE rows for the same pair (the race's
            # residue), one clean pair, one resolved history row.
            conn.execute(sa_text(
                "INSERT INTO nodes (ip, port, is_example, is_vulnerable, "
                "has_exposed_rpc, is_dev_version, first_seen, last_seen) VALUES "
                "('10.0.0.9', 8333, 0, 0, 0, 0, '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            ))
            conn.execute(sa_text(
                "INSERT INTO cve_entries (cve_id, severity, fetched_at) "
                "VALUES ('CVE-DUP-1', 'HIGH', '2026-01-01 00:00:00')"
            ))
            conn.execute(sa_text(
                "INSERT INTO node_vulnerabilities (node_id, cve_id, detected_at) "
                "VALUES (1, 'CVE-DUP-1', '2026-01-01 00:00:00')"
            ))
            conn.execute(sa_text(
                "INSERT INTO node_vulnerabilities (node_id, cve_id, detected_at) "
                "VALUES (1, 'CVE-DUP-1', '2026-01-02 00:00:00')"
            ))
            conn.execute(sa_text(
                "INSERT INTO node_vulnerabilities (node_id, cve_id, detected_at, resolved_at) "
                "VALUES (1, 'CVE-DUP-1', '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            ))
        engine.dispose()

        monkeypatch.setenv("DATABASE_URL", db_url)
        from src.db.connection import close_db, init_db

        close_db()  # reset cached engine from any earlier test
        try:
            init_db()
        finally:
            close_db()

        engine = create_engine(db_url)
        with engine.connect() as conn:
            active = conn.execute(sa_text(
                "SELECT id FROM node_vulnerabilities WHERE resolved_at IS NULL"
            )).fetchall()
            resolved = conn.execute(sa_text(
                "SELECT id, resolved_at FROM node_vulnerabilities "
                "WHERE resolved_at IS NOT NULL ORDER BY id"
            )).fetchall()
            idx = conn.execute(sa_text(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND name='uq_node_vuln_active'"
            )).fetchall()
        engine.dispose()

        assert len(active) == 1, "exactly one active link must survive"
        assert len(resolved) == 2, "the surplus active row was resolved; history kept"
        # The pre-existing resolved history row keeps its original timestamp.
        assert resolved[1][1] == "2026-01-01 00:00:00"
        assert len(idx) == 1

        # Clean DBs are untouched: the surviving active row is the oldest one.
        assert active[0][0] == 1
