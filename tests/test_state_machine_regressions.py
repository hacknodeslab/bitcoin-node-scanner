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
from sqlalchemy import create_engine, select
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

    def test_service_has_no_sqlite_only_dml(self):
        """Guard: the refresh path must not depend on a single dialect's DML."""
        import inspect
        import src.nvd.service as service_mod

        source = inspect.getsource(service_mod)
        assert "dialects.sqlite" not in source
        assert "on_conflict_do_update" not in source


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
