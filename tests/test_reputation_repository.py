"""Tests for ReputationRepository, ScanJob job types, and migration 009."""
import importlib.util
import json
import os
from datetime import timedelta

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

from src.db.models import IpReputation, _utcnow
from src.db.repositories import NodeRepository, ReputationRepository, ScanJobRepository


SOURCES = ["abuseipdb", "blocklists"]


def _node(repo, ip, port=8333, risk="LOW"):
    return repo.upsert({"ip": ip, "port": port, "risk_level": risk})


class TestUpsert:
    def test_creates_then_updates_in_place(self, db_session):
        repo = ReputationRepository(db_session)
        t1 = _utcnow()
        row = repo.upsert("1.2.3.4", {"abuseipdb": {"status": "ok"}},
                          {"abuse_confidence_score": 10}, enriched_at=t1)
        first = row.first_enriched_at

        repo.upsert("1.2.3.4", {"blocklists": {"status": "ok"}},
                    {"blocklists": ["feodo"]}, enriched_at=t1 + timedelta(hours=1))

        rows = db_session.query(IpReputation).all()
        assert len(rows) == 1
        assert rows[0].first_enriched_at == first
        assert rows[0].abuse_confidence_score == 10
        assert json.loads(rows[0].blocklists_json) == ["feodo"]
        # sources merge per name rather than replacing the whole map
        assert set(json.loads(rows[0].sources_json)) == {"abuseipdb", "blocklists"}

    def test_failed_run_keeps_enriched_at(self, db_session):
        repo = ReputationRepository(db_session)
        t1 = _utcnow()
        repo.upsert("1.2.3.4", {"abuseipdb": {"status": "ok"}}, {}, enriched_at=t1)
        repo.upsert("1.2.3.4", {"abuseipdb": {"status": "error"}}, {}, enriched_at=None)
        assert repo.get_by_ip("1.2.3.4").reputation_enriched_at == t1

    def test_one_row_shared_by_two_ports(self, db_session):
        nodes = NodeRepository(db_session)
        _node(nodes, "5.6.7.8", 8333)
        _node(nodes, "5.6.7.8", 8332)
        repo = ReputationRepository(db_session)
        repo.upsert("5.6.7.8", {}, {"abuse_confidence_score": 50}, enriched_at=_utcnow())
        assert db_session.query(IpReputation).count() == 1
        assert repo.get_by_ip("5.6.7.8").abuse_confidence_score == 50


class TestCandidates:
    def test_risk_ordering(self, db_session):
        nodes = NodeRepository(db_session)
        _node(nodes, "10.0.0.1", risk="LOW")
        _node(nodes, "10.0.0.2", risk="CRITICAL")
        _node(nodes, "10.0.0.3", risk="MEDIUM")
        _node(nodes, "10.0.0.4", risk="HIGH")
        _node(nodes, "10.0.0.5", risk=None)
        db_session.flush()
        repo = ReputationRepository(db_session)
        assert repo.ips_needing_enrichment(None, 7, SOURCES) == [
            "10.0.0.2", "10.0.0.4", "10.0.0.3", "10.0.0.1", "10.0.0.5",
        ]
        assert repo.ips_needing_enrichment(1, 7, SOURCES) == ["10.0.0.2"]

    def test_ip_ranked_by_highest_risk_of_its_nodes(self, db_session):
        nodes = NodeRepository(db_session)
        _node(nodes, "10.0.0.1", 8333, risk="LOW")
        _node(nodes, "10.0.0.1", 8332, risk="CRITICAL")
        _node(nodes, "10.0.0.2", risk="HIGH")
        db_session.flush()
        assert ReputationRepository(db_session).ips_needing_enrichment(None, 7, SOURCES) == [
            "10.0.0.1", "10.0.0.2",
        ]

    def test_staleness_cutoff(self, db_session):
        nodes = NodeRepository(db_session)
        _node(nodes, "10.0.0.1", risk="CRITICAL")
        _node(nodes, "10.0.0.2", risk="CRITICAL")
        _node(nodes, "10.0.0.3", risk="CRITICAL")
        repo = ReputationRepository(db_session)
        fresh, old = _utcnow() - timedelta(days=2), _utcnow() - timedelta(days=10)
        repo.upsert("10.0.0.1", {}, {"abuseipdb_checked_at": fresh, "blocklists_checked_at": fresh},
                    enriched_at=fresh)
        repo.upsert("10.0.0.2", {}, {"abuseipdb_checked_at": old, "blocklists_checked_at": old},
                    enriched_at=old)
        # never-enriched first, then the stale one; the fresh one is skipped
        assert repo.ips_needing_enrichment(None, 7, SOURCES) == ["10.0.0.3", "10.0.0.2"]

    def test_due_is_per_source(self, db_session):
        nodes = NodeRepository(db_session)
        _node(nodes, "10.0.0.1", risk="CRITICAL")
        repo = ReputationRepository(db_session)
        # Blocklists covered the IP; AbuseIPDB never did (quota/error/other run).
        repo.upsert("10.0.0.1", {}, {"blocklists_checked_at": _utcnow()}, enriched_at=_utcnow())
        assert repo.candidates(None, 7, SOURCES) == [("10.0.0.1", ["abuseipdb"])]
        assert repo.ips_needing_enrichment(None, 7, ["abuseipdb"]) == ["10.0.0.1"]
        assert repo.ips_needing_enrichment(None, 7, ["blocklists"]) == []

    def test_no_sources_no_candidates(self, db_session):
        _node(NodeRepository(db_session), "10.0.0.1")
        repo = ReputationRepository(db_session)
        assert repo.candidates(None, 7, []) == []
        assert sum(repo.candidate_counts_by_risk(7, []).values()) == 0

    def test_unknown_source_rejected(self, db_session):
        with pytest.raises(ValueError):
            ReputationRepository(db_session).candidates(None, 7, ["greynoise"])

    def test_example_ips_excluded(self, db_session):
        nodes = NodeRepository(db_session)
        _node(nodes, "203.0.113.42", risk="CRITICAL")  # canonical example IP
        _node(nodes, "10.0.0.1", risk="LOW")
        db_session.flush()
        repo = ReputationRepository(db_session)
        assert repo.ips_needing_enrichment(None, 7, SOURCES) == ["10.0.0.1"]
        assert repo.candidate_counts_by_risk(7, SOURCES)["CRITICAL"] == 0

    def test_counts_by_risk(self, db_session):
        nodes = NodeRepository(db_session)
        _node(nodes, "10.0.0.1", risk="CRITICAL")
        _node(nodes, "10.0.0.2", risk="LOW")
        _node(nodes, "10.0.0.3", risk="LOW")
        db_session.flush()
        counts = ReputationRepository(db_session).candidate_counts_by_risk(7, SOURCES)
        assert counts == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 2, "UNRATED": 0}


class TestScanJobTypes:
    def test_db_rejects_second_active_job_of_same_type(self, db_session):
        from sqlalchemy.exc import IntegrityError
        repo = ScanJobRepository(db_session)
        repo.create(job_type="enrichment")
        db_session.commit()
        repo.create(job_type="scan")  # other type is fine
        db_session.commit()
        with pytest.raises(IntegrityError):
            repo.create(job_type="enrichment")
            db_session.commit()
        db_session.rollback()

    def test_finished_jobs_do_not_count(self, db_session):
        repo = ScanJobRepository(db_session)
        job = repo.create(job_type="scan")
        repo.update_status(job, "completed")
        db_session.commit()
        repo.create(job_type="scan")
        db_session.commit()

    def test_active_job_is_per_type(self, db_session):
        repo = ScanJobRepository(db_session)
        repo.create(job_type="enrichment")
        assert repo.get_active_job("scan") is None
        assert repo.get_active_job("enrichment") is not None

    def test_default_type_is_scan(self, db_session):
        job = ScanJobRepository(db_session).create()
        assert job.job_type == "scan"


def _load_migration():
    path = os.path.join(os.path.dirname(__file__), "..", "migrations", "versions",
                        "009_add_ip_reputation.py")
    spec = importlib.util.spec_from_file_location("mig009", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMigration009:
    """Runs the migration on an in-memory connection (never the configured DB)."""

    @pytest.fixture
    def conn(self):
        engine = sa.create_engine("sqlite:///:memory:")
        with engine.begin() as c:
            c.execute(sa.text(
                "CREATE TABLE scan_jobs (id VARCHAR(36) PRIMARY KEY, status VARCHAR(20) NOT NULL, "
                "started_at DATETIME, finished_at DATETIME, result_summary TEXT, created_at DATETIME)"
            ))
            c.execute(sa.text("INSERT INTO scan_jobs (id, status) VALUES ('j1', 'completed')"))
            c.execute(sa.text("CREATE TABLE nodes (id INTEGER PRIMARY KEY, ip VARCHAR(45))"))
            c.execute(sa.text("INSERT INTO nodes (ip) VALUES ('1.2.3.4')"))
        with engine.begin() as c:
            yield c

    def _run(self, conn, fn_name):
        mod = _load_migration()
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            getattr(mod, fn_name)()

    def test_upgrade_is_additive_and_defaults_job_type(self, conn):
        self._run(conn, "upgrade")
        insp = sa.inspect(conn)
        assert {"ip_reputation", "enrichment_quota"} <= set(insp.get_table_names())
        assert "uq_scan_jobs_active_per_type" in {i["name"] for i in insp.get_indexes("scan_jobs")}
        assert conn.execute(sa.text("SELECT job_type FROM scan_jobs")).scalar() == "scan"
        assert conn.execute(sa.text("SELECT count(*) FROM nodes")).scalar() == 1
        assert conn.execute(sa.text("SELECT count(*) FROM ip_reputation")).scalar() == 0

    def test_upgrade_is_idempotent_and_downgrade_reverts(self, conn):
        self._run(conn, "upgrade")
        self._run(conn, "upgrade")  # objects already present (init_db ran first)
        self._run(conn, "downgrade")
        insp = sa.inspect(conn)
        assert "ip_reputation" not in insp.get_table_names()
        assert "job_type" not in {c["name"] for c in insp.get_columns("scan_jobs")}
        assert conn.execute(sa.text("SELECT count(*) FROM scan_jobs")).scalar() == 1
