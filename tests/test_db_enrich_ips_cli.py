"""Tests for the `db-enrich-ips` CLI command (all HTTP mocked)."""
import argparse
import logging
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from src.db.cli import cmd_enrich_ips
from src.db.models import EnrichmentQuota, IpReputation
from src.db.repositories import NodeRepository
from src.enrichers.blocklists import BlocklistEnricher

FEODO = "# feodo\n10.0.0.2\n"


def _args(**kw):
    base = {"limit": None, "source": None, "dry_run": False}
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def cli_db(db_session, tmp_path, monkeypatch):
    """Point the CLI at the in-memory test session and an empty blocklist cache."""
    monkeypatch.setenv("BLOCKLIST_CACHE_DIR", str(tmp_path / "bl"))
    monkeypatch.setenv("BLOCKLISTS", "feodo")
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    @contextmanager
    def _session():
        yield db_session
        db_session.flush()

    with patch("src.db.cli.is_database_configured", return_value=True), \
         patch("src.db.cli.init_db"), \
         patch("src.db.cli.get_db_session", _session):
        nodes = NodeRepository(db_session)
        nodes.upsert({"ip": "10.0.0.1", "port": 8333, "risk_level": "LOW"})
        nodes.upsert({"ip": "10.0.0.2", "port": 8333, "risk_level": "CRITICAL"})
        nodes.upsert({"ip": "10.0.0.3", "port": 8333, "risk_level": "MEDIUM"})
        nodes.upsert({"ip": "203.0.113.42", "port": 8333, "risk_level": "CRITICAL"})
        db_session.flush()
        yield db_session


def _rows(session):
    return sorted(r.ip for r in session.query(IpReputation).all())


def test_limit_one_picks_critical(cli_db):
    with patch.object(BlocklistEnricher, "_http_get", staticmethod(lambda url: FEODO)):
        assert cmd_enrich_ips(_args(limit=1)) == 0
    assert _rows(cli_db) == ["10.0.0.2"]


def test_no_keys_logs_unavailable_and_succeeds(cli_db, caplog):
    with patch.object(BlocklistEnricher, "_http_get", staticmethod(lambda url: FEODO)), \
         caplog.at_level(logging.INFO, logger="src.enrichers.service"):
        assert cmd_enrich_ips(_args()) == 0
    assert "enricher unavailable: abuseipdb" in caplog.text
    # every non-example IP enriched, the example IP untouched
    assert _rows(cli_db) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_source_blocklists_makes_no_abuseipdb_request(cli_db, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    with patch.object(BlocklistEnricher, "_http_get", staticmethod(lambda url: FEODO)), \
         patch("src.enrichers.abuseipdb.requests.get") as abuse_get:
        assert cmd_enrich_ips(_args(source="blocklists")) == 0
    abuse_get.assert_not_called()


def test_unknown_source_errors(cli_db, capsys):
    assert cmd_enrich_ips(_args(source="greynoise")) == 1
    assert "unknown enrichment source" in capsys.readouterr().out


def test_dry_run_is_offline_and_reports_quota_stop(cli_db, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    monkeypatch.setenv("ABUSEIPDB_DAILY_QUOTA", "2")
    monkeypatch.setenv("BLOCKLISTS", "feodo,tor_exit")
    with patch("requests.get") as any_get:
        assert cmd_enrich_ips(_args(dry_run=True, limit=2000)) == 0
    any_get.assert_not_called()
    out = capsys.readouterr().out
    assert "Candidate IPs:        3" in out
    assert "stops after 2 IPs (quota)" in out
    assert _rows(cli_db) == []
    assert cli_db.query(EnrichmentQuota).count() == 0
    assert not (tmp_path / "bl").exists()
