"""Tests for src.enrichers: quota, service orchestration, AbuseIPDB, blocklists.

All HTTP is mocked; nothing here touches the network.
"""
import json
import logging
import os
from datetime import datetime
from unittest.mock import MagicMock

import pytest
import requests

from src.db.models import IpReputation, _utcnow
from src.db.repositories import NodeRepository, ReputationRepository
from src.enrichers.abuseipdb import AbuseIPDBEnricher
from src.enrichers.blocklists import BlocklistEnricher, parse_networks
from src.enrichers.quota import DailyQuota
from src.enrichers.service import build_enrichers, enrich_ips, run_enrichment


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class FakeEnricher:
    def __init__(self, name, available=True, results=None, raises=None):
        self.name = name
        self._available = available
        self._results = results or {}
        self._raises = raises
        self.calls = []

    def available(self):
        return self._available

    def enrich(self, ips):
        self.calls.append(list(ips))
        if self._raises:
            raise self._raises
        return {ip: self._results[ip] for ip in ips if ip in self._results}


def ok(fields, data=None):
    return {"status": "ok", "fields": fields, "data": data}


def _resp(status=200, payload=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.json.return_value = payload if payload is not None else {}
    return r


def _quota(db_session, limit=1000, day="2026-10-05"):
    return DailyQuota(db_session, "abuseipdb", limit=limit, today=lambda: day,
                      sleep=lambda s: None)


ABUSE_OK = {"data": {
    "ipAddress": "10.0.0.1", "abuseConfidenceScore": 82, "totalReports": 41,
    "numDistinctUsers": 12, "lastReportedAt": "2026-09-30T10:00:00+00:00",
    "isTor": False, "isp": "ignored",
}}


# ---------------------------------------------------------------------------
# quota
# ---------------------------------------------------------------------------

class TestDailyQuota:
    def test_consume_until_limit(self, db_session):
        q = _quota(db_session, limit=2)
        assert q.consume() and q.consume()
        assert not q.consume()
        assert q.remaining() == 0

    def test_survives_new_session(self, db_engine):
        from sqlalchemy.orm import sessionmaker
        Session = sessionmaker(bind=db_engine)
        s1 = Session()
        q1 = DailyQuota(s1, "abuseipdb", limit=1000, today=lambda: "2026-10-05")
        for _ in range(600):
            q1.consume()
        s1.close()
        s2 = Session()
        assert DailyQuota(s2, "abuseipdb", limit=1000, today=lambda: "2026-10-05").remaining() == 400
        s2.close()

    def test_resets_next_utc_day(self, db_session):
        q = _quota(db_session, limit=1, day="2026-10-05")
        q.consume()
        q.mark_exhausted()
        assert q.remaining() == 0
        assert _quota(db_session, limit=1, day="2026-10-06").remaining() == 1

    def test_throttles_between_calls(self, db_session):
        slept = []
        clock = iter([0.0, 0.2, 0.2]).__next__
        q = DailyQuota(db_session, "abuseipdb", limit=10, min_interval=1.0,
                       today=lambda: "2026-10-05", clock=clock, sleep=slept.append)
        q.consume()
        q.consume()
        assert slept == [pytest.approx(0.8)]

    def test_concurrent_row_insert_is_tolerated(self, db_session, monkeypatch):
        q = _quota(db_session)
        q.consume()  # the day's row now exists
        other = _quota(db_session)
        real_row = DailyQuota._row
        calls = {"n": 0}

        def stale_first(self, day):
            calls["n"] += 1
            # Simulate a run that checked before the other one inserted.
            return None if calls["n"] == 2 else real_row(self, day)

        monkeypatch.setattr(DailyQuota, "_row", stale_first)
        assert other.consume() is True  # IntegrityError swallowed, increment applied
        monkeypatch.setattr(DailyQuota, "_row", real_row)
        assert q.used() == 2

    def test_two_counters_do_not_lose_increments(self, db_session):
        a, b = _quota(db_session, limit=3), _quota(db_session, limit=3)
        assert a.consume() and b.consume() and a.consume()
        assert not b.consume()
        assert a.used() == 3

    def test_sync_remaining_only_lowers(self, db_session):
        q = _quota(db_session, limit=1000)
        q.sync_remaining(100)
        assert q.remaining() == 100
        q.sync_remaining(500)
        assert q.remaining() == 100


# ---------------------------------------------------------------------------
# service
# ---------------------------------------------------------------------------

class TestService:
    def test_unavailable_enricher_skipped_and_logged_once(self, db_session, caplog):
        off = FakeEnricher("abuseipdb", available=False)
        on = FakeEnricher("blocklists", results={"10.0.0.1": ok({"blocklists": []})})
        with caplog.at_level(logging.INFO, logger="src.enrichers.service"):
            stats = enrich_ips(db_session, ["10.0.0.1"], [off, on])
        assert off.calls == []
        assert caplog.text.count("enricher unavailable: abuseipdb") == 1
        assert stats["sources"]["abuseipdb"]["error"] == 0
        row = ReputationRepository(db_session).get_by_ip("10.0.0.1")
        assert "abuseipdb" not in json.loads(row.sources_json)

    def test_one_source_fails_other_persists(self, db_session):
        bad = FakeEnricher("abuseipdb", raises=requests.ConnectionError("down"))
        good = FakeEnricher("blocklists", results={"10.0.0.1": ok({"blocklists": ["feodo"]})})
        enrich_ips(db_session, ["10.0.0.1"], [good, bad])
        row = ReputationRepository(db_session).get_by_ip("10.0.0.1")
        sources = json.loads(row.sources_json)
        assert sources["abuseipdb"]["status"] == "error"
        assert sources["blocklists"]["status"] == "ok"
        assert json.loads(row.blocklists_json) == ["feodo"]
        assert row.reputation_enriched_at is not None

    def test_all_sources_fail_keeps_ip_pending(self, db_session):
        bad1 = FakeEnricher("abuseipdb", raises=RuntimeError("x"))
        bad2 = FakeEnricher("blocklists", raises=RuntimeError("y"))
        enrich_ips(db_session, ["10.0.0.1"], [bad1, bad2])
        row = ReputationRepository(db_session).get_by_ip("10.0.0.1")
        assert row.reputation_enriched_at is None
        assert {s["status"] for s in json.loads(row.sources_json).values()} == {"error"}

    def test_unattempted_ip_not_written(self, db_session):
        partial = FakeEnricher("abuseipdb", results={"10.0.0.1": ok({"abuse_confidence_score": 1})})
        enrich_ips(db_session, ["10.0.0.1", "10.0.0.2"], [partial])
        assert ReputationRepository(db_session).get_by_ip("10.0.0.2") is None

    def test_example_ips_never_reach_a_source(self, db_session):
        e = FakeEnricher("blocklists", results={})
        stats = enrich_ips(db_session, ["203.0.113.42", "10.0.0.1"], [e])
        assert e.calls == [["10.0.0.1"]]
        assert stats["ips_skipped_example"] == 1

    def test_run_enrichment_db_with_examples_touches_no_example_row(self, db_session):
        nodes = NodeRepository(db_session)
        for ip in ("192.0.2.7", "198.51.100.13", "203.0.113.42", "10.0.0.1"):
            nodes.upsert({"ip": ip, "port": 8333, "risk_level": "CRITICAL"})
        db_session.flush()
        e = FakeEnricher("blocklists", results={"10.0.0.1": ok({"blocklists": []})})
        run_enrichment(db_session, enrichers=[e], stale_days=7)
        assert e.calls == [["10.0.0.1"]]
        assert [r.ip for r in db_session.query(IpReputation).all()] == ["10.0.0.1"]

    def test_unknown_source_rejected(self, db_session):
        with pytest.raises(ValueError):
            build_enrichers(db_session, "greynoise")

    def test_success_sets_per_source_checked_at_only(self, db_session):
        bad = FakeEnricher("abuseipdb", raises=RuntimeError("503"))
        good = FakeEnricher("blocklists", results={"10.0.0.1": ok({"blocklists": []})})
        enrich_ips(db_session, ["10.0.0.1"], [good, bad])
        row = ReputationRepository(db_session).get_by_ip("10.0.0.1")
        assert row.blocklists_checked_at is not None
        assert row.abuseipdb_checked_at is None  # errored source stays due

    def test_blocklist_run_leaves_ips_pending_for_abuseipdb(self, db_session):
        nodes = NodeRepository(db_session)
        nodes.upsert({"ip": "10.0.0.1", "port": 8333, "risk_level": "CRITICAL"})
        db_session.flush()
        bl = FakeEnricher("blocklists", results={"10.0.0.1": ok({"blocklists": []})})
        run_enrichment(db_session, enrichers=[bl], stale_days=7)
        abuse = FakeEnricher("abuseipdb", results={"10.0.0.1": ok({"abuse_confidence_score": 5})})
        stats = run_enrichment(db_session, enrichers=[abuse], stale_days=7)
        assert stats["candidates"] == 1
        assert abuse.calls == [["10.0.0.1"]]

    def test_quota_source_not_respent_on_covered_ip(self, db_session):
        nodes = NodeRepository(db_session)
        nodes.upsert({"ip": "10.0.0.1", "port": 8333, "risk_level": "CRITICAL"})
        db_session.flush()
        ReputationRepository(db_session).upsert(
            "10.0.0.1", {}, {"abuseipdb_checked_at": _utcnow()},
            enriched_at=None,
        )
        abuse = FakeEnricher("abuseipdb", results={})
        bl = FakeEnricher("blocklists", results={"10.0.0.1": ok({"blocklists": []})})
        run_enrichment(db_session, enrichers=[bl, abuse], stale_days=7)
        assert bl.calls == [["10.0.0.1"]]
        assert abuse.calls == []


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

class TestAbuseIPDB:
    def _enricher(self, db_session, http, key="k", limit=1000):
        return AbuseIPDBEnricher(_quota(db_session, limit=limit), key, http=http,
                                 sleep=lambda s: None)

    def test_no_key_unavailable_and_no_request(self, db_session):
        http = MagicMock()
        e = self._enricher(db_session, http, key=None)
        assert e.available() is False
        assert e.enrich(["10.0.0.1"]) == {}
        http.get.assert_not_called()

    def test_maps_fields(self, db_session):
        http = MagicMock()
        http.get.return_value = _resp(200, ABUSE_OK)
        result = self._enricher(db_session, http).enrich(["10.0.0.1"])["10.0.0.1"]
        assert result["status"] == "ok"
        assert result["fields"] == {
            "abuse_confidence_score": 82,
            "abuse_total_reports": 41,
            "abuse_last_reported_at": datetime(2026, 9, 30, 10, 0, 0),
        }
        assert "isp" not in result["data"]
        kwargs = http.get.call_args.kwargs
        assert kwargs["headers"]["Key"] == "k"
        assert kwargs["params"]["ipAddress"] == "10.0.0.1"

    def test_429_stops_source_and_exhausts_quota(self, db_session):
        http = MagicMock()
        http.get.return_value = _resp(429)
        e = self._enricher(db_session, http)
        assert e.enrich(["10.0.0.1", "10.0.0.2"]) == {}
        assert http.get.call_count == 1
        assert e.quota.remaining() == 0
        assert e.available() is False

    def test_retries_on_503_then_succeeds(self, db_session):
        http = MagicMock()
        http.get.side_effect = [_resp(503), _resp(200, ABUSE_OK)]
        result = self._enricher(db_session, http).enrich(["10.0.0.1"])["10.0.0.1"]
        assert result["status"] == "ok"
        assert http.get.call_count == 2

    def test_network_error_exhausts_retries(self, db_session):
        http = MagicMock()
        http.get.side_effect = requests.ConnectionError("boom")
        result = self._enricher(db_session, http).enrich(["10.0.0.1"])["10.0.0.1"]
        assert result["status"] == "error"
        assert http.get.call_count == 3

    def test_quota_cut_mid_run(self, db_session):
        q = _quota(db_session, limit=1000)
        for _ in range(998):
            q.consume()
        http = MagicMock()
        http.get.return_value = _resp(200, ABUSE_OK)
        e = AbuseIPDBEnricher(q, "k", http=http, sleep=lambda s: None)
        ips = [f"10.0.0.{i}" for i in range(10)]
        results = e.enrich(ips)
        assert http.get.call_count == 2
        assert list(results) == ips[:2]

    @pytest.mark.parametrize("code", [401, 403])
    def test_bad_key_disables_source_without_burning_quota(self, db_session, code):
        http = MagicMock()
        http.get.return_value = _resp(code)
        e = self._enricher(db_session, http)
        assert e.enrich([f"10.0.0.{i}" for i in range(5)]) == {}
        assert http.get.call_count == 1
        assert e.available() is False
        assert e.quota.remaining() == 999  # one call spent, day not marked exhausted

    def test_rate_limit_header_lowers_remaining(self, db_session):
        http = MagicMock()
        http.get.return_value = _resp(200, ABUSE_OK, headers={"X-RateLimit-Remaining": "5"})
        e = self._enricher(db_session, http)
        e.enrich(["10.0.0.1"])
        assert e.quota.remaining() == 5


# ---------------------------------------------------------------------------
# Blocklists
# ---------------------------------------------------------------------------

LISTS = {
    "https://www.spamhaus.org/drop/drop.txt":
        "; Spamhaus DROP\n203.0.113.0/24 ; SBL1\n",
    "https://www.spamhaus.org/drop/dropv6.txt":
        "; v6\n2001:db8:abcd::/48 ; SBL2\n",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt":
        "# feodo\n10.9.9.9\n",
}


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("BLOCKLIST_CACHE_DIR", str(tmp_path))
    return tmp_path


def _fetcher(mapping, fail=()):
    calls = []

    def fetch(url):
        calls.append(url)
        if url in fail:
            raise requests.ConnectionError("down")
        return mapping[url]
    fetch.calls = calls
    return fetch


class TestPartialResults:
    def test_partial_result_keeps_data_but_stays_due(self, db_session):
        e = FakeEnricher("blocklists", results={"10.0.0.1": {
            "status": "ok", "partial": True, "fields": {"blocklists": ["tor_exit"]},
            "data": {"lists_failed": ["feodo"]},
        }})
        enrich_ips(db_session, ["10.0.0.1"], [e])
        row = ReputationRepository(db_session).get_by_ip("10.0.0.1")
        assert json.loads(row.blocklists_json) == ["tor_exit"]
        assert row.blocklists_checked_at is None  # retried next run
        assert json.loads(row.sources_json)["blocklists"]["status"] == "partial"

    def test_blocklist_enricher_flags_partial_when_a_list_failed(self, cache):
        fetch = _fetcher(LISTS, fail={"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"})
        r = BlocklistEnricher(["spamhaus_drop", "feodo"], fetch=fetch).enrich(["8.8.8.8"])
        assert r["8.8.8.8"]["partial"] is True
        full = BlocklistEnricher(["spamhaus_drop"], fetch=_fetcher(LISTS)).enrich(["8.8.8.8"])
        assert full["8.8.8.8"]["partial"] is False


class TestBlocklists:
    def test_parse_skips_comments_and_junk(self):
        nets = parse_networks("# c\n1.2.3.0/24 ; x\nnot-an-ip\n\n2001:db8::/32\n5.6.7.8\n")
        assert [str(n) for n in nets] == ["1.2.3.0/24", "2001:db8::/32", "5.6.7.8/32"]

    def test_cidr_hit_v4_v6_and_clean(self, cache):
        e = BlocklistEnricher(["spamhaus_drop", "feodo"], fetch=_fetcher(LISTS))
        r = e.enrich(["203.0.113.7", "2001:db8:abcd::1", "10.9.9.9", "8.8.8.8"])
        assert r["203.0.113.7"]["fields"]["blocklists"] == ["spamhaus_drop"]
        assert r["2001:db8:abcd::1"]["fields"]["blocklists"] == ["spamhaus_drop"]
        assert r["10.9.9.9"]["fields"]["blocklists"] == ["feodo"]
        assert r["8.8.8.8"]["fields"]["blocklists"] == []

    def test_one_list_failing_others_still_match(self, cache):
        fetch = _fetcher(LISTS, fail={"https://feodotracker.abuse.ch/downloads/ipblocklist.txt"})
        e = BlocklistEnricher(["spamhaus_drop", "feodo"], fetch=fetch)
        r = e.enrich(["203.0.113.7"])["203.0.113.7"]
        assert r["fields"]["blocklists"] == ["spamhaus_drop"]
        assert r["data"]["lists_failed"] == ["feodo"]

    def test_all_lists_failing_raises(self, cache):
        e = BlocklistEnricher(["feodo"], fetch=_fetcher(LISTS, fail=set(LISTS)))
        with pytest.raises(RuntimeError):
            e.enrich(["10.9.9.9"])

    def test_fresh_cache_skips_fetch(self, cache):
        BlocklistEnricher(["feodo"], fetch=_fetcher(LISTS)).enrich(["1.1.1.1"])
        fetch = _fetcher(LISTS)
        BlocklistEnricher(["feodo"], fetch=fetch).enrich(["1.1.1.1"])
        assert fetch.calls == []

    def test_stale_cache_used_when_refresh_fails(self, cache):
        BlocklistEnricher(["feodo"], fetch=_fetcher(LISTS)).enrich(["1.1.1.1"])
        path = os.path.join(str(cache), "feodo.0.txt")
        old = os.path.getmtime(path) - 2 * 86400
        os.utime(path, (old, old))
        fetch = _fetcher(LISTS, fail=set(LISTS))
        r = BlocklistEnricher(["feodo"], fetch=fetch).enrich(["10.9.9.9"])
        assert fetch.calls  # a refresh was attempted
        assert r["10.9.9.9"]["fields"]["blocklists"] == ["feodo"]

    def test_html_payload_rejected(self, cache):
        e = BlocklistEnricher(["feodo"], fetch=lambda url: "<html>blocked</html>")
        with pytest.raises(RuntimeError):
            e.enrich(["10.9.9.9"])

    def test_env_selects_lists(self, monkeypatch):
        monkeypatch.setenv("BLOCKLISTS", "feodo, nope")
        assert BlocklistEnricher.from_env().list_ids == ["feodo"]
        monkeypatch.setenv("BLOCKLISTS", "")
        assert BlocklistEnricher.from_env().available() is False
