"""Tests for the Nostr repository and the db-import-nostr flow."""
import json

import pytest

from src.db.repositories import NostrRepository
from src.db.models import NostrRelay, NostrScan


def _import_dump(session, dump, source="dump.json"):
    """Mirror cmd_import_nostr against a live session (uses the bulk path)."""
    repo = NostrRepository(session)
    scan = repo.create_scan(
        source=source,
        total=dump["total"],
        resolved=dump["resolved"],
        behind_any_cdn=dump["behind_any_cdn"],
    )
    repo.bulk_upsert_relays(dump["results"], scan)
    session.commit()
    return scan


DUMP_A = {
    "total": 4,
    "resolved": 3,
    "behind_any_cdn": 2,
    "counts": {"cloudflare": 1, "fastly": 1, "direct": 1, "dns_error": 1},
    "results": [
        {"host": "cf.relay", "verdict": "cloudflare", "ips": ["104.16.0.1"], "providers": ["cloudflare"], "error": None},
        {"host": "fast.relay", "verdict": "fastly", "ips": ["151.101.1.1"], "providers": ["fastly"], "error": None},
        {"host": "plain.relay", "verdict": "direct", "ips": ["8.8.8.8"], "providers": [], "error": None},
        {"host": "broken.relay", "verdict": "dns_error", "ips": [], "providers": [], "error": "nxdomain"},
    ],
}


class TestImport:
    def test_import_creates_scan_and_relays(self, db_session):
        _import_dump(db_session, DUMP_A)
        assert db_session.query(NostrScan).count() == 1
        assert db_session.query(NostrRelay).count() == 4
        cf = db_session.query(NostrRelay).filter_by(host="cf.relay").one()
        assert cf.verdict == "cloudflare"
        assert json.loads(cf.providers_json) == ["cloudflare"]
        assert json.loads(cf.ips_json) == ["104.16.0.1"]

    def test_bulk_dedupes_duplicate_hosts_within_one_dump(self, db_session):
        # A dump that lists the same host twice must yield one row (last wins).
        repo = NostrRepository(db_session)
        scan = repo.create_scan(source="dup.json", total=2, resolved=2, behind_any_cdn=1)
        repo.bulk_upsert_relays(
            [
                {"host": "dup.relay", "verdict": "direct", "providers": [], "ips": ["1.1.1.1"], "error": None},
                {"host": "dup.relay", "verdict": "cloudflare", "providers": ["cloudflare"], "ips": ["104.16.0.1"], "error": None},
            ],
            scan,
        )
        db_session.commit()
        rows = db_session.query(NostrRelay).filter_by(host="dup.relay").all()
        assert len(rows) == 1
        assert rows[0].verdict == "cloudflare"

    def test_bulk_skips_results_without_a_host(self, db_session):
        # A malformed entry (no host) must be skipped, not abort the import.
        repo = NostrRepository(db_session)
        scan = repo.create_scan(source="bad.json", total=2, resolved=2, behind_any_cdn=1)
        imported = repo.bulk_upsert_relays(
            [
                {"host": "ok.relay", "verdict": "cloudflare", "providers": ["cloudflare"], "ips": ["104.16.0.1"], "error": None},
                {"verdict": "direct", "providers": [], "ips": [], "error": None},  # no host
            ],
            scan,
        )
        db_session.commit()
        assert imported == 1
        assert db_session.query(NostrRelay).count() == 1
        assert db_session.query(NostrRelay).one().host == "ok.relay"

    def test_reimport_updates_in_place_no_duplicate(self, db_session):
        _import_dump(db_session, DUMP_A)
        # Second scan: cf.relay moved off Cloudflare to direct.
        dump_b = json.loads(json.dumps(DUMP_A))
        dump_b["results"][0]["verdict"] = "direct"
        dump_b["results"][0]["providers"] = []
        _import_dump(db_session, dump_b, source="dump_b.json")

        # Two scans, but still 4 relays (upserted, not duplicated).
        assert db_session.query(NostrScan).count() == 2
        assert db_session.query(NostrRelay).count() == 4
        cf = db_session.query(NostrRelay).filter_by(host="cf.relay").one()
        assert cf.verdict == "direct"


class TestQueries:
    def test_latest_scan_scoping(self, db_session):
        _import_dump(db_session, DUMP_A)
        _import_dump(db_session, DUMP_A, source="dump_b.json")
        repo = NostrRepository(db_session)
        latest = repo.latest_scan()
        # All relays should be scoped to the latest scan after re-import.
        total, rows = repo.list_relays()
        assert total == 4
        assert all(r.scan_id == latest.id for r in rows)

    def test_filter_by_verdict(self, db_session):
        _import_dump(db_session, DUMP_A)
        repo = NostrRepository(db_session)
        total, rows = repo.list_relays(verdict="cloudflare")
        assert total == 1
        assert rows[0].host == "cf.relay"

    def test_filter_by_provider(self, db_session):
        _import_dump(db_session, DUMP_A)
        repo = NostrRepository(db_session)
        total, rows = repo.list_relays(provider="fastly")
        assert total == 1
        assert rows[0].host == "fast.relay"

    def test_provider_filter_escapes_like_wildcards(self, db_session):
        # A provider value containing a LIKE wildcard must NOT match everything.
        # Unescaped, `%"cloud%"%` would match `"cloudflare"`; escaped, it matches nothing.
        _import_dump(db_session, DUMP_A)
        repo = NostrRepository(db_session)
        total, rows = repo.list_relays(provider="cloud%")
        assert total == 0
        assert rows == []

    def test_behind_cdn_filter_excludes_non_cdn(self, db_session):
        _import_dump(db_session, DUMP_A)
        repo = NostrRepository(db_session)
        total, rows = repo.list_relays(behind_cdn=True)
        assert total == 2
        assert {r.host for r in rows} == {"cf.relay", "fast.relay"}

    def test_pagination(self, db_session):
        _import_dump(db_session, DUMP_A)
        repo = NostrRepository(db_session)
        total, page = repo.list_relays(limit=2, offset=0)
        assert total == 4
        assert len(page) == 2

    def test_stats_aggregate(self, db_session):
        _import_dump(db_session, DUMP_A)
        repo = NostrRepository(db_session)
        stats = repo.stats()
        assert stats["total"] == 4
        assert stats["resolved"] == 3
        assert stats["behind_any_cdn"] == 2
        assert stats["behind_cdn_pct"] == pytest.approx(66.7, abs=0.1)
        assert stats["counts"]["cloudflare"] == 1
        assert stats["counts"]["dns_error"] == 1
        # provider breakdown derived server-side (non-CDN verdicts excluded)
        assert stats["providers"] == {"cloudflare": 1, "fastly": 1}

    def test_stats_derived_from_rows_not_dump_summary(self, db_session):
        # Stats must reconcile with the persisted rows even when the dump's
        # top-level aggregates are wrong (here: zeroed) and a host is duplicated.
        repo = NostrRepository(db_session)
        scan = repo.create_scan(source="skewed.json", total=999, resolved=0, behind_any_cdn=0)
        repo.bulk_upsert_relays(
            [
                {"host": "cf.relay", "verdict": "cloudflare", "providers": ["cloudflare"], "ips": ["104.16.0.1"], "error": None},
                {"host": "cf.relay", "verdict": "cloudflare", "providers": ["cloudflare"], "ips": ["104.16.0.1"], "error": None},  # dup
                {"host": "plain.relay", "verdict": "direct", "providers": [], "ips": ["8.8.8.8"], "error": None},
                {"host": "bad.relay", "verdict": "dns_error", "providers": [], "ips": [], "error": "nxdomain"},
            ],
            scan,
        )
        db_session.commit()
        stats = repo.stats()
        # 3 deduped rows; resolved = 3 - 1 dns_error = 2; behind = 1 cloudflare.
        assert stats["total"] == 3
        assert stats["resolved"] == 2
        assert stats["behind_any_cdn"] == 1
        assert stats["behind_cdn_pct"] == pytest.approx(50.0, abs=0.1)
        assert sum(stats["counts"].values()) == stats["total"]

    def test_stats_empty_when_no_scan(self, db_session):
        repo = NostrRepository(db_session)
        stats = repo.stats()
        assert stats["total"] == 0
        assert stats["counts"] == {}
        total, rows = repo.list_relays()
        assert total == 0 and rows == []
