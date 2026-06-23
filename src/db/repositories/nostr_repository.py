"""Repository for Nostr relay CDN-recon persistence.

Operates on the dedicated `NostrScan` / `NostrRelay` tables (independent of the
Bitcoin `Scan` / `Node` tables). The list/stats queries scope to the most
recent scan, which is also the scan whose `scan_id` every relay row carries
after import (relays are upserted in place, one row per host).
"""
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import NostrRelay, NostrScan
from ...nostr.classifier import NON_CDN_VERDICTS, provider_counts  # single source of truth

logger = logging.getLogger(__name__)

# Chunk the existing-host IN(...) lookup to stay under SQLite's bind-parameter
# limit (999 on builds older than 3.32); a real import is ~1000+ hosts.
_HOST_LOOKUP_CHUNK = 500


def _escape_like(value: str) -> str:
    """Escape LIKE metacharacters so a filter value can't act as a wildcard."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class NostrRepository:
    """CRUD + aggregates for Nostr relay CDN-recon data."""

    def __init__(self, session: Session):
        self.session = session

    # ------------------------------------------------------------------
    # Writes (used by db-import-nostr)
    # ------------------------------------------------------------------

    def create_scan(
        self,
        source: Optional[str],
        total: int,
        resolved: int,
        behind_any_cdn: int,
        status: str = "completed",
    ) -> NostrScan:
        scan = NostrScan(
            source=source,
            total=total,
            resolved=resolved,
            behind_any_cdn=behind_any_cdn,
            status=status,
        )
        self.session.add(scan)
        self.session.flush()  # assign scan.id for relay FK
        return scan

    def upsert_relay(
        self,
        host: str,
        verdict: str,
        providers: List[str],
        ips: List[str],
        error: Optional[str],
        scan: NostrScan,
        seen_at: Optional[datetime] = None,
    ) -> NostrRelay:
        """Insert a relay or update the existing row for this host in place."""
        now = seen_at or datetime.utcnow()
        existing = self.session.scalar(select(NostrRelay).where(NostrRelay.host == host))
        if existing:
            existing.verdict = verdict
            existing.providers_json = json.dumps(providers)
            existing.ips_json = json.dumps(ips)
            existing.error = error
            existing.scan_id = scan.id
            existing.last_seen = now
            return existing

        relay = NostrRelay(
            host=host,
            verdict=verdict,
            providers_json=json.dumps(providers),
            ips_json=json.dumps(ips),
            error=error,
            scan_id=scan.id,
            first_seen=now,
            last_seen=now,
        )
        self.session.add(relay)
        return relay

    def bulk_upsert_relays(
        self,
        results: List[dict],
        scan: NostrScan,
        seen_at: Optional[datetime] = None,
    ) -> int:
        """Upsert a whole scan's results with a single existing-host lookup.

        Each result is a dict with `host`, `verdict`, `providers`, `ips`,
        `error` (the scanner dump shape). Avoids the per-relay SELECT that
        `upsert_relay` issues — one chunked `IN` lookup covers the whole batch
        — so a ~1000-relay import is a few reads + N writes instead of N reads
        + N writes. Entries with no `host` are skipped (a malformed row must
        not abort the whole import). Returns the number of relays upserted.
        """
        now = seen_at or datetime.utcnow()
        valid = [r for r in results if r.get("host")]
        skipped = len(results) - len(valid)
        if skipped:
            logger.warning("bulk_upsert_relays: skipping %d result(s) with no host", skipped)
        hosts = [r["host"] for r in valid]
        existing: Dict[str, NostrRelay] = {}
        for i in range(0, len(hosts), _HOST_LOOKUP_CHUNK):
            chunk = hosts[i : i + _HOST_LOOKUP_CHUNK]
            for rel in self.session.scalars(
                select(NostrRelay).where(NostrRelay.host.in_(chunk))
            ).all():
                existing[rel.host] = rel
        for r in valid:
            host = r["host"]
            verdict = r.get("verdict", "direct")
            providers_json = json.dumps(r.get("providers", []))
            ips_json = json.dumps(r.get("ips", []))
            error = r.get("error")
            rel = existing.get(host)
            if rel is not None:
                rel.verdict = verdict
                rel.providers_json = providers_json
                rel.ips_json = ips_json
                rel.error = error
                rel.scan_id = scan.id
                rel.last_seen = now
            else:
                rel = NostrRelay(
                    host=host,
                    verdict=verdict,
                    providers_json=providers_json,
                    ips_json=ips_json,
                    error=error,
                    scan_id=scan.id,
                    first_seen=now,
                    last_seen=now,
                )
                self.session.add(rel)
                # Guard against duplicate hosts within the same dump.
                existing[host] = rel
        return len(valid)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def latest_scan(self) -> Optional[NostrScan]:
        return self.session.scalar(
            select(NostrScan).order_by(NostrScan.started_at.desc(), NostrScan.id.desc()).limit(1)
        )

    def list_relays(
        self,
        verdict: Optional[str] = None,
        provider: Optional[str] = None,
        behind_cdn: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[int, List[NostrRelay]]:
        """Paginated relays from the latest scan, with optional filters.

        Returns `(total_matching, page)`. Empty `(0, [])` when no scan exists.
        """
        scan = self.latest_scan()
        if scan is None:
            return 0, []

        conds = [NostrRelay.scan_id == scan.id]
        if verdict:
            conds.append(NostrRelay.verdict == verdict)
        if provider:
            # providers stored as a JSON array of names — match membership.
            # Escape LIKE metachars so a value with %/_ can't act as a wildcard.
            conds.append(
                NostrRelay.providers_json.like(f'%"{_escape_like(provider)}"%', escape="\\")
            )
        if behind_cdn is True:
            conds.append(NostrRelay.verdict.notin_(NON_CDN_VERDICTS))
        elif behind_cdn is False:
            conds.append(NostrRelay.verdict.in_(NON_CDN_VERDICTS))

        total = self.session.scalar(
            select(func.count()).select_from(NostrRelay).where(*conds)
        ) or 0

        rows = list(
            self.session.scalars(
                select(NostrRelay)
                .where(*conds)
                .order_by(NostrRelay.host)
                .offset(offset)
                .limit(limit)
            ).all()
        )
        return total, rows

    def counts_by_verdict(self, scan: NostrScan) -> Dict[str, int]:
        """`{verdict: count}` for the relays of a given scan, in one query."""
        rows = self.session.execute(
            select(NostrRelay.verdict, func.count())
            .where(NostrRelay.scan_id == scan.id)
            .group_by(NostrRelay.verdict)
        ).all()
        return {verdict: count for verdict, count in rows}

    def stats(self) -> dict:
        """Aggregates for the latest scan, or zeroed values when none exists.

        Every headline number is derived from the persisted relay rows (not the
        `NostrScan` summary columns), so `total`/`resolved`/`behind_cdn_pct`
        always reconcile with the per-verdict `counts` and the relay table the
        UI renders — even if the imported dump's top-level aggregates were
        stale, missing, or counted duplicate hosts the upsert later deduped.
        """
        scan = self.latest_scan()
        if scan is None:
            return {
                "total": 0,
                "resolved": 0,
                "behind_any_cdn": 0,
                "behind_cdn_pct": 0.0,
                "counts": {},
                "providers": {},
                "started_at": None,
            }

        counts = self.counts_by_verdict(scan)
        total = sum(counts.values())
        behind_any_cdn = sum(c for v, c in counts.items() if v not in NON_CDN_VERDICTS)
        non_resolving = counts.get("skipped", 0) + counts.get("dns_error", 0)
        resolved = total - non_resolving
        pct = round(100.0 * behind_any_cdn / resolved, 1) if resolved else 0.0
        return {
            "total": total,
            "resolved": resolved,
            "behind_any_cdn": behind_any_cdn,
            "behind_cdn_pct": pct,
            "counts": counts,
            "providers": provider_counts(counts),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
        }
