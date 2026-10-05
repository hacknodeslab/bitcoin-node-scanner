"""Repository for passive IP-reputation data (`ip_reputation`).

One row per IP, shared by every `(ip, port)` node row. Candidate selection
for enrichment runs lives here so the risk ordering and the example-IP
exclusion are expressed once, in SQL.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from ..models import IpReputation, Node, _utcnow

logger = logging.getLogger(__name__)

# Lower rank = enriched first. Unrated nodes go last.
_RISK_RANK = case(
    (Node.risk_level == 'CRITICAL', 0),
    (Node.risk_level == 'HIGH', 1),
    (Node.risk_level == 'MEDIUM', 2),
    (Node.risk_level == 'LOW', 3),
    else_=4,
)
RISK_RANK_LABELS = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED')


def _loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return default


class ReputationRepository:
    """Reads/writes `ip_reputation` and selects IPs needing enrichment."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_ip(self, ip: str) -> Optional[IpReputation]:
        return self.session.scalar(select(IpReputation).where(IpReputation.ip == ip))

    def upsert(
        self,
        ip: str,
        sources: Dict[str, Dict[str, Any]],
        fields: Dict[str, Any],
        enriched_at: Optional[datetime] = None,
    ) -> IpReputation:
        """Insert or update the row for ``ip``.

        ``sources`` is merged per source name into ``sources_json`` (a run
        limited to one source keeps the others' last status). ``fields`` holds
        typed columns to overwrite (``abuse_*``, ``blocklists``,
        ``<source>_checked_at``). When ``enriched_at`` is None (every source
        failed) the display timestamp is left untouched.
        """
        row = self.get_by_ip(ip)
        if row is None:
            row = IpReputation(ip=ip, first_enriched_at=_utcnow())
            self.session.add(row)

        merged = _loads(row.sources_json, {})
        merged.update(sources)
        row.sources_json = json.dumps(merged, default=str)

        for key, value in fields.items():
            if key == 'blocklists':
                row.blocklists_json = json.dumps(value)
            else:
                setattr(row, key, value)

        if enriched_at is not None:
            row.reputation_enriched_at = enriched_at
        row.updated_at = _utcnow()
        self.session.flush()
        return row

    # Per-source "last successful check" columns. A new source needs an entry
    # here plus its `<name>_checked_at` column.
    CHECKED_AT = {
        'abuseipdb': IpReputation.abuseipdb_checked_at,
        'blocklists': IpReputation.blocklists_checked_at,
    }

    def _checked_cols(self, sources: Sequence[str]):
        unknown = [s for s in sources if s not in self.CHECKED_AT]
        if unknown:
            raise ValueError(f"no checked_at column for source(s): {', '.join(unknown)}")
        return [self.CHECKED_AT[s] for s in sources]

    def _candidates_stmt(self, stale_days: int, sources: Sequence[str]):
        """IPs where at least one of ``sources`` never succeeded or is stale."""
        cutoff = _utcnow() - timedelta(days=stale_days)
        cols = self._checked_cols(sources)
        per_ip = (
            select(Node.ip.label('ip'), func.min(_RISK_RANK).label('rank'))
            .where(Node.is_example.is_(False))
            .group_by(Node.ip)
            .subquery()
        )
        enriched = IpReputation.reputation_enriched_at
        return (
            select(per_ip.c.ip, per_ip.c.rank, *cols)
            .outerjoin(IpReputation, IpReputation.ip == per_ip.c.ip)
            .where(or_(*[(c.is_(None)) | (c < cutoff) for c in cols]))
            .order_by(per_ip.c.rank, enriched.is_not(None), enriched, per_ip.c.ip)
        )

    def candidates(
        self, limit: Optional[int], stale_days: int, sources: Sequence[str]
    ) -> List[Tuple[str, List[str]]]:
        """``[(ip, sources_due)]`` for distinct non-example IPs, highest risk first.

        ``sources_due`` lists which of ``sources`` still need this IP (never
        succeeded or older than ``stale_days``), so a quota-bound source is
        not re-spent on IPs it already covers. Ordered CRITICAL → HIGH →
        MEDIUM → LOW → unrated (highest risk among the IP's nodes), then
        never-enriched first, then oldest enrichment.
        """
        if not sources:
            return []
        cutoff = _utcnow() - timedelta(days=stale_days)
        stmt = self._candidates_stmt(stale_days, sources)
        if limit is not None:
            stmt = stmt.limit(limit)
        out: List[Tuple[str, List[str]]] = []
        for row in self.session.execute(stmt):
            checked = row[2:]
            due = [s for s, at in zip(sources, checked) if at is None or at < cutoff]
            out.append((row.ip, due))
        return out

    def ips_needing_enrichment(
        self, limit: Optional[int], stale_days: int, sources: Sequence[str]
    ) -> List[str]:
        return [ip for ip, _ in self.candidates(limit, stale_days, sources)]

    def candidate_counts_by_risk(self, stale_days: int, sources: Sequence[str]) -> Dict[str, int]:
        """Candidate IP counts keyed by risk label (for the dry-run plan)."""
        counts = {label: 0 for label in RISK_RANK_LABELS}
        if not sources:
            return counts
        sub = self._candidates_stmt(stale_days, sources).order_by(None).subquery()
        rows = self.session.execute(
            select(sub.c.rank, func.count()).group_by(sub.c.rank)
        ).all()
        for rank, count in rows:
            counts[RISK_RANK_LABELS[rank]] = count
        return counts

    @staticmethod
    def blocklists_of(row: IpReputation) -> Optional[List[str]]:
        return _loads(row.blocklists_json, None)

    @staticmethod
    def sources_of(row: IpReputation) -> Dict[str, Dict[str, Any]]:
        return _loads(row.sources_json, {})
