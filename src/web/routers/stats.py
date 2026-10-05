"""
GET /api/v1/stats — aggregate scan statistics.

`period_stats` mirrors the CLI `db-stats` output
(HistoricalAnalyzer.get_summary_statistics, src/db/analysis.py) over the
last `days` days. It is computed against the injected session — the analyzer
opens its own session via get_db_session(), which tests cannot override.
"""
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from ..auth import require_api_key
from pydantic import BaseModel
from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from ...db.models import Node
from ...db.repositories import NodeRepository, ScanRepository
from .nodes import get_db


def _stale_threshold_days() -> int:
    """How old (days) before a node is considered STALE. Configurable via env."""
    try:
        return max(1, int(os.getenv("STALE_THRESHOLD_DAYS", "7")))
    except ValueError:
        return 7

router = APIRouter()


def _resolve_commit() -> Optional[str]:
    env = os.getenv("GIT_COMMIT")
    if env:
        return env.strip()[:7] or None
    git_dir = Path(__file__).resolve().parents[3] / ".git"
    head = git_dir / "HEAD"
    if not head.is_file():
        return None
    try:
        ref = head.read_text().strip()
        if ref.startswith("ref:"):
            ref_path = git_dir / ref.split(" ", 1)[1]
            if ref_path.is_file():
                return ref_path.read_text().strip()[:7] or None
            packed = git_dir / "packed-refs"
            if packed.is_file():
                target = ref.split(" ", 1)[1]
                for line in packed.read_text().splitlines():
                    if line and not line.startswith("#") and line.endswith(target):
                        return line.split(" ", 1)[0][:7] or None
            return None
        return ref[:7] or None
    except OSError:
        return None


_COMMIT = _resolve_commit()


class TopAsn(BaseModel):
    asn: Optional[str]
    count: int


class PeriodStats(BaseModel):
    """Period-scoped statistics, mirroring the CLI `db-stats` output."""

    period: str
    days: int
    total_nodes: int
    vulnerable_nodes: int
    critical_nodes: int
    new_nodes: int
    exposed_rpc: int
    dev_versions: int
    unique_countries: int
    vulnerability_rate: float
    exposed_rpc_rate: float
    dev_version_rate: float
    top_asns: List[TopAsn]


class StatsOut(BaseModel):
    total_nodes: int
    by_risk_level: Dict[str, int]
    by_country: Dict[str, int]
    vulnerable_nodes_count: int
    # Strip tokens — see frontend StatsStrip (§8.3). EXPOSED/STALE/TOR/OK use
    # positive criteria; OK is strict (LOW + not exposed + fresh) and is not
    # the inverse of the other three.
    exposed_count: int
    stale_count: int
    tor_count: int
    ok_count: int
    stale_threshold_days: int
    last_scan_at: Optional[str]
    commit: Optional[str]
    # CLI db-stats parity: period-scoped metrics over the last `days` days.
    # Note the counts above (total_nodes, vulnerable_nodes_count, ...) are
    # all-time; the same-named fields inside period_stats are period-scoped.
    period_stats: PeriodStats


def _compute_period_stats(db: Session, days: int) -> PeriodStats:
    """Replicates HistoricalAnalyzer.get_summary_statistics on a given session."""
    end_date = datetime.now(timezone.utc).replace(tzinfo=None)
    start_date = end_date - timedelta(days=days)
    in_period = and_(Node.last_seen >= start_date, Node.last_seen <= end_date)

    total_nodes = db.query(Node).filter(in_period).count()
    vulnerable_nodes = db.query(Node).filter(in_period, Node.is_vulnerable == True).count()
    critical_nodes = db.query(Node).filter(in_period, Node.risk_level == "CRITICAL").count()
    exposed_rpc = db.query(Node).filter(in_period, Node.has_exposed_rpc == True).count()
    dev_versions = db.query(Node).filter(in_period, Node.is_dev_version == True).count()
    new_nodes = db.query(Node).filter(
        and_(Node.first_seen >= start_date, Node.first_seen <= end_date)
    ).count()
    unique_countries = db.query(func.count(func.distinct(Node.country_code))).filter(
        in_period
    ).scalar()

    top_asns = db.query(
        Node.asn,
        func.count(Node.id),
    ).filter(
        in_period,
        Node.asn.isnot(None),
    ).group_by(Node.asn).order_by(
        func.count(Node.id).desc()
    ).limit(5).all()

    return PeriodStats(
        period=f"{start_date.date()} to {end_date.date()}",
        days=days,
        total_nodes=total_nodes,
        vulnerable_nodes=vulnerable_nodes,
        critical_nodes=critical_nodes,
        new_nodes=new_nodes,
        exposed_rpc=exposed_rpc,
        dev_versions=dev_versions,
        unique_countries=unique_countries,
        vulnerability_rate=(vulnerable_nodes / total_nodes * 100) if total_nodes > 0 else 0,
        exposed_rpc_rate=(exposed_rpc / total_nodes * 100) if total_nodes > 0 else 0,
        dev_version_rate=(dev_versions / total_nodes * 100) if total_nodes > 0 else 0,
        top_asns=[TopAsn(asn=asn, count=count) for asn, count in top_asns],
    )


@router.get("/stats", response_model=StatsOut, dependencies=[Depends(require_api_key)])
def get_stats(
    db: Annotated[Session, Depends(get_db)],
    days: Annotated[int, Query(ge=1, le=3650, description="Period (days) for period_stats")] = 30,
):
    node_repo = NodeRepository(db)
    scan_repo = ScanRepository(db)

    total = node_repo.count_all()
    by_risk = node_repo.count_by_risk_level()
    by_country_all = node_repo.count_by_country()

    # Top 10 countries
    top_countries = dict(
        sorted(by_country_all.items(), key=lambda x: x[1], reverse=True)[:10]
    )

    vulnerable_count = node_repo.count_vulnerable()

    threshold_days = _stale_threshold_days()
    stale_before = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=threshold_days)
    exposed_count = node_repo.count_exposed()
    stale_count = node_repo.count_stale(stale_before)
    tor_count = node_repo.count_tor()
    ok_count = node_repo.count_ok(stale_before)

    # Last completed scan timestamp
    last_scan_at = None
    latest_scan = scan_repo.get_latest()
    if latest_scan:
        last_scan_at = latest_scan.timestamp.isoformat()

    return StatsOut(
        total_nodes=total,
        by_risk_level=by_risk,
        by_country=top_countries,
        vulnerable_nodes_count=vulnerable_count,
        exposed_count=exposed_count,
        stale_count=stale_count,
        tor_count=tor_count,
        ok_count=ok_count,
        stale_threshold_days=threshold_days,
        last_scan_at=last_scan_at,
        commit=_COMMIT,
        period_stats=_compute_period_stats(db, days),
    )
