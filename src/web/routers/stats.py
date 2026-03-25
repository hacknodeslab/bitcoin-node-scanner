"""
GET /api/v1/stats — aggregate scan statistics.
"""
from typing import Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db.repositories import NodeRepository, ScanRepository
from ..auth import require_api_key
from .nodes import get_db

router = APIRouter()


class StatsOut(BaseModel):
    total_nodes: int
    by_risk_level: Dict[str, int]
    by_country: Dict[str, int]
    vulnerable_nodes_count: int
    last_scan_at: Optional[str]


@router.get("/stats", response_model=StatsOut, dependencies=[Depends(require_api_key)])
def get_stats(db: Session = Depends(get_db)):
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
        last_scan_at=last_scan_at,
    )
