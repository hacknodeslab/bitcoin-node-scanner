"""
GET /api/v1/stats — aggregate scan statistics.
"""
import os
from pathlib import Path
from typing import Dict, Optional

from fastapi import APIRouter, Depends
from ..auth import require_api_key
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db.repositories import NodeRepository, ScanRepository
from .nodes import get_db

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


class StatsOut(BaseModel):
    total_nodes: int
    by_risk_level: Dict[str, int]
    by_country: Dict[str, int]
    vulnerable_nodes_count: int
    last_scan_at: Optional[str]
    commit: Optional[str]


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
        commit=_COMMIT,
    )
