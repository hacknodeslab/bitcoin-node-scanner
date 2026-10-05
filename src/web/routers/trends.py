"""
GET /api/v1/trends — vulnerability trends over time (REST parity with `db-trends`).

Mirrors HistoricalAnalyzer.get_vulnerability_trends (src/db/analysis.py) but
runs against the injected `get_db` session so tests can override it; the
analyzer opens its own session via get_db_session() and is used read-only
as the reference implementation.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Annotated, Dict, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import and_
from sqlalchemy.orm import Session

from ...db.models import Node
from ..auth import require_api_key
from .nodes import get_db

router = APIRouter()

Granularity = Literal["day", "week", "month"]


class TrendBucket(BaseModel):
    total: int
    vulnerable: int
    critical: int
    high: int


class TrendsSummary(BaseModel):
    total_nodes: int
    total_vulnerable: int
    vulnerability_rate: float


class TrendsOut(BaseModel):
    period: str
    days: int
    granularity: str
    data: Dict[str, TrendBucket]
    summary: TrendsSummary


@router.get("/trends", response_model=TrendsOut, dependencies=[Depends(require_api_key)])
def get_trends(
    db: Annotated[Session, Depends(get_db)],
    days: Annotated[int, Query(ge=1, le=3650, description="Number of days to analyze")] = 30,
    granularity: Annotated[Granularity, Query(description="Time grouping")] = "day",
):
    end_date = datetime.now(timezone.utc).replace(tzinfo=None)
    start_date = end_date - timedelta(days=days)

    nodes_in_period = db.query(Node).filter(
        and_(
            Node.last_seen >= start_date,
            Node.last_seen <= end_date,
        )
    ).all()

    # Grouping identical to HistoricalAnalyzer.get_vulnerability_trends.
    trends: Dict[str, dict] = defaultdict(lambda: {"total": 0, "vulnerable": 0, "critical": 0, "high": 0})
    for node in nodes_in_period:
        if granularity == "week":
            key = node.last_seen.strftime("%Y-W%W")
        elif granularity == "month":
            key = node.last_seen.strftime("%Y-%m")
        else:  # day
            key = node.last_seen.strftime("%Y-%m-%d")

        trends[key]["total"] += 1
        if node.is_vulnerable:
            trends[key]["vulnerable"] += 1
        if node.risk_level == "CRITICAL":
            trends[key]["critical"] += 1
        elif node.risk_level == "HIGH":
            trends[key]["high"] += 1

    total_vulnerable = sum(1 for n in nodes_in_period if n.is_vulnerable)

    return TrendsOut(
        period=f"{start_date.date()} to {end_date.date()}",
        days=days,
        granularity=granularity,
        data={k: TrendBucket(**v) for k, v in trends.items()},
        summary=TrendsSummary(
            total_nodes=len(nodes_in_period),
            total_vulnerable=total_vulnerable,
            vulnerability_rate=(
                total_vulnerable / len(nodes_in_period) * 100 if nodes_in_period else 0
            ),
        ),
    )
