"""
GET /api/v1/trends — vulnerability trends over time (REST parity with `db-trends`).

The bucketing and summary computation lives in
src/db/analysis.py:compute_vulnerability_trends, shared with the CLI; this
router only validates the query params and maps the result to the response
model.
"""
from datetime import datetime, timedelta, timezone
from typing import Annotated, Dict, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db.analysis import compute_vulnerability_trends
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

    trends = compute_vulnerability_trends(db, start_date, end_date, granularity)

    return TrendsOut(
        period=trends["period"],
        days=days,
        granularity=granularity,
        data={k: TrendBucket(**v) for k, v in trends["data"].items()},
        summary=TrendsSummary(**trends["summary"]),
    )
