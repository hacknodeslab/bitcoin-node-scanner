"""
GET /api/v1/credits — locally tracked Shodan credit usage.

Reads the CreditTracker usage log (output/logs/credit_usage.json) only; it
never calls the Shodan API, so polling this endpoint is free and fast. Live
account balances stay in the CLI's `--check-credits`.
"""
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ...credit_tracker import CreditTracker
from ..auth import require_api_key

router = APIRouter()

_DEFAULT_LOG_FILE = "output/logs/credit_usage.json"


def _plan_limit() -> int:
    """Monthly credit budget used to derive `remaining`. Env-overridable."""
    try:
        return max(1, int(os.getenv("SHODAN_PLAN_LIMIT", "100")))
    except ValueError:
        return 100


def _credit_tracker() -> CreditTracker:
    """Build a tracker for the current request (re-reads the log file).

    Relative paths resolve against the project root so the endpoint works
    regardless of the process cwd. CREDIT_USAGE_LOG overrides the location
    (used by tests).
    """
    log_file = os.getenv("CREDIT_USAGE_LOG", _DEFAULT_LOG_FILE)
    if not os.path.isabs(log_file):
        log_file = str(Path(__file__).resolve().parents[3] / log_file)
    return CreditTracker(log_file=log_file)


class CreditUsageBucket(BaseModel):
    used: int
    limit: int
    remaining: int
    projected_eom: int


class CreditPeriodUsage(BaseModel):
    query_credits_used: int
    scan_credits_used: int


class CreditTodayUsage(CreditPeriodUsage):
    date: str


class CreditMonthUsage(CreditPeriodUsage):
    year: int
    month: int
    total_scans: int
    scan_type_breakdown: Dict[str, int]


class CreditsOut(BaseModel):
    # "local" — figures come from the on-disk tracker log, not the Shodan API.
    source: str
    plan_limit: int
    tracked_entries: int
    today: CreditTodayUsage
    month: CreditMonthUsage
    query_credits: CreditUsageBucket
    scan_credits: CreditUsageBucket
    last_entry_at: Optional[str]


@router.get("/credits", response_model=CreditsOut, dependencies=[Depends(require_api_key)])
def get_credits():
    tracker = _credit_tracker()
    plan_limit = _plan_limit()

    now = datetime.now()
    today_entries = [
        e for e in tracker.history
        if datetime.fromisoformat(e["timestamp"]).date() == now.date()
    ]
    today = CreditTodayUsage(
        date=now.date().isoformat(),
        query_credits_used=sum(e["query_credits_used"] for e in today_entries),
        scan_credits_used=sum(e["scan_credits_used"] for e in today_entries),
    )

    monthly = tracker.get_monthly_usage()
    month = CreditMonthUsage(
        year=monthly["year"],
        month=monthly["month"],
        total_scans=monthly["total_scans"],
        query_credits_used=monthly["query_credits_used"],
        scan_credits_used=monthly["scan_credits_used"],
        scan_type_breakdown=monthly["scan_type_breakdown"],
    )

    # No live API values are passed: remaining is derived from the local log.
    projection = tracker.project_monthly_usage(plan_limit=plan_limit)

    return CreditsOut(
        source="local",
        plan_limit=plan_limit,
        tracked_entries=len(tracker.history),
        today=today,
        month=month,
        query_credits=CreditUsageBucket(
            used=monthly["query_credits_used"],
            limit=plan_limit,
            remaining=projection["query_credits"]["remaining"],
            projected_eom=projection["query_credits"]["projected_eom"],
        ),
        scan_credits=CreditUsageBucket(
            used=monthly["scan_credits_used"],
            limit=plan_limit,
            remaining=projection["scan_credits"]["remaining"],
            projected_eom=projection["scan_credits"]["projected_eom"],
        ),
        last_entry_at=tracker.history[-1]["timestamp"] if tracker.history else None,
    )
