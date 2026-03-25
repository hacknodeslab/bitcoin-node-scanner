"""
POST /api/v1/scans  — trigger a background scan
GET  /api/v1/scans/{job_id} — get scan job status
"""
import json
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db.repositories import ScanJobRepository
from ..auth import require_api_key
from .nodes import get_db

router = APIRouter()


class ScanJobOut(BaseModel):
    job_id: str
    status: str
    started_at: Optional[str]
    finished_at: Optional[str]
    result_summary: Optional[dict]


@router.post(
    "/scans",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanJobOut,
    dependencies=[Depends(require_api_key)],
)
def trigger_scan(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    repo = ScanJobRepository(db)

    active = repo.get_active_job()
    if active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A scan is already {active.status} (job_id={active.id}). Wait for it to finish.",
        )

    job = repo.create()
    db.commit()
    job_id = job.id

    # Import here to avoid circular imports at module load time
    from ..background import run_scan_job
    background_tasks.add_task(run_scan_job, job_id)

    return ScanJobOut(
        job_id=job.id,
        status=job.status,
        started_at=None,
        finished_at=None,
        result_summary=None,
    )


@router.get(
    "/scans/{job_id}",
    response_model=ScanJobOut,
    dependencies=[Depends(require_api_key)],
)
def get_scan_job(job_id: str, db: Session = Depends(get_db)):
    repo = ScanJobRepository(db)
    job = repo.get_by_id(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found.")

    summary = None
    if job.result_summary:
        try:
            summary = json.loads(job.result_summary)
        except (ValueError, TypeError):
            summary = {"raw": job.result_summary}

    return ScanJobOut(
        job_id=job.id,
        status=job.status,
        started_at=job.started_at.isoformat() if job.started_at else None,
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
        result_summary=summary,
    )
