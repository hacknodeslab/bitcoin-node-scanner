"""
POST /api/v1/enrichment/run — start a bounded background IP-reputation batch.
POST /api/v1/enrich-geo      — start a retroactive MaxMind geo enrichment.

Job status is read via GET /api/v1/scans/{job_id} (jobs share the ScanJob
table, discriminated by `job_type`).

Both endpoints reuse job_type='enrichment': geo enrichment is the same
category of work (a retroactive enrichment pass over existing DB rows), and
the shared single-flight keeps the two batch writers from running
concurrently — on SQLite a second writer would just contend on the database
lock. The result_summary shape discriminates them: geo jobs carry
{kind: "geo", total, updated, skipped, no_match}.
"""
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...db.repositories import ScanJobRepository
from ...enrichers import REGISTRY
from ..auth import require_api_key, require_csrf_token
from .nodes import get_db
from .scans import ScanJobOut

router = APIRouter()


class EnrichmentRunIn(BaseModel):
    limit: int = Field(default=100, ge=1, le=1000)
    source: Optional[str] = None

    @field_validator("source")
    @classmethod
    def _known_source(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and value not in REGISTRY:
            raise ValueError(f"unknown source; expected one of: {', '.join(REGISTRY)}")
        return value


@router.post(
    "/enrichment/run",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanJobOut,
    dependencies=[Depends(require_api_key), Depends(require_csrf_token)],
)
def trigger_enrichment(
    background_tasks: BackgroundTasks,
    body: Optional[EnrichmentRunIn] = Body(default=None),
    db: Session = Depends(get_db),
):
    params = body or EnrichmentRunIn()
    repo = ScanJobRepository(db)

    active = repo.get_active_job("enrichment")
    if active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An enrichment run is already {active.status} (job_id={active.id}).",
        )

    try:
        job = repo.create(job_type="enrichment")
        db.commit()
    except IntegrityError:
        # Lost a race with a concurrent request (uq_scan_jobs_active_per_type).
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An enrichment run is already pending or running.",
        )

    from ..background import run_enrichment_job
    background_tasks.add_task(run_enrichment_job, job.id, params.limit, params.source)

    return ScanJobOut(
        job_id=job.id,
        job_type=job.job_type,
        status=job.status,
        started_at=None,
        finished_at=None,
        result_summary=None,
    )


@router.post(
    "/enrich-geo",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanJobOut,
    dependencies=[Depends(require_api_key), Depends(require_csrf_token)],
)
def trigger_geo_enrichment(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    repo = ScanJobRepository(db)

    active = repo.get_active_job("enrichment")
    if active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An enrichment run is already {active.status} (job_id={active.id}).",
        )

    try:
        job = repo.create(job_type="enrichment")
        db.commit()
    except IntegrityError:
        # Lost a race with a concurrent request (uq_scan_jobs_active_per_type).
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An enrichment run is already pending or running.",
        )

    from ..background import run_geo_enrichment_job
    background_tasks.add_task(run_geo_enrichment_job, job.id)

    return ScanJobOut(
        job_id=job.id,
        job_type=job.job_type,
        status=job.status,
        started_at=None,
        finished_at=None,
        result_summary=None,
    )
