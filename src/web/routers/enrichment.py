"""
POST /api/v1/enrichment/run — start a bounded background IP-reputation batch.

Job status is read via GET /api/v1/scans/{job_id} (jobs share the ScanJob
table, discriminated by `job_type`).
"""
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
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

    job = repo.create(job_type="enrichment")
    db.commit()

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
