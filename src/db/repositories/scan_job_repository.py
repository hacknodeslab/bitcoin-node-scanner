"""
Repository for ScanJob database operations.
"""
import json
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ScanJob


class ScanJobRepository:
    """Repository for ScanJob CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(self) -> ScanJob:
        """Create a new scan job in 'pending' state."""
        job = ScanJob(
            id=str(uuid.uuid4()),
            status='pending',
            created_at=datetime.utcnow(),
        )
        self.session.add(job)
        self.session.flush()
        return job

    def get_by_id(self, job_id: str) -> Optional[ScanJob]:
        """Get a scan job by ID."""
        return self.session.get(ScanJob, job_id)

    def update_status(
        self,
        job: ScanJob,
        status: str,
        result_summary: Optional[Dict[str, Any]] = None,
    ) -> ScanJob:
        """Update job status and optionally set timestamps and result summary."""
        job.status = status
        if status == 'running':
            job.started_at = datetime.utcnow()
        elif status in ('completed', 'failed'):
            job.finished_at = datetime.utcnow()
        if result_summary is not None:
            job.result_summary = json.dumps(result_summary)
        return job

    def get_active_job(self) -> Optional[ScanJob]:
        """Return the first job in 'pending' or 'running' state, or None."""
        stmt = select(ScanJob).where(
            ScanJob.status.in_(['pending', 'running'])
        ).order_by(ScanJob.created_at)
        return self.session.scalar(stmt)
