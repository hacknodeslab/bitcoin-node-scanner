"""
Repository for ScanJob database operations.

Job lifecycle (see docs/state-machines.md §1):

    pending ──► running ──► completed
       │           │
       └─────► failed ◄──────┘

Jobs orphaned in `pending`/`running` by a crash or restart are reaped as
`failed` once they pass a staleness cutoff — otherwise the partial unique
index would reject every future job of that type forever.
"""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..models import ScanJob

_PENDING = 'pending'
_RUNNING = 'running'
_COMPLETED = 'completed'
_FAILED = 'failed'

# Valid transitions; anything else raises in update_status().
_ALLOWED_TRANSITIONS = {
    _PENDING: {_RUNNING, _FAILED},
    _RUNNING: {_COMPLETED, _FAILED},
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _stale_cutoffs() -> Dict[str, timedelta]:
    """Age past which an active job is considered orphaned. Env-tunable."""
    try:
        pending_min = int(os.getenv('SCAN_JOB_STALE_PENDING_MINUTES', '30'))
    except ValueError:
        pending_min = 30
    try:
        running_min = int(os.getenv('SCAN_JOB_STALE_RUNNING_MINUTES', '720'))
    except ValueError:
        running_min = 720
    return {
        _PENDING: timedelta(minutes=pending_min),
        _RUNNING: timedelta(minutes=running_min),
    }


class ScanJobRepository:
    """Repository for ScanJob CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, job_type: str = 'scan') -> ScanJob:
        """Create a new job of ``job_type`` ('scan' | 'enrichment') in 'pending' state."""
        job = ScanJob(
            id=str(uuid.uuid4()),
            job_type=job_type,
            status=_PENDING,
            created_at=_utcnow(),
        )
        self.session.add(job)
        self.session.flush()
        return job

    def get_by_id(self, job_id: str) -> Optional[ScanJob]:
        """Get a scan job by ID."""
        return self.session.get(ScanJob, job_id)

    def _stale_candidates(self) -> list:
        """Active jobs past their staleness cutoff, based on current state."""
        cutoffs = _stale_cutoffs()
        now = _utcnow()
        stale = []
        for job in self.session.scalars(
            select(ScanJob).where(ScanJob.status.in_([_PENDING, _RUNNING]))
        ):
            anchor = job.created_at if job.status == _PENDING else (job.started_at or job.created_at)
            if anchor is not None and now - anchor > cutoffs[job.status]:
                stale.append(job)
        return stale

    def _reap_one(self, job: ScanJob) -> bool:
        """Fail one stale job, only if nothing moved it since we looked.

        The WHERE repeats the status and the timestamp that made the job
        stale, so a concurrent transition (start, terminal write) makes the
        UPDATE match zero rows instead of being overwritten — a completed
        job keeps its result, and a job another session just started keeps
        its active slot. Returns True when this session did the reaping.
        """
        now = _utcnow()
        if job.status == _PENDING or job.started_at is None:
            anchor_col, anchor = ScanJob.created_at, job.created_at
        else:
            anchor_col, anchor = ScanJob.started_at, job.started_at
        stmt = (
            update(ScanJob)
            .where(
                ScanJob.id == job.id,
                ScanJob.status == job.status,
                anchor_col == anchor,
            )
            .values(
                status=_FAILED,
                finished_at=now,
                result_summary=json.dumps(
                    {"error": f"job reaped: stuck in '{job.status}' past the staleness cutoff"}
                ),
            )
            .execution_options(synchronize_session=False)
        )
        return self.session.execute(stmt).rowcount == 1

    def reap_stale(self) -> int:
        """Mark active jobs past their staleness cutoff as failed.

        Covers jobs orphaned by a process crash/restart between POST and
        background-task execution, and jobs whose 'running' mark failed. The
        single-flight unique index counts `pending`/`running` rows, so an
        orphaned row would otherwise 409 every future request of that type
        forever. Executes immediately (no commit) — the caller owns the
        transaction.
        """
        reaped = 0
        for job in self._stale_candidates():
            if self._reap_one(job):
                reaped += 1
        if reaped:
            self.session.flush()
        return reaped

    def update_status(
        self,
        job: ScanJob,
        status: str,
        result_summary: Optional[Dict[str, Any]] = None,
    ) -> ScanJob:
        """Update job status, enforcing the lifecycle transition table.

        Terminal states are final: re-driving a completed/failed job raises
        ValueError instead of silently resetting timestamps. The write is
        conditional on the row still holding the expected status — a
        concurrent reap (or start) between load and write makes the UPDATE
        match zero rows, and we raise instead of overwriting their change.
        """
        if job.status == status == _RUNNING:
            return job  # idempotent re-mark
        if status not in _ALLOWED_TRANSITIONS.get(job.status, set()):
            raise ValueError(f"invalid ScanJob transition: {job.status!r} -> {status!r}")
        expected = job.status
        values: Dict[str, Any] = {"status": status}
        if status == _RUNNING:
            values["started_at"] = _utcnow()
        elif status in (_COMPLETED, _FAILED):
            values["finished_at"] = _utcnow()
        if result_summary is not None:
            values["result_summary"] = json.dumps(result_summary)
        stmt = (
            update(ScanJob)
            .where(ScanJob.id == job.id, ScanJob.status == expected)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if self.session.execute(stmt).rowcount != 1:
            raise ValueError(
                f"ScanJob {job.id} changed concurrently: expected status {expected!r}"
            )
        for key, value in values.items():
            setattr(job, key, value)
        return job

    def get_active_job(self, job_type: str = 'scan') -> Optional[ScanJob]:
        """Return the first ``job_type`` job in 'pending' or 'running' state, or None.

        Single-flight is per job type: an enrichment run never blocks a scan.
        Stale orphaned jobs are reaped to 'failed' first so they can't block
        single-flight forever.
        """
        self.reap_stale()
        stmt = select(ScanJob).where(
            ScanJob.job_type == job_type,
            ScanJob.status.in_([_PENDING, _RUNNING]),
        ).order_by(ScanJob.created_at)
        return self.session.scalar(stmt)
