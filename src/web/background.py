"""
Background job executor for the web interface.

Runs Bitcoin Node Scanner scans and IP-reputation enrichment batches in a thread pool so that the HTTP layer
stays responsive during long-running scans.
"""
import asyncio
import logging
from typing import Callable, Optional

from sqlalchemy.orm import Session

from ..db.connection import get_session_factory
from ..db.repositories import ScanJobRepository

logger = logging.getLogger(__name__)


def _execute_scan() -> dict:
    """
    Run the scanner synchronously and return a result summary dict.

    Called inside a ThreadPoolExecutor so it must not use async primitives.
    """
    from ..db.scanner_integration import create_db_scanner

    scanner = create_db_scanner(use_optimized=False)
    scanner.run_full_scan()

    stats = scanner.generate_statistics()
    risk_dist = stats.get("risk_distribution", {})

    return {
        "total_nodes": stats.get("total_results", 0),
        "critical": risk_dist.get("CRITICAL", 0),
        "high": risk_dist.get("HIGH", 0),
        "medium": risk_dist.get("MEDIUM", 0),
        "low": risk_dist.get("LOW", 0),
        "vulnerable": stats.get("vulnerable_nodes", 0),
    }


def _update_job_status(job_id: str, status: str, summary: Optional[dict]) -> None:
    """Update a scan job status synchronously (safe to call from any thread)."""
    factory = get_session_factory()
    if factory is None:
        return
    session = factory()
    try:
        repo = ScanJobRepository(session)
        job = repo.get_by_id(job_id)
        if job is not None:
            repo.update_status(job, status, result_summary=summary)
            session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _mark_failed_best_effort(job_id: str, kind: str, error: str) -> None:
    """Try to record a terminal 'failed' state; never raise from here."""
    try:
        _update_job_status(job_id, "failed", {"error": error})
    except Exception:
        logger.exception("Could not mark %s job %s as failed.", kind, job_id)


async def _record_terminal_status(job_id: str, kind: str, status: str,
                                  summary: Optional[dict]) -> None:
    """Write the terminal status with a few retries, then give up to the reaper.

    A transient failure (e.g. 'database is locked' on SQLite) must not leave
    the job 'running' for the whole running-staleness cutoff, blocking new
    jobs of its type with 409s — so retry briefly with backoff. If all
    attempts fail, log; ScanJobRepository.reap_stale cleans the residue.
    """
    for attempt in range(3):
        try:
            _update_job_status(job_id, status, summary)
            return
        except Exception:
            if attempt == 2:
                logger.exception(
                    "%s job %s: could not record terminal status after 3 attempts",
                    kind, job_id,
                )
                return
            await asyncio.sleep(2 ** attempt)


async def _run_job(job_id: str, kind: str, work: Callable[[], dict]) -> None:
    """Mark the job running, execute ``work`` in a thread pool, record the outcome."""
    factory = get_session_factory()
    if factory is None:
        logger.error("Cannot run %s job %s: DATABASE_URL not configured.", kind, job_id)
        return

    # Mark as running. If this fails the job must NOT be left 'pending'
    # forever — the single-flight unique index would reject every future job
    # of this type — so record 'failed' best-effort and bail.
    try:
        _update_job_status(job_id, "running", None)
    except Exception as exc:
        logger.exception("%s job %s could not start: %s", kind.capitalize(), job_id, exc)
        _mark_failed_best_effort(job_id, kind, f"could not mark job running: {exc}")
        return

    # Run in a thread so the async event loop is not blocked
    loop = asyncio.get_event_loop()
    result_summary: Optional[dict] = None
    error_summary: Optional[dict] = None

    try:
        result_summary = await loop.run_in_executor(None, work)
    except Exception as exc:
        logger.exception("%s job %s failed: %s", kind.capitalize(), job_id, exc)
        error_summary = {"error": str(exc)}

    if error_summary:
        await _record_terminal_status(job_id, kind, "failed", error_summary)
    else:
        await _record_terminal_status(job_id, kind, "completed", result_summary)


async def run_scan_job(job_id: str) -> None:
    """
    FastAPI BackgroundTask entry point.

    Updates job status to 'running', executes the scan in a thread pool
    (so the event loop is not blocked), then marks the job 'completed'
    or 'failed'.
    """
    await _run_job(job_id, "scan", _execute_scan)


def _run_with_session(work: Callable[[Session], dict]) -> dict:
    """Open a session, run ``work`` in it, commit on success, roll back on error."""
    factory = get_session_factory()
    session = factory()
    try:
        result = work(session)
        session.commit()
        return result
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _execute_enrichment(limit: int, source: Optional[str]) -> dict:
    """Run one bounded IP-reputation enrichment batch in its own session."""
    from ..enrichers.service import run_enrichment

    return _run_with_session(lambda session: run_enrichment(session, limit=limit, source=source))


async def run_enrichment_job(job_id: str, limit: int, source: Optional[str] = None) -> None:
    """FastAPI BackgroundTask entry point for `POST /api/v1/enrichment/run`."""
    await _run_job(job_id, "enrichment", lambda: _execute_enrichment(limit, source))


def _execute_geo_enrichment() -> dict:
    """Retroactive MaxMind geo enrichment over all nodes (mirrors CLI `enrich-geo`)."""
    import os

    from ..db.geo_enrichment import enrich_nodes_geo
    from ..geoip import GeoIPService

    db_dir = os.getenv("GEOIP_DB_DIR", "./geoip_dbs")
    geoip = GeoIPService(db_dir=db_dir)
    try:
        # Trigger lazy init up front so a missing .mmdb fails the job fast
        # instead of iterating the whole node table for nothing.
        geoip._init_readers()
        if not geoip._available:
            raise RuntimeError(
                f"MaxMind GeoLite2 databases not found in '{db_dir}'. "
                "Run scripts/download_geoip_dbs.sh to download them."
            )

        # Batch loop + gap-filling precedence shared with the CLI — see
        # src/db/geo_enrichment.py.
        summary = _run_with_session(lambda session: enrich_nodes_geo(session, geoip))
        return {"kind": "geo", **summary}
    finally:
        geoip.close()


async def run_geo_enrichment_job(job_id: str) -> None:
    """FastAPI BackgroundTask entry point for `POST /api/v1/enrich-geo`."""
    await _run_job(job_id, "geo-enrichment", _execute_geo_enrichment)
