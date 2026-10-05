"""Orchestrates passive IP-reputation enrichment.

Selects candidate IPs (never example IPs), runs every available enricher in
chunks, isolates per-source failures, and upserts one `ip_reputation` row
per IP. Commits after each chunk so a long AbuseIPDB run that dies midway
keeps what it already paid for.
"""
import logging
import os
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy.orm import Session

from ..db.models import _utcnow
from ..db.repositories import ReputationRepository
from ..example_ips import is_example_ip
from . import REGISTRY, Enricher

logger = logging.getLogger(__name__)

CHUNK_SIZE = 50


def stale_days_from_env() -> int:
    try:
        return max(1, int(os.getenv("REPUTATION_STALE_DAYS", "7")))
    except ValueError:
        return 7


def build_enrichers(session: Session, source: Optional[str] = None) -> List[Enricher]:
    """Instantiate registered enrichers, optionally just one by name."""
    if source is not None and source not in REGISTRY:
        raise ValueError(f"unknown enrichment source: {source}")
    names = [source] if source else list(REGISTRY)
    return [REGISTRY[name](session) for name in names]


def _new_stats(enrichers: Sequence[Enricher]) -> Dict[str, Any]:
    return {
        "ips_processed": 0,
        "ips_skipped_example": 0,
        "sources": {e.name: {"ok": 0, "error": 0, "unavailable": False} for e in enrichers},
    }


def _partition(enrichers: Sequence[Enricher], stats: Dict[str, Any]) -> List[Enricher]:
    """Return the available enrichers; log each unavailable one once."""
    active: List[Enricher] = []
    for enricher in enrichers:
        if enricher.available():
            active.append(enricher)
        else:
            logger.info("enricher unavailable: %s", enricher.name)
            stats["sources"][enricher.name]["unavailable"] = True
    return active


def _enrich(
    session: Session,
    ips: Sequence[str],
    active: Sequence[Enricher],
    due: Optional[Dict[str, Sequence[str]]],
    stats: Dict[str, Any],
) -> None:
    repo = ReputationRepository(session)
    targets = [ip for ip in ips if not is_example_ip(ip)]
    stats["ips_skipped_example"] = len(ips) - len(targets)
    if not active or not targets:
        return

    for start in range(0, len(targets), CHUNK_SIZE):
        chunk = targets[start:start + CHUNK_SIZE]
        per_ip: Dict[str, Dict[str, Dict[str, Any]]] = {ip: {} for ip in chunk}

        for enricher in active:
            # Only IPs this source still owes (a quota-bound source must not be
            # re-spent on IPs it already covers).
            batch = [ip for ip in chunk if due is None or enricher.name in due.get(ip, ())]
            # Re-check: a source can run out mid-run (quota, 429, bad key).
            if not batch or not enricher.available():
                continue
            try:
                results = enricher.enrich(batch)
            except Exception as exc:  # isolate one source's failure
                logger.warning("enricher %s failed: %s", enricher.name, exc)
                results = {ip: {"status": "error", "error": str(exc)} for ip in batch}
            for ip, result in results.items():
                if ip in per_ip:
                    per_ip[ip][enricher.name] = result

        now = _utcnow()
        for ip, by_source in per_ip.items():
            if not by_source:
                continue  # nothing attempted for this IP (quota) — stays pending
            sources: Dict[str, Dict[str, Any]] = {}
            fields: Dict[str, Any] = {}
            any_ok = False
            for name, result in by_source.items():
                status = result.get("status", "error")
                entry: Dict[str, Any] = {"status": status, "fetched_at": now.isoformat()}
                if result.get("data") is not None:
                    entry["data"] = result["data"]
                if status == "ok":
                    any_ok = True
                    fields.update(result.get("fields") or {})
                    if result.get("partial"):
                        # Usable but incomplete (e.g. one list unavailable):
                        # keep the data, leave the source due for a retry.
                        entry["status"] = "partial"
                    else:
                        # Per-source success marker; errored/partial stay due.
                        fields[f"{name}_checked_at"] = now
                    stats["sources"][name]["ok"] += 1
                else:
                    entry["error"] = result.get("error")
                    stats["sources"][name]["error"] += 1
                sources[name] = entry
            repo.upsert(ip, sources, fields, enriched_at=now if any_ok else None)
            stats["ips_processed"] += 1
        session.commit()


def enrich_ips(
    session: Session,
    ips: Sequence[str],
    enrichers: Sequence[Enricher],
    due: Optional[Dict[str, Sequence[str]]] = None,
) -> Dict[str, Any]:
    """Enrich ``ips`` with ``enrichers`` and persist the results.

    ``due`` maps ip → source names still owed; None means every source.
    """
    stats = _new_stats(enrichers)
    _enrich(session, ips, _partition(enrichers, stats), due, stats)
    return stats


def run_enrichment(
    session: Session,
    limit: Optional[int] = None,
    source: Optional[str] = None,
    stale_days: Optional[int] = None,
    enrichers: Optional[Sequence[Enricher]] = None,
) -> Dict[str, Any]:
    """Select candidates (highest risk first) for the available sources and enrich them."""
    stale = stale_days if stale_days is not None else stale_days_from_env()
    if enrichers is None:
        enrichers = build_enrichers(session, source)
    stats = _new_stats(enrichers)
    active = _partition(enrichers, stats)
    candidates = ReputationRepository(session).candidates(
        limit, stale, [e.name for e in active]
    )
    ips = [ip for ip, _ in candidates]
    _enrich(session, ips, active, dict(candidates), stats)
    stats["candidates"] = len(ips)
    stats["quota_remaining"] = {
        e.name: e.quota.remaining() for e in enrichers if getattr(e, "quota", None) is not None
    }
    return stats
