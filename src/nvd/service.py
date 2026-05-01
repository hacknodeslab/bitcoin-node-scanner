"""NVD vulnerability service — cache logic and database interaction."""
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import select, text
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..db.models import CVEEntry as CVEEntryModel
from .client import NVDClient
from .models import CVEEntry, NVDAPIError

logger = logging.getLogger(__name__)

_DEFAULT_TTL_HOURS = 24


class NVDService:
    """Manages fetching and caching of Bitcoin CVE data from NVD."""

    def __init__(self, session: Session):
        self._session = session
        ttl_hours = int(os.getenv("NVD_CACHE_TTL_HOURS", str(_DEFAULT_TTL_HOURS)))
        self._ttl = timedelta(hours=ttl_hours)

    def get_vulnerabilities(self) -> List[CVEEntryModel]:
        """
        Return Bitcoin CVE entries from the database cache.

        If the cache is empty or stale (older than TTL), a fresh fetch from
        the NVD API is performed first.

        Returns a list of CVEEntryModel objects sorted by cvss_score DESC
        (NULLs last).

        Raises NVDAPIError if the upstream is unreachable and the cache is empty.
        """
        if self._is_cache_stale():
            logger.info("NVD cache is empty or stale — fetching fresh data")
            self._refresh()

        return self._fetch_sorted()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_cache_stale(self) -> bool:
        """Return True if the cache is empty or the most recent fetch is past TTL."""
        result = self._session.execute(
            select(CVEEntryModel.fetched_at)
            .order_by(CVEEntryModel.fetched_at.desc())
            .limit(1)
        ).scalar_one_or_none()

        if result is None:
            return True  # cache is empty

        # Make both datetimes naive UTC for comparison
        last_fetched: datetime = result
        if last_fetched.tzinfo is not None:
            last_fetched = last_fetched.astimezone(timezone.utc).replace(tzinfo=None)

        return datetime.utcnow() - last_fetched > self._ttl

    def _refresh(self) -> None:
        """Fetch fresh CVE data from NVD and upsert into the database."""
        client = NVDClient()
        entries: List[CVEEntry] = client.fetch_bitcoin_cves()

        # Snapshot existing affected_versions hashes so we can detect changes.
        previous = {
            row[0]: row[1]
            for row in self._session.execute(
                select(CVEEntryModel.cve_id, CVEEntryModel.affected_versions)
            ).all()
        }

        now = datetime.utcnow()
        stored = 0
        changed_cves = 0
        for entry in entries:
            if not entry.affected_versions:
                # Defensive: client should already have skipped non-Bitcoin-Core CVEs
                continue
            new_affected_json = json.dumps(entry.affected_versions)
            prev_affected = previous.get(entry.cve_id)
            if prev_affected is None or prev_affected != new_affected_json:
                changed_cves += 1

            stmt = sqlite_insert(CVEEntryModel).values(
                cve_id=entry.cve_id,
                published=entry.published,
                last_modified=entry.last_modified,
                severity=entry.severity,
                cvss_score=entry.cvss_score,
                description=entry.description,
                affected_versions=new_affected_json,
                fetched_at=now,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id"],
                set_={
                    "published": stmt.excluded.published,
                    "last_modified": stmt.excluded.last_modified,
                    "severity": stmt.excluded.severity,
                    "cvss_score": stmt.excluded.cvss_score,
                    "description": stmt.excluded.description,
                    "affected_versions": stmt.excluded.affected_versions,
                    "fetched_at": stmt.excluded.fetched_at,
                },
            )
            self._session.execute(stmt)
            stored += 1

        self._session.commit()
        logger.info("NVD cache refreshed: %d entries stored, %d new/changed", stored, changed_cves)

        if changed_cves and os.getenv("NVD_AUTO_RELINK", "true").lower() in {"1", "true", "yes"}:
            self._relink_all_nodes()

    def _relink_all_nodes(self) -> None:
        """Rebuild node_vulnerabilities for every node using the refreshed catalog."""
        from ..db.models import Node
        from ..db.repositories import VulnerabilityRepository
        from .matcher import CVEMatcher

        entries = list(self._session.scalars(select(CVEEntryModel)).all())
        matcher = CVEMatcher(entries)
        vuln_repo = VulnerabilityRepository(self._session)

        added = resolved = is_vuln_changed = 0
        nodes = list(self._session.scalars(select(Node)).all())
        for node in nodes:
            expected = matcher.matches_for(node.version)
            a, r = vuln_repo.sync_node_links(node, expected)
            added += a
            resolved += r
            desired = bool(expected)
            if node.is_vulnerable != desired:
                node.is_vulnerable = desired
                is_vuln_changed += 1
        self._session.commit()
        logger.info(
            "Auto-relink complete: %d nodes processed, %d links added, %d resolved, %d is_vulnerable updated",
            len(nodes), added, resolved, is_vuln_changed,
        )

    def _fetch_sorted(self) -> List[CVEEntryModel]:
        """Return all cached CVE entries sorted by cvss_score DESC, NULLs last."""
        stmt = (
            select(CVEEntryModel)
            .order_by(
                CVEEntryModel.cvss_score.is_(None),   # NULLs last
                CVEEntryModel.cvss_score.desc(),
            )
        )
        return list(self._session.execute(stmt).scalars().all())
