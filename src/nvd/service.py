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

        now = datetime.utcnow()
        for entry in entries:
            stmt = sqlite_insert(CVEEntryModel).values(
                cve_id=entry.cve_id,
                published=entry.published,
                last_modified=entry.last_modified,
                severity=entry.severity,
                cvss_score=entry.cvss_score,
                description=entry.description,
                affected_versions=json.dumps(entry.affected_versions),
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

        self._session.commit()
        logger.info("NVD cache refreshed: %d entries stored", len(entries))

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
