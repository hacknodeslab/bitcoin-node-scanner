"""Persistent per-source daily quota for enrichment APIs.

Counts live in `enrichment_quota` (one row per source per UTC day) so the
budget is shared by CLI and API runs and survives restarts — unlike the
in-memory `credit_tracker.py`, a crashed or repeated run cannot re-spend it.
Each consumed call is committed immediately, and increments are atomic SQL
updates so concurrent runs neither lose counts nor collide on the day's row.
"""
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from sqlalchemy import case, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db.models import EnrichmentQuota


def _today_utc() -> str:
    return datetime.now(timezone.utc).date().isoformat()


class DailyQuota:
    """Daily call budget for one source, plus a minimum gap between calls."""

    def __init__(
        self,
        session: Session,
        source: str,
        limit: int,
        min_interval: float = 0.0,
        today: Callable[[], str] = _today_utc,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.session = session
        self.source = source
        self.limit = limit
        self.min_interval = min_interval
        self._today = today
        self._clock = clock
        self._sleep = sleep
        self._last_call: Optional[float] = None

    def _row(self, day: str) -> Optional[EnrichmentQuota]:
        row = self.session.scalar(
            select(EnrichmentQuota).where(
                EnrichmentQuota.source == self.source, EnrichmentQuota.day_utc == day
            )
        )
        if row is not None:
            self.session.refresh(row)  # see other processes' commits
        return row

    def _ensure_row(self, day: str) -> None:
        """Create the day's row if missing; a concurrent insert is not an error."""
        if self._row(day) is not None:
            return
        try:
            self.session.add(EnrichmentQuota(source=self.source, day_utc=day, calls=0, exhausted=False))
            self.session.commit()
        except IntegrityError:
            # Another run created it first. Nothing else is pending here: the
            # service commits reputation writes per chunk, before quota calls.
            self.session.rollback()

    def _update(self, day: str, *where, **values) -> int:
        stmt = (
            update(EnrichmentQuota)
            .where(EnrichmentQuota.source == self.source, EnrichmentQuota.day_utc == day, *where)
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        return self.session.execute(stmt).rowcount

    def used(self) -> int:
        row = self._row(self._today())
        return row.calls if row else 0

    def remaining(self) -> int:
        row = self._row(self._today())
        if row is None:
            return self.limit
        if row.exhausted:
            return 0
        return max(0, self.limit - row.calls)

    def consume(self) -> bool:
        """Reserve one call: throttle, atomically increment, commit. False when none left."""
        if self.remaining() <= 0:
            return False
        if self._last_call is not None and self.min_interval > 0:
            wait = self.min_interval - (self._clock() - self._last_call)
            if wait > 0:
                self._sleep(wait)
        day = self._today()
        self._ensure_row(day)
        # Conditional increment: two runs racing for the last slot can't both win.
        won = self._update(
            day,
            EnrichmentQuota.exhausted.is_(False),
            EnrichmentQuota.calls < self.limit,
            calls=EnrichmentQuota.calls + 1,
        ) == 1
        self.session.commit()
        if won:
            self._last_call = self._clock()
        return won

    def mark_exhausted(self) -> None:
        """The server said the day's budget is gone (e.g. HTTP 429)."""
        day = self._today()
        self._ensure_row(day)
        self._update(day, exhausted=True)
        self.session.commit()

    def sync_remaining(self, server_remaining: int) -> None:
        """Lower our counter's headroom if the server reports less than we think."""
        floor = self.limit - server_remaining
        if floor <= self.used():
            return
        day = self._today()
        self._ensure_row(day)
        self._update(
            day,
            calls=case((EnrichmentQuota.calls < floor, floor), else_=EnrichmentQuota.calls),
        )
        self.session.commit()
