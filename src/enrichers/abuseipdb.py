"""AbuseIPDB v2 `check` enricher.

Per-IP lookup of the abuse confidence score and report history. Note that
each lookup discloses the node IP to AbuseIPDB (a passive third-party
database; nothing is sent to the node itself). Opt-in via ABUSEIPDB_API_KEY.
"""
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Sequence

import requests
from sqlalchemy.orm import Session

from . import SourceResult
from .quota import DailyQuota

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"
USER_AGENT = "bitcoin-node-scanner (HackNodes passive recon)"
MAX_AGE_DAYS = 365
DEFAULT_DAILY_QUOTA = 1000
_KEPT_FIELDS = (
    "abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt",
    "isTor", "isWhitelisted", "usageType",
)


class _QuotaExhausted(Exception):
    pass


class _AuthRejected(Exception):
    pass


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _parse_ts(value: Any) -> Optional[datetime]:
    """ISO-8601 → naive UTC (the schema stores naive UTC)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


class AbuseIPDBEnricher:
    name = "abuseipdb"

    def __init__(
        self,
        quota: DailyQuota,
        api_key: Optional[str],
        timeout: float = 15,
        max_retries: int = 3,
        http: Any = requests,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.quota = quota
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max_retries
        self._http = http
        self._sleep = sleep
        # Set when the key is rejected (401/403): off for the rest of this run.
        self._disabled = False

    @classmethod
    def from_env(cls, session: Session) -> "AbuseIPDBEnricher":
        quota = DailyQuota(
            session,
            cls.name,
            limit=_env_int("ABUSEIPDB_DAILY_QUOTA", DEFAULT_DAILY_QUOTA),
            min_interval=_env_float("ABUSEIPDB_MIN_INTERVAL", 1.0),
        )
        return cls(quota, os.getenv("ABUSEIPDB_API_KEY") or None)

    def available(self) -> bool:
        return bool(self._api_key) and not self._disabled and self.quota.remaining() > 0

    def enrich(self, ips: Sequence[str]) -> Dict[str, SourceResult]:
        results: Dict[str, SourceResult] = {}
        if not self._api_key or self._disabled:
            return results
        for ip in ips:
            try:
                results[ip] = self._lookup(ip)
            except _QuotaExhausted:
                logger.warning("AbuseIPDB quota exhausted; remaining IPs left pending")
                break
            except _AuthRejected as exc:
                # A bad/revoked key fails every IP the same way; stop instead of
                # burning the local quota. Not marked exhausted: a fixed key works
                # again on the next run.
                logger.error("AbuseIPDB rejected the API key (%s); source disabled for this run", exc)
                self._disabled = True
                break
        return results

    def _lookup(self, ip: str) -> SourceResult:
        last_error = "unknown error"
        for attempt in range(self._max_retries):
            if not self.quota.consume():
                raise _QuotaExhausted()
            try:
                resp = self._http.get(
                    API_URL,
                    params={"ipAddress": ip, "maxAgeInDays": MAX_AGE_DAYS},
                    headers={
                        "Key": self._api_key,
                        "Accept": "application/json",
                        "User-Agent": USER_AGENT,
                    },
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                last_error = f"network error: {exc}"
            else:
                remaining = _as_int(resp.headers.get("X-RateLimit-Remaining"))
                if remaining is not None:
                    self.quota.sync_remaining(remaining)
                if resp.status_code == 429:
                    self.quota.mark_exhausted()
                    raise _QuotaExhausted()
                if resp.status_code in (401, 403):
                    raise _AuthRejected(f"HTTP {resp.status_code}")
                if resp.status_code == 200:
                    return self._parse(resp)
                last_error = f"HTTP {resp.status_code}"
                if resp.status_code < 500:
                    break  # 4xx other than 429: retrying won't help
            if attempt < self._max_retries - 1:
                self._sleep(2 ** attempt)
        return {"status": "error", "error": last_error}

    @staticmethod
    def _parse(resp: Any) -> SourceResult:
        try:
            data = (resp.json() or {}).get("data") or {}
        except ValueError:
            return {"status": "error", "error": "invalid JSON response"}
        return {
            "status": "ok",
            "fields": {
                "abuse_confidence_score": _as_int(data.get("abuseConfidenceScore")),
                "abuse_total_reports": _as_int(data.get("totalReports")),
                "abuse_last_reported_at": _parse_ts(data.get("lastReportedAt")),
            },
            "data": {k: data.get(k) for k in _KEPT_FIELDS if k in data},
        }
