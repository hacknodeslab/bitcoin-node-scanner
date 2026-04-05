"""NVD REST API v2 client for fetching Bitcoin-related CVE entries."""
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from .models import CVEEntry, NVDAPIError

logger = logging.getLogger(__name__)

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RESULTS_PER_PAGE = 2000
# Public rate limit: 5 requests / 30s → 0.6s minimum gap
_PUBLIC_DELAY_SECONDS = 0.6


class NVDClient:
    """Fetches Bitcoin CVE data from the NVD REST API v2."""

    def __init__(self, timeout: int = 30):
        self._api_key: Optional[str] = os.getenv("NVD_API_KEY")
        self._timeout = timeout

    def fetch_bitcoin_cves(self) -> List[CVEEntry]:
        """
        Fetch all CVE entries related to Bitcoin from the NVD API.

        Handles pagination automatically. Inserts a rate-limit-safe delay
        between requests when no API key is configured.

        Returns a list of CVEEntry instances.
        Raises NVDAPIError on HTTP errors or network timeouts.
        """
        entries: List[CVEEntry] = []
        start_index = 0
        first_request = True

        while True:
            if not first_request and not self._api_key:
                time.sleep(_PUBLIC_DELAY_SECONDS)
            first_request = False

            params: Dict[str, Any] = {
                "keywordSearch": "bitcoin",
                "resultsPerPage": _RESULTS_PER_PAGE,
                "startIndex": start_index,
            }
            headers: Dict[str, str] = {}
            if self._api_key:
                headers["apiKey"] = self._api_key

            try:
                response = requests.get(_NVD_API_URL, params=params, headers=headers, timeout=self._timeout)
            except requests.Timeout:
                raise NVDAPIError(
                    f"Request to NVD API timed out after {self._timeout}s"
                )
            except requests.RequestException as exc:
                raise NVDAPIError(f"Network error contacting NVD API: {exc}")

            if response.status_code != 200:
                raise NVDAPIError(
                    f"NVD API returned HTTP {response.status_code}: {response.text[:200]}",
                    status_code=response.status_code,
                )

            data = response.json()
            total_results: int = data.get("totalResults", 0)
            vulnerabilities: List[Dict] = data.get("vulnerabilities", [])

            for item in vulnerabilities:
                entry = self._map_cve(item.get("cve", {}))
                if entry:
                    entries.append(entry)

            start_index += len(vulnerabilities)
            logger.debug(
                "NVD fetch: retrieved %d/%d entries", start_index, total_results
            )

            if start_index >= total_results or not vulnerabilities:
                break

        return entries

    def _map_cve(self, cve: Dict) -> Optional[CVEEntry]:
        """Map a raw NVD CVE dict to a CVEEntry dataclass."""
        cve_id: str = cve.get("id", "")
        if not cve_id:
            return None

        # Timestamps
        published = self._parse_dt(cve.get("published"))
        last_modified = self._parse_dt(cve.get("lastModified"))

        # Description (English preferred)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS score and severity — prefer v3.1, then v3.0, then v2
        severity = "UNKNOWN"
        cvss_score: Optional[float] = None

        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                base_score = cvss_data.get("baseScore")
                base_severity = cvss_data.get("baseSeverity")
                # cvssMetricV2 stores severity under exploitabilityScore; check both
                if base_severity is None:
                    base_severity = metric_list[0].get("baseSeverity")
                if base_score is not None:
                    cvss_score = float(base_score)
                if base_severity:
                    severity = base_severity.upper()
                break

        # Affected versions from CPE matches
        affected_versions: List[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    if "bitcoin" in cpe.lower():
                        affected_versions.append(cpe)

        return CVEEntry(
            cve_id=cve_id,
            published=published,
            last_modified=last_modified,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
            affected_versions=list(dict.fromkeys(affected_versions)),  # deduplicate, preserve order
        )

    @staticmethod
    def _parse_dt(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value[:26], fmt)
            except ValueError:
                continue
        return None
