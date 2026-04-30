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

        # Affected versions from CPE matches — restrict to Bitcoin Core
        affected_versions: List[Dict[str, str]] = []
        seen: set = set()
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    entry = self._parse_cpe_match(cpe_match)
                    if entry is None:
                        continue
                    key = (
                        entry.get("cpe"),
                        entry.get("version", ""),
                        entry.get("start_inc", ""),
                        entry.get("start_exc", ""),
                        entry.get("end_inc", ""),
                        entry.get("end_exc", ""),
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    affected_versions.append(entry)

        if not affected_versions:
            # Not a Bitcoin Core CVE; skip entirely
            return None

        return CVEEntry(
            cve_id=cve_id,
            published=published,
            last_modified=last_modified,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
            affected_versions=affected_versions,
        )

    @staticmethod
    def _parse_cpe_match(cpe_match: Dict) -> Optional[Dict[str, str]]:
        """Convert a raw `cpeMatch` to our structured dict, or None if not Bitcoin Core."""
        cpe = cpe_match.get("criteria", "")
        if not cpe:
            return None

        # CPE 2.3 format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
        parts = cpe.split(":")
        if len(parts) < 6:
            return None
        vendor = parts[3].lower()
        product = parts[4].lower()
        # Accept the modern Bitcoin Core CPE forms used in NVD:
        #   - bitcoin:bitcoin_core (most common since 2020)
        #   - bitcoin:bitcoin (older entries)
        #   - bitcoincore:bitcoin_core (rare alt vendor)
        if (vendor, product) not in {
            ("bitcoin", "bitcoin"),
            ("bitcoin", "bitcoin_core"),
            ("bitcoincore", "bitcoin_core"),
        }:
            return None

        entry: Dict[str, str] = {"cpe": cpe}
        version = parts[5]
        if version and version not in ("*", "-"):
            entry["version"] = version
        for src_key, dst_key in (
            ("versionStartIncluding", "start_inc"),
            ("versionStartExcluding", "start_exc"),
            ("versionEndIncluding", "end_inc"),
            ("versionEndExcluding", "end_exc"),
        ):
            value = cpe_match.get(src_key)
            if value:
                entry[dst_key] = value

        # Reject pure catch-all entries: a CPE with version=* (or `-`) and no
        # range bounds means "affects every version", which NVD often emits
        # for ancient CVEs whose data was never updated. Treating those as
        # catch-alls would mark every modern node as vulnerable to bugs from
        # 2012. Drop them and accept some lost coverage rather than flooding
        # the dashboard with false positives.
        if "version" not in entry and not any(
            k in entry for k in ("start_inc", "start_exc", "end_inc", "end_exc")
        ):
            return None
        return entry

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
