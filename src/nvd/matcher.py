"""In-memory matcher between Bitcoin Core versions and NVD CVE entries."""
import json
import logging
import re
from typing import Iterable, List, Optional, Set, Tuple

from ..db.models import CVEEntry as CVEEntryModel
from ..utils import parse_version_number

logger = logging.getLogger(__name__)

VersionTuple = Tuple[int, int, int]

# NVD frequently expresses Bitcoin Core versions in short form ("25.0", "30")
# meaning "25.0.0" / "30.0.0". The strict 3-component regex in
# `parse_version_number` would reject those, so we fall back to a permissive
# matcher that pads missing components with zero.
_TWO_COMPONENT_RE = re.compile(r"^\s*(\d{1,10})\.(\d{1,10})\s*$")
_ONE_COMPONENT_RE = re.compile(r"^\s*(\d{1,10})\s*$")


def _parse_version(value: Optional[str]) -> Optional[VersionTuple]:
    if not value or value in ("*", "-"):
        return None

    # Strict three-component first (handles "0.21.0", "Satoshi:0.18.0" etc.)
    parsed = parse_version_number(value)
    if parsed is not None and len(parsed) == 3:
        return parsed  # type: ignore[return-value]

    # NVD short forms: "25.0" → (25, 0, 0); "30" → (30, 0, 0)
    m2 = _TWO_COMPONENT_RE.match(value)
    if m2:
        return (int(m2.group(1)), int(m2.group(2)), 0)
    m1 = _ONE_COMPONENT_RE.match(value)
    if m1:
        return (int(m1.group(1)), 0, 0)
    return None


_BITCOIN_CORE_PRODUCTS = {
    ("bitcoin", "bitcoin"),
    ("bitcoin", "bitcoin_core"),
    ("bitcoincore", "bitcoin_core"),
}


def _legacy_cpe_to_dict(cpe: str) -> Optional[dict]:
    """Convert a raw CPE 2.3 string from a pre-structured catalog into a dict.

    Filters out non-Bitcoin-Core products in the same way as `NVDClient._parse_cpe_match`.
    A bare `*` version (no range info) is **dropped** rather than treated as a
    catch-all: legacy catalog rows lack the `versionStartIncluding`/`-Excluding`
    metadata, so a `*` would otherwise match every modern Bitcoin Core node
    against every old CVE. Re-fetch the NVD catalog to get structured ranges.
    """
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    if (parts[3].lower(), parts[4].lower()) not in _BITCOIN_CORE_PRODUCTS:
        return None
    version = parts[5]
    if not version or version in ("*", "-"):
        return None
    return {"cpe": cpe, "version": version}


class CVEMatcher:
    """Match Bitcoin Core versions against the cached NVD CVE catalog.

    Built once per scan from the rows in `cve_entries`. Internal indexes:
    - `_exact`: maps an exact version tuple → set of cve_ids that explicitly list it.
    - `_ranges`: list of (cve_id, start_inc, start_exc, end_inc, end_exc) for entries
      with a version range. `None` on a bound means "open".
    Pure catch-all entries (CPE `version=*` with no range) are intentionally
    NOT supported: NVD emits those for ancient CVEs whose data was never
    updated, and treating them as "affects every version" produces a sea of
    false positives against modern nodes. The NVD client filters them at
    refresh time; this builder also rejects them defensively.
    """

    def __init__(self, entries: Iterable[CVEEntryModel]):
        self._exact: dict[VersionTuple, Set[str]] = {}
        self._ranges: list[tuple[str, Optional[VersionTuple], Optional[VersionTuple], Optional[VersionTuple], Optional[VersionTuple]]] = []
        self._build(entries)

    def _build(self, entries: Iterable[CVEEntryModel]) -> None:
        for cve in entries:
            raw = cve.affected_versions
            if not raw:
                continue
            try:
                items = json.loads(raw)
            except (TypeError, ValueError):
                logger.warning("CVEMatcher: could not parse affected_versions for %s", cve.cve_id)
                continue

            for item in items:
                # Backwards-compat: catalogs cached before the structured rewrite
                # store raw CPE 2.3 strings instead of dicts.
                if isinstance(item, str):
                    item = _legacy_cpe_to_dict(item)
                    if item is None:
                        continue
                if not isinstance(item, dict):
                    continue

                raw_version = item.get("version")
                raw_bounds = (
                    item.get("start_inc"),
                    item.get("start_exc"),
                    item.get("end_inc"),
                    item.get("end_exc"),
                )
                has_raw_bound = any(b is not None for b in raw_bounds)
                version = _parse_version(raw_version)
                start_inc = _parse_version(raw_bounds[0])
                start_exc = _parse_version(raw_bounds[1])
                end_inc = _parse_version(raw_bounds[2])
                end_exc = _parse_version(raw_bounds[3])

                has_range = any(b is not None for b in (start_inc, start_exc, end_inc, end_exc))

                if version is not None and not has_range:
                    self._exact.setdefault(version, set()).add(cve.cve_id)
                elif has_range:
                    self._ranges.append((cve.cve_id, start_inc, start_exc, end_inc, end_exc))
                elif raw_version is not None or has_raw_bound:
                    # Entry had specific bounds that we couldn't parse (NVD
                    # short form we don't recognise, etc.). Skip the entry.
                    logger.warning(
                        "CVEMatcher: unparseable bounds for %s (version=%r, bounds=%r) — entry skipped",
                        cve.cve_id, raw_version, raw_bounds,
                    )
                    continue
                else:
                    # No version, no range — pure catch-all. Drop it: see the
                    # class docstring for rationale.
                    logger.debug(
                        "CVEMatcher: dropping catch-all entry for %s", cve.cve_id
                    )
                    continue

    def matches_for(self, version: Optional[str]) -> Set[str]:
        """Return the set of cve_ids that affect this Bitcoin Core version."""
        parsed = _parse_version(version)
        if parsed is None:
            return set()

        result: Set[str] = set()
        result.update(self._exact.get(parsed, set()))
        for cve_id, s_inc, s_exc, e_inc, e_exc in self._ranges:
            if s_inc is not None and parsed < s_inc:
                continue
            if s_exc is not None and parsed <= s_exc:
                continue
            if e_inc is not None and parsed > e_inc:
                continue
            if e_exc is not None and parsed >= e_exc:
                continue
            result.add(cve_id)
        return result

    @property
    def cve_count(self) -> int:
        ids: Set[str] = set()
        for s in self._exact.values():
            ids.update(s)
        for cve_id, *_ in self._ranges:
            ids.add(cve_id)
        return len(ids)
