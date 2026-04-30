"""In-memory matcher between Bitcoin Core versions and NVD CVE entries."""
import json
import logging
from typing import Iterable, List, Optional, Set, Tuple

from ..db.models import CVEEntry as CVEEntryModel
from ..utils import parse_version_number

logger = logging.getLogger(__name__)

VersionTuple = Tuple[int, int, int]


def _parse_version(value: Optional[str]) -> Optional[VersionTuple]:
    if not value or value in ("*", "-"):
        return None
    parsed = parse_version_number(value)
    if parsed is None:
        return None
    if len(parsed) != 3:
        return None
    return parsed  # type: ignore[return-value]


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
    - `_unbounded`: cve_ids whose only entry is `version=*` with no range; these are
      treated as catch-alls (apply to every parseable version).
    """

    def __init__(self, entries: Iterable[CVEEntryModel]):
        self._exact: dict[VersionTuple, Set[str]] = {}
        self._ranges: list[tuple[str, Optional[VersionTuple], Optional[VersionTuple], Optional[VersionTuple], Optional[VersionTuple]]] = []
        self._unbounded: Set[str] = set()
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

            specific_added = False  # any exact version or range registered
            unbounded_seen = False

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
                version = _parse_version(raw_version)
                start_inc = _parse_version(item.get("start_inc"))
                start_exc = _parse_version(item.get("start_exc"))
                end_inc = _parse_version(item.get("end_inc"))
                end_exc = _parse_version(item.get("end_exc"))

                has_range = any(b is not None for b in (start_inc, start_exc, end_inc, end_exc))

                if version is not None and not has_range:
                    self._exact.setdefault(version, set()).add(cve.cve_id)
                    specific_added = True
                elif has_range:
                    self._ranges.append((cve.cve_id, start_inc, start_exc, end_inc, end_exc))
                    specific_added = True
                elif raw_version is not None:
                    # Version present but unparseable (e.g. CPE version "22.0"
                    # without patch). Skip — neither catch-all nor matchable.
                    continue
                else:
                    # No version, no range — catch-all for the product
                    unbounded_seen = True

            if unbounded_seen and not specific_added:
                self._unbounded.add(cve.cve_id)

    def matches_for(self, version: Optional[str]) -> Set[str]:
        """Return the set of cve_ids that affect this Bitcoin Core version."""
        parsed = _parse_version(version)
        if parsed is None:
            return set()

        result: Set[str] = set(self._unbounded)
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
        ids: Set[str] = set(self._unbounded)
        for s in self._exact.values():
            ids.update(s)
        for cve_id, *_ in self._ranges:
            ids.add(cve_id)
        return len(ids)
