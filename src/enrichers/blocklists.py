"""Public IP blocklists matched locally.

Lists are downloaded in bulk, cached on disk (same pattern as
`src/nostr/cdn_ranges.py`), and matched by CIDR in memory. No node IP is
ever sent to a third party, and there is no quota.

Terms: FireHOL level1 aggregates freely redistributable lists; Spamhaus DROP
is free to use but some commercial use requires a Spamhaus agreement — drop
`spamhaus_drop` from BLOCKLISTS if that applies; abuse.ch Feodo Tracker is
CC0; the Tor bulk exit list is public.
"""
import bisect
import ipaddress
import logging
import os
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple, Union

import requests

from . import SourceResult

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 24 * 3600
_Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
USER_AGENT = "bitcoin-node-scanner (HackNodes passive recon)"


@dataclass(frozen=True)
class BlocklistSpec:
    id: str
    urls: Tuple[str, ...]


BLOCKLISTS: Dict[str, BlocklistSpec] = {
    spec.id: spec for spec in (
        BlocklistSpec("firehol_level1", (
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        )),
        BlocklistSpec("spamhaus_drop", (
            "https://www.spamhaus.org/drop/drop.txt",
            "https://www.spamhaus.org/drop/dropv6.txt",
        )),
        BlocklistSpec("feodo", ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt",)),
        BlocklistSpec("tor_exit", ("https://check.torproject.org/torbulkexitlist",)),
    )
}


def cache_dir() -> str:
    return os.getenv("BLOCKLIST_CACHE_DIR", ".blocklist_cache")


def enabled_ids() -> List[str]:
    """List ids from BLOCKLISTS (comma-separated), default all; unknown ids dropped."""
    raw = os.getenv("BLOCKLISTS")
    if raw is None:
        return list(BLOCKLISTS)
    ids = [i.strip() for i in raw.split(",") if i.strip()]
    unknown = [i for i in ids if i not in BLOCKLISTS]
    if unknown:
        logger.warning("ignoring unknown blocklist ids: %s", ", ".join(unknown))
    return [i for i in ids if i in BLOCKLISTS]


def parse_networks(text: str) -> List[_Network]:
    """Parse one CIDR/IP per line; `#` and `;` start comments; junk is skipped."""
    nets = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line.split()[0], strict=False))
        except ValueError:
            continue
    return nets


def _looks_valid(text: str) -> bool:
    """Reject empty bodies and HTML error pages. An empty-but-commented list is valid."""
    stripped = text.lstrip()
    return bool(stripped) and not stripped.startswith("<")


class _Matcher:
    """Sorted, merged integer ranges per address family; bisect lookup."""

    def __init__(self, nets: Sequence[_Network]):
        self._ranges: Dict[int, Tuple[List[int], List[int]]] = {}
        by_family: Dict[int, List[Tuple[int, int]]] = {4: [], 6: []}
        for net in nets:
            by_family[net.version].append(
                (int(net.network_address), int(net.broadcast_address))
            )
        for family, spans in by_family.items():
            spans.sort()
            starts: List[int] = []
            ends: List[int] = []
            for lo, hi in spans:
                if ends and lo <= ends[-1] + 1:
                    ends[-1] = max(ends[-1], hi)
                else:
                    starts.append(lo)
                    ends.append(hi)
            self._ranges[family] = (starts, ends)

    def __contains__(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        starts, ends = self._ranges[addr.version]
        i = bisect.bisect_right(starts, int(addr)) - 1
        return i >= 0 and int(addr) <= ends[i]


class BlocklistEnricher:
    name = "blocklists"

    def __init__(
        self,
        list_ids: Sequence[str],
        fetch: Optional[Callable[[str], str]] = None,
        now: Callable[[], float] = time.time,
    ):
        self.list_ids = list(list_ids)
        self._fetch = fetch or self._http_get
        self._now = now
        self._matchers: Optional[Dict[str, _Matcher]] = None
        self.failed: List[str] = []

    @classmethod
    def from_env(cls) -> "BlocklistEnricher":
        return cls(enabled_ids())

    def available(self) -> bool:
        return bool(self.list_ids)

    @staticmethod
    def _http_get(url: str) -> str:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        return resp.text

    def _cache_path(self, list_id: str, index: int) -> str:
        return os.path.join(cache_dir(), f"{list_id}.{index}.txt")

    def _load_url(self, list_id: str, index: int, url: str) -> str:
        """Fresh cache → cache; else fetch; on fetch failure fall back to a stale cache."""
        path = self._cache_path(list_id, index)
        cached: Optional[str] = None
        if os.path.exists(path):
            with open(path) as f:
                cached = f.read()
            if not _looks_valid(cached):
                cached = None
            elif self._now() - os.path.getmtime(path) < CACHE_TTL_SECONDS:
                return cached
        try:
            text = self._fetch(url)
            if not _looks_valid(text):
                raise ValueError("empty or non-list payload")
        except Exception as exc:
            if cached is not None:
                logger.warning("blocklist %s refresh failed (%s); using stale cache", list_id, exc)
                return cached
            raise
        os.makedirs(cache_dir(), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, path)
        return text

    def _load(self) -> Dict[str, _Matcher]:
        if self._matchers is not None:
            return self._matchers
        matchers: Dict[str, _Matcher] = {}
        self.failed = []
        for list_id in self.list_ids:
            spec = BLOCKLISTS[list_id]
            try:
                nets: List[_Network] = []
                for i, url in enumerate(spec.urls):
                    nets.extend(parse_networks(self._load_url(list_id, i, url)))
                matchers[list_id] = _Matcher(nets)
            except Exception as exc:
                logger.warning("blocklist %s unavailable: %s", list_id, exc)
                self.failed.append(list_id)
        if not matchers:
            raise RuntimeError("no blocklist could be loaded")
        self._matchers = matchers
        return matchers

    def enrich(self, ips: Sequence[str]) -> Dict[str, SourceResult]:
        matchers = self._load()
        checked = list(matchers)
        results: Dict[str, SourceResult] = {}
        # Some configured lists failed with no usable cache: keep the hits we
        # have, but flag the result partial so the source stays due for a retry.
        partial = bool(self.failed)
        for ip in ips:
            hits = [list_id for list_id, m in matchers.items() if ip in m]
            results[ip] = {
                "status": "ok",
                "partial": partial,
                "fields": {"blocklists": hits},
                "data": {"lists_checked": checked, "lists_failed": list(self.failed)},
            }
        return results
