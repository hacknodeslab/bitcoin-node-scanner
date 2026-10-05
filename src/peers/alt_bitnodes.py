"""alt-bitnodes snapshots → an ``--ips``-ready peer list.

alt-bitnodes (https://pesquisa.hacknodes.xyz, repo ``ifuensan/alt-bitnodes``)
publishes a snapshot of every reachable node roughly every 40 minutes. This
module builds the union of the snapshots in the last N days:

1. page through ``GET /api/v1/snapshots/`` until snapshots fall out of the window;
2. download only snapshots not already in the local cache
   (``<INPUT_DIR>/peers/alt-bitnodes/cache/<ts>.txt``);
3. prune cache files older than the window;
4. write the union to ``<INPUT_DIR>/peers/alt-bitnodes.txt``.

Snapshot keys are ``host:port`` with IPv6 **unbracketed**
(``2a07:9a07:3::2:105:8333``). That string is itself a valid IPv6 address,
so the generic ``--ips`` reader would misread it; here the key is split on
its last ``:`` (the trailing group is always the port) and IPv6 is written
bracketed. Entries Shodan can't look up — onion, I2P, CJDNS and any other
non-globally-routable address — are skipped and counted.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import requests

from ..safe_paths import input_root, safe_input_write

logger = logging.getLogger(__name__)

SOURCE_NAME = "alt-bitnodes"
DEFAULT_URL = "https://pesquisa.hacknodes.xyz"
DEFAULT_WINDOW_DAYS = 8
DEFAULT_DELAY = 0.2
# Explicit UA: the API sits behind CloudFront, which answers 403 to the
# default `Python-urllib` agent.
USER_AGENT = "bitcoin-node-scanner (HackNodes passive recon)"
PAGE_LIMIT = 100
_CACHE_MARKER = "# alt-bitnodes snapshot"
_CJDNS = ipaddress.ip_network("fc00::/8")


class FetchError(RuntimeError):
    """The snapshot listing or a snapshot could not be retrieved."""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def classify_key(key: Any) -> Tuple[Optional[Tuple[str, int]], Optional[str]]:
    """``(ip, port), None`` for a usable key, else ``None, <skip reason>``.

    Reasons: ``onion``, ``i2p``, ``cjdns``, ``non_global``, ``invalid``.
    """
    if not isinstance(key, str) or ":" not in key:
        return None, "invalid"
    host, _, port_s = key.rpartition(":")
    host = host.strip("[]")
    lowered = host.lower()
    if lowered.endswith(".onion"):
        return None, "onion"
    if lowered.endswith(".i2p"):
        return None, "i2p"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None, "invalid"
    if ip.version == 6 and ip in _CJDNS:
        return None, "cjdns"
    if not ip.is_global:
        return None, "non_global"
    try:
        port = int(port_s)
    except ValueError:
        return None, "invalid"
    if not 0 < port <= 65535:
        return None, "invalid"
    return (str(ip), port), None


def parse_node_key(key: Any) -> Optional[Tuple[str, int]]:
    """``(ip, port)`` for a usable snapshot key, else ``None``."""
    return classify_key(key)[0]


def format_entry(ip: str, port: int) -> str:
    """``host:port`` as the ``--ips`` reader expects it (IPv6 bracketed)."""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _sort_key(entry: str) -> Tuple[int, int, int]:
    host, _, port = entry.rpartition(":")
    ip = ipaddress.ip_address(host.strip("[]"))
    return ip.version, int(ip), int(port)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class AltBitnodesClient:
    """Read-only client for the alt-bitnodes snapshot API."""

    def __init__(
        self,
        base_url: str = DEFAULT_URL,
        timeout: float = 30,
        attempts: int = 3,
        delay: float = DEFAULT_DELAY,
        http: Any = requests,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._attempts = attempts
        self._delay = delay
        self._http = http
        self._sleep = sleep
        self._downloads = 0

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.base_url}{path}"
        last = "unknown error"
        for attempt in range(self._attempts):
            try:
                resp = self._http.get(
                    url, params=params, timeout=self._timeout,
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                )
            except requests.RequestException as exc:
                last = f"network error: {exc}"
            else:
                if resp.status_code == 200:
                    try:
                        return resp.json()
                    except ValueError as exc:
                        raise FetchError(f"invalid JSON from {url}") from exc
                if resp.status_code == 403:
                    raise FetchError(
                        f"access denied by {self.base_url} (HTTP 403) — check CDN/WAF rules"
                    )
                last = f"HTTP {resp.status_code}"
                if resp.status_code < 500:
                    break  # other 4xx: retrying won't help
            if attempt < self._attempts - 1:
                self._sleep(2 ** attempt)
        raise FetchError(f"GET {url} failed: {last}")

    def list_snapshots(self, since: float) -> List[Tuple[int, str]]:
        """``[(timestamp, url)]`` for snapshots at or after ``since`` (newest first)."""
        out: List[Tuple[int, str]] = []
        page = 1
        while True:
            data = self._get("/api/v1/snapshots/", params={"page": page, "limit": PAGE_LIMIT})
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list):
                raise FetchError("unexpected snapshot listing format")
            reached_end = False
            for item in results:
                try:
                    ts = int(item["timestamp"])
                    url = str(item.get("url") or f"/api/v1/snapshots/{ts}/")
                except (KeyError, TypeError, ValueError):
                    continue
                if ts < since:
                    reached_end = True
                    continue
                out.append((ts, url))
            if reached_end or not data.get("next") or not results:
                return out
            page += 1

    def fetch_snapshot(self, url: str) -> Dict[str, Any]:
        """The ``nodes`` map of one snapshot (``{"host:port": [...]}``)."""
        if self._downloads and self._delay > 0:
            self._sleep(self._delay)
        self._downloads += 1
        path = url if url.startswith("/") else f"/{url}"
        data = self._get(path)
        nodes = data.get("nodes") if isinstance(data, dict) else None
        if not isinstance(nodes, dict):
            raise FetchError(f"snapshot {url} has no nodes map")
        return nodes


# ---------------------------------------------------------------------------
# Cache + union
# ---------------------------------------------------------------------------

def default_output() -> Path:
    return input_root() / "peers" / "alt-bitnodes.txt"


def cache_dir() -> Path:
    return input_root() / "peers" / "alt-bitnodes" / "cache"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def read_cache(path: Path) -> Optional[List[str]]:
    """Cached entries, or ``None`` when the file is missing, empty or not ours."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    if not lines or not lines[0].startswith(_CACHE_MARKER):
        return None
    return [ln.strip() for ln in lines[1:] if ln.strip() and not ln.startswith("#")]


def _write_cache(path: Path, ts: int, entries: Iterable[str]) -> None:
    body = "\n".join(sorted(set(entries), key=_sort_key))
    _atomic_write(path, f"{_CACHE_MARKER} {ts}\n{body}\n" if body else f"{_CACHE_MARKER} {ts}\n")


def _cached_timestamps(directory: Path) -> Dict[int, Path]:
    out: Dict[int, Path] = {}
    if directory.is_dir():
        for f in directory.glob("*.txt"):
            try:
                out[int(f.stem)] = f
            except ValueError:
                continue
    return out


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def build_union(
    days: int = DEFAULT_WINDOW_DAYS,
    output: Optional[str] = None,
    client: Optional[AltBitnodesClient] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Refresh the cache for the last ``days`` days and write the union file.

    Paths are validated before any request. Raises ``FetchError`` when the
    listing fails or the window has no snapshot (the previous output file is
    left untouched), and ``UnsafePathError`` for an output outside INPUT_DIR.
    """
    if days < 1:
        raise ValueError("days must be >= 1")
    out_path = safe_input_write(str(output) if output else str(default_output()))
    cdir = cache_dir()
    safe_input_write(str(cdir / "probe.txt"))  # cache must also sit under INPUT_DIR

    client = client or AltBitnodesClient()
    now = time.time() if now is None else now
    since = now - days * 86400

    listed = client.list_snapshots(since)
    if not listed:
        raise FetchError(f"no alt-bitnodes snapshot in the last {days} days")

    cached = _cached_timestamps(cdir)
    skipped: Counter = Counter()
    from_cache = downloaded = failed = 0
    for ts, url in sorted(listed):
        path = cdir / f"{ts}.txt"
        if ts in cached and read_cache(path) is not None:
            from_cache += 1
            continue
        try:
            nodes = client.fetch_snapshot(url)
        except (FetchError, requests.RequestException) as exc:
            logger.warning("alt-bitnodes snapshot %s skipped: %s", ts, exc)
            failed += 1
            continue
        entries = []
        for key in nodes:
            parsed, reason = classify_key(key)
            if parsed:
                entries.append(format_entry(*parsed))
            else:
                skipped[reason] += 1
        _write_cache(path, ts, entries)
        downloaded += 1

    pruned = 0
    for ts, path in _cached_timestamps(cdir).items():
        if ts < since:
            path.unlink(missing_ok=True)
            pruned += 1

    union: set = set()
    used: List[int] = []
    for ts, path in sorted(_cached_timestamps(cdir).items()):
        entries = read_cache(path)
        if entries is None:
            continue
        union.update(entries)
        used.append(ts)
    if not used:
        raise FetchError("no alt-bitnodes snapshot could be retrieved")

    ordered = sorted(union, key=_sort_key)
    ips = {e.rpartition(":")[0].strip("[]") for e in ordered}
    unique_v6 = sum(1 for ip in ips if ":" in ip)
    header = [
        f"# source: {SOURCE_NAME} {client.base_url}",
        f"# window: last {days} days ({_utc(since)} → {_utc(now)})",
        f"# snapshots: {len(used)} (first {_utc(used[0])}, last {_utc(used[-1])})",
        f"# entries: {len(ordered)} host:port, {len(ips)} unique IPs",
        f"# generated: {_utc(now)} — scan with --ips <this file> --source-tag {SOURCE_NAME}",
    ]
    _atomic_write(out_path, "\n".join(header + ordered) + "\n")

    return {
        "days": days,
        "snapshots_listed": len(listed),
        "from_cache": from_cache,
        "downloaded": downloaded,
        "failed": failed,
        "pruned": pruned,
        "snapshots_used": len(used),
        "skipped": dict(skipped),
        "entries": len(ordered),
        "unique_ips": len(ips),
        "unique_ipv4": len(ips) - unique_v6,
        "unique_ipv6": unique_v6,
        "output": str(out_path),
    }
