"""Nostr relay CDN-recon scanner.

    python -m src.nostr.scanner <relays.txt> [--workers N] [--timeout S] [--json PATH]

Reads a relay host list, classifies each host by CDN presence in parallel, and
writes a JSON dump (`{counts, total, resolved, behind_any_cdn, results[]}`) to
`output/`. The dump is loaded into the database with the `db-import-nostr` CLI —
this scanner never writes to the database directly (mirrors the Bitcoin flow).

Phase 2 (origin-IP unmasking) is intentionally out of scope.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime
from typing import Dict, List

from .cdn_ranges import build_provider_nets
from .classifier import NON_CDN_VERDICTS, classify, normalize


def read_hosts(path: str) -> List[str]:
    """Read and deduplicate normalized hosts from a relay-list file."""
    hosts: List[str] = []
    seen = set()
    with open(path) as f:
        for line in f:
            h = normalize(line)
            if h and h not in seen:
                seen.add(h)
                hosts.append(h)
    return hosts


def scan_hosts(
    hosts: List[str],
    nets: Dict[str, List],
    workers: int = 50,
    timeout: float = 5.0,
) -> List[dict]:
    """Classify every host concurrently and return the per-host results.

    Each resolution is bounded by ``timeout`` seconds. Because ``getaddrinfo``
    ignores socket-level timeouts, the deadline is enforced here via the future
    result timeout; a host that exceeds it is recorded as a ``dns_error``
    instead of stalling the whole scan.
    """
    results: List[dict] = []
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        future_to_host = {pool.submit(classify, h, nets): h for h in hosts}
        for fut, host in future_to_host.items():
            try:
                results.append(fut.result(timeout=timeout))
            except FuturesTimeout:
                results.append(
                    {"host": host, "verdict": "dns_error", "ips": [], "providers": [], "error": "timeout"}
                )
    finally:
        # Don't block on a hung resolver thread (getaddrinfo can outlive the
        # deadline); abandon any stragglers rather than joining them.
        pool.shutdown(wait=False)
    return results


def summarize(results: List[dict]) -> dict:
    """Build the aggregate dump from per-host results.

    `resolved = total - skipped - dns_error`;
    `behind_any_cdn = count of verdicts not in NON_CDN_VERDICTS`.
    """
    counts: Dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1

    total = len(results)
    skipped = counts.get("skipped", 0)
    dns_err = counts.get("dns_error", 0)
    resolved = total - skipped - dns_err
    behind_any_cdn = sum(c for v, c in counts.items() if v not in NON_CDN_VERDICTS)

    return {
        "counts": counts,
        "total": total,
        "resolved": resolved,
        "behind_any_cdn": behind_any_cdn,
        "results": results,
    }


def _default_output_path() -> str:
    out_dir = os.getenv("OUTPUT_DIR", "output")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return os.path.join(out_dir, f"nostr_relays_{ts}.json")


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Nostr relay CDN-recon scanner")
    ap.add_argument("input", help="path to a file with one relay URL/host per line")
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--json", dest="json_out", default=None, help="output dump path (default: output/nostr_relays_<ts>.json)")
    args = ap.parse_args(argv)

    nets = build_provider_nets()
    for name, ranges in nets.items():
        print(f"  {name}: {len(ranges)} ranges")

    hosts = read_hosts(args.input)
    print(f"Resolving {len(hosts)} unique hosts with {args.workers} workers…")

    results = scan_hosts(hosts, nets, workers=args.workers, timeout=args.timeout)
    dump = summarize(results)

    out_path = args.json_out or _default_output_path()
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(dump, f, indent=2)

    resolved = dump["resolved"]
    behind = dump["behind_any_cdn"]
    pct = f"{100 * behind / resolved:.1f}%" if resolved else "-"
    print(f"total={dump['total']} resolved={resolved} behind_any_cdn={behind} ({pct})")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
