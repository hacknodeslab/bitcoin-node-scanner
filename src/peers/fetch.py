"""Fetch a peer list for the scanner's ``--ips`` mode.

    python -m src.peers.fetch alt-bitnodes [--days N] [--output PATH]

Writes ``<INPUT_DIR>/peers/alt-bitnodes.txt`` by default and prints the
follow-up scan command. Environment: ``ALT_BITNODES_URL``,
``ALT_BITNODES_WINDOW_DAYS``, ``ALT_BITNODES_DELAY``.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import List, Optional

from ..safe_paths import UnsafePathError
from . import alt_bitnodes


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


def _display(path: str) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:
        return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch a node IP list for `src.scanner --ips`")
    parser.add_argument("source", choices=[alt_bitnodes.SOURCE_NAME])
    parser.add_argument(
        "--days", type=int,
        default=_env_int("ALT_BITNODES_WINDOW_DAYS", alt_bitnodes.DEFAULT_WINDOW_DAYS),
        help="Union of the snapshots in the last N days (default: %(default)s)",
    )
    parser.add_argument("--output", default=None,
                        help="Output file under INPUT_DIR (default: <INPUT_DIR>/peers/alt-bitnodes.txt)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    if args.days < 1:
        print("ERROR: --days must be >= 1")
        return 1

    client = alt_bitnodes.AltBitnodesClient(
        base_url=os.getenv("ALT_BITNODES_URL") or alt_bitnodes.DEFAULT_URL,
        delay=_env_float("ALT_BITNODES_DELAY", alt_bitnodes.DEFAULT_DELAY),
    )
    try:
        s = alt_bitnodes.build_union(days=args.days, output=args.output, client=client)
    except (alt_bitnodes.FetchError, UnsafePathError) as exc:
        print(f"ERROR: {exc}")
        return 1

    skipped = ", ".join(f"{k}={v}" for k, v in sorted(s["skipped"].items())) or "none"
    out = _display(s["output"])
    print("=" * 60)
    print(f"ALT-BITNODES PEER LIST — last {s['days']} days")
    print("=" * 60)
    print(f"  Snapshots in window:  {s['snapshots_listed']}"
          f"  (cache {s['from_cache']}, downloaded {s['downloaded']}, failed {s['failed']})")
    print(f"  Cache pruned:         {s['pruned']}")
    print(f"  Unique IPs:           {s['unique_ips']}"
          f"  (IPv4 {s['unique_ipv4']}, IPv6 {s['unique_ipv6']}; {s['entries']} host:port)")
    print(f"  Skipped keys:         {skipped}")
    print(f"  Output:               {out}")
    print()
    print("Next:")
    print(f"  python -m src.scanner --ips {out} --source-tag {alt_bitnodes.SOURCE_NAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
