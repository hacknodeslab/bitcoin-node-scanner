"""Parse a node IP list for the scanner's ``--ips`` mode.

Accepts peer-observer's clearnet exports and common hand-edited forms, per line:
- IPv4 ``host:port``           e.g. ``1.10.205.86:8333``
- IPv6 bracketed ``[ip]:port`` e.g. ``[2001:db8::1]:8333``
- CSV ``ip,port``              e.g. ``203.0.113.5,8333``
- a bare IP (v4 or v6) with no port
- unbracketed full IPv6 + port e.g. ``2001:0:...:79f6:8333``

To attach a port to a *compressed* IPv6 literal, use the bracketed form: an
unbracketed compressed address such as ``2001:db8::1:8333`` is itself valid
IPv6 and is read as a bare address (the trailing group is not a port).

Blank lines and ``#`` comments are ignored. The colon split is careful not to
mistake a bare (unbracketed) IPv6 address — which also contains colons — for a
``host:port`` pair. IPs are validated; duplicates are collapsed (one entry per
IP) with any extra ports merged.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple

_BRACKETED = re.compile(r"^\[([0-9A-Fa-f:]+)\](?::(\d+))?$")


def _validate(ip: str, port: Optional[str]) -> Optional[Tuple[str, Optional[int]]]:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    if port is None or port == "":
        return ip, None
    try:
        p = int(port)
    except ValueError:
        return None
    if p == 0:
        # peer-observer uses :0 for an unknown port — keep the IP, drop the port
        # so it is still looked up against the default Bitcoin port set.
        return ip, None
    if not 0 < p <= 65535:
        return None
    return ip, p


def parse_ip_line(line: str) -> Optional[Tuple[str, Optional[int]]]:
    """Parse one line into ``(ip, port|None)``, or ``None`` if blank/comment/invalid."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    # CSV `ip,port` (also covers `ip,` and bare `ip` with a trailing comma).
    # Reject rows with more than two fields rather than silently truncating a
    # malformed export into a plausible-but-wrong entry.
    if "," in s:
        parts = [p.strip() for p in s.split(",")]
        if len(parts) > 2:
            return None
        return _validate(parts[0], parts[1] if len(parts) == 2 else None)

    # Bracketed IPv6, optionally with a port: `[2001:db8::1]:8333`.
    if s.startswith("["):
        m = _BRACKETED.match(s)
        return _validate(m.group(1), m.group(2)) if m else None

    # No colon → bare IPv4.
    if ":" not in s:
        return _validate(s, None)

    # Exactly one colon → IPv4 `host:port`.
    if s.count(":") == 1:
        ip, _, port = s.partition(":")
        return _validate(ip, port)

    # More than one colon, unbracketed: either a bare IPv6, or an unbracketed
    # IPv6 with a trailing `:port` (peer-observer emits full Teredo addresses
    # this way). Try the whole string as an IPv6 first, then fall back to
    # splitting a trailing `:port`.
    #
    # LIMITATION: for a *compressed* literal this is inherently ambiguous —
    # e.g. `2001:db8::1:8333` is itself a valid IPv6, so it is taken as a bare
    # address and the trailing group is NOT treated as a port. To attach a port
    # to a compressed IPv6, bracket it (`[2001:db8::1]:8333`). This only affects
    # non-default ports on compressed unbracketed input; peer-observer's IPv6
    # export is already bracketed, and its unbracketed entries are full (so they
    # fail the whole-string parse and recover their port via the split).
    whole = _validate(s, None)
    if whole is not None:
        return whole
    host, sep, port = s.rpartition(":")
    return _validate(host, port) if sep else None


def read_ip_list(path: str) -> Tuple[List[Tuple[str, List[int]]], Dict[str, int]]:
    """Read a file into ``([(ip, [ports...]), ...], counts)``.

    Entries are deduped by IP, preserving first-seen order, with ports merged
    and sorted. ``counts`` reports ``raw`` (non-blank, non-comment lines),
    ``invalid`` (lines dropped), and ``unique`` (distinct valid IPs).
    """
    ports_by_ip: Dict[str, set] = {}
    order: List[str] = []
    raw = 0
    invalid = 0

    with open(path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            raw += 1
            parsed = parse_ip_line(line)
            if parsed is None:
                invalid += 1
                continue
            ip, port = parsed
            if ip not in ports_by_ip:
                ports_by_ip[ip] = set()
                order.append(ip)
            if port is not None:
                ports_by_ip[ip].add(port)

    entries = [(ip, sorted(ports_by_ip[ip])) for ip in order]
    return entries, {"raw": raw, "invalid": invalid, "unique": len(entries)}
