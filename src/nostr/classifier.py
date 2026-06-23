"""Normalize, resolve, and classify Nostr relay hosts by CDN presence.

A relay's verdict is the matching provider name, a `+`-joined combination when
its resolved IPs span multiple providers, `direct` when no tracked range
matches, `skipped` for `.onion`/`.i2p` (no DNS), or `dns_error` on resolution
failure.

Ported from `../nostr-cf-recon/check_cf.py`.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse

# Verdicts that are not "behind a tracked CDN".
NON_CDN_VERDICTS = frozenset({"direct", "dns_error", "skipped"})


def provider_counts(counts: Dict[str, int]) -> Dict[str, int]:
    """Sum per-verdict counts into per-provider counts.

    Combo verdicts like ``cloudflare+fastly`` contribute to each provider, so a
    relay behind two CDNs is counted once per provider. Non-CDN verdicts are
    skipped. This is the single source of truth for the provider breakdown —
    the API exposes it so the frontend never re-parses verdict strings.
    """
    out: Dict[str, int] = {}
    for verdict, n in counts.items():
        if verdict in NON_CDN_VERDICTS:
            continue
        for provider in verdict.split("+"):
            out[provider] = out.get(provider, 0) + n
    return out


def normalize(line: str) -> Optional[str]:
    """Reduce an input line to a bare lowercase hostname.

    Accepts `wss://relay.x/`, `relay.x`, and mixed forms. Returns None for
    blank lines, comments (`#…`), and inputs with no parseable host.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if "://" not in s:
        s = "wss://" + s
    host = urlparse(s).hostname
    return host.lower() if host else None


def provider_for(ip: str, nets: Dict[str, List]) -> Optional[str]:
    """Return the provider whose ranges contain `ip`, or None."""
    addr = ipaddress.ip_address(ip)
    for name, ranges in nets.items():
        if any(addr in n for n in ranges):
            return name
    return None


def resolve(host: str, timeout: float) -> List[str]:
    """Resolve a host to its sorted, de-duplicated A/AAAA addresses."""
    socket.setdefaulttimeout(timeout)
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({i[4][0] for i in infos})


def classify(host: str, timeout: float, nets: Dict[str, List]) -> dict:
    """Classify a single host. Returns `{host, verdict, ips, providers, error}`."""
    if host.endswith(".onion") or host.endswith(".i2p"):
        return {"host": host, "verdict": "skipped", "ips": [], "providers": [], "error": "onion/i2p"}
    try:
        ips = resolve(host, timeout)
    except (socket.gaierror, socket.timeout, OSError, UnicodeError) as e:
        return {"host": host, "verdict": "dns_error", "ips": [], "providers": [], "error": str(e)}
    matches = sorted({p for ip in ips if (p := provider_for(ip, nets))})
    if matches:
        verdict = matches[0] if len(matches) == 1 else "+".join(matches)
    else:
        verdict = "direct"
    return {"host": host, "verdict": verdict, "ips": ips, "providers": matches, "error": None}
