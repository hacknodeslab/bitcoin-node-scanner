"""Fetch and cache the published IP ranges of the tracked CDNs.

Ranges are fetched once and cached on disk for `CACHE_TTL_DAYS`. If the live
Cloudflare fetch fails and no fresh cache exists, a hardcoded fallback list
(from CF-Hero) is used so classification still produces meaningful verdicts —
Cloudflare is ~99% of real hits, so the fallback alone keeps the headline
number trustworthy even fully offline.

Ported from `../nostr-cf-recon/check_cf.py`.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.request
from typing import Dict, List

# Cache location is overridable so tests and CI don't write to the repo root.
CACHE_DIR = os.getenv("NOSTR_CDN_CACHE_DIR", ".cdn_cache")
CACHE_TTL_DAYS = 7

# The three CDNs that publish a usable public IP-range list. Akamai and others
# need ASN/CNAME heuristics and are out of scope (see proposal Non-goals).
PROVIDERS = ("cloudflare", "cloudfront", "fastly")

# Hardcoded fallback (CF-Hero list) used only if the live Cloudflare fetch fails.
CLOUDFLARE_FALLBACK = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22",   "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",   "172.64.0.0/13",   "131.0.72.0/22",
    "2400:cb00::/32",  "2606:4700::/32",  "2803:f800::/32",
    "2405:b500::/32",  "2405:8100::/32",  "2a06:98c0::/29",
    "2c0f:f248::/32",
]


def _cache_path(name: str) -> str:
    return os.path.join(CACHE_DIR, name)


def _fresh(path: str) -> bool:
    if not os.path.exists(path):
        return False
    return (time.time() - os.path.getmtime(path)) < CACHE_TTL_DAYS * 86400


def _nonempty_lines(data: str) -> bool:
    """A line-oriented payload is valid only if it has at least one entry."""
    return any(line.strip() for line in data.splitlines())


def _is_json_obj(data: str) -> bool:
    """A JSON payload is valid only if it decodes to an object."""
    try:
        return isinstance(json.loads(data), dict)
    except (ValueError, TypeError):
        return False


def _fetch(url: str, cache_name: str, validate=None) -> str:
    """Return the cached payload if fresh AND valid, else (re)fetch it.

    ``validate`` (if given) gates both the cache read and the freshly fetched
    payload, so an empty/truncated/corrupt cache file — which ``_fresh`` would
    otherwise trust for the full TTL since it only checks mtime — is ignored
    and refetched rather than silently served. Writes go through a temp file +
    ``os.replace`` so an interrupted write can never leave a partial cache.
    """
    os.makedirs(CACHE_DIR, exist_ok=True)
    p = _cache_path(cache_name)
    if _fresh(p):
        try:
            with open(p) as f:
                cached = f.read()
            if validate is None or validate(cached):
                return cached
        except OSError:
            pass  # unreadable cache → fall through and refetch
    req = urllib.request.Request(url, headers={"User-Agent": "nostr-cf-recon/0.1"})
    with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 - fixed CDN URLs
        data = resp.read().decode()
    if validate is not None and not validate(data):
        raise ValueError(f"fetched payload for {cache_name} failed validation")
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        f.write(data)
    os.replace(tmp, p)
    return data


def load_cloudflare() -> List[str]:
    try:
        v4 = _fetch("https://www.cloudflare.com/ips-v4", "cloudflare-v4.txt", _nonempty_lines).splitlines()
        v6 = _fetch("https://www.cloudflare.com/ips-v6", "cloudflare-v6.txt", _nonempty_lines).splitlines()
        cidrs = [c.strip() for c in v4 + v6 if c.strip()]
        # An empty result (e.g. an empty 200) must not silently zero out
        # Cloudflare — ~99% of real hits — so fall back to the hardcoded list.
        return cidrs or CLOUDFLARE_FALLBACK
    except Exception:
        return CLOUDFLARE_FALLBACK


def load_cloudfront() -> List[str]:
    raw = _fetch("https://ip-ranges.amazonaws.com/ip-ranges.json", "aws-ip-ranges.json", _is_json_obj)
    data = json.loads(raw)
    nets = [p["ip_prefix"] for p in data.get("prefixes", []) if p.get("service") == "CLOUDFRONT"]
    nets += [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", []) if p.get("service") == "CLOUDFRONT"]
    return nets


def load_fastly() -> List[str]:
    raw = _fetch("https://api.fastly.com/public-ip-list", "fastly.json", _is_json_obj)
    data = json.loads(raw)
    return data.get("addresses", []) + data.get("ipv6_addresses", [])


_LOADERS = {
    "cloudflare": load_cloudflare,
    "cloudfront": load_cloudfront,
    "fastly": load_fastly,
}


def build_provider_nets() -> Dict[str, List]:
    """Return `{provider: [ip_network, ...]}` for every tracked CDN.

    A provider whose fetch raises (other than Cloudflare, which has a fallback)
    degrades to an empty range list rather than aborting the whole scan.
    """
    nets: Dict[str, List] = {}
    for name in PROVIDERS:
        try:
            cidrs = _LOADERS[name]()
        except Exception:
            cidrs = []
        nets[name] = [ipaddress.ip_network(c) for c in cidrs]
    return nets
