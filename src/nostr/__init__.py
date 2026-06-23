"""Nostr relay CDN-recon (phase 0).

Ports the `nostr-cf-recon` PoC into the scanner: resolve each relay host and
classify it by CDN presence (Cloudflare / CloudFront / Fastly) against cached
CIDR ranges. The runnable entrypoint is `python -m src.nostr.scanner`.

Phase 2 (origin-IP unmasking) is intentionally out of scope.
"""
from .classifier import classify, normalize, provider_for, resolve
from .cdn_ranges import build_provider_nets

__all__ = [
    "classify",
    "normalize",
    "provider_for",
    "resolve",
    "build_provider_nets",
]
