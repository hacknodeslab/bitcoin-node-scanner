"""Pluggable passive IP-reputation enrichment.

Every source implements the `Enricher` protocol and is registered in
`REGISTRY`; adding a source is one new module, one registry entry, and its
`<name>_checked_at` column on `ip_reputation` (+ `ReputationRepository.CHECKED_AT`),
which drives per-source staleness. Its raw payload lands in
`ip_reputation.sources_json` under its `name`.

All sources are passive: they query third-party databases or match against
downloaded lists and never send traffic to the node IPs themselves.
"""
from typing import Any, Callable, Dict, Protocol, Sequence

from sqlalchemy.orm import Session

# Per-IP result of one source:
#   {"status": "ok" | "error",
#    "fields": {typed ip_reputation columns to set},   # only when ok
#    "partial": bool,  # ok but incomplete: fields saved, source stays due
#    "data":   {raw/summary payload kept in sources_json},
#    "error":  "message"}                               # only when error
# IPs a source did not attempt (e.g. quota ran out) are simply absent.
SourceResult = Dict[str, Any]


class Enricher(Protocol):
    name: str

    def available(self) -> bool:
        """True when the source can run (key configured, lists enabled, quota left)."""
        ...

    def enrich(self, ips: Sequence[str]) -> Dict[str, SourceResult]:
        """Return a result for each IP actually processed."""
        ...


def _abuseipdb(session: Session) -> Enricher:
    from .abuseipdb import AbuseIPDBEnricher
    return AbuseIPDBEnricher.from_env(session)


def _blocklists(session: Session) -> Enricher:
    from .blocklists import BlocklistEnricher
    return BlocklistEnricher.from_env()


# Order matters: the cheap local source runs first.
REGISTRY: Dict[str, Callable[[Session], Enricher]] = {
    "blocklists": _blocklists,
    "abuseipdb": _abuseipdb,
}

__all__ = ["Enricher", "SourceResult", "REGISTRY"]
