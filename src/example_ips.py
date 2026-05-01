"""
Canonical list of example/demo IP addresses used in tests, fixtures, and
screenshots. Nodes whose IP appears here are flagged with `is_example=True`
in the database and rendered with a distinct visual treatment in the UI so
they can be excluded from analytics or hidden from operators.

Single source of truth for the entire backend; do not duplicate this list in
the frontend (the frontend reacts to `node.is_example` from the API).
"""
from __future__ import annotations

from typing import Any

EXAMPLE_IPS: frozenset[str] = frozenset({
    "1.2.3.4",
    "5.6.7.8",
    "9.10.11.12",
    "1.3.3.7",
})


def is_example_ip(ip: Any) -> bool:
    """Return True iff `ip` is in the canonical example list.

    Returns False for None, non-string inputs, empty strings, or any value
    not in the list — never raises.
    """
    if not isinstance(ip, str) or not ip:
        return False
    return ip in EXAMPLE_IPS
