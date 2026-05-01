"""
Canonical list of example/demo IP addresses used in tests, fixtures, and
screenshots. Nodes whose IP appears here are flagged with `is_example=True`
in the database and rendered with a distinct visual treatment in the UI so
they can be excluded from analytics or hidden from operators.

Single source of truth for the entire backend; do not duplicate this list in
the frontend (the frontend reacts to `node.is_example` from the API).
"""
from __future__ import annotations

import json
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


# Synthetic example nodes — each models a different operator-relevant state so
# the dashboard can demo every pill (EXAMPLE, EXPOSED, TOR, CVE) at once. The
# `db-seed-examples` CLI upserts these rows; the IPs are RFC 5737 TEST-NET /
# leetspeak so Shodan never returns them in real scans.
EXAMPLE_NODES: list[dict[str, Any]] = [
    {
        "ip": "1.2.3.4",
        "port": 8333,
        "version": "Satoshi:25.0.0",
        "user_agent": "/Satoshi:25.0.0/",
        "banner": "/Satoshi:25.0.0/",
        "protocol_version": 70016,
        "services": "NETWORK,WITNESS",
        "country_code": "US",
        "country_name": "United States",
        "city": "New York",
        "asn": "AS13335",
        "asn_name": "Cloudflare, Inc.",
        "isp": "Cloudflare",
        "org": "Cloudflare",
        "hostname": "node-1.example",
        "risk_level": "LOW",
        "is_vulnerable": False,
        "has_exposed_rpc": False,
        "is_dev_version": False,
        "tags_json": json.dumps(["bitcoin"]),
    },
    {
        "ip": "5.6.7.8",
        "port": 8332,
        "version": "Satoshi:24.0.1",
        "user_agent": "/Satoshi:24.0.1/",
        "banner": "/Satoshi:24.0.1/",
        "protocol_version": 70016,
        "services": "NETWORK",
        "country_code": "DE",
        "country_name": "Germany",
        "city": "Frankfurt",
        "asn": "AS3320",
        "asn_name": "Deutsche Telekom AG",
        "isp": "Deutsche Telekom",
        "org": "Deutsche Telekom",
        "hostname": "node-2.example",
        "risk_level": "CRITICAL",
        "is_vulnerable": False,
        "has_exposed_rpc": True,
        "is_dev_version": False,
        "tags_json": json.dumps(["bitcoin"]),
    },
    {
        "ip": "9.10.11.12",
        "port": 8333,
        "version": "Satoshi:23.0.0",
        "user_agent": "/Satoshi:23.0.0/",
        "banner": "/Satoshi:23.0.0/",
        "protocol_version": 70016,
        "services": "NETWORK,WITNESS",
        "country_code": "NL",
        "country_name": "Netherlands",
        "city": "Amsterdam",
        "asn": "AS1101",
        "asn_name": "SURFnet bv",
        "isp": "SURFnet",
        "org": "SURFnet",
        "hostname": "abcdefghijklmnop.onion",
        "risk_level": "MEDIUM",
        "is_vulnerable": False,
        "has_exposed_rpc": False,
        "is_dev_version": False,
        "tags_json": json.dumps(["bitcoin", "tor"]),
    },
    {
        "ip": "1.3.3.7",
        "port": 8333,
        "version": "Satoshi:0.20.0",
        "user_agent": "/Satoshi:0.20.0/",
        "banner": "/Satoshi:0.20.0/",
        "protocol_version": 70015,
        "services": "NETWORK",
        "country_code": "SE",
        "country_name": "Sweden",
        "city": "Stockholm",
        "asn": "AS1257",
        "asn_name": "Tele2 AB",
        "isp": "Tele2",
        "org": "Tele2",
        "hostname": "node-4.example",
        "risk_level": "HIGH",
        "is_vulnerable": True,
        "has_exposed_rpc": False,
        "is_dev_version": False,
        "tags_json": json.dumps(["bitcoin"]),
    },
]
