"""
Shared JSON-dump node import logic.

Single code path used by both the CLI (`db-import`, via
scripts/import_json_to_db.py) and the REST endpoint
(`POST /api/v1/import`). Handles deduplication by (ip, port), preserves
first_seen on updates, and derives risk/vulnerability flags the same way
for every caller.
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from .repositories import NodeRepository, ScanRepository


def merge_tag(tags_json: Optional[str], tag: str) -> str:
    """Return tags_json with `tag` added (idempotent, preserves existing)."""
    try:
        tags = json.loads(tags_json) if tags_json else []
        if not isinstance(tags, list):
            tags = []
    except (ValueError, TypeError):
        tags = []
    if tag not in tags:
        tags.append(tag)
    return json.dumps(tags)


def is_vulnerable_version(version: str) -> bool:
    """Check if version is known vulnerable."""
    # Load vulnerable versions from config
    try:
        from src.scanner import Config
        for vuln_version in Config.VULNERABLE_VERSIONS.keys():
            if vuln_version in version:
                return True
    except ImportError:
        pass

    # Basic check for old versions
    if "Satoshi:0." in version:
        try:
            ver_num = version.split(":")[1].split(".")[1]
            if int(ver_num) < 21:
                return True
        except (IndexError, ValueError):
            pass

    return False


def analyze_risk_level(node_data: Dict[str, Any]) -> str:
    """Determine risk level for a node."""
    if node_data.get("port") == 8332:
        return "CRITICAL"

    risk_factors = 0
    if is_vulnerable_version(node_data.get("version", "")):
        risk_factors += 1
    if ".99." in node_data.get("version", ""):
        risk_factors += 1

    if risk_factors >= 2:
        return "HIGH"
    elif risk_factors == 1:
        return "MEDIUM"
    return "LOW"


def extract_nodes(data: Any) -> List[Dict[str, Any]]:
    """Extract the node list from a dump in any of the accepted formats.

    Accepts a {"nodes": [...]} envelope (the shape `GET /api/v1/export`
    and `db-export` produce), a single-node object ({"ip": ...}), an
    arbitrary {key: node} mapping, or a bare list of node objects.
    """
    if isinstance(data, dict):
        if "nodes" in data:
            return data["nodes"]
        if "ip" in data:
            return [data]
        return list(data.values())
    if isinstance(data, list):
        return data
    return []


def import_node(
    node_repo: NodeRepository,
    node_data: Dict[str, Any],
    file_timestamp: Optional[datetime] = None,
) -> Tuple[str, Optional[str], bool]:
    """
    Import a single node, handling deduplication.

    Returns a tuple of (result, risk_level, is_vulnerable) where
    result is 'imported', 'updated', or 'skipped'.
    """
    ip = node_data.get("ip")
    if not ip:
        return "skipped", None, False

    port = node_data.get("port", 8333)

    # Check if node exists
    existing = node_repo.find_by_ip_port(ip, port)

    # Prepare data
    db_data = {
        "ip": ip,
        "port": port,
        "country_code": node_data.get("country_code"),
        "country_name": node_data.get("country") or node_data.get("country_name"),
        "city": node_data.get("city"),
        "asn": node_data.get("asn"),
        "asn_name": node_data.get("organization") or node_data.get("isp") or node_data.get("asn_name"),
        "version": node_data.get("version"),
        "user_agent": node_data.get("product"),
        "banner": node_data.get("banner"),
    }

    # Determine risk level
    db_data["risk_level"] = analyze_risk_level(node_data)
    db_data["is_vulnerable"] = is_vulnerable_version(node_data.get("version", ""))
    db_data["has_exposed_rpc"] = port == 8332
    db_data["is_dev_version"] = ".99." in node_data.get("version", "")

    # Provenance marker: records from the --ips host-lookup mode carry a
    # `query` of "ip-list:<file>" and the operator-supplied `source_tag`
    # (`--source-tag`, e.g. "peer-observer"). Add that tag so these nodes stay
    # distinguishable from query-discovered ones (the Node table has no
    # dedicated source column). Dumps written before `source_tag` existed
    # fall back to the neutral "ip-list". Tags are merged, never clobbered.
    prov_tag = None
    if str(node_data.get("query", "")).startswith("ip-list:"):
        prov_tag = str(node_data.get("source_tag") or "ip-list")

    if existing:
        # Update existing node, preserve first_seen
        for key, value in db_data.items():
            if key not in ("id", "first_seen") and value is not None:
                setattr(existing, key, value)
        if prov_tag:
            existing.tags_json = merge_tag(existing.tags_json, prov_tag)
        existing.last_seen = file_timestamp or datetime.now(timezone.utc).replace(tzinfo=None)
        return "updated", db_data["risk_level"], db_data["is_vulnerable"]
    else:
        # Create new node
        if prov_tag:
            db_data["tags_json"] = json.dumps([prov_tag])
        node_repo.upsert(db_data)
        return "imported", db_data["risk_level"], db_data["is_vulnerable"]


def import_dump(
    data: Any,
    session: Session,
    source_name: str = "api-import",
    timestamp: Optional[datetime] = None,
) -> Dict[str, int]:
    """
    Import all nodes from a parsed JSON dump and record a Scan provenance row.

    Args:
        data: Parsed JSON (any shape accepted by extract_nodes()).
        session: Open database session; the caller commits.
        source_name: Provenance label recorded as `json-import:<source_name>`.
        timestamp: Timestamp for last_seen on updated nodes and the Scan row.

    Returns:
        Counts: {"imported", "updated", "skipped", "errors"}.
    """
    stats = {"imported": 0, "updated": 0, "skipped": 0, "errors": 0}
    nodes = extract_nodes(data)
    if not nodes:
        return stats

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    vulnerable_count = 0

    node_repo = NodeRepository(session)
    for node_data in nodes:
        try:
            result, risk_level, is_vulnerable = import_node(node_repo, node_data, timestamp)
            if result in stats:
                stats[result] += 1
            if result in ("imported", "updated"):
                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1
                if is_vulnerable:
                    vulnerable_count += 1
        except Exception:
            stats["errors"] += 1

    # Record the import as a Scan row (provenance marker) in the same
    # transaction as the nodes, so a failed import leaves no completed
    # scan behind.
    scan_repo = ScanRepository(session)
    scan_repo.record_import(
        file_name=source_name,
        total_nodes=stats["imported"] + stats["updated"],
        critical_nodes=risk_counts["CRITICAL"],
        high_risk_nodes=risk_counts["HIGH"],
        vulnerable_nodes=vulnerable_count,
        timestamp=timestamp,
    )

    return stats
