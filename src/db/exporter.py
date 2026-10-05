"""
Shared database dump builder.

Used by the CLI (`db-export`) and the REST endpoint (`GET /api/v1/export`)
so both produce the exact same dump shape.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from sqlalchemy import and_
from sqlalchemy.orm import Session

from .models import Node
from .repositories import ScanRepository


def build_export_dump(session: Session, days: int = 30) -> Dict[str, Any]:
    """
    Build the JSON-serializable export dump for nodes/scans seen in the
    last `days` days.

    Args:
        session: Open database session (read-only use).
        days: Number of days to export.

    Returns:
        The dump dict with keys: export_date, period, summary, nodes, scans.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    start_date = now - timedelta(days=days)

    nodes = session.query(Node).filter(
        and_(
            Node.last_seen >= start_date,
            Node.last_seen <= now,
        )
    ).all()
    scans = ScanRepository(session).get_by_date_range(start_date)

    return {
        "export_date": now.isoformat(),
        "period": {
            "start": start_date.isoformat(),
            "end": now.isoformat(),
        },
        "summary": {
            "total_nodes": len(nodes),
            "total_scans": len(scans),
        },
        "nodes": [
            {
                "ip": n.ip,
                "port": n.port,
                "country_code": n.country_code,
                "country_name": n.country_name,
                "city": n.city,
                "asn": n.asn,
                "asn_name": n.asn_name,
                "version": n.version,
                "risk_level": n.risk_level,
                "is_vulnerable": n.is_vulnerable,
                "has_exposed_rpc": n.has_exposed_rpc,
                "first_seen": n.first_seen.isoformat() if n.first_seen else None,
                "last_seen": n.last_seen.isoformat() if n.last_seen else None,
            }
            for n in nodes
        ],
        "scans": [
            {
                "id": s.id,
                "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                "total_nodes": s.total_nodes,
                "critical_nodes": s.critical_nodes,
                "vulnerable_nodes": s.vulnerable_nodes,
                "status": s.status,
            }
            for s in scans
        ],
    }
