"""
GET  /api/v1/export — JSON dump of nodes and scans (REST parity with `db-export`).
POST /api/v1/import — import a dump (REST parity with `db-import`).

Both use the exact dump shape the CLI produces/consumes, so a file written
by `db-export` can be posted to /import unchanged and vice versa.
"""
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import and_
from sqlalchemy.orm import Session

from ...db.importer import import_dump
from ...db.models import Node
from ...db.repositories import ScanRepository
from ..auth import require_api_key, require_csrf_token
from .nodes import get_db

router = APIRouter()


class ImportOut(BaseModel):
    imported: int
    updated: int
    skipped: int
    errors: int


@router.get("/export", dependencies=[Depends(require_api_key)])
def export_data(
    db: Annotated[Session, Depends(get_db)],
    days: Annotated[int, Query(ge=1, le=3650, description="Number of days to export")] = 30,
):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    start_date = now - timedelta(days=days)

    nodes = db.query(Node).filter(
        and_(
            Node.last_seen >= start_date,
            Node.last_seen <= now,
        )
    ).all()
    scans = ScanRepository(db).get_by_date_range(start_date)

    # Field set identical to the CLI's db-export.
    payload = {
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

    filename = f"export_{now.strftime('%Y%m%d_%H%M%S')}.json"
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post(
    "/import",
    response_model=ImportOut,
    dependencies=[Depends(require_api_key), Depends(require_csrf_token)],
)
def import_data(
    db: Annotated[Session, Depends(get_db)],
    payload: Annotated[Any, Body(description="JSON dump in the db-export shape")] = None,
):
    if payload is None or not isinstance(payload, (dict, list)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Body must be a JSON object or array containing node records.",
        )

    stats = import_dump(payload, db, source_name="api-import")
    db.commit()

    return ImportOut(**stats)
