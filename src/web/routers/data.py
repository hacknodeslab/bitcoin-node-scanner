"""
GET  /api/v1/export — JSON dump of nodes and scans (REST parity with `db-export`).
POST /api/v1/import — import a dump (REST parity with `db-import`).

Both use the exact dump shape the CLI produces/consumes, so a file written
by `db-export` can be posted to /import unchanged and vice versa.
"""
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db.exporter import build_export_dump
from ...db.importer import import_dump
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
    payload = build_export_dump(db, days)

    filename = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
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
