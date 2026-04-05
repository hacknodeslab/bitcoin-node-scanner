"""
GET /api/v1/vulnerabilities — cached Bitcoin CVE entries from NVD.
"""
import json
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...nvd.models import NVDAPIError
from ...nvd.service import NVDService
from .nodes import get_db

router = APIRouter()


class CVEEntryOut(BaseModel):
    cve_id: str
    published: Optional[str]
    last_modified: Optional[str]
    severity: str
    cvss_score: Optional[float]
    description: Optional[str]
    affected_versions: Optional[List[str]]
    fetched_at: str


class VulnerabilitiesOut(BaseModel):
    total: int
    items: List[CVEEntryOut]


@router.get(
    "/vulnerabilities",
    response_model=VulnerabilitiesOut,
)
def get_vulnerabilities(db: Session = Depends(get_db)):
    service = NVDService(db)
    try:
        entries = service.get_vulnerabilities()
    except NVDAPIError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="NVD API unavailable and no cached data",
        ) from exc

    items: List[CVEEntryOut] = []
    for e in entries:
        affected: Optional[List[str]] = None
        if e.affected_versions:
            try:
                affected = json.loads(e.affected_versions)
            except (ValueError, TypeError):
                affected = None

        items.append(
            CVEEntryOut(
                cve_id=e.cve_id,
                published=e.published.isoformat() if e.published else None,
                last_modified=e.last_modified.isoformat() if e.last_modified else None,
                severity=e.severity,
                cvss_score=e.cvss_score,
                description=e.description,
                affected_versions=affected,
                fetched_at=e.fetched_at.isoformat(),
            )
        )

    return VulnerabilitiesOut(total=len(items), items=items)
