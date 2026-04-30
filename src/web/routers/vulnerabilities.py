"""
GET /api/v1/vulnerabilities — cached Bitcoin CVE entries from NVD.
GET /api/v1/vulnerabilities/{cve_id}/nodes — nodes currently affected by a CVE.
"""
import json
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db.repositories import VulnerabilityRepository
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
    affected_versions: Optional[List[Any]]
    fetched_at: str


class VulnerabilitiesOut(BaseModel):
    total: int
    items: List[CVEEntryOut]


class AffectedNodeOut(BaseModel):
    id: int
    ip: str
    port: int
    version: Optional[str]
    risk_level: Optional[str]
    country_name: Optional[str]
    last_seen: Optional[str]


class AffectedNodesOut(BaseModel):
    cve_id: str
    total: int
    nodes: List[AffectedNodeOut]


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
        affected: Optional[List[Any]] = None
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


@router.get(
    "/vulnerabilities/{cve_id}/nodes",
    response_model=AffectedNodesOut,
)
def get_affected_nodes(cve_id: str, db: Session = Depends(get_db)):
    repo = VulnerabilityRepository(db)
    cve = repo.find_by_cve_id(cve_id)
    if cve is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE {cve_id} not found in catalog",
        )
    nodes = repo.get_nodes_by_cve(cve)
    items = [
        AffectedNodeOut(
            id=n.id,
            ip=n.ip,
            port=n.port,
            version=n.version,
            risk_level=n.risk_level,
            country_name=n.country_name,
            last_seen=n.last_seen.isoformat() if n.last_seen else None,
        )
        for n in nodes
    ]
    return AffectedNodesOut(cve_id=cve.cve_id, total=len(items), nodes=items)
