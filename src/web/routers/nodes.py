"""
GET /api/v1/nodes            — paginated node list with filtering and sorting.
GET /api/v1/nodes/countries  — distinct country_name values for filter dropdown.
GET /api/v1/nodes/{id}/geo   — full geo detail for a single node.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import asc, desc, func, select
from sqlalchemy.orm import Session

from ...db.connection import get_session_factory
from ...db.models import Node
from ...db.repositories import NodeRepository
from ..auth import require_api_key

router = APIRouter()

# Whitelist of allowed sort columns mapped to Node attributes
_SORT_COLUMNS = {
    "ip": Node.ip,
    "port": Node.port,
    "version": Node.version,
    "risk_level": Node.risk_level,
    "country_name": Node.country_name,
    "geo_country_name": Node.geo_country_name,
    "last_seen": Node.last_seen,
}


class NodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip: str
    port: int
    version: Optional[str]
    risk_level: Optional[str]
    country_code: Optional[str]
    country_name: Optional[str]
    geo_country_code: Optional[str]
    geo_country_name: Optional[str]
    city: Optional[str]
    subdivision: Optional[str]
    last_seen: Optional[str]


class NodeGeoOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip: str
    country_code: Optional[str]
    country_name: Optional[str]
    geo_country_code: Optional[str]
    geo_country_name: Optional[str]
    city: Optional[str]
    subdivision: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    asn: Optional[str]
    asn_name: Optional[str]


def get_db() -> Session:
    factory = get_session_factory()
    if factory is None:
        raise RuntimeError("Database not configured. Set DATABASE_URL environment variable.")
    db = factory()
    try:
        yield db
    finally:
        db.close()


def _make_node_out(n: Node) -> NodeOut:
    return NodeOut(
        id=n.id,
        ip=n.ip,
        port=n.port,
        version=n.version,
        risk_level=n.risk_level,
        country_code=n.country_code,
        country_name=n.country_name,
        geo_country_code=getattr(n, "geo_country_code", None),
        geo_country_name=getattr(n, "geo_country_name", None),
        city=n.city,
        subdivision=getattr(n, "subdivision", None),
        last_seen=n.last_seen.isoformat() if n.last_seen else None,
    )


@router.get("/nodes/countries", response_model=List[str], dependencies=[Depends(require_api_key)])
def list_countries(db: Session = Depends(get_db)):
    """Return distinct non-null country_name values, alphabetically sorted (max 100)."""
    stmt = (
        select(Node.country_name)
        .where(Node.country_name.isnot(None))
        .distinct()
        .order_by(Node.country_name)
        .limit(100)
    )
    return list(db.scalars(stmt).all())


@router.get("/nodes", response_model=List[NodeOut], dependencies=[Depends(require_api_key)])
def list_nodes(
    risk_level: Optional[str] = Query(None, description="Filter by risk level: CRITICAL, HIGH, MEDIUM, LOW"),
    country: Optional[str] = Query(None, description="Filter by server location country name (case-insensitive)"),
    sort_by: Optional[str] = Query(None, description="Column to sort by"),
    sort_dir: Optional[str] = Query("desc", description="Sort direction: asc or desc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    # Resolve sort column (fall back to last_seen for unknown values)
    sort_col = _SORT_COLUMNS.get(sort_by or "", Node.last_seen)
    order_fn = asc if (sort_dir or "desc").lower() == "asc" else desc

    stmt = select(Node)

    if risk_level:
        stmt = stmt.where(Node.risk_level == risk_level.upper())
    if country:
        stmt = stmt.where(func.lower(Node.country_name) == country.lower())

    stmt = stmt.order_by(order_fn(sort_col)).offset(offset).limit(limit)
    nodes = list(db.scalars(stmt).all())

    return [_make_node_out(n) for n in nodes]


@router.get(
    "/nodes/{node_id}/geo",
    response_model=NodeGeoOut,
    dependencies=[Depends(require_api_key)],
)
def get_node_geo(node_id: int, db: Session = Depends(get_db)):
    repo = NodeRepository(db)
    node = repo.get_by_id(node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found.")
    return NodeGeoOut(
        id=node.id,
        ip=node.ip,
        country_code=node.country_code,
        country_name=node.country_name,
        geo_country_code=getattr(node, "geo_country_code", None),
        geo_country_name=getattr(node, "geo_country_name", None),
        city=node.city,
        subdivision=getattr(node, "subdivision", None),
        latitude=node.latitude,
        longitude=node.longitude,
        asn=node.asn,
        asn_name=node.asn_name,
    )
