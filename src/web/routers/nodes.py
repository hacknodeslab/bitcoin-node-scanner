"""
GET /api/v1/nodes            — paginated node list with filtering and sorting.
GET /api/v1/nodes/countries  — distinct country_name values for filter dropdown.
GET /api/v1/nodes/{id}/geo   — full geo detail for a single node.
"""
import json
from typing import Annotated, Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import asc, desc, func, or_, select
from sqlalchemy.orm import Session

from ...db.connection import get_session_factory
from ...db.models import Node
from ...db.repositories import NodeRepository
from ..auth import require_api_key

router = APIRouter()

# Whitelist of allowed sort columns mapped to Node attributes
_SORT_COLUMNS = {
    "ip": Node.ip_numeric,  # sort numerically, not lexicographically
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
    user_agent: Optional[str]
    protocol_version: Optional[int]
    services: Optional[str]
    risk_level: Optional[str]
    is_vulnerable: bool
    has_exposed_rpc: bool
    is_dev_version: bool
    country_code: Optional[str]
    country_name: Optional[str]
    city: Optional[str]
    subdivision: Optional[str]
    asn: Optional[str]
    asn_name: Optional[str]
    geo_country_code: Optional[str]
    geo_country_name: Optional[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    # Shodan enrichment
    hostname: Optional[str]
    os_info: Optional[str]
    isp: Optional[str]
    org: Optional[str]
    open_ports: Optional[List[Any]]
    vulns: Optional[List[str]]
    tags: Optional[List[str]]
    cpe: Optional[List[str]]


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


def _parse_json_col(value: Optional[str]) -> Optional[List]:
    if not value:
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def _make_node_out(n: Node) -> NodeOut:
    return NodeOut(
        id=n.id,
        ip=n.ip,
        port=n.port,
        version=n.version,
        user_agent=n.user_agent,
        protocol_version=n.protocol_version,
        services=n.services,
        risk_level=n.risk_level,
        is_vulnerable=n.is_vulnerable,
        has_exposed_rpc=n.has_exposed_rpc,
        is_dev_version=n.is_dev_version,
        country_code=n.country_code,
        country_name=n.country_name,
        city=n.city,
        subdivision=getattr(n, "subdivision", None),
        asn=n.asn,
        asn_name=n.asn_name,
        geo_country_code=getattr(n, "geo_country_code", None),
        geo_country_name=getattr(n, "geo_country_name", None),
        first_seen=n.first_seen.isoformat() if n.first_seen else None,
        last_seen=n.last_seen.isoformat() if n.last_seen else None,
        hostname=getattr(n, "hostname", None),
        os_info=getattr(n, "os_info", None),
        isp=getattr(n, "isp", None),
        org=getattr(n, "org", None),
        open_ports=_parse_json_col(getattr(n, "open_ports_json", None)),
        vulns=_parse_json_col(getattr(n, "vulns_json", None)),
        tags=_parse_json_col(getattr(n, "tags_json", None)),
        cpe=_parse_json_col(getattr(n, "cpe_json", None)),
    )


@router.get("/nodes/countries", response_model=List[str])
#def list_countries(db: Session = Depends(get_db)):
def list_countries(db: Annotated[Session, Depends(get_db)]):
    """Return distinct non-null country_name values, alphabetically sorted (max 100)."""
    stmt = (
        select(Node.country_name)
        .where(Node.country_name.isnot(None))
        .distinct()
        .order_by(Node.country_name)
        .limit(100)
    )
    return list(db.scalars(stmt).all())


@router.get("/nodes", response_model=List[NodeOut])
def list_nodes(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    risk_level: Annotated[Optional[str], Query(description="Filter by risk level: CRITICAL, HIGH, MEDIUM, LOW")] = None,
    country: Annotated[Optional[str], Query(description="Filter by server location country name (case-insensitive)")] = None,
    exposed: Annotated[Optional[bool], Query(description="Filter by has_exposed_rpc.")] = None,
    tor: Annotated[Optional[bool], Query(description="Filter by tor signal (tags include 'tor' or hostname ends in '.onion'). Only `true` is supported in v0.")] = None,
    sort_by: Annotated[Optional[str], Query(description="Column to sort by")] = None,
    sort_dir: Annotated[Optional[str], Query(description="Sort direction: asc_or_desc")] = "desc",
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    # Resolve sort column (fall back to last_seen for unknown values)
    sort_col = _SORT_COLUMNS.get(sort_by or "", Node.last_seen)
    order_fn = asc if (sort_dir or "desc").lower() == "asc" else desc

    if tor is False:
        # NULL-aware negation is fiddly across dialects; defer until a
        # dedicated `is_tor` column exists. The query bar in §8.2 doesn't
        # emit this combination, so dropping it here is safe for v0.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="tor=false is not supported in v0; omit the filter or use tor=true.",
        )

    conds = []
    if risk_level:
        conds.append(Node.risk_level == risk_level.upper())
    if country:
        conds.append(func.lower(Node.country_name) == country.lower())
    if exposed is not None:
        conds.append(Node.has_exposed_rpc == exposed)
    if tor is True:
        # Same predicate as NodeRepository.count_tor — keep them in sync.
        conds.append(or_(Node.tags_json.like("%tor%"), Node.hostname.like("%.onion")))

    total = db.scalar(select(func.count()).select_from(Node).where(*conds)) or 0
    response.headers["X-Total-Count"] = str(total)

    stmt = (
        select(Node)
        .where(*conds)
        .order_by(order_fn(sort_col))
        .offset(offset)
        .limit(limit)
    )
    nodes = list(db.scalars(stmt).all())

    return [_make_node_out(n) for n in nodes]


@router.get(
    "/nodes/{node_id}/geo",
    response_model=NodeGeoOut,
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
