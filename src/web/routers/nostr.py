"""
GET /api/v1/nostr/relays — paginated Nostr relays classified by CDN presence.
GET /api/v1/nostr/stats  — aggregates for the latest Nostr CDN-recon scan.

Both scope to the most recent imported scan (see `db-import-nostr`).
"""
from typing import Annotated, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db.repositories import NostrRepository
from ..auth import require_api_key
from .nodes import _parse_json_col, get_db

router = APIRouter()


def _json_list(value: Optional[str]) -> List:
    """Parse a JSON-array column, defaulting to [] (reuses nodes._parse_json_col)."""
    return _parse_json_col(value) or []


class NostrRelayOut(BaseModel):
    host: str
    verdict: str
    providers: List[str]
    ips: List[str]
    error: Optional[str] = None
    last_seen: Optional[str] = None


class NostrStatsOut(BaseModel):
    total: int
    resolved: int
    behind_any_cdn: int
    behind_cdn_pct: float
    counts: Dict[str, int]
    # Per-provider counts (derived server-side from `counts`; combos count once
    # per provider) so the frontend never re-parses verdict strings.
    providers: Dict[str, int]
    started_at: Optional[str] = None


@router.get(
    "/nostr/relays",
    response_model=List[NostrRelayOut],
    dependencies=[Depends(require_api_key)],
)
def list_nostr_relays(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    verdict: Annotated[Optional[str], Query(description="Filter by exact verdict (e.g. cloudflare, direct)")] = None,
    provider: Annotated[Optional[str], Query(description="Filter to relays whose providers include this CDN")] = None,
    behind_cdn: Annotated[Optional[bool], Query(description="true → only relays behind a tracked CDN; false → only direct/dns_error/skipped")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    repo = NostrRepository(db)
    total, rows = repo.list_relays(
        verdict=verdict,
        provider=provider,
        behind_cdn=behind_cdn,
        limit=limit,
        offset=offset,
    )
    response.headers["X-Total-Count"] = str(total)
    return [
        NostrRelayOut(
            host=r.host,
            verdict=r.verdict,
            providers=_json_list(r.providers_json),
            ips=_json_list(r.ips_json),
            error=r.error,
            last_seen=r.last_seen.isoformat() if r.last_seen else None,
        )
        for r in rows
    ]


@router.get(
    "/nostr/stats",
    response_model=NostrStatsOut,
    dependencies=[Depends(require_api_key)],
)
def get_nostr_stats(db: Annotated[Session, Depends(get_db)]):
    stats = NostrRepository(db).stats()
    return NostrStatsOut(**stats)
