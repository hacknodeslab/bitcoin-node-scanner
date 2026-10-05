"""
Retroactive MaxMind GeoIP enrichment over persisted nodes.

Shared by the CLI (`enrich-geo`) and the web background job
(`POST /api/v1/enrich-geo`) so the gap-filling precedence rules live in
exactly one place: Shodan-provided values win for fields Shodan supplies;
MaxMind-only fields (subdivision, coordinates, geo_country_*) are always set.
"""
from typing import TYPE_CHECKING, Callable, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Node

if TYPE_CHECKING:
    from ..geoip import GeoIPService

DEFAULT_BATCH_SIZE = 500


def enrich_nodes_geo(
    session: Session,
    geoip: "GeoIPService",
    batch_size: int = DEFAULT_BATCH_SIZE,
    progress: Optional[Callable[[int, int], None]] = None,
) -> Dict[str, int]:
    """
    Enrich every node in the database with MaxMind geo data.

    Args:
        session: Open database session; the caller commits.
        geoip: GeoIPService instance, already initialized and available.
        batch_size: Nodes per batch (flushed per batch).
        progress: Optional callback(processed, total) invoked after each batch.

    Returns:
        Counts: {"total", "updated", "skipped", "no_match"}.
    """
    total = session.query(Node).count()
    updated = skipped = no_match = 0

    offset = 0
    while True:
        batch = list(session.scalars(select(Node).offset(offset).limit(batch_size)).all())
        if not batch:
            break

        for node in batch:
            geo = geoip.lookup(node.ip)
            if geo is None:
                no_match += 1
                continue

            changed = False
            # Fill geo gaps (Shodan-provided values take precedence)
            if not node.country_code and geo.country_code:
                node.country_code = geo.country_code
                changed = True
            if not node.country_name and geo.country_name:
                node.country_name = geo.country_name
                changed = True
            if not node.city and geo.city:
                node.city = geo.city
                changed = True
            if not node.asn and geo.asn:
                node.asn = geo.asn
                changed = True
            if not node.asn_name and geo.asn_name:
                node.asn_name = geo.asn_name
                changed = True
            # Always use MaxMind for these (Shodan doesn't provide them)
            if geo.subdivision is not None:
                node.subdivision = geo.subdivision
                changed = True
            if geo.latitude is not None:
                node.latitude = geo.latitude
                node.longitude = geo.longitude
                changed = True
            # Always store MaxMind country separately (independent of Shodan)
            if geo.country_code is not None:
                node.geo_country_code = geo.country_code
                node.geo_country_name = geo.country_name
                changed = True

            if changed:
                updated += 1
            else:
                skipped += 1

        session.flush()
        offset += batch_size
        if progress:
            progress(min(offset, total), total)

    return {"total": total, "updated": updated, "skipped": skipped, "no_match": no_match}
