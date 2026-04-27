"""
Full Bitcoin node scan saving all results to the database.

Uses Shodan search_cursor for automatic pagination and bulk inserts
for efficiency. Stops gracefully when credits run out.

Usage:
    DATABASE_URL=sqlite:///./bitcoin_scanner.db python scripts/full_db_scan.py
    DATABASE_URL=sqlite:///./bitcoin_scanner.db python scripts/full_db_scan.py --dry-run
    DATABASE_URL=sqlite:///./bitcoin_scanner.db python scripts/full_db_scan.py --limit 500
"""
import os
import sys
import time
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shodan

from src.db.connection import init_db, get_db_session, is_database_configured
from src.db.repositories import NodeRepository, ScanRepository
from src.scanner import BitcoinNodeScanner


QUERY = "product:Satoshi"
BATCH_SIZE = 200  # nodes to accumulate before bulk-writing to DB
API_KEY = os.getenv("SHODAN_API_KEY", "9Tk6l4k6Gr1xsHdL8mJJg2aQuoyd16LS")


def extract_version(match: dict) -> str | None:
    """Extract version string from Shodan match data."""
    data = match.get("data", "")
    if "/Satoshi:" in data:
        try:
            return "Satoshi:" + data.split("/Satoshi:")[1].split("/")[0]
        except Exception:
            pass
    return match.get("version")


def map_match(match: dict, scanner: BitcoinNodeScanner) -> dict:
    """Convert a Shodan match dict to a DB node_data dict."""
    version = extract_version(match)
    port = match.get("port", 8333)
    node_data = {
        "ip": match.get("ip_str"),
        "port": port,
        "country_code": match.get("location", {}).get("country_code"),
        "country_name": match.get("location", {}).get("country_name"),
        "city": match.get("location", {}).get("city"),
        "latitude": match.get("location", {}).get("latitude"),
        "longitude": match.get("location", {}).get("longitude"),
        "asn": match.get("asn"),
        "asn_name": match.get("org"),
        "version": version,
        "banner": match.get("data", "")[:500],
        "risk_level": scanner.analyze_risk_level({"port": port, "version": version or ""}),
        "is_vulnerable": scanner.is_vulnerable_version(version or ""),
        "has_exposed_rpc": port == 8332,
        "is_dev_version": ".99." in (version or ""),
    }
    return node_data


def bulk_save(session_nodes: list, scan_id: int) -> int:
    """Bulk-upsert a batch of nodes and associate them with the scan."""
    with get_db_session() as session:
        if session is None:
            return 0
        node_repo = NodeRepository(session)
        scan_repo = ScanRepository(session)
        scan = scan_repo.get_by_id(scan_id)

        count = node_repo.bulk_upsert(session_nodes)
        if scan and count:
            # Associate the upserted nodes with the scan
            nodes = [node_repo.find_by_ip_port(n["ip"], n["port"])
                     for n in session_nodes if n.get("ip")]
            nodes = [n for n in nodes if n]
            scan_repo.add_nodes(scan, nodes)
        return count


def main():
    parser = argparse.ArgumentParser(description="Full Bitcoin node DB scan")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max nodes to fetch (0 = all available within credits)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Count nodes without saving to DB")
    args = parser.parse_args()

    if not is_database_configured():
        print("ERROR: DATABASE_URL not set")
        sys.exit(1)

    init_db()
    api = shodan.Shodan(API_KEY)

    # Credit check
    info = api.info()
    credits_available = info["query_credits"]
    max_fetchable = credits_available * 100

    result_count = api.search(QUERY, limit=1)["total"]
    print(f"Nodos en Shodan: {result_count:,}")
    print(f"Créditos disponibles: {credits_available}  →  máximo {max_fetchable:,} nodos")

    target = result_count
    if args.limit > 0:
        target = min(args.limit, target)
    target = min(target, max_fetchable)
    print(f"Nodos a recuperar: {target:,}")

    if args.dry_run:
        print("(dry-run: sin escritura en BD)")
        return

    # Create scan record
    with get_db_session() as session:
        scan_repo = ScanRepository(session)
        scan = scan_repo.create(queries_executed=[QUERY], status="running")
        session.flush()
        scan_id = scan.id
        print(f"Scan iniciado en BD: ID={scan_id}\n")

    scanner = BitcoinNodeScanner(api_key=API_KEY)

    batch = []
    total_saved = 0
    start_time = time.time()
    credits_used = 0

    PAGE_SIZE = 100    # Shodan max per page
    PAGE_DELAY = 2.0   # seconds between pages (Shodan: 1 req/s, extra margin)
    RETRY_WAIT = 30    # seconds to wait after a rate limit error before retrying

    page = 1
    time.sleep(PAGE_DELAY)  # wait after the count query before first page
    try:
        while total_saved < target:
            try:
                results = api.search(QUERY, page=page, limit=PAGE_SIZE)
            except shodan.APIError as e:
                err = str(e)
                if "Rate limit" in err:
                    print(f"  Rate limit en página {page}, esperando {RETRY_WAIT}s...")
                    time.sleep(RETRY_WAIT)
                    continue  # retry same page
                if "No information available" in err or "page" in err.lower():
                    break  # No more pages
                raise

            matches = results.get("matches", [])
            if not matches:
                break

            for match in matches:
                batch.append(map_match(match, scanner))
                total_saved += 1
                if total_saved >= target:
                    break

            # Bulk save after each page
            if batch:
                bulk_save(batch, scan_id)
                credits_used = page
                elapsed = time.time() - start_time
                rate = total_saved / elapsed if elapsed > 0 else 0
                remaining = (target - total_saved) / rate if rate > 0 else 0
                print(f"  [{total_saved:>6}/{target:,}]  página: {page}  créditos: ~{credits_used}  "
                      f"velocidad: {rate:.0f}/s  ETA: {remaining:.0f}s")
                batch = []

            page += 1
            if total_saved < target:
                time.sleep(PAGE_DELAY)

    except shodan.APIError as e:
        print(f"\nError Shodan (posiblemente sin créditos): {e}")

    finally:
        elapsed = time.time() - start_time
        # Complete scan record
        with get_db_session() as session:
            scan_repo = ScanRepository(session)
            scan = scan_repo.get_by_id(scan_id)
            if scan:
                scan_repo.complete(
                    scan,
                    total_nodes=total_saved,
                    duration_seconds=elapsed,
                )
        print(f"\nFinalizado: {total_saved:,} nodos en {elapsed:.1f}s "
              f"(~{credits_used} créditos usados)")


if __name__ == "__main__":
    main()
