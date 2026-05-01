#!/usr/bin/env python3
"""
Database CLI commands for Bitcoin Node Scanner.

Provides subcommands for database operations:
- db-stats: Show database statistics
- db-trends: Analyze vulnerability trends
- db-export: Export historical data
- db-import: Import JSON data

Usage:
    python -m src.db.cli db-stats
    python -m src.db.cli db-trends --days 30
    python -m src.db.cli db-export --output export.json
    python -m src.db.cli db-import path/to/file.json
"""
import argparse
import json
import sys
import os
from datetime import datetime, timedelta
from typing import Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.db.connection import is_database_configured, init_db, get_db_session
from src.db.analysis import HistoricalAnalyzer
from src.db.repositories import NodeRepository, ScanRepository, VulnerabilityRepository


def cmd_stats(args):
    """Show database statistics."""
    if not is_database_configured():
        print("Error: DATABASE_URL not configured")
        return 1

    init_db()

    days = args.days or 30
    start_date = datetime.utcnow() - timedelta(days=days)

    analyzer = HistoricalAnalyzer()
    stats = analyzer.get_summary_statistics(start_date)

    if "error" in stats:
        print(f"Error: {stats['error']}")
        return 1

    print("\n" + "=" * 60)
    print("BITCOIN NODE SCANNER - DATABASE STATISTICS")
    print("=" * 60)
    print(f"Period: {stats['period']}")
    print()
    print(f"Total Nodes:        {stats['total_nodes']:,}")
    print(f"Vulnerable Nodes:   {stats['vulnerable_nodes']:,} ({stats['vulnerability_rate']:.1f}%)")
    print(f"Critical Nodes:     {stats['critical_nodes']:,}")
    print(f"New Nodes:          {stats['new_nodes']:,}")
    print(f"Exposed RPC:        {stats['exposed_rpc']:,} ({stats['exposed_rpc_rate']:.1f}%)")
    print(f"Dev Versions:       {stats['dev_versions']:,} ({stats['dev_version_rate']:.1f}%)")
    print(f"Unique Countries:   {stats['unique_countries']}")
    print()
    print("Top ASNs:")
    for asn_info in stats.get('top_asns', []):
        print(f"  {asn_info['asn']}: {asn_info['count']:,} nodes")
    print("=" * 60)

    return 0


def cmd_trends(args):
    """Analyze vulnerability trends."""
    if not is_database_configured():
        print("Error: DATABASE_URL not configured")
        return 1

    init_db()

    days = args.days or 30
    granularity = args.granularity or "day"
    start_date = datetime.utcnow() - timedelta(days=days)

    analyzer = HistoricalAnalyzer()
    trends = analyzer.get_vulnerability_trends(start_date, granularity=granularity)

    if "error" in trends:
        print(f"Error: {trends['error']}")
        return 1

    print("\n" + "=" * 60)
    print("VULNERABILITY TRENDS")
    print("=" * 60)
    print(f"Period: {trends['period']}")
    print(f"Granularity: {trends['granularity']}")
    print()

    print(f"{'Date':<15} {'Total':>8} {'Vulnerable':>12} {'Critical':>10} {'High':>8}")
    print("-" * 60)

    for date_key in sorted(trends['data'].keys()):
        data = trends['data'][date_key]
        print(f"{date_key:<15} {data['total']:>8} {data['vulnerable']:>12} {data['critical']:>10} {data['high']:>8}")

    print()
    print("Summary:")
    print(f"  Total Nodes: {trends['summary']['total_nodes']:,}")
    print(f"  Vulnerable:  {trends['summary']['total_vulnerable']:,}")
    print(f"  Rate:        {trends['summary']['vulnerability_rate']:.1f}%")
    print("=" * 60)

    return 0


def cmd_export(args):
    """Export historical data."""
    if not is_database_configured():
        print("Error: DATABASE_URL not configured")
        return 1

    init_db()

    output_file = args.output or f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    days = args.days or 30
    start_date = datetime.utcnow() - timedelta(days=days)

    with get_db_session() as session:
        if session is None:
            print("Error: Could not connect to database")
            return 1

        node_repo = NodeRepository(session)
        scan_repo = ScanRepository(session)

        # Get nodes in date range
        from src.db.models import Node
        from sqlalchemy import and_

        nodes = session.query(Node).filter(
            and_(
                Node.last_seen >= start_date,
                Node.last_seen <= datetime.utcnow()
            )
        ).all()

        # Get scans in date range
        scans = scan_repo.get_by_date_range(start_date)

        export_data = {
            "export_date": datetime.utcnow().isoformat(),
            "period": {
                "start": start_date.isoformat(),
                "end": datetime.utcnow().isoformat(),
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

    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=2)

    print(f"Exported {len(nodes)} nodes and {len(scans)} scans to {output_file}")
    return 0


def cmd_import(args):
    """Import JSON data."""
    if not args.file:
        print("Error: No file specified")
        return 1

    # Delegate to the import script
    import subprocess  # nosec B404
    result = subprocess.run(  # nosec B603
        [sys.executable, "scripts/import_json_to_db.py", args.file],
        cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
    return result.returncode


def cmd_node(args):
    """Get node lifecycle information."""
    if not args.ip:
        print("Error: No IP specified")
        return 1

    if not is_database_configured():
        print("Error: DATABASE_URL not configured")
        return 1

    init_db()

    analyzer = HistoricalAnalyzer()
    lifecycle = analyzer.get_node_lifecycle(args.ip)

    if "error" in lifecycle:
        print(f"Error: {lifecycle['error']}")
        return 1

    print("\n" + "=" * 60)
    print(f"NODE LIFECYCLE: {lifecycle['ip']}")
    print("=" * 60)
    print(f"First Seen: {lifecycle['first_seen']}")
    print(f"Last Seen:  {lifecycle['last_seen']}")
    print()
    print("Ports:")
    for port_info in lifecycle['ports']:
        print(f"  {port_info['port']}: {port_info['version']} ({port_info['risk_level']})")
    print()
    print(f"Versions Seen: {', '.join(lifecycle['versions_seen'])}")
    print(f"Risk Levels:   {', '.join(lifecycle['risk_levels'])}")
    print()
    if lifecycle['vulnerabilities']:
        print("Vulnerabilities:")
        for vuln in lifecycle['vulnerabilities']:
            status = "ACTIVE" if not vuln['resolved_at'] else f"Resolved: {vuln['resolved_at']}"
            print(f"  {vuln['cve_id']} ({vuln['severity']}): {status}")
    print("=" * 60)

    return 0


def cmd_enrich_geo(args):
    """Retroactively enrich all nodes in the database with MaxMind GeoIP data."""
    if not is_database_configured():
        print("Error: DATABASE_URL not configured")
        return 1

    from src.geoip import GeoIPService

    db_dir = os.getenv("GEOIP_DB_DIR", "./geoip_dbs")
    geoip = GeoIPService(db_dir=db_dir)

    # Trigger lazy init to check availability before iterating the whole DB
    geoip._init_readers()
    if not geoip._available:
        print(
            f"Error: MaxMind GeoLite2 databases not found in '{db_dir}'.\n"
            "Run scripts/download_geoip_dbs.sh to download them, then re-run this command."
        )
        return 1

    init_db()

    BATCH_SIZE = 500
    total = updated = skipped = no_match = 0

    from src.db.models import Node
    from sqlalchemy import select

    with get_db_session() as session:
        if session is None:
            print("Error: Could not connect to database")
            return 1

        # Count total
        total = session.query(Node).count()
        print(f"Enriching {total} nodes with MaxMind GeoIP data...")

        offset = 0
        while True:
            stmt = select(Node).offset(offset).limit(BATCH_SIZE)
            batch = list(session.scalars(stmt).all())
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
            offset += BATCH_SIZE
            print(f"  Processed {min(offset, total)}/{total}...", end="\r")

    geoip.close()
    print()
    print("=" * 50)
    print("GEO ENRICHMENT COMPLETE")
    print("=" * 50)
    print(f"  Total nodes:  {total}")
    print(f"  Updated:      {updated}")
    print(f"  Skipped:      {skipped}  (already complete)")
    print(f"  No match:     {no_match}  (not in MaxMind DB)")
    return 0


def cmd_link_cves(args):
    """Backfill or refresh CVE links for all nodes (or those of a single scan)."""
    if not is_database_configured():
        print("Error: DATABASE_URL not configured")
        return 1

    init_db()

    from src.db.models import CVEEntry, Node, ScanNode
    from sqlalchemy import select
    from src.nvd.matcher import CVEMatcher

    with get_db_session() as session:
        if session is None:
            print("Error: Could not connect to database")
            return 1

        entries = list(session.scalars(select(CVEEntry)).all())
        matcher = CVEMatcher(entries)
        print(f"Loaded {len(entries)} CVE entries from catalog ({matcher.cve_count} matchable).")

        # Resolve node selection
        if args.scan_id:
            stmt = select(Node).join(ScanNode, ScanNode.c.node_id == Node.id).where(
                ScanNode.c.scan_id == args.scan_id
            )
        else:
            stmt = select(Node)
        nodes = list(session.scalars(stmt).all())

        vuln_repo = VulnerabilityRepository(session)
        total_added = 0
        total_resolved = 0
        skipped = 0
        for node in nodes:
            expected = matcher.matches_for(node.version)
            if not expected and not node.version:
                skipped += 1
                continue
            added, resolved = vuln_repo.sync_node_links(node, expected)
            total_added += added
            total_resolved += resolved

        session.commit()

    print("=" * 50)
    print("CVE LINK BACKFILL COMPLETE")
    print("=" * 50)
    print(f"  Nodes processed:  {len(nodes)}")
    print(f"  Skipped (no version): {skipped}")
    print(f"  Links created:    {total_added}")
    print(f"  Links resolved:   {total_resolved}")
    return 0


def cmd_mark_examples(args):
    """Backfill the is_example flag on existing nodes."""
    if not is_database_configured():
        print("Error: DATABASE_URL not configured")
        return 1

    init_db()

    with get_db_session() as session:
        if session is None:
            print("Error: Could not connect to database")
            return 1

        node_repo = NodeRepository(session)
        result = node_repo.backfill_example_flag()

    print("=" * 50)
    print("EXAMPLE IP BACKFILL COMPLETE")
    print("=" * 50)
    print(f"  Flagged (set True):   {result['flagged']}")
    print(f"  Cleared (set False):  {result['cleared']}")
    return 0


def cmd_seed_examples(args):
    """Upsert the canonical example nodes (idempotent).

    With --purge-extras, also delete any other rows whose `is_example=True`
    but whose (ip, port) is not part of the canonical seed set — useful when
    legacy scans left example-IP rows at non-canonical ports.
    """
    if not is_database_configured():
        print("Error: DATABASE_URL not configured")
        return 1

    init_db()

    from src.example_ips import EXAMPLE_NODES

    canonical_keys = [(n["ip"], n["port"]) for n in EXAMPLE_NODES]
    purged = 0

    with get_db_session() as session:
        if session is None:
            print("Error: Could not connect to database")
            return 1

        node_repo = NodeRepository(session)
        for node_data in EXAMPLE_NODES:
            node_repo.upsert({**node_data, "is_example": True})

        if getattr(args, "purge_extras", False):
            purged = node_repo.purge_example_extras(canonical_keys)

    print("=" * 50)
    print("EXAMPLE NODES SEEDED")
    print("=" * 50)
    for n in EXAMPLE_NODES:
        print(f"  {n['ip']}:{n['port']:<5}  {n['risk_level']:<8}  {n['country_name']}")
    if getattr(args, "purge_extras", False):
        print(f"  Purged extras: {purged}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Bitcoin Node Scanner Database CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # db-stats command
    stats_parser = subparsers.add_parser("db-stats", help="Show database statistics")
    stats_parser.add_argument("--days", "-d", type=int, default=30, help="Number of days to analyze")

    # db-trends command
    trends_parser = subparsers.add_parser("db-trends", help="Analyze vulnerability trends")
    trends_parser.add_argument("--days", "-d", type=int, default=30, help="Number of days to analyze")
    trends_parser.add_argument("--granularity", "-g", choices=["day", "week", "month"], default="day")

    # db-export command
    export_parser = subparsers.add_parser("db-export", help="Export historical data")
    export_parser.add_argument("--output", "-o", help="Output file path")
    export_parser.add_argument("--days", "-d", type=int, default=30, help="Number of days to export")

    # db-import command
    import_parser = subparsers.add_parser("db-import", help="Import JSON data")
    import_parser.add_argument("file", help="JSON file to import")

    # db-node command
    node_parser = subparsers.add_parser("db-node", help="Get node lifecycle information")
    node_parser.add_argument("ip", help="IP address of the node")

    # enrich-geo command
    subparsers.add_parser(
        "enrich-geo",
        help="Retroactively enrich all nodes with MaxMind GeoIP data (requires GEOIP_DB_DIR)",
    )

    # db-link-cves command
    link_parser = subparsers.add_parser(
        "db-link-cves",
        help="Backfill node→CVE links from cve_entries (rebuilds node_vulnerabilities)",
    )
    link_parser.add_argument(
        "--scan-id",
        type=int,
        default=None,
        help="Limit backfill to nodes of a specific scan id",
    )

    # db-mark-examples command
    subparsers.add_parser(
        "db-mark-examples",
        help="Reconcile is_example flag on existing nodes against the canonical example IP list",
    )

    # db-seed-examples command
    seed_parser = subparsers.add_parser(
        "db-seed-examples",
        help="Upsert the canonical example nodes (idempotent) so the dashboard has demo rows",
    )
    seed_parser.add_argument(
        "--purge-extras",
        action="store_true",
        default=False,
        help="Also delete is_example=True rows whose (ip, port) is not in the canonical seed set",
    )

    args = parser.parse_args()

    if args.command == "db-stats":
        return cmd_stats(args)
    elif args.command == "db-trends":
        return cmd_trends(args)
    elif args.command == "db-export":
        return cmd_export(args)
    elif args.command == "db-import":
        return cmd_import(args)
    elif args.command == "db-node":
        return cmd_node(args)
    elif args.command == "enrich-geo":
        return cmd_enrich_geo(args)
    elif args.command == "db-link-cves":
        return cmd_link_cves(args)
    elif args.command == "db-mark-examples":
        return cmd_mark_examples(args)
    elif args.command == "db-seed-examples":
        return cmd_seed_examples(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
