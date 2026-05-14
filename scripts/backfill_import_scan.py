#!/usr/bin/env python3
"""
One-off backfill: insert the Scan provenance row for a JSON import that
predates the "db-import records a Scan row" change.

JSON imports performed before that change left no row in the `scans`
table, so the dashboard's "last scan" date stayed stale. This script
inserts the missing row for a given JSON file, deriving the timestamp
from the filename the same way the importer does.

Usage:
    python scripts/backfill_import_scan.py output/raw_data/nodes_20260513_213234.json

Idempotent: skips if a `json-import:<filename>` Scan row already exists.
"""
import json
import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "scripts"))

from sqlalchemy import select

from src.db.connection import get_db_session, is_database_configured, init_db
from src.db.repositories import ScanRepository
from src.db.models import Scan
from import_json_to_db import JSONImporter


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/backfill_import_scan.py <json-file>")
        return 1

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return 1

    if not is_database_configured() or not init_db():
        print("Error: database not configured")
        return 1

    filename = os.path.basename(file_path)
    importer = JSONImporter(verbose=False)
    file_timestamp = importer._extract_timestamp(filename)

    with open(file_path) as f:
        data = json.load(f)
    nodes = data if isinstance(data, list) else data.get("nodes", [])
    nodes = [n for n in nodes if n.get("ip")]

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    vulnerable = 0
    for n in nodes:
        risk_level = importer._analyze_risk_level(n)
        if risk_level in risk_counts:
            risk_counts[risk_level] += 1
        if importer._is_vulnerable_version(n.get("version", "")):
            vulnerable += 1

    with get_db_session() as session:
        if session is None:
            print("Error: could not open DB session")
            return 1

        marker = f"json-import:{filename}"
        existing = session.scalar(select(Scan).where(Scan.queries_executed == marker))
        if existing:
            print(f"Scan row already exists (id={existing.id}); nothing to do.")
            return 0

        scan_repo = ScanRepository(session)
        scan = scan_repo.record_import(
            file_name=filename,
            total_nodes=len(nodes),
            critical_nodes=risk_counts["CRITICAL"],
            high_risk_nodes=risk_counts["HIGH"],
            vulnerable_nodes=vulnerable,
            timestamp=file_timestamp,
        )
        print(
            f"Inserted Scan row id={scan.id} timestamp={scan.timestamp} "
            f"total_nodes={scan.total_nodes} marker={marker}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
