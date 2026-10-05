#!/usr/bin/env python3
"""
Import JSON scan data into the database.

This script imports historical scan data from JSON files into the database,
handling deduplication and preserving first_seen timestamps.

Usage:
    python scripts/import_json_to_db.py path/to/nodes.json
    python scripts/import_json_to_db.py --dir output/raw_data/
    python scripts/import_json_to_db.py --all  # Import all from output/raw_data/
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.db.connection import get_db_session, is_database_configured, init_db
from src.safe_paths import UnsafePathError, safe_output_dir, safe_output_file
from src.db.importer import (
    analyze_risk_level,
    import_node,
    is_vulnerable_version,
    merge_tag,
)
from src.db.repositories import NodeRepository, ScanRepository


class ProgressBar:
    """Simple progress bar for console output."""

    def __init__(self, total: int, prefix: str = "", width: int = 50):
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0

    def update(self, current: int = None):
        if current is not None:
            self.current = current
        else:
            self.current += 1

        if self.total == 0:
            return

        percent = self.current / self.total
        filled = int(self.width * percent)
        bar = "=" * filled + "-" * (self.width - filled)
        print(f"\r{self.prefix} [{bar}] {percent*100:.1f}% ({self.current}/{self.total})", end="", flush=True)

    def finish(self):
        print()  # New line


class JSONImporter:
    """Import JSON scan data into the database."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.stats = {
            "files_processed": 0,
            "nodes_imported": 0,
            "nodes_updated": 0,
            "nodes_skipped": 0,
            "errors": 0,
        }

    def log(self, message: str):
        if self.verbose:
            print(message)

    def import_file(self, file_path: str) -> Dict[str, int]:
        """
        Import a single JSON file.

        Args:
            file_path: Path to JSON file

        Returns:
            Dictionary with import statistics
        """
        file_stats = {"imported": 0, "updated": 0, "skipped": 0, "errors": 0}

        if not os.path.exists(file_path):
            self.log(f"File not found: {file_path}")
            return file_stats
        # Dumps are only read from under OUTPUT_DIR (the path is CLI-supplied).
        try:
            safe_path = safe_output_file(file_path)
        except (UnsafePathError, OSError) as e:
            self.log(f"Refusing to import {file_path}: {e}")
            file_stats["errors"] += 1
            self.stats["errors"] += 1
            return file_stats

        self.log(f"\nImporting: {file_path}")

        try:
            with open(safe_path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            self.log(f"Error parsing JSON: {e}")
            file_stats["errors"] += 1
            return file_stats

        # Handle both list and dict formats
        if isinstance(data, dict):
            # Might be a single node or have a 'nodes' key
            if "nodes" in data:
                nodes = data["nodes"]
            elif "ip" in data:
                nodes = [data]
            else:
                nodes = list(data.values())
        elif isinstance(data, list):
            nodes = data
        else:
            self.log(f"Unexpected data format in {file_path}")
            return file_stats

        if not nodes:
            self.log("No nodes found in file")
            return file_stats

        self.log(f"Found {len(nodes)} nodes")

        # Extract timestamp from filename if available
        filename = os.path.basename(file_path)
        file_timestamp = self._extract_timestamp(filename)

        # Process nodes
        progress = ProgressBar(len(nodes), prefix="Processing")
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        vulnerable_count = 0

        with get_db_session() as session:
            if session is None:
                self.log("Database not configured")
                return file_stats

            node_repo = NodeRepository(session)

            for node_data in nodes:
                try:
                    result, risk_level, is_vulnerable = self._import_node(
                        node_repo, node_data, file_timestamp
                    )
                    if result == "imported":
                        file_stats["imported"] += 1
                    elif result == "updated":
                        file_stats["updated"] += 1
                    else:
                        file_stats["skipped"] += 1

                    if result in ("imported", "updated"):
                        if risk_level in risk_counts:
                            risk_counts[risk_level] += 1
                        if is_vulnerable:
                            vulnerable_count += 1
                except Exception as e:
                    file_stats["errors"] += 1
                    if self.verbose:
                        print(f"\nError importing node: {e}")

                progress.update()

            progress.finish()

            # Record the import as a Scan row (provenance marker) in the
            # same transaction as the nodes, so a failed import leaves no
            # completed scan behind.
            scan_repo = ScanRepository(session)
            scan_repo.record_import(
                file_name=filename,
                total_nodes=file_stats["imported"] + file_stats["updated"],
                critical_nodes=risk_counts["CRITICAL"],
                high_risk_nodes=risk_counts["HIGH"],
                vulnerable_nodes=vulnerable_count,
                timestamp=file_timestamp,
            )

        self.log(f"Imported: {file_stats['imported']}, Updated: {file_stats['updated']}, "
                f"Skipped: {file_stats['skipped']}, Errors: {file_stats['errors']}")

        self.stats["files_processed"] += 1
        self.stats["nodes_imported"] += file_stats["imported"]
        self.stats["nodes_updated"] += file_stats["updated"]
        self.stats["nodes_skipped"] += file_stats["skipped"]
        self.stats["errors"] += file_stats["errors"]

        return file_stats

    def _import_node(
        self,
        node_repo: NodeRepository,
        node_data: Dict[str, Any],
        file_timestamp: datetime = None
    ) -> tuple:
        """
        Import a single node, handling deduplication.

        Returns a tuple of (result, risk_level, is_vulnerable) where
        result is 'imported', 'updated', or 'skipped'.
        """
        # Shared with POST /api/v1/import — see src/db/importer.py.
        return import_node(node_repo, node_data, file_timestamp)

    @staticmethod
    def _merge_tag(tags_json: str, tag: str) -> str:
        """Return tags_json with `tag` added (idempotent, preserves existing)."""
        return merge_tag(tags_json, tag)

    def _analyze_risk_level(self, node_data: Dict) -> str:
        """Determine risk level for a node."""
        return analyze_risk_level(node_data)

    def _is_vulnerable_version(self, version: str) -> bool:
        """Check if version is known vulnerable."""
        return is_vulnerable_version(version)

    def _extract_timestamp(self, filename: str) -> datetime:
        """Extract timestamp from filename like nodes_20240115_120000.json"""
        try:
            # Try common formats
            parts = filename.replace(".json", "").split("_")
            for i, part in enumerate(parts):
                if len(part) == 8 and part.isdigit():
                    # YYYYMMDD format
                    if i + 1 < len(parts) and len(parts[i + 1]) == 6:
                        # Has time part
                        return datetime.strptime(f"{part}_{parts[i + 1]}", "%Y%m%d_%H%M%S")
                    return datetime.strptime(part, "%Y%m%d")
        except (ValueError, IndexError):
            pass

        return datetime.now(timezone.utc).replace(tzinfo=None)

    def import_directory(self, dir_path: str, pattern: str = "*.json") -> Dict[str, int]:
        """
        Import all JSON files from a directory.

        Args:
            dir_path: Directory path
            pattern: Glob pattern for files (default: *.json)

        Returns:
            Aggregated statistics
        """
        if not Path(dir_path).exists():
            self.log(f"Directory not found: {dir_path}")
            return self.stats
        try:
            path = safe_output_dir(dir_path)
        except UnsafePathError as e:
            self.log(f"Refusing to import from {dir_path}: {e}")
            self.stats["errors"] += 1
            return self.stats

        files = list(path.glob(pattern))
        self.log(f"Found {len(files)} JSON files in {dir_path}")

        for file_path in sorted(files):
            self.import_file(str(file_path))

        return self.stats

    def print_summary(self):
        """Print import summary."""
        print("\n" + "=" * 60)
        print("IMPORT SUMMARY")
        print("=" * 60)
        print(f"Files processed: {self.stats['files_processed']}")
        print(f"Nodes imported:  {self.stats['nodes_imported']}")
        print(f"Nodes updated:   {self.stats['nodes_updated']}")
        print(f"Nodes skipped:   {self.stats['nodes_skipped']}")
        print(f"Errors:          {self.stats['errors']}")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Import JSON scan data into the database"
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="JSON file to import"
    )
    parser.add_argument(
        "--dir", "-d",
        help="Directory containing JSON files to import"
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Import all files from output/raw_data/"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output"
    )

    args = parser.parse_args()

    # Check database configuration
    if not is_database_configured():
        print("Error: DATABASE_URL environment variable is not set")
        print("Set it to your PostgreSQL or SQLite connection string:")
        print("  export DATABASE_URL=postgresql://user:pass@localhost/dbname")
        print("  export DATABASE_URL=sqlite:///./bitcoin_scanner.db")
        sys.exit(1)

    # Initialize database
    if not init_db():
        print("Error: Failed to initialize database")
        sys.exit(1)

    importer = JSONImporter(verbose=not args.quiet)

    if args.all:
        importer.import_directory("output/raw_data")
    elif args.dir:
        importer.import_directory(args.dir)
    elif args.file:
        importer.import_file(args.file)
    else:
        parser.print_help()
        sys.exit(1)

    importer.print_summary()


if __name__ == "__main__":
    main()
