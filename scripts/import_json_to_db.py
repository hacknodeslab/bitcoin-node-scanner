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
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.db.connection import get_db_session, is_database_configured, init_db
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

        self.log(f"\nImporting: {file_path}")

        try:
            with open(file_path, "r") as f:
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

        with get_db_session() as session:
            if session is None:
                self.log("Database not configured")
                return file_stats

            node_repo = NodeRepository(session)

            for node_data in nodes:
                try:
                    result = self._import_node(node_repo, node_data, file_timestamp)
                    if result == "imported":
                        file_stats["imported"] += 1
                    elif result == "updated":
                        file_stats["updated"] += 1
                    else:
                        file_stats["skipped"] += 1
                except Exception as e:
                    file_stats["errors"] += 1
                    if self.verbose:
                        print(f"\nError importing node: {e}")

                progress.update()

            progress.finish()

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
    ) -> str:
        """
        Import a single node, handling deduplication.

        Returns 'imported', 'updated', or 'skipped'.
        """
        ip = node_data.get("ip")
        if not ip:
            return "skipped"

        port = node_data.get("port", 8333)

        # Check if node exists
        existing = node_repo.find_by_ip_port(ip, port)

        # Prepare data
        db_data = {
            "ip": ip,
            "port": port,
            "country_code": node_data.get("country_code"),
            "country_name": node_data.get("country"),
            "city": node_data.get("city"),
            "asn": node_data.get("asn"),
            "asn_name": node_data.get("organization") or node_data.get("isp"),
            "version": node_data.get("version"),
            "user_agent": node_data.get("product"),
            "banner": node_data.get("banner"),
        }

        # Determine risk level
        db_data["risk_level"] = self._analyze_risk_level(node_data)
        db_data["is_vulnerable"] = self._is_vulnerable_version(node_data.get("version", ""))
        db_data["has_exposed_rpc"] = port == 8332
        db_data["is_dev_version"] = ".99." in node_data.get("version", "")

        if existing:
            # Update existing node, preserve first_seen
            for key, value in db_data.items():
                if key not in ("id", "first_seen") and value is not None:
                    setattr(existing, key, value)
            existing.last_seen = file_timestamp or datetime.utcnow()
            return "updated"
        else:
            # Create new node
            node_repo.upsert(db_data)
            return "imported"

    def _analyze_risk_level(self, node_data: Dict) -> str:
        """Determine risk level for a node."""
        if node_data.get("port") == 8332:
            return "CRITICAL"

        risk_factors = 0
        if self._is_vulnerable_version(node_data.get("version", "")):
            risk_factors += 1
        if ".99." in node_data.get("version", ""):
            risk_factors += 1

        if risk_factors >= 2:
            return "HIGH"
        elif risk_factors == 1:
            return "MEDIUM"
        return "LOW"

    def _is_vulnerable_version(self, version: str) -> bool:
        """Check if version is known vulnerable."""
        # Load vulnerable versions from config
        try:
            from src.scanner import Config
            for vuln_version in Config.VULNERABLE_VERSIONS.keys():
                if vuln_version in version:
                    return True
        except ImportError:
            pass

        # Basic check for old versions
        if "Satoshi:0." in version:
            try:
                ver_num = version.split(":")[1].split(".")[1]
                if int(ver_num) < 21:
                    return True
            except (IndexError, ValueError):
                pass

        return False

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

        return datetime.utcnow()

    def import_directory(self, dir_path: str, pattern: str = "*.json") -> Dict[str, int]:
        """
        Import all JSON files from a directory.

        Args:
            dir_path: Directory path
            pattern: Glob pattern for files (default: *.json)

        Returns:
            Aggregated statistics
        """
        path = Path(dir_path)
        if not path.exists():
            self.log(f"Directory not found: {dir_path}")
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
