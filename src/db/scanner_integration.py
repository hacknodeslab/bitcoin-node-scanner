"""
Database integration for BitcoinNodeScanner.

This module provides a mixin class that adds database persistence
capabilities to the scanner without modifying the original class.
"""
import json
import logging
import socket
import struct
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

from .connection import get_db_session, is_database_configured, init_db
from .repositories import NodeRepository, ScanRepository, VulnerabilityRepository
from .models import Node, Scan

logger = logging.getLogger(__name__)


class DatabaseScannerMixin:
    """
    Mixin that adds database persistence to BitcoinNodeScanner.

    Usage:
        class MyScanner(DatabaseScannerMixin, BitcoinNodeScanner):
            pass

        scanner = MyScanner()
        scanner.run_full_scan()  # Results automatically saved to DB
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._db_enabled = is_database_configured()
        self._current_scan: Optional[Scan] = None
        self._current_scan_id: Optional[int] = None
        self._scan_start_time: Optional[float] = None

        if self._db_enabled:
            init_db()
            self.log("Database persistence enabled")
        else:
            self.log("Database not configured, using file-only mode")

    def _save_node_to_db(self, node_data: Dict[str, Any]) -> Optional[Node]:
        """
        Save a single node to the database.

        Args:
            node_data: Node data from parse_node_data()

        Returns:
            The saved Node object, or None if DB not configured
        """
        if not self._db_enabled:
            return None

        with get_db_session() as session:
            if session is None:
                return None

            node_repo = NodeRepository(session)

            # Map scanner data to DB model fields
            db_data = self._map_node_data(node_data)

            # Determine risk level
            risk_level = self.analyze_risk_level(node_data)
            db_data["risk_level"] = risk_level
            db_data["is_vulnerable"] = self.is_vulnerable_version(
                node_data.get("version", "")
            )
            db_data["has_exposed_rpc"] = node_data.get("port") == 8332
            db_data["is_dev_version"] = ".99." in node_data.get("version", "")

            node = node_repo.upsert(db_data)

            # Associate with current scan (re-fetch to avoid DetachedInstanceError)
            if self._current_scan_id and node:
                scan_repo = ScanRepository(session)
                scan = scan_repo.get_by_id(self._current_scan_id)
                if scan:
                    scan_repo.add_node(scan, node)

            return node

    @staticmethod
    def _ip_to_int(ip: str) -> int:
        try:
            return struct.unpack("!I", socket.inet_aton(ip))[0]
        except Exception:
            return 0

    def _map_node_data(self, node_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map scanner node data to database model fields."""
        ip = node_data.get("ip")

        # JSON-serialise list fields; None if empty/missing
        hostnames = node_data.get("hostnames") or []
        vulns = node_data.get("vulns") or []
        cpe = node_data.get("cpe") or []
        tags = node_data.get("tags") or []

        # Enrichment (full host scan) — open_ports_json and tags override
        enrichment = node_data.get("enrichment") or {}
        all_services = enrichment.get("all_services") or []
        enrichment_tags = enrichment.get("tags") or tags  # prefer enrichment tags if present
        enrichment_os = enrichment.get("os") or node_data.get("os") or None

        return {
            "ip": ip,
            "ip_numeric": self._ip_to_int(ip) if ip else None,
            "port": node_data.get("port", 8333),
            "country_code": node_data.get("country_code"),
            "country_name": node_data.get("country"),
            "city": node_data.get("city"),
            "subdivision": node_data.get("subdivision"),
            "latitude": node_data.get("latitude"),
            "longitude": node_data.get("longitude"),
            "asn": node_data.get("asn"),
            "asn_name": node_data.get("organization"),
            "geo_country_code": node_data.get("geo_country_code"),
            "geo_country_name": node_data.get("geo_country_name"),
            "version": node_data.get("version"),
            "user_agent": node_data.get("product"),
            "banner": node_data.get("banner"),
            # Enrichment fields
            "hostname": hostnames[0] if hostnames else None,
            "os_info": enrichment_os or None,
            "isp": node_data.get("isp") or None,
            "org": node_data.get("organization") or None,
            "vulns_json": json.dumps(vulns) if vulns else None,
            "cpe_json": json.dumps(cpe) if cpe else None,
            "tags_json": json.dumps(enrichment_tags) if enrichment_tags else None,
            "open_ports_json": json.dumps(all_services) if all_services else None,
        }

    def _start_scan_session(self, queries: List[str]) -> Optional[Scan]:
        """
        Create a new scan session in the database.

        Args:
            queries: List of queries being executed

        Returns:
            The created Scan object, or None if DB not configured
        """
        if not self._db_enabled:
            return None

        self._scan_start_time = time.time()

        with get_db_session() as session:
            if session is None:
                return None

            scan_repo = ScanRepository(session)
            self._current_scan = scan_repo.create(
                queries_executed=queries,
                status="running"
            )
            # Flush to get the ID before session closes
            session.flush()
            self._current_scan_id = self._current_scan.id
            self.log(f"Database scan session created: ID={self._current_scan_id}")
            return self._current_scan

    def _complete_scan_session(self, stats: Dict[str, Any]) -> None:
        """
        Mark the scan session as completed and save statistics.

        Args:
            stats: Statistics dictionary from generate_statistics()
        """
        if not self._db_enabled or self._current_scan_id is None:
            return

        duration = None
        if self._scan_start_time:
            duration = time.time() - self._scan_start_time

        with get_db_session() as session:
            if session is None:
                return

            scan_repo = ScanRepository(session)

            # Fetch fresh scan object in this session
            scan = scan_repo.get_by_id(self._current_scan_id)
            if scan:
                scan_repo.complete(
                    scan,
                    total_nodes=stats.get("total_results", 0),
                    critical_nodes=stats.get("risk_distribution", {}).get("CRITICAL", 0),
                    high_risk_nodes=stats.get("risk_distribution", {}).get("HIGH", 0),
                    vulnerable_nodes=stats.get("vulnerable_nodes", 0),
                    credits_used=getattr(self, "credit_usage", {}).get("query_credits_used", 0),
                    duration_seconds=duration,
                )
                self.log(f"Database scan session completed: ID={scan.id}")

        self._current_scan = None
        self._current_scan_id = None
        self._scan_start_time = None

    def _save_nodes_bulk(self, nodes_data: List[Dict[str, Any]]) -> int:
        """
        Save multiple nodes to the database efficiently.

        Args:
            nodes_data: List of node data dictionaries

        Returns:
            Number of nodes saved
        """
        if not self._db_enabled:
            return 0

        with get_db_session() as session:
            if session is None:
                return 0

            node_repo = NodeRepository(session)

            # Map all node data
            db_nodes = []
            for node_data in nodes_data:
                db_data = self._map_node_data(node_data)
                db_data["risk_level"] = self.analyze_risk_level(node_data)
                db_data["is_vulnerable"] = self.is_vulnerable_version(
                    node_data.get("version", "")
                )
                db_data["has_exposed_rpc"] = node_data.get("port") == 8332
                db_data["is_dev_version"] = ".99." in node_data.get("version", "")
                db_nodes.append(db_data)

            count = node_repo.bulk_upsert(db_nodes)
            self.log(f"Saved {count} nodes to database")
            return count


class DatabaseEnabledScanner(DatabaseScannerMixin):
    """
    A wrapper that adds database capabilities to any scanner.

    This class can wrap either BitcoinNodeScanner or OptimizedBitcoinScanner.
    """

    def __init__(self, scanner_class, *args, **kwargs):
        """
        Initialize with a specific scanner class.

        Args:
            scanner_class: The scanner class to wrap (BitcoinNodeScanner or OptimizedBitcoinScanner)
            *args, **kwargs: Arguments passed to the scanner class
        """
        # Store scanner class for reference
        self._scanner_class = scanner_class

        # Create mixin-enabled scanner dynamically
        class _DBScanner(DatabaseScannerMixin, scanner_class):
            pass

        self._scanner = _DBScanner(*args, **kwargs)

    def __getattr__(self, name):
        """Delegate attribute access to the wrapped scanner."""
        return getattr(self._scanner, name)

    def run_full_scan(self, *args, **kwargs):
        """Run full scan with database persistence."""
        # Start scan session
        self._scanner._start_scan_session(self._scanner.__class__.__bases__[1].QUERIES if hasattr(self._scanner.__class__.__bases__[1], 'QUERIES') else [])

        try:
            # Run the original scan
            result = self._scanner.run_full_scan(*args, **kwargs)

            # Save results to database
            if self._scanner.results:
                self._scanner._save_nodes_bulk(self._scanner.results)

            # Complete scan session with statistics
            stats = self._scanner.generate_statistics()
            self._scanner._complete_scan_session(stats)

            return result
        except Exception as e:
            # Mark scan as failed
            if self._scanner._current_scan:
                with get_db_session() as session:
                    if session:
                        scan_repo = ScanRepository(session)
                        scan = scan_repo.get_by_id(self._scanner._current_scan.id)
                        if scan:
                            scan_repo.fail(scan, str(e))
            raise

    def run_optimized_scan(self, *args, **kwargs):
        """Run optimized scan with database persistence."""
        from ..scanner import OptimizedConfig

        # Start scan session
        self._scanner._start_scan_session(OptimizedConfig.QUERIES_OPTIMIZED)

        try:
            # Run the original scan
            result = self._scanner.run_optimized_scan(*args, **kwargs)

            # Save results to database
            if self._scanner.results:
                self._scanner._save_nodes_bulk(self._scanner.results)

            # Complete scan session with statistics
            stats = self._scanner.generate_statistics()
            self._scanner._complete_scan_session(stats)

            return result
        except Exception as e:
            # Mark scan as failed
            if self._scanner._current_scan:
                with get_db_session() as session:
                    if session:
                        scan_repo = ScanRepository(session)
                        scan = scan_repo.get_by_id(self._scanner._current_scan.id)
                        if scan:
                            scan_repo.fail(scan, str(e))
            raise


def create_db_scanner(use_optimized: bool = False, **kwargs):
    """
    Factory function to create a database-enabled scanner.

    Args:
        use_optimized: Use OptimizedBitcoinScanner instead of BitcoinNodeScanner
        **kwargs: Arguments passed to the scanner

    Returns:
        DatabaseEnabledScanner instance
    """
    from ..scanner import BitcoinNodeScanner, OptimizedBitcoinScanner

    scanner_class = OptimizedBitcoinScanner if use_optimized else BitcoinNodeScanner
    return DatabaseEnabledScanner(scanner_class, **kwargs)
