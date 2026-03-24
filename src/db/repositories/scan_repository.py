"""
Repository for Scan database operations.
"""
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from sqlalchemy import select, and_
from sqlalchemy.orm import Session

from ..models import Scan, Node, ScanNode

logger = logging.getLogger(__name__)


class ScanRepository:
    """Repository for Scan CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        queries_executed: Optional[List[str]] = None,
        status: str = "running"
    ) -> Scan:
        """
        Create a new scan session.

        Args:
            queries_executed: List of Shodan queries executed
            status: Initial status (running, completed, failed)

        Returns:
            The created Scan object
        """
        scan = Scan(
            timestamp=datetime.utcnow(),
            queries_executed=json.dumps(queries_executed) if queries_executed else None,
            status=status,
        )
        self.session.add(scan)
        self.session.flush()  # Get the ID
        return scan

    def complete(
        self,
        scan: Scan,
        total_nodes: int = 0,
        critical_nodes: int = 0,
        high_risk_nodes: int = 0,
        vulnerable_nodes: int = 0,
        credits_used: int = 0,
        duration_seconds: Optional[float] = None,
    ) -> Scan:
        """
        Mark a scan as completed and update statistics.

        Args:
            scan: The Scan to complete
            total_nodes: Total number of nodes found
            critical_nodes: Number of critical risk nodes
            high_risk_nodes: Number of high risk nodes
            vulnerable_nodes: Number of vulnerable nodes
            credits_used: Shodan credits used
            duration_seconds: Scan duration in seconds

        Returns:
            The updated Scan object
        """
        scan.status = "completed"
        scan.total_nodes = total_nodes
        scan.critical_nodes = critical_nodes
        scan.high_risk_nodes = high_risk_nodes
        scan.vulnerable_nodes = vulnerable_nodes
        scan.credits_used = credits_used
        scan.duration_seconds = duration_seconds
        return scan

    def fail(self, scan: Scan, error_message: str) -> Scan:
        """
        Mark a scan as failed.

        Args:
            scan: The Scan that failed
            error_message: Error description

        Returns:
            The updated Scan object
        """
        scan.status = "failed"
        scan.error_message = error_message
        return scan

    def add_node(self, scan: Scan, node: Node) -> None:
        """Associate a node with a scan."""
        if node not in scan.nodes:
            scan.nodes.append(node)

    def add_nodes(self, scan: Scan, nodes: List[Node]) -> None:
        """Associate multiple nodes with a scan."""
        for node in nodes:
            self.add_node(scan, node)

    def get_by_id(self, scan_id: int) -> Optional[Scan]:
        """Get scan by ID."""
        return self.session.get(Scan, scan_id)

    def get_latest(self) -> Optional[Scan]:
        """Get the most recent scan."""
        stmt = select(Scan).order_by(Scan.timestamp.desc()).limit(1)
        return self.session.scalar(stmt)

    def get_by_date_range(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None,
        status: Optional[str] = None
    ) -> List[Scan]:
        """
        Get scans within a date range.

        Args:
            start_date: Start of the date range
            end_date: End of the date range (defaults to now)
            status: Filter by status (optional)

        Returns:
            List of Scan objects
        """
        if end_date is None:
            end_date = datetime.utcnow()

        conditions = [
            Scan.timestamp >= start_date,
            Scan.timestamp <= end_date,
        ]

        if status:
            conditions.append(Scan.status == status)

        stmt = select(Scan).where(and_(*conditions)).order_by(Scan.timestamp.desc())
        return list(self.session.scalars(stmt).all())

    def get_statistics(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get aggregated statistics for scans in a date range.

        Args:
            start_date: Start of the date range
            end_date: End of the date range (defaults to now)

        Returns:
            Dictionary with aggregated statistics
        """
        from sqlalchemy import func

        if end_date is None:
            end_date = datetime.utcnow()

        # Get completed scans in range
        scans = self.get_by_date_range(start_date, end_date, status="completed")

        if not scans:
            return {
                "total_scans": 0,
                "total_nodes": 0,
                "total_critical": 0,
                "total_high_risk": 0,
                "total_vulnerable": 0,
                "total_credits": 0,
                "avg_duration": 0,
            }

        total_nodes = sum(s.total_nodes for s in scans)
        total_critical = sum(s.critical_nodes for s in scans)
        total_high_risk = sum(s.high_risk_nodes for s in scans)
        total_vulnerable = sum(s.vulnerable_nodes for s in scans)
        total_credits = sum(s.credits_used for s in scans)

        durations = [s.duration_seconds for s in scans if s.duration_seconds]
        avg_duration = sum(durations) / len(durations) if durations else 0

        return {
            "total_scans": len(scans),
            "total_nodes": total_nodes,
            "total_critical": total_critical,
            "total_high_risk": total_high_risk,
            "total_vulnerable": total_vulnerable,
            "total_credits": total_credits,
            "avg_duration": avg_duration,
            "first_scan": min(s.timestamp for s in scans),
            "last_scan": max(s.timestamp for s in scans),
        }

    def count_all(self) -> int:
        """Count total scans."""
        return self.session.query(Scan).count()

    def count_by_status(self) -> Dict[str, int]:
        """Get scan count by status."""
        from sqlalchemy import func
        result = self.session.query(
            Scan.status, func.count(Scan.id)
        ).group_by(Scan.status).all()
        return {status: count for status, count in result}

    def delete(self, scan: Scan) -> None:
        """Delete a scan."""
        self.session.delete(scan)
