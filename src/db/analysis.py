"""
Historical analysis module for Bitcoin Node Scanner database.

Provides trend analysis, version tracking, and geographic distribution
analysis over time.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

from sqlalchemy import func, and_, or_, extract
from sqlalchemy.orm import Session

from .models import Node, Scan, CVEEntry, NodeVulnerability
from .connection import get_db_session

logger = logging.getLogger(__name__)


class HistoricalAnalyzer:
    """
    Analyzer for historical data and trend detection.

    Provides methods for analyzing vulnerability trends, version distribution,
    geographic patterns, and node lifecycle over time.
    """

    def __init__(self, session: Optional[Session] = None):
        """
        Initialize analyzer with optional session.

        If no session provided, methods will create their own sessions.
        """
        self._session = session

    def _get_session(self):
        """Get session from context manager if not provided."""
        if self._session:
            return self._session
        return None

    def get_vulnerability_trends(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None,
        granularity: str = "day"
    ) -> Dict[str, Any]:
        """
        Analyze vulnerability trends over time.

        Args:
            start_date: Start of analysis period
            end_date: End of analysis period (defaults to now)
            granularity: Time grouping - 'day', 'week', or 'month'

        Returns:
            Dictionary with trend data including counts by period
        """
        if end_date is None:
            end_date = datetime.utcnow()

        with get_db_session() as session:
            if session is None:
                return {"error": "Database not configured"}

            # Get nodes seen in period with vulnerability status
            nodes_in_period = session.query(Node).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date
                )
            ).all()

            # Group by date
            trends = defaultdict(lambda: {"total": 0, "vulnerable": 0, "critical": 0, "high": 0})

            for node in nodes_in_period:
                # Determine grouping key
                if granularity == "week":
                    key = node.last_seen.strftime("%Y-W%W")
                elif granularity == "month":
                    key = node.last_seen.strftime("%Y-%m")
                else:  # day
                    key = node.last_seen.strftime("%Y-%m-%d")

                trends[key]["total"] += 1
                if node.is_vulnerable:
                    trends[key]["vulnerable"] += 1
                if node.risk_level == "CRITICAL":
                    trends[key]["critical"] += 1
                elif node.risk_level == "HIGH":
                    trends[key]["high"] += 1

            # Calculate rates
            result = {
                "period": f"{start_date.date()} to {end_date.date()}",
                "granularity": granularity,
                "data": dict(trends),
                "summary": {
                    "total_nodes": len(nodes_in_period),
                    "total_vulnerable": sum(1 for n in nodes_in_period if n.is_vulnerable),
                    "vulnerability_rate": (
                        sum(1 for n in nodes_in_period if n.is_vulnerable) / len(nodes_in_period) * 100
                        if nodes_in_period else 0
                    ),
                }
            }

            return result

    def compare_periods(
        self,
        period1_start: datetime,
        period1_end: datetime,
        period2_start: datetime,
        period2_end: datetime
    ) -> Dict[str, Any]:
        """
        Compare vulnerability metrics between two periods.

        Args:
            period1_start: Start of first period
            period1_end: End of first period
            period2_start: Start of second period
            period2_end: End of second period

        Returns:
            Dictionary with comparison metrics
        """
        with get_db_session() as session:
            if session is None:
                return {"error": "Database not configured"}

            def get_period_stats(start: datetime, end: datetime) -> Dict:
                nodes = session.query(Node).filter(
                    and_(Node.last_seen >= start, Node.last_seen <= end)
                ).all()

                return {
                    "total": len(nodes),
                    "vulnerable": sum(1 for n in nodes if n.is_vulnerable),
                    "critical": sum(1 for n in nodes if n.risk_level == "CRITICAL"),
                    "high": sum(1 for n in nodes if n.risk_level == "HIGH"),
                }

            stats1 = get_period_stats(period1_start, period1_end)
            stats2 = get_period_stats(period2_start, period2_end)

            def calc_change(old: int, new: int) -> float:
                if old == 0:
                    return 100.0 if new > 0 else 0.0
                return ((new - old) / old) * 100

            return {
                "period1": {
                    "range": f"{period1_start.date()} to {period1_end.date()}",
                    **stats1
                },
                "period2": {
                    "range": f"{period2_start.date()} to {period2_end.date()}",
                    **stats2
                },
                "changes": {
                    "total_change_pct": calc_change(stats1["total"], stats2["total"]),
                    "vulnerable_change_pct": calc_change(stats1["vulnerable"], stats2["vulnerable"]),
                    "critical_change_pct": calc_change(stats1["critical"], stats2["critical"]),
                    "high_change_pct": calc_change(stats1["high"], stats2["high"]),
                }
            }

    def get_top_vulnerabilities(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most common vulnerabilities by affected node count.

        Args:
            limit: Maximum number of vulnerabilities to return

        Returns:
            List of vulnerability info with node counts
        """
        with get_db_session() as session:
            if session is None:
                return []

            result = session.query(
                CVEEntry,
                func.count(NodeVulnerability.node_id).label("node_count")
            ).join(NodeVulnerability, NodeVulnerability.cve_id == CVEEntry.cve_id).filter(
                NodeVulnerability.resolved_at.is_(None)
            ).group_by(
                CVEEntry.cve_id
            ).order_by(
                func.count(NodeVulnerability.node_id).desc()
            ).limit(limit).all()

            return [
                {
                    "cve_id": vuln.cve_id,
                    "severity": vuln.severity,
                    "description": vuln.description,
                    "affected_nodes": count,
                }
                for vuln, count in result
            ]

    def get_version_distribution(self, date: Optional[datetime] = None) -> Dict[str, int]:
        """
        Get version distribution at a specific date.

        Groups versions by major.minor (e.g., "0.21.x", "0.22.x").

        Args:
            date: Date to analyze (defaults to now)

        Returns:
            Dictionary mapping version groups to counts
        """
        if date is None:
            date = datetime.utcnow()

        with get_db_session() as session:
            if session is None:
                return {}

            nodes = session.query(Node).filter(
                Node.last_seen <= date,
                Node.version.isnot(None)
            ).all()

            distribution = defaultdict(int)
            for node in nodes:
                version = node.version or "Unknown"

                # Extract major.minor version
                version_group = self._normalize_version(version)
                distribution[version_group] += 1

            return dict(sorted(distribution.items(), key=lambda x: x[1], reverse=True))

    def _normalize_version(self, version: str) -> str:
        """Normalize version string to major.minor.x format."""
        if not version:
            return "Unknown"

        # Handle Satoshi format
        if "Satoshi:" in version:
            try:
                ver_part = version.split("Satoshi:")[1].split("/")[0]
                parts = ver_part.split(".")
                if len(parts) >= 2:
                    return f"{parts[0]}.{parts[1]}.x"
            except (IndexError, ValueError):
                pass

        # Handle standard format
        try:
            parts = version.split(".")
            if len(parts) >= 2:
                return f"{parts[0]}.{parts[1]}.x"
        except (IndexError, ValueError):
            pass

        return version

    def get_version_evolution(
        self,
        version_prefix: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, int]:
        """
        Track adoption of a specific version over time.

        Args:
            version_prefix: Version prefix to track (e.g., "0.21", "25")
            start_date: Start of tracking period (defaults to 90 days ago)
            end_date: End of tracking period (defaults to now)

        Returns:
            Dictionary mapping dates to adoption counts
        """
        if end_date is None:
            end_date = datetime.utcnow()
        if start_date is None:
            start_date = end_date - timedelta(days=90)

        with get_db_session() as session:
            if session is None:
                return {}

            # Get all scans in the period
            scans = session.query(Scan).filter(
                and_(
                    Scan.timestamp >= start_date,
                    Scan.timestamp <= end_date,
                    Scan.status == "completed"
                )
            ).order_by(Scan.timestamp).all()

            evolution = {}
            for scan in scans:
                date_key = scan.timestamp.strftime("%Y-%m-%d")

                # Count nodes with this version in the scan
                count = session.query(Node).filter(
                    Node.version.like(f"%{version_prefix}%"),
                    Node.last_seen <= scan.timestamp
                ).count()

                evolution[date_key] = count

            return evolution

    def get_geographic_distribution(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get geographic distribution of nodes in a period.

        Args:
            start_date: Start of analysis period
            end_date: End of analysis period (defaults to now)

        Returns:
            Dictionary with country distribution and changes
        """
        if end_date is None:
            end_date = datetime.utcnow()

        with get_db_session() as session:
            if session is None:
                return {}

            # Current distribution
            current = session.query(
                Node.country_code,
                func.count(Node.id).label("count")
            ).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date
                )
            ).group_by(Node.country_code).all()

            # Previous period for comparison
            period_length = end_date - start_date
            prev_start = start_date - period_length
            prev_end = start_date

            previous = session.query(
                Node.country_code,
                func.count(Node.id).label("count")
            ).filter(
                and_(
                    Node.last_seen >= prev_start,
                    Node.last_seen <= prev_end
                )
            ).group_by(Node.country_code).all()

            current_dict = {c or "Unknown": count for c, count in current}
            previous_dict = {c or "Unknown": count for c, count in previous}

            # Calculate changes
            countries = set(current_dict.keys()) | set(previous_dict.keys())
            distribution = []
            for country in countries:
                curr = current_dict.get(country, 0)
                prev = previous_dict.get(country, 0)
                change = curr - prev
                distribution.append({
                    "country": country,
                    "count": curr,
                    "previous": prev,
                    "change": change,
                    "change_pct": (change / prev * 100) if prev > 0 else (100 if curr > 0 else 0)
                })

            distribution.sort(key=lambda x: x["count"], reverse=True)

            return {
                "period": f"{start_date.date()} to {end_date.date()}",
                "total_countries": len([d for d in distribution if d["count"] > 0]),
                "distribution": distribution[:30],  # Top 30
            }

    def get_asn_concentration(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Analyze ASN concentration of nodes.

        Args:
            start_date: Start of analysis period
            end_date: End of analysis period (defaults to now)
            limit: Maximum ASNs to return

        Returns:
            List of ASN info with node counts
        """
        if end_date is None:
            end_date = datetime.utcnow()

        with get_db_session() as session:
            if session is None:
                return []

            result = session.query(
                Node.asn,
                Node.asn_name,
                func.count(Node.id).label("count")
            ).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date,
                    Node.asn.isnot(None)
                )
            ).group_by(Node.asn, Node.asn_name).order_by(
                func.count(Node.id).desc()
            ).limit(limit).all()

            total = session.query(Node).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date
                )
            ).count()

            return [
                {
                    "asn": asn,
                    "name": name or "Unknown",
                    "count": count,
                    "percentage": (count / total * 100) if total > 0 else 0
                }
                for asn, name, count in result
            ]

    def get_node_lifecycle(self, ip: str) -> Dict[str, Any]:
        """
        Get complete lifecycle history for a specific node.

        Args:
            ip: IP address of the node

        Returns:
            Dictionary with node history including version changes
        """
        with get_db_session() as session:
            if session is None:
                return {}

            nodes = session.query(Node).filter(Node.ip == ip).all()

            if not nodes:
                return {"error": "Node not found"}

            # Combine data from all ports
            history = {
                "ip": ip,
                "ports": [],
                "first_seen": None,
                "last_seen": None,
                "versions_seen": set(),
                "risk_levels": set(),
                "vulnerabilities": [],
            }

            for node in nodes:
                history["ports"].append({
                    "port": node.port,
                    "version": node.version,
                    "risk_level": node.risk_level,
                    "first_seen": node.first_seen.isoformat() if node.first_seen else None,
                    "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                })

                if node.version:
                    history["versions_seen"].add(node.version)
                if node.risk_level:
                    history["risk_levels"].add(node.risk_level)

                if history["first_seen"] is None or (node.first_seen and node.first_seen < history["first_seen"]):
                    history["first_seen"] = node.first_seen
                if history["last_seen"] is None or (node.last_seen and node.last_seen > history["last_seen"]):
                    history["last_seen"] = node.last_seen

                # Get vulnerabilities
                for nv in node.vulnerabilities:
                    history["vulnerabilities"].append({
                        "cve_id": nv.cve_entry.cve_id if nv.cve_entry else nv.cve_id,
                        "severity": nv.cve_entry.severity if nv.cve_entry else None,
                        "detected_at": nv.detected_at.isoformat() if nv.detected_at else None,
                        "resolved_at": nv.resolved_at.isoformat() if nv.resolved_at else None,
                    })

            history["versions_seen"] = list(history["versions_seen"])
            history["risk_levels"] = list(history["risk_levels"])
            history["first_seen"] = history["first_seen"].isoformat() if history["first_seen"] else None
            history["last_seen"] = history["last_seen"].isoformat() if history["last_seen"] else None

            return history

    def get_nodes_not_seen_since(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Find nodes not seen for a specified number of days.

        Args:
            days: Number of days threshold

        Returns:
            List of stale node info
        """
        threshold = datetime.utcnow() - timedelta(days=days)

        with get_db_session() as session:
            if session is None:
                return []

            nodes = session.query(Node).filter(
                Node.last_seen < threshold
            ).order_by(Node.last_seen).limit(100).all()

            return [
                {
                    "ip": node.ip,
                    "port": node.port,
                    "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                    "days_ago": (datetime.utcnow() - node.last_seen).days if node.last_seen else None,
                    "version": node.version,
                    "country": node.country_code,
                }
                for node in nodes
            ]

    def get_churn_rate(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Calculate node churn rate (new vs disappeared).

        Args:
            start_date: Start of analysis period
            end_date: End of analysis period (defaults to now)

        Returns:
            Dictionary with churn metrics
        """
        if end_date is None:
            end_date = datetime.utcnow()

        with get_db_session() as session:
            if session is None:
                return {}

            # New nodes (first_seen in period)
            new_nodes = session.query(Node).filter(
                and_(
                    Node.first_seen >= start_date,
                    Node.first_seen <= end_date
                )
            ).count()

            # Disappeared nodes (last_seen before period, first_seen before period)
            disappeared = session.query(Node).filter(
                and_(
                    Node.last_seen < start_date,
                    Node.first_seen < start_date
                )
            ).count()

            # Active nodes (seen in period)
            active = session.query(Node).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date
                )
            ).count()

            return {
                "period": f"{start_date.date()} to {end_date.date()}",
                "new_nodes": new_nodes,
                "disappeared_nodes": disappeared,
                "active_nodes": active,
                "churn_rate": (
                    ((new_nodes + disappeared) / (active + disappeared) * 100)
                    if (active + disappeared) > 0 else 0
                ),
            }

    def get_summary_statistics(
        self,
        start_date: datetime,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive summary statistics for a period.

        Args:
            start_date: Start of analysis period
            end_date: End of analysis period (defaults to now)

        Returns:
            Dictionary with all key metrics for dashboards
        """
        if end_date is None:
            end_date = datetime.utcnow()

        with get_db_session() as session:
            if session is None:
                return {}

            # Basic counts
            total_nodes = session.query(Node).filter(
                and_(Node.last_seen >= start_date, Node.last_seen <= end_date)
            ).count()

            vulnerable_nodes = session.query(Node).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date,
                    Node.is_vulnerable == True
                )
            ).count()

            critical_nodes = session.query(Node).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date,
                    Node.risk_level == "CRITICAL"
                )
            ).count()

            exposed_rpc = session.query(Node).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date,
                    Node.has_exposed_rpc == True
                )
            ).count()

            dev_versions = session.query(Node).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date,
                    Node.is_dev_version == True
                )
            ).count()

            new_nodes = session.query(Node).filter(
                and_(
                    Node.first_seen >= start_date,
                    Node.first_seen <= end_date
                )
            ).count()

            countries = session.query(func.count(func.distinct(Node.country_code))).filter(
                and_(Node.last_seen >= start_date, Node.last_seen <= end_date)
            ).scalar()

            # Top ASNs
            top_asns = session.query(
                Node.asn,
                func.count(Node.id)
            ).filter(
                and_(
                    Node.last_seen >= start_date,
                    Node.last_seen <= end_date,
                    Node.asn.isnot(None)
                )
            ).group_by(Node.asn).order_by(
                func.count(Node.id).desc()
            ).limit(5).all()

            return {
                "period": f"{start_date.date()} to {end_date.date()}",
                "total_nodes": total_nodes,
                "vulnerable_nodes": vulnerable_nodes,
                "critical_nodes": critical_nodes,
                "new_nodes": new_nodes,
                "exposed_rpc": exposed_rpc,
                "dev_versions": dev_versions,
                "unique_countries": countries,
                "vulnerability_rate": (vulnerable_nodes / total_nodes * 100) if total_nodes > 0 else 0,
                "exposed_rpc_rate": (exposed_rpc / total_nodes * 100) if total_nodes > 0 else 0,
                "dev_version_rate": (dev_versions / total_nodes * 100) if total_nodes > 0 else 0,
                "top_asns": [{"asn": asn, "count": count} for asn, count in top_asns],
            }
