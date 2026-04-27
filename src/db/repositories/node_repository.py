"""
Repository for Node database operations.
"""
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from sqlalchemy import select, and_, or_
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from ..models import Node
from ..connection import is_postgresql, get_database_url

logger = logging.getLogger(__name__)


class NodeRepository:
    """Repository for Node CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def upsert(self, node_data: Dict[str, Any]) -> Node:
        """
        Insert or update a node based on IP and port.

        If node exists, updates last_seen and changed fields.
        If node is new, creates with first_seen and last_seen set to now.
        """
        ip = node_data.get("ip")
        port = node_data.get("port", 8333)

        existing = self.find_by_ip_port(ip, port)

        if existing:
            # Update existing node
            for key, value in node_data.items():
                if key not in ("id", "first_seen") and hasattr(existing, key):
                    setattr(existing, key, value)
            existing.last_seen = datetime.utcnow()
            return existing
        else:
            # Create new node
            now = datetime.utcnow()
            node = Node(
                ip=ip,
                port=port,
                country_code=node_data.get("country_code"),
                country_name=node_data.get("country_name"),
                city=node_data.get("city"),
                latitude=node_data.get("latitude"),
                longitude=node_data.get("longitude"),
                asn=node_data.get("asn"),
                asn_name=node_data.get("asn_name"),
                version=node_data.get("version"),
                user_agent=node_data.get("user_agent"),
                banner=node_data.get("banner"),
                protocol_version=node_data.get("protocol_version"),
                services=node_data.get("services"),
                risk_level=node_data.get("risk_level"),
                is_vulnerable=node_data.get("is_vulnerable", False),
                has_exposed_rpc=node_data.get("has_exposed_rpc", False),
                is_dev_version=node_data.get("is_dev_version", False),
                first_seen=now,
                last_seen=now,
            )
            self.session.add(node)
            return node

    def bulk_upsert(self, nodes_data: List[Dict[str, Any]], batch_size: int = 100) -> int:
        """
        Bulk insert or update nodes efficiently.

        Uses database-specific upsert functionality when available.
        Returns the number of nodes processed.
        """
        processed = 0
        database_url = get_database_url()

        for i in range(0, len(nodes_data), batch_size):
            batch = nodes_data[i:i + batch_size]

            if database_url and is_postgresql(database_url):
                # Use PostgreSQL's ON CONFLICT for efficient upsert
                processed += self._bulk_upsert_postgresql(batch)
            else:
                # Fallback to individual upserts for SQLite
                for node_data in batch:
                    self.upsert(node_data)
                    processed += 1

            self.session.flush()

        return processed

    def _bulk_upsert_postgresql(self, batch: List[Dict[str, Any]]) -> int:
        """PostgreSQL-specific bulk upsert using ON CONFLICT."""
        if not batch:
            return 0

        now = datetime.utcnow()

        # Prepare values for insert
        values = []
        for node_data in batch:
            values.append({
                "ip": node_data.get("ip"),
                "port": node_data.get("port", 8333),
                "country_code": node_data.get("country_code"),
                "country_name": node_data.get("country_name"),
                "city": node_data.get("city"),
                "latitude": node_data.get("latitude"),
                "longitude": node_data.get("longitude"),
                "asn": node_data.get("asn"),
                "asn_name": node_data.get("asn_name"),
                "version": node_data.get("version"),
                "user_agent": node_data.get("user_agent"),
                "banner": node_data.get("banner"),
                "protocol_version": node_data.get("protocol_version"),
                "services": node_data.get("services"),
                "risk_level": node_data.get("risk_level"),
                "is_vulnerable": node_data.get("is_vulnerable", False),
                "has_exposed_rpc": node_data.get("has_exposed_rpc", False),
                "is_dev_version": node_data.get("is_dev_version", False),
                "first_seen": now,
                "last_seen": now,
            })

        stmt = pg_insert(Node).values(values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["ip", "port"],
            set_={
                "country_code": stmt.excluded.country_code,
                "country_name": stmt.excluded.country_name,
                "city": stmt.excluded.city,
                "latitude": stmt.excluded.latitude,
                "longitude": stmt.excluded.longitude,
                "asn": stmt.excluded.asn,
                "asn_name": stmt.excluded.asn_name,
                "version": stmt.excluded.version,
                "user_agent": stmt.excluded.user_agent,
                "banner": stmt.excluded.banner,
                "protocol_version": stmt.excluded.protocol_version,
                "services": stmt.excluded.services,
                "risk_level": stmt.excluded.risk_level,
                "is_vulnerable": stmt.excluded.is_vulnerable,
                "has_exposed_rpc": stmt.excluded.has_exposed_rpc,
                "is_dev_version": stmt.excluded.is_dev_version,
                "last_seen": now,
            }
        )

        self.session.execute(stmt)
        return len(batch)

    def find_by_ip(self, ip: str) -> List[Node]:
        """Find all nodes with the given IP address."""
        stmt = select(Node).where(Node.ip == ip)
        return list(self.session.scalars(stmt).all())

    def find_by_ip_port(self, ip: str, port: int) -> Optional[Node]:
        """Find a specific node by IP and port."""
        stmt = select(Node).where(and_(Node.ip == ip, Node.port == port))
        return self.session.scalar(stmt)

    def find_vulnerable(self, since: Optional[datetime] = None) -> List[Node]:
        """Find all vulnerable nodes, optionally filtered by last_seen date."""
        conditions = [Node.is_vulnerable == True]
        if since:
            conditions.append(Node.last_seen >= since)
        stmt = select(Node).where(and_(*conditions)).order_by(Node.last_seen.desc())
        return list(self.session.scalars(stmt).all())

    def find_by_country(self, country_code: str) -> List[Node]:
        """Find all nodes in a specific country."""
        stmt = select(Node).where(Node.country_code == country_code).order_by(Node.last_seen.desc())
        return list(self.session.scalars(stmt).all())

    def find_by_risk_level(self, risk_level: str) -> List[Node]:
        """Find all nodes with a specific risk level."""
        stmt = select(Node).where(Node.risk_level == risk_level).order_by(Node.last_seen.desc())
        return list(self.session.scalars(stmt).all())

    def find_critical_and_high(self) -> List[Node]:
        """Find all nodes with CRITICAL or HIGH risk level."""
        stmt = select(Node).where(
            or_(Node.risk_level == "CRITICAL", Node.risk_level == "HIGH")
        ).order_by(Node.risk_level, Node.last_seen.desc())
        return list(self.session.scalars(stmt).all())

    def find_not_seen_since(self, since: datetime) -> List[Node]:
        """Find nodes not seen since a specific date."""
        stmt = select(Node).where(Node.last_seen < since).order_by(Node.last_seen)
        return list(self.session.scalars(stmt).all())

    def count_all(self) -> int:
        """Count total nodes."""
        return self.session.query(Node).count()

    def count_vulnerable(self) -> int:
        """Count vulnerable nodes."""
        return self.session.query(Node).filter(Node.is_vulnerable == True).count()

    def count_by_country(self) -> Dict[str, int]:
        """Get node count by country."""
        from sqlalchemy import func
        result = self.session.query(
            Node.country_code, func.count(Node.id)
        ).group_by(Node.country_code).all()
        return {country or "Unknown": count for country, count in result}

    def count_by_risk_level(self) -> Dict[str, int]:
        """Get node count by risk level."""
        from sqlalchemy import func
        result = self.session.query(
            Node.risk_level, func.count(Node.id)
        ).group_by(Node.risk_level).all()
        return {level or "Unknown": count for level, count in result}

    def count_exposed(self) -> int:
        """Count nodes with exposed RPC."""
        return self.session.query(Node).filter(Node.has_exposed_rpc == True).count()

    def count_stale(self, before: datetime) -> int:
        """Count nodes whose last_seen is older than `before`."""
        return self.session.query(Node).filter(Node.last_seen < before).count()

    def count_tor(self) -> int:
        """Count nodes with a tor signal — `tor` in the tag set or a `.onion` hostname."""
        return (
            self.session.query(Node)
            .filter(or_(Node.tags_json.like("%tor%"), Node.hostname.like("%.onion")))
            .count()
        )

    def count_ok(self, stale_before: datetime) -> int:
        """
        Count nodes considered "clean": LOW risk, no exposed RPC, recent last_seen.
        Stricter than the complement of EXPOSED/STALE/TOR — those categories can
        overlap with each other, so a strip-friendly OK count uses positive criteria.
        """
        return (
            self.session.query(Node)
            .filter(
                Node.risk_level == "LOW",
                Node.has_exposed_rpc == False,
                Node.last_seen >= stale_before,
            )
            .count()
        )

    def get_by_id(self, node_id: int) -> Optional[Node]:
        """Get node by ID."""
        return self.session.get(Node, node_id)

    def delete(self, node: Node) -> None:
        """Delete a node."""
        self.session.delete(node)
