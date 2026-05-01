"""
SQLAlchemy models for Bitcoin Node Scanner database.
"""
from datetime import datetime
from typing import List, Optional
import uuid

import sqlalchemy as sa
from sqlalchemy import (
    Boolean, Column, Integer, String, Float, DateTime, Text, ForeignKey, Index, Table
)
from sqlalchemy.sql import expression
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


# Association table for many-to-many relationship between Scan and Node
ScanNode = Table(
    'scan_nodes',
    Base.metadata,
    Column('scan_id', Integer, ForeignKey('scans.id', ondelete='CASCADE'), primary_key=True),
    Column('node_id', Integer, ForeignKey('nodes.id', ondelete='CASCADE'), primary_key=True),
)


class Node(Base):
    """Model representing a Bitcoin node."""
    __tablename__ = 'nodes'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv6 max length
    ip_numeric: Mapped[Optional[int]] = mapped_column(sa.BigInteger(), nullable=True)  # for numeric IP sort
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=8333)

    # Geographic information (Shodan-sourced; Shodan takes precedence)
    country_code: Mapped[Optional[str]] = mapped_column(String(2))
    country_name: Mapped[Optional[str]] = mapped_column(String(100))
    city: Mapped[Optional[str]] = mapped_column(String(100))
    subdivision: Mapped[Optional[str]] = mapped_column(String(100))  # region/state from MaxMind
    latitude: Mapped[Optional[float]] = mapped_column(Float)
    longitude: Mapped[Optional[float]] = mapped_column(Float)
    # MaxMind-specific country (always from GeoLite2, never overwritten by Shodan)
    geo_country_code: Mapped[Optional[str]] = mapped_column(String(2))
    geo_country_name: Mapped[Optional[str]] = mapped_column(String(100))

    # Network information
    asn: Mapped[Optional[str]] = mapped_column(String(20))
    asn_name: Mapped[Optional[str]] = mapped_column(String(255))

    # Bitcoin node information
    version: Mapped[Optional[str]] = mapped_column(String(100))
    user_agent: Mapped[Optional[str]] = mapped_column(String(255))
    banner: Mapped[Optional[str]] = mapped_column(Text)
    protocol_version: Mapped[Optional[int]] = mapped_column(Integer)
    services: Mapped[Optional[str]] = mapped_column(String(50))

    # Shodan enrichment — host-level data
    hostname: Mapped[Optional[str]] = mapped_column(String(255))       # first hostname
    os_info: Mapped[Optional[str]] = mapped_column(String(255))        # OS detected by Shodan
    isp: Mapped[Optional[str]] = mapped_column(String(255))            # ISP name
    org: Mapped[Optional[str]] = mapped_column(String(255))            # Organisation
    open_ports_json: Mapped[Optional[str]] = mapped_column(Text)       # JSON: [{port, transport, product, version}]
    vulns_json: Mapped[Optional[str]] = mapped_column(Text)            # JSON: [CVE-IDs]
    tags_json: Mapped[Optional[str]] = mapped_column(Text)             # JSON: [tags]
    cpe_json: Mapped[Optional[str]] = mapped_column(Text)              # JSON: [CPE strings]

    # Risk assessment
    risk_level: Mapped[Optional[str]] = mapped_column(String(20))  # CRITICAL, HIGH, MEDIUM, LOW
    is_vulnerable: Mapped[bool] = mapped_column(default=False)
    has_exposed_rpc: Mapped[bool] = mapped_column(default=False)
    is_dev_version: Mapped[bool] = mapped_column(default=False)

    # Marks rows whose IP is in src.example_ips.EXAMPLE_IPS — set at write time
    # by db.scanner_integration; backfilled by `db-mark-examples`.
    is_example: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=expression.false(),
    )

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        secondary=ScanNode,
        back_populates="nodes"
    )
    vulnerabilities: Mapped[List["NodeVulnerability"]] = relationship(
        "NodeVulnerability",
        back_populates="node",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index('idx_nodes_ip', 'ip'),
        Index('idx_nodes_ip_port', 'ip', 'port', unique=True),
        Index('idx_nodes_last_seen', 'last_seen'),
        Index('idx_nodes_country_code', 'country_code'),
        Index('idx_nodes_risk_level', 'risk_level'),
        Index('idx_nodes_is_vulnerable', 'is_vulnerable'),
        Index('idx_nodes_is_example', 'is_example'),
    )

    def __repr__(self) -> str:
        return f"<Node(ip={self.ip}, port={self.port}, version={self.version})>"


class Scan(Base):
    """Model representing a scanning session."""
    __tablename__ = 'scans'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Scan configuration
    queries_executed: Mapped[Optional[str]] = mapped_column(Text)  # JSON list of queries

    # Results
    total_nodes: Mapped[int] = mapped_column(Integer, default=0)
    critical_nodes: Mapped[int] = mapped_column(Integer, default=0)
    high_risk_nodes: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_nodes: Mapped[int] = mapped_column(Integer, default=0)

    # Resource usage
    credits_used: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float)

    # Status
    status: Mapped[str] = mapped_column(String(20), default='running')  # running, completed, failed
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    nodes: Mapped[List["Node"]] = relationship(
        "Node",
        secondary=ScanNode,
        back_populates="scans"
    )

    __table_args__ = (
        Index('idx_scans_timestamp', 'timestamp'),
        Index('idx_scans_status', 'status'),
    )

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, timestamp={self.timestamp}, total_nodes={self.total_nodes})>"


class CVEEntry(Base):
    """Model representing a cached CVE entry fetched from the NVD API."""
    __tablename__ = 'cve_entries'

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    published: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_modified: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default='UNKNOWN')
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_versions: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON list of {cpe, version, start_inc, start_exc, end_inc, end_exc}
    fetched_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)

    affected_nodes: Mapped[List["NodeVulnerability"]] = relationship(
        "NodeVulnerability",
        back_populates="cve_entry",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index('idx_cve_entries_severity', 'severity'),
        Index('idx_cve_entries_fetched_at', 'fetched_at'),
    )

    def __repr__(self) -> str:
        return f"<CVEEntry(cve_id={self.cve_id}, severity={self.severity}, cvss_score={self.cvss_score})>"


class NodeVulnerability(Base):
    """Association model between Node and CVEEntry with detection metadata."""
    __tablename__ = 'node_vulnerabilities'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[int] = mapped_column(Integer, ForeignKey('nodes.id', ondelete='CASCADE'), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(20), ForeignKey('cve_entries.cve_id', ondelete='CASCADE'), nullable=False)

    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    detected_version: Mapped[Optional[str]] = mapped_column(String(100))

    node: Mapped["Node"] = relationship("Node", back_populates="vulnerabilities")
    cve_entry: Mapped["CVEEntry"] = relationship("CVEEntry", back_populates="affected_nodes")

    __table_args__ = (
        Index('idx_node_vuln_node_id', 'node_id'),
        Index('idx_node_vuln_cve_id', 'cve_id'),
        Index('idx_node_vuln_detected_at', 'detected_at'),
        Index('idx_node_vuln_resolved', 'resolved_at'),
    )

    def __repr__(self) -> str:
        return f"<NodeVulnerability(node_id={self.node_id}, cve_id={self.cve_id})>"


class ScanJob(Base):
    """Model representing a background scan job triggered via the web API."""
    __tablename__ = 'scan_jobs'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default='pending')  # pending, running, completed, failed
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_scan_jobs_status', 'status'),
    )

    def __repr__(self) -> str:
        return f"<ScanJob(id={self.id}, status={self.status})>"
