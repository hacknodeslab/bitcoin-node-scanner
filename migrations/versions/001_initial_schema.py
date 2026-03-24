"""Initial schema with all tables and relationships.

Revision ID: 001_initial
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create nodes table
    op.create_table(
        'nodes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('country_code', sa.String(length=2), nullable=True),
        sa.Column('country_name', sa.String(length=100), nullable=True),
        sa.Column('city', sa.String(length=100), nullable=True),
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        sa.Column('asn', sa.String(length=20), nullable=True),
        sa.Column('asn_name', sa.String(length=255), nullable=True),
        sa.Column('version', sa.String(length=100), nullable=True),
        sa.Column('user_agent', sa.String(length=255), nullable=True),
        sa.Column('banner', sa.Text(), nullable=True),
        sa.Column('protocol_version', sa.Integer(), nullable=True),
        sa.Column('services', sa.String(length=50), nullable=True),
        sa.Column('risk_level', sa.String(length=20), nullable=True),
        sa.Column('is_vulnerable', sa.Boolean(), nullable=True, default=False),
        sa.Column('has_exposed_rpc', sa.Boolean(), nullable=True, default=False),
        sa.Column('is_dev_version', sa.Boolean(), nullable=True, default=False),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_nodes_ip', 'nodes', ['ip'], unique=False)
    op.create_index('idx_nodes_ip_port', 'nodes', ['ip', 'port'], unique=True)
    op.create_index('idx_nodes_last_seen', 'nodes', ['last_seen'], unique=False)
    op.create_index('idx_nodes_country_code', 'nodes', ['country_code'], unique=False)
    op.create_index('idx_nodes_risk_level', 'nodes', ['risk_level'], unique=False)
    op.create_index('idx_nodes_is_vulnerable', 'nodes', ['is_vulnerable'], unique=False)

    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('queries_executed', sa.Text(), nullable=True),
        sa.Column('total_nodes', sa.Integer(), nullable=True, default=0),
        sa.Column('critical_nodes', sa.Integer(), nullable=True, default=0),
        sa.Column('high_risk_nodes', sa.Integer(), nullable=True, default=0),
        sa.Column('vulnerable_nodes', sa.Integer(), nullable=True, default=0),
        sa.Column('credits_used', sa.Integer(), nullable=True, default=0),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True, default='running'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_scans_timestamp', 'scans', ['timestamp'], unique=False)
    op.create_index('idx_scans_status', 'scans', ['status'], unique=False)

    # Create scan_nodes association table
    op.create_table(
        'scan_nodes',
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('node_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('scan_id', 'node_id')
    )

    # Create vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('cve_id', sa.String(length=20), nullable=False),
        sa.Column('affected_versions', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('reference_url', sa.String(length=500), nullable=True),
        sa.Column('published_date', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cve_id')
    )
    op.create_index('idx_vulnerabilities_cve_id', 'vulnerabilities', ['cve_id'], unique=False)
    op.create_index('idx_vulnerabilities_severity', 'vulnerabilities', ['severity'], unique=False)

    # Create node_vulnerabilities association table
    op.create_table(
        'node_vulnerabilities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('node_id', sa.Integer(), nullable=False),
        sa.Column('vulnerability_id', sa.Integer(), nullable=False),
        sa.Column('detected_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('detected_version', sa.String(length=100), nullable=True),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_node_vuln_node_id', 'node_vulnerabilities', ['node_id'], unique=False)
    op.create_index('idx_node_vuln_vulnerability_id', 'node_vulnerabilities', ['vulnerability_id'], unique=False)
    op.create_index('idx_node_vuln_detected_at', 'node_vulnerabilities', ['detected_at'], unique=False)
    op.create_index('idx_node_vuln_resolved', 'node_vulnerabilities', ['resolved_at'], unique=False)


def downgrade() -> None:
    op.drop_table('node_vulnerabilities')
    op.drop_table('vulnerabilities')
    op.drop_table('scan_nodes')
    op.drop_table('scans')
    op.drop_table('nodes')
