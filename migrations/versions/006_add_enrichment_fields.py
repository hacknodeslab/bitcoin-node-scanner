"""Add Shodan enrichment fields to nodes table

Revision ID: 006_add_enrichment_fields
Revises: 005_add_ip_numeric
Create Date: 2026-03-26
"""
from alembic import op
import sqlalchemy as sa

revision = '006_add_enrichment_fields'
down_revision = '005_add_ip_numeric'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('nodes', sa.Column('hostname', sa.String(255), nullable=True))
    op.add_column('nodes', sa.Column('os_info', sa.String(255), nullable=True))
    op.add_column('nodes', sa.Column('isp', sa.String(255), nullable=True))
    op.add_column('nodes', sa.Column('org', sa.String(255), nullable=True))
    op.add_column('nodes', sa.Column('open_ports_json', sa.Text(), nullable=True))
    op.add_column('nodes', sa.Column('vulns_json', sa.Text(), nullable=True))
    op.add_column('nodes', sa.Column('tags_json', sa.Text(), nullable=True))
    op.add_column('nodes', sa.Column('cpe_json', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('nodes', 'cpe_json')
    op.drop_column('nodes', 'tags_json')
    op.drop_column('nodes', 'vulns_json')
    op.drop_column('nodes', 'open_ports_json')
    op.drop_column('nodes', 'org')
    op.drop_column('nodes', 'isp')
    op.drop_column('nodes', 'os_info')
    op.drop_column('nodes', 'hostname')
