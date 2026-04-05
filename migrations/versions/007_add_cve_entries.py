"""Add cve_entries table for NVD vulnerability cache

Revision ID: 007_add_cve_entries
Revises: 006_add_enrichment_fields
Create Date: 2026-04-02
"""
from alembic import op
import sqlalchemy as sa

revision = '007_add_cve_entries'
down_revision = '006_add_enrichment_fields'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'cve_entries',
        sa.Column('cve_id', sa.String(20), primary_key=True),
        sa.Column('published', sa.DateTime(), nullable=True),
        sa.Column('last_modified', sa.DateTime(), nullable=True),
        sa.Column('severity', sa.String(20), nullable=False, server_default='UNKNOWN'),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('affected_versions', sa.Text(), nullable=True),
        sa.Column('fetched_at', sa.DateTime(), nullable=False),
    )
    op.create_index('idx_cve_entries_severity', 'cve_entries', ['severity'])
    op.create_index('idx_cve_entries_fetched_at', 'cve_entries', ['fetched_at'])


def downgrade():
    op.drop_index('idx_cve_entries_fetched_at', table_name='cve_entries')
    op.drop_index('idx_cve_entries_severity', table_name='cve_entries')
    op.drop_table('cve_entries')
