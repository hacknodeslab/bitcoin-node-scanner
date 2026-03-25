"""Add geo_country_code and geo_country_name columns (MaxMind-specific, never overwritten by Shodan)

Revision ID: 004
Revises: 003
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa

revision = '004_add_geo_country'
down_revision = '003_add_subdivision'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('nodes', sa.Column('geo_country_code', sa.String(2), nullable=True))
    op.add_column('nodes', sa.Column('geo_country_name', sa.String(100), nullable=True))


def downgrade():
    op.drop_column('nodes', 'geo_country_name')
    op.drop_column('nodes', 'geo_country_code')
