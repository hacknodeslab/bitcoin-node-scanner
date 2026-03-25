"""Add subdivision column to nodes table for MaxMind GeoIP region/state data.

Revision ID: 003_add_subdivision
Revises: 002_add_scan_jobs
Create Date: 2024-01-03 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003_add_subdivision'
down_revision: Union[str, None] = '002_add_scan_jobs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('nodes', sa.Column('subdivision', sa.String(length=100), nullable=True))


def downgrade() -> None:
    op.drop_column('nodes', 'subdivision')
