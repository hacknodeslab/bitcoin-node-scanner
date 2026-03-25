"""Add scan_jobs table for web background scan tracking.

Revision ID: 002_add_scan_jobs
Revises: 001_initial
Create Date: 2024-01-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '002_add_scan_jobs'
down_revision: Union[str, None] = '001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scan_jobs',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='pending'),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('result_summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('idx_scan_jobs_status', 'scan_jobs', ['status'])


def downgrade() -> None:
    op.drop_index('idx_scan_jobs_status', table_name='scan_jobs')
    op.drop_table('scan_jobs')
