"""Add ip_reputation + enrichment_quota tables and scan_jobs.job_type.

Revision ID: 009_add_ip_reputation
Revises: 008_link_node_vuln_to_cve
Create Date: 2026-10-05

Additive only — the `nodes` table is untouched. Every step is guarded by an
inspector check because `init_db()` (`Base.metadata.create_all` +
`_migrate_schema`) may already have created these objects on a database that
was started before `alembic upgrade head` ran.
"""
from alembic import op
import sqlalchemy as sa

revision = '009_add_ip_reputation'
down_revision = '008_link_node_vuln_to_cve'
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def upgrade() -> None:
    insp = _inspector()
    tables = set(insp.get_table_names())

    if 'ip_reputation' not in tables:
        op.create_table(
            'ip_reputation',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('ip', sa.String(45), nullable=False),
            sa.Column('abuse_confidence_score', sa.Integer(), nullable=True),
            sa.Column('abuse_total_reports', sa.Integer(), nullable=True),
            sa.Column('abuse_last_reported_at', sa.DateTime(), nullable=True),
            sa.Column('blocklists_json', sa.Text(), nullable=True),
            sa.Column('sources_json', sa.Text(), nullable=True),
            sa.Column('abuseipdb_checked_at', sa.DateTime(), nullable=True),
            sa.Column('blocklists_checked_at', sa.DateTime(), nullable=True),
            sa.Column('reputation_enriched_at', sa.DateTime(), nullable=True),
            sa.Column('first_enriched_at', sa.DateTime(), nullable=True),
            sa.Column('updated_at', sa.DateTime(), nullable=True),
        )
        op.create_index('idx_ip_reputation_ip', 'ip_reputation', ['ip'], unique=True)
        op.create_index('idx_ip_reputation_enriched_at', 'ip_reputation', ['reputation_enriched_at'])

    if 'enrichment_quota' not in tables:
        op.create_table(
            'enrichment_quota',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('source', sa.String(50), nullable=False),
            sa.Column('day_utc', sa.String(10), nullable=False),
            sa.Column('calls', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('exhausted', sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        op.create_index(
            'idx_enrichment_quota_source_day', 'enrichment_quota', ['source', 'day_utc'], unique=True
        )

    if 'scan_jobs' in tables:
        cols = {c['name'] for c in insp.get_columns('scan_jobs')}
        if 'job_type' not in cols:
            op.add_column(
                'scan_jobs',
                sa.Column('job_type', sa.String(20), nullable=False, server_default='scan'),
            )
        # One active job per type (same statement on SQLite and PostgreSQL).
        op.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_jobs_active_per_type "
            "ON scan_jobs (job_type) WHERE status IN ('pending', 'running')"
        )


def downgrade() -> None:
    insp = _inspector()
    tables = set(insp.get_table_names())

    if 'scan_jobs' in tables:
        op.execute("DROP INDEX IF EXISTS uq_scan_jobs_active_per_type")
        cols = {c['name'] for c in insp.get_columns('scan_jobs')}
        if 'job_type' in cols:
            with op.batch_alter_table('scan_jobs') as batch:
                batch.drop_column('job_type')

    if 'enrichment_quota' in tables:
        op.drop_index('idx_enrichment_quota_source_day', table_name='enrichment_quota')
        op.drop_table('enrichment_quota')

    if 'ip_reputation' in tables:
        op.drop_index('idx_ip_reputation_enriched_at', table_name='ip_reputation')
        op.drop_index('idx_ip_reputation_ip', table_name='ip_reputation')
        op.drop_table('ip_reputation')
