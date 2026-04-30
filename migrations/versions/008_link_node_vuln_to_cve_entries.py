"""Repoint node_vulnerabilities at cve_entries; drop legacy vulnerabilities table.

Revision ID: 008_link_node_vuln_to_cve
Revises: 007_add_cve_entries
Create Date: 2026-04-30

The legacy `vulnerabilities` table predates the NVD-fed `cve_entries` catalog.
We collapse the two by repointing `node_vulnerabilities.vulnerability_id` (FK to
`vulnerabilities.id`) to `node_vulnerabilities.cve_id` (FK to
`cve_entries.cve_id`). Existing links are remapped via a JOIN on
`vulnerabilities.cve_id == cve_entries.cve_id`; orphans are dropped.

SQLite needs the table to be recreated to drop a column. We use raw SQL to
build a new table, copy migrated rows into it, swap names, and rebuild
indexes. Postgres is supported via the same migration but uses ALTER TABLE
when available.
"""
from alembic import op
import sqlalchemy as sa

revision = '008_link_node_vuln_to_cve'
down_revision = '007_add_cve_entries'
branch_labels = None
depends_on = None


def _is_sqlite() -> bool:
    return op.get_context().dialect.name == "sqlite"


def upgrade() -> None:
    if _is_sqlite():
        _upgrade_sqlite()
    else:
        _upgrade_postgres()


def downgrade() -> None:
    if _is_sqlite():
        _downgrade_sqlite()
    else:
        _downgrade_postgres()


# ---------------------------------------------------------------------------
# SQLite path — recreate node_vulnerabilities by hand
# ---------------------------------------------------------------------------

def _upgrade_sqlite() -> None:
    bind = op.get_bind()

    bind.execute(sa.text("""
        CREATE TABLE node_vulnerabilities_new (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            node_id INTEGER NOT NULL,
            cve_id VARCHAR(20) NOT NULL,
            detected_at DATETIME,
            resolved_at DATETIME,
            detected_version VARCHAR(100),
            FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
            FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id) ON DELETE CASCADE
        )
    """))

    # Copy rows that map cleanly to a CVE in the new catalog.
    bind.execute(sa.text("""
        INSERT INTO node_vulnerabilities_new
            (id, node_id, cve_id, detected_at, resolved_at, detected_version)
        SELECT nv.id, nv.node_id, c.cve_id, nv.detected_at, nv.resolved_at, nv.detected_version
        FROM node_vulnerabilities nv
        JOIN vulnerabilities v ON v.id = nv.vulnerability_id
        JOIN cve_entries c ON c.cve_id = v.cve_id
    """))

    bind.execute(sa.text("DROP TABLE node_vulnerabilities"))
    bind.execute(sa.text("ALTER TABLE node_vulnerabilities_new RENAME TO node_vulnerabilities"))

    op.create_index('idx_node_vuln_node_id', 'node_vulnerabilities', ['node_id'], unique=False)
    op.create_index('idx_node_vuln_cve_id', 'node_vulnerabilities', ['cve_id'], unique=False)
    op.create_index('idx_node_vuln_detected_at', 'node_vulnerabilities', ['detected_at'], unique=False)
    op.create_index('idx_node_vuln_resolved', 'node_vulnerabilities', ['resolved_at'], unique=False)

    op.drop_index('idx_vulnerabilities_severity', table_name='vulnerabilities')
    op.drop_index('idx_vulnerabilities_cve_id', table_name='vulnerabilities')
    op.drop_table('vulnerabilities')


def _downgrade_sqlite() -> None:
    bind = op.get_bind()

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
        sa.UniqueConstraint('cve_id'),
    )
    op.create_index('idx_vulnerabilities_cve_id', 'vulnerabilities', ['cve_id'])
    op.create_index('idx_vulnerabilities_severity', 'vulnerabilities', ['severity'])

    bind.execute(sa.text("""
        CREATE TABLE node_vulnerabilities_old (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            node_id INTEGER NOT NULL,
            vulnerability_id INTEGER NOT NULL,
            detected_at DATETIME,
            resolved_at DATETIME,
            detected_version VARCHAR(100),
            FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
        )
    """))
    # No data is migrated back — historical links can be rebuilt with `db-link-cves`.

    bind.execute(sa.text("DROP TABLE node_vulnerabilities"))
    bind.execute(sa.text("ALTER TABLE node_vulnerabilities_old RENAME TO node_vulnerabilities"))

    op.create_index('idx_node_vuln_node_id', 'node_vulnerabilities', ['node_id'])
    op.create_index('idx_node_vuln_vulnerability_id', 'node_vulnerabilities', ['vulnerability_id'])
    op.create_index('idx_node_vuln_detected_at', 'node_vulnerabilities', ['detected_at'])
    op.create_index('idx_node_vuln_resolved', 'node_vulnerabilities', ['resolved_at'])


# ---------------------------------------------------------------------------
# Postgres path — use ALTER TABLE
# ---------------------------------------------------------------------------

def _upgrade_postgres() -> None:
    bind = op.get_bind()

    op.add_column('node_vulnerabilities',
                  sa.Column('cve_id', sa.String(length=20), nullable=True))

    bind.execute(sa.text("""
        UPDATE node_vulnerabilities
        SET cve_id = (
            SELECT v.cve_id
            FROM vulnerabilities v
            INNER JOIN cve_entries c ON c.cve_id = v.cve_id
            WHERE v.id = node_vulnerabilities.vulnerability_id
        )
    """))
    bind.execute(sa.text("DELETE FROM node_vulnerabilities WHERE cve_id IS NULL"))

    op.alter_column('node_vulnerabilities', 'cve_id', nullable=False)
    op.drop_index('idx_node_vuln_vulnerability_id', table_name='node_vulnerabilities')
    op.drop_constraint('node_vulnerabilities_vulnerability_id_fkey',
                       'node_vulnerabilities', type_='foreignkey')
    op.drop_column('node_vulnerabilities', 'vulnerability_id')
    op.create_foreign_key(
        'node_vulnerabilities_cve_id_fkey',
        'node_vulnerabilities', 'cve_entries',
        ['cve_id'], ['cve_id'], ondelete='CASCADE',
    )
    op.create_index('idx_node_vuln_cve_id', 'node_vulnerabilities', ['cve_id'])

    op.drop_index('idx_vulnerabilities_severity', table_name='vulnerabilities')
    op.drop_index('idx_vulnerabilities_cve_id', table_name='vulnerabilities')
    op.drop_table('vulnerabilities')


def _downgrade_postgres() -> None:
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
        sa.UniqueConstraint('cve_id'),
    )
    op.create_index('idx_vulnerabilities_cve_id', 'vulnerabilities', ['cve_id'])
    op.create_index('idx_vulnerabilities_severity', 'vulnerabilities', ['severity'])

    op.drop_index('idx_node_vuln_cve_id', table_name='node_vulnerabilities')
    op.drop_constraint('node_vulnerabilities_cve_id_fkey',
                       'node_vulnerabilities', type_='foreignkey')
    op.add_column('node_vulnerabilities',
                  sa.Column('vulnerability_id', sa.Integer(), nullable=True))
    # Active rows would be inconsistent — clear them; backfill via db-link-cves.
    op.execute("DELETE FROM node_vulnerabilities")
    op.alter_column('node_vulnerabilities', 'vulnerability_id', nullable=False)
    op.drop_column('node_vulnerabilities', 'cve_id')
    op.create_foreign_key(
        'node_vulnerabilities_vulnerability_id_fkey',
        'node_vulnerabilities', 'vulnerabilities',
        ['vulnerability_id'], ['id'], ondelete='CASCADE',
    )
    op.create_index('idx_node_vuln_vulnerability_id',
                    'node_vulnerabilities', ['vulnerability_id'])
