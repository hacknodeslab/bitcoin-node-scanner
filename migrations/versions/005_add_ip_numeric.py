"""Add ip_numeric column for correct IP address sorting

Revision ID: 005_add_ip_numeric
Revises: 004_add_geo_country
Create Date: 2026-03-25
"""
import struct
import socket
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision = '005_add_ip_numeric'
down_revision = '004_add_geo_country'
branch_labels = None
depends_on = None


def ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0


def upgrade():
    op.add_column('nodes', sa.Column('ip_numeric', sa.BigInteger(), nullable=True))

    bind = op.get_bind()
    rows = bind.execute(text("SELECT id, ip FROM nodes")).fetchall()
    for row_id, ip in rows:
        bind.execute(
            text("UPDATE nodes SET ip_numeric = :val WHERE id = :id"),
            {"val": ip_to_int(ip), "id": row_id},
        )


def downgrade():
    op.drop_column('nodes', 'ip_numeric')
