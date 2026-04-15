"""add risk breakdown to scans

Revision ID: 005
Revises: 004
Create Date: 2026-04-14 11:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade():
    # We use if_not_exists logic or check because I just added it manually
    # But in standard alembic upgrade, it should just work if the DB is fresh.
    # To handle the current state where I already added it:
    conn = op.get_bind()
    res = conn.execute(sa.text("SELECT column_name FROM information_schema.columns WHERE table_name='scans' AND column_name='risk_breakdown'"))
    if not res.fetchone():
        op.add_column("scans", sa.Column("risk_breakdown", postgresql.JSONB(), nullable=True))


def downgrade():
    op.drop_column("scans", "risk_breakdown")
