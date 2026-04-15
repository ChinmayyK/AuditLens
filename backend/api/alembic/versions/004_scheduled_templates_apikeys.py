"""scheduled scans templates api keys

Revision ID: 004
Revises: 003
Create Date: 2026-01-01 00:03:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("scan_type", sa.String(20), server_default="url"),
        sa.Column("intensity", sa.String(20), server_default="standard"),
        sa.Column("is_active", sa.Boolean, server_default=sa.true()),
        sa.Column("frequency", sa.String(20), server_default="weekly"),
        sa.Column("day_of_week", sa.Integer, nullable=True),
        sa.Column("hour_utc", sa.Integer, server_default="2"),
        sa.Column("last_run_at", sa.DateTime, nullable=True),
        sa.Column("next_run_at", sa.DateTime, nullable=True),
        sa.Column("run_count", sa.Integer, server_default="0"),
        sa.Column("last_scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("notify_email", sa.Boolean, server_default=sa.true()),
        sa.Column("notify_on_new", sa.Boolean, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )
    op.create_index(
        "idx_schedules_user_active",
        "scan_schedules",
        ["user_id", "is_active"],
    )
    op.create_index(
        "idx_schedules_next_run",
        "scan_schedules",
        ["next_run_at", "is_active"],
    )

    op.create_table(
        "scan_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("scan_type", sa.String(20), server_default="url"),
        sa.Column("intensity", sa.String(20), server_default="standard"),
        sa.Column("config", postgresql.JSON, server_default=sa.text("'{}'::json")),
        sa.Column("is_public", sa.Boolean, server_default=sa.false()),
        sa.Column("use_count", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("key_hash", sa.String(128), nullable=False),
        sa.Column("key_preview", sa.String(12), nullable=False),
        sa.Column("scopes", postgresql.JSON, server_default=sa.text("'[]'::json")),
        sa.Column("is_active", sa.Boolean, server_default=sa.true()),
        sa.Column("last_used_at", sa.DateTime, nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("request_count", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index(
        "idx_api_keys_user_active",
        "api_keys",
        ["user_id", "is_active"],
    )


def downgrade():
    op.drop_index("idx_api_keys_user_active", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_table("scan_templates")
    op.drop_index("idx_schedules_next_run", table_name="scan_schedules")
    op.drop_index("idx_schedules_user_active", table_name="scan_schedules")
    op.drop_table("scan_schedules")
