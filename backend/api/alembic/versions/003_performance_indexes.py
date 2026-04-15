"""performance indexes

Revision ID: 003
Revises: 002
Create Date: 2026-01-01 00:02:00
"""
from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "idx_findings_scan_severity",
        "findings",
        ["scan_id", "severity"],
    )
    op.create_index(
        "idx_findings_attack_worked_sev",
        "findings",
        ["attack_worked", "severity"],
    )
    op.create_index(
        "idx_scan_events_scan_created",
        "scan_events",
        ["scan_id", "created_at"],
    )
    op.create_index(
        "idx_ide_ann_session_file",
        "ide_annotations",
        ["session_id", "file_path", "is_resolved"],
    )


def downgrade():
    op.drop_index("idx_findings_scan_severity", table_name="findings")
    op.drop_index("idx_findings_attack_worked_sev", table_name="findings")
    op.drop_index("idx_scan_events_scan_created", table_name="scan_events")
    op.drop_index("idx_ide_ann_session_file", table_name="ide_annotations")
