"""create all scan and ide tables

Revision ID: 002
Revises: 001
Create Date: 2026-01-01 00:01:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():

    # ── scans ─────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  nullable=False,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  nullable=False),
        sa.Column("scan_type", sa.String(20), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("intensity", sa.String(20),
                  server_default="standard"),
        sa.Column("ownership_confirmed", sa.Boolean(),
                  server_default="false"),
        sa.Column("estimated_asset_value",
                  sa.Integer(), nullable=True),
        sa.Column("status", sa.String(20),
                  server_default="queued"),
        sa.Column("progress_pct", sa.Integer(),
                  server_default="0"),
        sa.Column("current_phase", sa.String(100),
                  nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("risk_grade", sa.String(5), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("duration_seconds", sa.Integer(),
                  nullable=True),
        sa.Column("open_ports", postgresql.JSONB(),
                  nullable=True),
        sa.Column("subdomains", postgresql.JSONB(),
                  nullable=True),
        sa.Column("tech_stack", postgresql.JSONB(),
                  nullable=True),
        sa.Column("os_guess", sa.String(100), nullable=True),
        sa.Column("cdn_detected", sa.Boolean(), nullable=True),
        sa.Column("waf_detected", sa.Boolean(), nullable=True),
        sa.Column("waf_name", sa.String(100), nullable=True),
        sa.Column("stress_results", postgresql.JSONB(),
                  nullable=True),
        sa.Column("celery_task_id", sa.String(255),
                  nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_scans_user_id", "scans", ["user_id"])
    op.create_index("idx_scans_status", "scans", ["status"])
    op.create_index("idx_scans_created_at",
                    "scans", ["created_at"])
    op.create_index("idx_scans_scan_type",
                    "scans", ["scan_type"])

    # ── findings ──────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  nullable=False,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  nullable=False),
        sa.Column("vuln_type", sa.String(200), nullable=False),
        sa.Column("category", sa.String(100), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cve_id", sa.String(50), nullable=True),
        sa.Column("cwe_id", sa.String(50), nullable=True),
        sa.Column("owasp_category", sa.String(100),
                  nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("parameter", sa.String(500), nullable=True),
        sa.Column("http_method", sa.String(10), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("column_number", sa.Integer(), nullable=True),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("tool_source", sa.String(50), nullable=True),
        sa.Column("attack_payload", sa.Text(), nullable=True),
        sa.Column("attack_worked", sa.Boolean(),
                  server_default="true"),
        sa.Column("was_attempted", sa.Boolean(),
                  server_default="false"),
        sa.Column("request_sent", sa.Text(), nullable=True),
        sa.Column("response_received", sa.Text(),
                  nullable=True),
        sa.Column("attack_name", sa.String(200), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("layman_explanation", sa.Text(),
                  nullable=True),
        sa.Column("money_loss_min", sa.Integer(), nullable=True),
        sa.Column("money_loss_max", sa.Integer(), nullable=True),
        sa.Column("breach_examples", postgresql.JSONB(),
                  nullable=True),
        sa.Column("ai_fix", postgresql.JSONB(), nullable=True),
        sa.Column("waf_rule", postgresql.JSONB(), nullable=True),
        sa.Column("quick_fix", sa.Text(), nullable=True),
        sa.Column("correlated_finding_id",
                  postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("correlation_message", sa.Text(),
                  nullable=True),
        sa.Column("correlation_confidence",
                  sa.Integer(), nullable=True),
        sa.Column("fix_verified", sa.Boolean(),
                  server_default="false"),
        sa.Column("fix_verified_at", sa.DateTime(),
                  nullable=True),
        sa.Column("marked_fixed_at", sa.DateTime(),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["correlated_finding_id"], ["findings.id"],
            ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_findings_scan_id",
                    "findings", ["scan_id"])
    op.create_index("idx_findings_severity",
                    "findings", ["severity"])
    op.create_index("idx_findings_tool_source",
                    "findings", ["tool_source"])
    op.create_index("idx_findings_attack_worked",
                    "findings", ["attack_worked"])
    op.create_index("idx_findings_vuln_type",
                    "findings", ["vuln_type"])

    # ── attack_surfaces ───────────────────────────────
    op.create_table(
        "attack_surfaces",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  nullable=False,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  nullable=False),
        sa.Column("nodes", postgresql.JSONB(), nullable=True),
        sa.Column("edges", postgresql.JSONB(), nullable=True),
        sa.Column("api_endpoints", postgresql.JSONB(),
                  nullable=True),
        sa.Column("forms_found", postgresql.JSONB(),
                  nullable=True),
        sa.Column("parameters_found", postgresql.JSONB(),
                  nullable=True),
        sa.Column("discovered_urls", postgresql.JSONB(),
                  nullable=True),
        sa.Column("total_requests_sent", sa.Integer(),
                  server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"],
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )

    # ── compliance_results ────────────────────────────
    op.create_table(
        "compliance_results",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  nullable=False,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  nullable=False),
        sa.Column("owasp_score", sa.Integer(), nullable=True),
        sa.Column("pci_dss_score", sa.Integer(), nullable=True),
        sa.Column("hipaa_score", sa.Integer(), nullable=True),
        sa.Column("gdpr_score", sa.Integer(), nullable=True),
        sa.Column("owasp_breakdown", postgresql.JSONB(),
                  nullable=True),
        sa.Column("pci_dss_gaps", postgresql.JSONB(),
                  nullable=True),
        sa.Column("hipaa_gaps", postgresql.JSONB(),
                  nullable=True),
        sa.Column("gdpr_gaps", postgresql.JSONB(),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"],
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )

    # ── scan_events ───────────────────────────────────
    op.create_table(
        "scan_events",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  nullable=False,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("progress_pct", sa.Integer(), nullable=True),
        sa.Column("tool", sa.String(50), nullable=True),
        sa.Column("target_url", sa.Text(), nullable=True),
        sa.Column("result", sa.String(50), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"],
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_scan_events_scan_id",
                    "scan_events", ["scan_id"])
    op.create_index("idx_scan_events_created_at",
                    "scan_events", ["created_at"])

    # ── ide_sessions ──────────────────────────────────
    op.create_table(
        "ide_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  nullable=False,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  nullable=True),
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("repo_url", sa.Text(), nullable=True),
        sa.Column("repo_name", sa.String(255), nullable=True),
        sa.Column("zip_filename", sa.String(255),
                  nullable=True),
        sa.Column("clone_path", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20),
                  server_default="cloning"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("file_tree", postgresql.JSONB(),
                  nullable=True),
        sa.Column("file_contents", postgresql.JSONB(),
                  nullable=True),
        sa.Column("file_scores", postgresql.JSONB(),
                  nullable=True),
        sa.Column("security_score", sa.Integer(),
                  nullable=True),
        sa.Column("total_findings", sa.Integer(),
                  server_default="0"),
        sa.Column("languages_detected", postgresql.JSONB(),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"],
                                ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_ide_sessions_user_id",
                    "ide_sessions", ["user_id"])
    op.create_index("idx_ide_sessions_status",
                    "ide_sessions", ["status"])

    # ── ide_annotations ───────────────────────────────
    op.create_table(
        "ide_annotations",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  nullable=False,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("session_id", postgresql.UUID(as_uuid=True),
                  nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True),
                  nullable=True),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=False),
        sa.Column("column_number", sa.Integer(),
                  nullable=True),
        sa.Column("annotation_type", sa.String(20),
                  nullable=False),
        sa.Column("vuln_type", sa.String(200), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("quick_fix", sa.Text(), nullable=True),
        sa.Column("is_resolved", sa.Boolean(),
                  server_default="false"),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["session_id"], ["ide_sessions.id"],
            ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"],
            ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_ide_annotations_session_id",
                    "ide_annotations", ["session_id"])
    op.create_index("idx_ide_annotations_file_path",
                    "ide_annotations", ["file_path"])

    # ── reports ───────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  nullable=False,
                  server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True),
                  nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  nullable=False),
        sa.Column("report_type", sa.String(20),
                  nullable=False),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(),
                  nullable=True),
        sa.Column("ai_executive_summary", sa.Text(),
                  nullable=True),
        sa.Column("generated_at", sa.DateTime(),
                  nullable=True),
        sa.Column("download_count", sa.Integer(),
                  server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False,
                  server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_reports_scan_id",
                    "reports", ["scan_id"])


def downgrade():
    op.drop_table("reports")
    op.drop_table("ide_annotations")
    op.drop_table("ide_sessions")
    op.drop_table("scan_events")
    op.drop_table("compliance_results")
    op.drop_table("attack_surfaces")
    op.drop_table("findings")
    op.drop_table("scans")
