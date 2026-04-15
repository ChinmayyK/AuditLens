import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, DateTime,
    Integer, Text, ForeignKey, Float, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from models.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True),
                     ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)

    scan_type = Column(String(20), nullable=False)
    target = Column(Text, nullable=False)
    intensity = Column(String(20), default="standard")
    ownership_confirmed = Column(Boolean, default=False)
    estimated_asset_value = Column(Integer, nullable=True)

    status = Column(String(20), default="queued", index=True)
    progress_pct = Column(Integer, default=0)
    current_phase = Column(String(100), nullable=True)
    error_message = Column(Text, nullable=True)

    risk_score = Column(Integer, nullable=True)
    risk_grade = Column(String(5), nullable=True)
    risk_breakdown = Column(JSONB, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow,
                        nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    open_ports = Column(JSONB, nullable=True)
    subdomains = Column(JSONB, nullable=True)
    tech_stack = Column(JSONB, nullable=True)
    os_guess = Column(String(100), nullable=True)
    cdn_detected = Column(Boolean, nullable=True)
    waf_detected = Column(Boolean, nullable=True)
    waf_name = Column(String(100), nullable=True)

    stress_results = Column(JSONB, nullable=True)

    celery_task_id = Column(String(255), nullable=True)

    user = relationship("User", back_populates="scans")
    findings = relationship("Finding",
                            back_populates="scan",
                            cascade="all, delete-orphan")
    attack_surface = relationship("AttackSurface",
                                  back_populates="scan",
                                  uselist=False,
                                  cascade="all, delete-orphan")
    compliance = relationship("ComplianceResult",
                              back_populates="scan",
                              uselist=False,
                              cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scans_user_id", "user_id"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_created_at", "created_at"),
        Index("idx_scans_scan_type", "scan_type"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True),
                     ForeignKey("scans.id", ondelete="CASCADE"),
                     nullable=False, index=True)

    vuln_type = Column(String(200), nullable=False)
    category = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(50), nullable=True)
    cwe_id = Column(String(50), nullable=True)
    owasp_category = Column(String(100), nullable=True)

    url = Column(Text, nullable=True)
    parameter = Column(String(500), nullable=True)
    http_method = Column(String(10), nullable=True)
    file_path = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)
    column_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)

    tool_source = Column(String(50), nullable=True)
    attack_payload = Column(Text, nullable=True)
    attack_worked = Column(Boolean, default=True)
    was_attempted = Column(Boolean, default=False)
    request_sent = Column(Text, nullable=True)
    response_received = Column(Text, nullable=True)
    attack_name = Column(String(200), nullable=True)

    evidence = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    layman_explanation = Column(Text, nullable=True)

    money_loss_min = Column(Integer, nullable=True)
    money_loss_max = Column(Integer, nullable=True)
    breach_examples = Column(JSONB, nullable=True)

    ai_fix = Column(JSONB, nullable=True)
    waf_rule = Column(JSONB, nullable=True)
    quick_fix = Column(Text, nullable=True)

    correlated_finding_id = Column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True
    )
    correlation_message = Column(Text, nullable=True)
    correlation_confidence = Column(Integer, nullable=True)

    fix_verified = Column(Boolean, default=False)
    fix_verified_at = Column(DateTime, nullable=True)
    marked_fixed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow,
                        nullable=False)

    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_tool_source", "tool_source"),
        Index("idx_findings_attack_worked", "attack_worked"),
        Index("idx_findings_vuln_type", "vuln_type"),
    )


class AttackSurface(Base):
    __tablename__ = "attack_surfaces"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True),
                     ForeignKey("scans.id", ondelete="CASCADE"),
                     nullable=False, unique=True)

    nodes = Column(JSONB, nullable=True)
    edges = Column(JSONB, nullable=True)
    api_endpoints = Column(JSONB, nullable=True)
    forms_found = Column(JSONB, nullable=True)
    parameters_found = Column(JSONB, nullable=True)
    discovered_urls = Column(JSONB, nullable=True)
    total_requests_sent = Column(Integer, default=0)

    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="attack_surface")


class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True),
                     ForeignKey("scans.id", ondelete="CASCADE"),
                     nullable=False, unique=True)

    owasp_score = Column(Integer, nullable=True)
    pci_dss_score = Column(Integer, nullable=True)
    hipaa_score = Column(Integer, nullable=True)
    gdpr_score = Column(Integer, nullable=True)

    owasp_breakdown = Column(JSONB, nullable=True)
    pci_dss_gaps = Column(JSONB, nullable=True)
    hipaa_gaps = Column(JSONB, nullable=True)
    gdpr_gaps = Column(JSONB, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="compliance")


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True),
                     ForeignKey("scans.id", ondelete="CASCADE"),
                     nullable=False, index=True)

    event_type = Column(String(50), nullable=False)
    message = Column(Text, nullable=False)
    progress_pct = Column(Integer, nullable=True)
    tool = Column(String(50), nullable=True)
    target_url = Column(Text, nullable=True)
    result = Column(String(50), nullable=True)
    metadata_ = Column("metadata", JSONB, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow,
                        nullable=False)

    __table_args__ = (
        Index("idx_scan_events_scan_id", "scan_id"),
        Index("idx_scan_events_created_at", "created_at"),
    )
