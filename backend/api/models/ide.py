import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, DateTime,
    Integer, Text, ForeignKey, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from models.base import Base


class IDESession(Base):
    __tablename__ = "ide_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True),
                     ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True),
                     ForeignKey("scans.id", ondelete="SET NULL"),
                     nullable=True)

    source_type = Column(String(20), nullable=False)
    repo_url = Column(Text, nullable=True)
    repo_name = Column(String(255), nullable=True)
    zip_filename = Column(String(255), nullable=True)
    clone_path = Column(Text, nullable=True)

    status = Column(String(20), default="cloning")
    error_message = Column(Text, nullable=True)

    file_tree = Column(JSONB, nullable=True)
    file_contents = Column(JSONB, nullable=True)
    file_scores = Column(JSONB, nullable=True)

    security_score = Column(Integer, nullable=True)
    total_findings = Column(Integer, default=0)
    languages_detected = Column(JSONB, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow,
                        nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow,
                        onupdate=datetime.utcnow)

    annotations = relationship(
        "IDEAnnotation",
        back_populates="session",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_ide_sessions_user_id", "user_id"),
        Index("idx_ide_sessions_status", "status"),
    )


class IDEAnnotation(Base):
    __tablename__ = "ide_annotations"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True),
                        ForeignKey("ide_sessions.id",
                                   ondelete="CASCADE"),
                        nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True),
                        ForeignKey("findings.id",
                                   ondelete="CASCADE"),
                        nullable=True)

    file_path = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=False)
    column_number = Column(Integer, nullable=True)
    annotation_type = Column(String(20), nullable=False)
    vuln_type = Column(String(200), nullable=True)
    severity = Column(String(20), nullable=True)
    message = Column(Text, nullable=False)
    quick_fix = Column(Text, nullable=True)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("IDESession",
                           back_populates="annotations")

    __table_args__ = (
        Index("idx_ide_annotations_session_id", "session_id"),
        Index("idx_ide_annotations_file_path", "file_path"),
    )
