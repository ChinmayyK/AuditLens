import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, DateTime,
    Integer, Text, ForeignKey, Index
)
from sqlalchemy.dialects.postgresql import UUID
from models.base import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True,
                default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True),
                     ForeignKey("scans.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True),
                     ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False)

    report_type = Column(String(20), nullable=False)
    file_path = Column(Text, nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    ai_executive_summary = Column(Text, nullable=True)
    generated_at = Column(DateTime, nullable=True)
    download_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_reports_scan_id", "scan_id"),
    )
