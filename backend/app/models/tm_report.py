"""
Threat Modeling Report database model.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, ForeignKey, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

class TMReport(Base):
    __tablename__ = "tm_reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    stride_summary: Mapped[dict] = mapped_column(JSON, default=dict)  # STRIDE threats summary
    mitigations: Mapped[dict] = mapped_column(JSON, default=dict)     # Mitigations roadmap
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="tm_reports")
