"""
Threat Intelligence Report database model.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, ForeignKey, DateTime, Text, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

class TIReport(Base):
    __tablename__ = "ti_reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    overall_risk: Mapped[float] = mapped_column(Float, default=0.0)
    risk_summary: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="ti_reports")
