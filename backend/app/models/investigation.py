"""
Investigation database model.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, Float, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List
from app.database.base import Base

class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending, running, completed, failed
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Orchestration and progress columns
    include_ti: Mapped[bool] = mapped_column(default=True)
    tm_mode: Mapped[str] = mapped_column(default="enhanced")
    current_stage: Mapped[str] = mapped_column(default="Pending")
    progress_percent: Mapped[float] = mapped_column(default=0.0)
    pipeline_state: Mapped[dict] = mapped_column(JSON, default=dict, nullable=True)
    final_result: Mapped[dict] = mapped_column(JSON, default=dict, nullable=True)

    # Relationships
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    assets: Mapped[List["Asset"]] = relationship(
        "Asset",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    ti_reports: Mapped[List["TIReport"]] = relationship(
        "TIReport",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    tm_reports: Mapped[List["TMReport"]] = relationship(
        "TMReport",
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
