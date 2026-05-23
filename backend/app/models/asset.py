"""
Asset database model.
"""
import uuid
from sqlalchemy import String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id: Mapped[str] = mapped_column(String, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String, nullable=False)  # target, domain, ip, subdomain, technology, etc.
    url: Mapped[str] = mapped_column(String, nullable=False)
    technology: Mapped[str] = mapped_column(String, nullable=True)

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="assets")
