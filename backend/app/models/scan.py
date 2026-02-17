"""
Scan-related Pydantic models.
"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


# ─── Request Models ──────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str  # URL or file hash
    scan_type: str = "url"  # "url" or "file"


# ─── Response Models ─────────────────────────────────────────

class ScanResponse(BaseModel):
    id: str
    user_id: str
    scan_type: str
    target: str
    status: str  # "pending", "in_progress", "completed", "failed"
    threat_level: Optional[str] = None
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanReportResponse(BaseModel):
    id: str
    scan_id: str
    summary: str
    details: Dict[str, Any] = {}
    indicators: List[Dict[str, Any]] = []
    created_at: Optional[datetime] = None
