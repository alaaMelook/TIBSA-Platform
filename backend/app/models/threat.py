"""
Threat Intelligence Pydantic models.
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


# ─── Request Models ──────────────────────────────────────────

class IOCLookupRequest(BaseModel):
    indicator_type: str  # "ip", "domain", "hash", "url", "email"
    value: str


class ReputationCheckRequest(BaseModel):
    target: str  # domain, IP, or URL


# ─── Response Models ─────────────────────────────────────────

class ThreatIndicatorResponse(BaseModel):
    id: Optional[str] = None
    type: str
    value: str
    threat_level: str  # "safe", "low", "medium", "high", "critical"
    source: str
    last_seen: Optional[datetime] = None


class ThreatFeedResponse(BaseModel):
    id: str
    name: str
    source_url: str
    is_active: bool
    last_updated: Optional[datetime] = None


class ReputationCheckResponse(BaseModel):
    target: str
    reputation_score: float  # 0.0 (safe) to 100.0 (malicious)
    threat_level: str
    details: dict = {}
    sources_checked: List[str] = []
