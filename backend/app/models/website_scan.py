"""
Website Scanner Pydantic models.
"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


# ─── Request ─────────────────────────────────────────────────

class WebsiteScanRequest(BaseModel):
    target: str  # URL to scan
    tests: List[str] = [
        "security_headers",
        "xss",
        "sqli",
        "endpoint_crawling",
        "cookie_analysis",
    ]


# ─── Response ────────────────────────────────────────────────

class WebsiteScanFinding(BaseModel):
    id: str
    title: str
    severity: str  # "high", "medium", "low"
    url: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None


class WebsiteScanResponse(BaseModel):
    scan_id: str
    target: str
    started_at: str
    duration: float  # seconds
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0
    endpoints_found: int = 0
    findings: List[WebsiteScanFinding] = []
    headers: Dict[str, str] = {}
    endpoints: List[Dict[str, Any]] = []


# ─── History ─────────────────────────────────────────────────

class WebsiteScanSummary(BaseModel):
    scan_id: Optional[str] = None
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0
    endpoints_found: int = 0
    duration: Optional[float] = None
    started_at: Optional[str] = None


class WebsiteScanHistoryItem(BaseModel):
    id: str
    target: str
    summary: WebsiteScanSummary = WebsiteScanSummary()
    created_at: str


class WebsiteScanDetail(BaseModel):
    id: str
    target: str
    summary: WebsiteScanSummary = WebsiteScanSummary()
    findings: List[Dict[str, Any]] = []
    created_at: str
