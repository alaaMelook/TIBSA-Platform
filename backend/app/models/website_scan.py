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
    severity: str  # "critical", "high", "medium", "low", "info"
    url: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    classification: Optional[str] = None
    confidence_label: Optional[str] = None
    severity_justification: Optional[str] = None
    false_positive_check: Optional[str] = None
    auto_fix: Optional[str] = None


class WebsiteScanResponse(BaseModel):
    scan_id: str
    target: str
    started_at: str
    duration: float  # seconds
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    endpoints_found: int = 0
    findings: List[WebsiteScanFinding] = []
    headers: Dict[str, str] = {}
    endpoints: List[Dict[str, Any]] = []
    false_positives_filtered: List[str] = []
    error: Optional[str] = None


# ─── History ─────────────────────────────────────────────────

class WebsiteScanSummary(BaseModel):
    scan_id: Optional[str] = None
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
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
    headers: Dict[str, str] = {}
    endpoints: List[Dict[str, Any]] = []
    false_positives_filtered: List[str] = []
    error: Optional[str] = None
    created_at: str
