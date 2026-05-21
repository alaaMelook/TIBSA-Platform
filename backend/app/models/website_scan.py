"""
Website Scanner Pydantic models — v4.
Includes scan modes, confidence scoring, and risk score.
"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Union
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
        "misconfiguration",
        "directory_discovery",
        "auth_security",
    ]
    mode: Optional[str] = "safe"  # passive, safe, aggressive
    session_cookie: Optional[str] = None
    auth: Dict[str, Any] = {}
    enable_sqlmap: bool = False
    auth_browser_analysis: bool = False
    authorized_auth_mode: bool = False
    auth_lifecycle_checks: bool = False
    authz_transition_checks: bool = False


# ─── Response ────────────────────────────────────────────────

class WebsiteScanFinding(BaseModel):
    id: str
    title: str
    module: Optional[str] = None
    severity: str  # "critical", "high", "medium", "low", "info"
    confidence: Optional[str] = None  # "high", "medium", "low"
    url: str
    description: str
    evidence: Optional[Union[str, Dict[str, Any]]] = None
    recommendation: Optional[str] = None
    remediation: Optional[str] = None  # Backward compat
    classification: Optional[str] = None
    confidence_label: Optional[str] = None
    severity_justification: Optional[str] = None
    false_positive_check: Optional[str] = None
    auto_fix: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    tags: List[str] = []


class WebsiteScanResponse(BaseModel):
    scan_id: str
    target: str
    mode: Optional[str] = "safe"
    started_at: str
    duration: float  # seconds
    risk_score: float = 0.0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    endpoints_found: int = 0
    attack_surface_endpoints_count: int = 0
    findings: List[WebsiteScanFinding] = []
    headers: Dict[str, str] = {}
    endpoints: List[Dict[str, Any]] = []
    scan_logs: List[Dict[str, Any]] = []
    modules_run: List[str] = []
    false_positives_filtered: List[str] = []
    error: Optional[str] = None
    detected_technologies: List[Dict[str, Any]] = []
    detected_assets: List[Dict[str, Any]] = []
    technology_metadata: List[Dict[str, Any]] = []
    scanner_json: Optional[Dict[str, Any]] = None


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
    attack_surface_endpoints_count: int = 0
    duration: Optional[float] = None
    started_at: Optional[str] = None
    risk_score: Optional[float] = None
    mode: Optional[str] = None


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
    detected_technologies: List[Dict[str, Any]] = []
    detected_assets: List[Dict[str, Any]] = []
    technology_metadata: List[Dict[str, Any]] = []
    scanner_json: Dict[str, Any] = {}
