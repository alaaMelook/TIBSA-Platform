"""
Pydantic schemas for Investigations, Assets, and Reports.
"""
from pydantic import BaseModel, ConfigDict, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# ─── TI Schema ───────────────────────────────────────────
class TIFinding(BaseModel):
    finding_id: str
    title: str
    category: str
    classification: str
    severity: str
    confidence: float
    false_positive_probability: float
    verification_status: str
    exploitability: str
    affected_asset: str
    risk_score: float
    risk_multiplier: float
    reputation_context: Optional[Dict[str, Any]] = None
    source_modules: List[str] = []
    evidence: Optional[str] = None
    tags: List[str] = []
    exploitability_score: float = 0.0

    # Enriched OTX/VT Threat Intelligence fields
    ioc: Optional[str] = None
    type: Optional[str] = None
    vt_score: Optional[int] = None
    vt_status: Optional[str] = None
    otx_pulses: Optional[List[str]] = []
    threat_tags: Optional[List[str]] = []
    campaign_context: Optional[List[str]] = []
    related_malware_families: Optional[List[str]] = []
    confidence_level: Optional[str] = None
    risk_reason: Optional[str] = None
    recommended_action: Optional[str] = None
    confidence_score: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

class TIInvestigationResponse(BaseModel):
    investigation_id: str
    status: str
    risk_score: float
    summary: Dict[str, Any]
    ti_findings: List[TIFinding]
    reputation_context: Dict[str, Any]

    # Optional fields for frontend integration
    scan_id: Optional[str] = None
    target: Optional[str] = None
    mode: Optional[str] = None
    started_at: Optional[str] = None
    duration: Optional[float] = None
    critical: Optional[int] = None
    high: Optional[int] = None
    medium: Optional[int] = None
    low: Optional[int] = None
    info: Optional[int] = None
    total: Optional[int] = None
    findings: Optional[List[Dict[str, Any]]] = None
    detected_technologies: Optional[List[Dict[str, Any]]] = None
    detected_assets: Optional[List[Dict[str, Any]]] = None
    technology_metadata: Optional[List[Dict[str, Any]]] = None
    scanner_json: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    executions_confirmed: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

# ─── Investigation Schemas (Creation & Status) ───────────────────────────
class InvestigationBase(BaseModel):
    target: str

class InvestigationCreate(InvestigationBase):
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
    mode: Optional[str] = "safe"
    include_ti: Optional[bool] = True
    tm_mode: Optional[str] = "enhanced"
    enable_sqlmap: Optional[bool] = False
    auth_browser_analysis: Optional[bool] = False
    authorized_auth_mode: Optional[bool] = False
    auth_lifecycle_checks: Optional[bool] = False
    authz_transition_checks: Optional[bool] = False
    session_cookie: Optional[str] = None
    enable_strict_correlation_hardening: Optional[bool] = True

class InvestigationStatusResponse(BaseModel):
    id: str
    scan_id: str
    target: str
    status: str
    risk_score: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    current_stage: str
    progress_percent: float

    model_config = ConfigDict(from_attributes=True)


class InvestigationResponse(TIInvestigationResponse):
    scan_id: str
    target: str
    current_stage: str
    progress_percent: float
    pipeline_state: Optional[Dict[str, Any]] = None
    final_result: Optional[Dict[str, Any]] = None

