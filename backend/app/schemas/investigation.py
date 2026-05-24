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

    model_config = ConfigDict(from_attributes=True)

class TIInvestigationResponse(BaseModel):
    investigation_id: str
    status: str
    risk_score: float
    summary: Dict[str, Any]
    ti_findings: List[TIFinding]
    reputation_context: Dict[str, Any]

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

class InvestigationStatusResponse(BaseModel):
    id: str
    scan_id: str
    status: str
    risk_score: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    current_stage: str
    progress_percent: float

    model_config = ConfigDict(from_attributes=True)

class InvestigationResponse(TIInvestigationResponse):
    pass
