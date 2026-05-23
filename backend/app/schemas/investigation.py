"""
Pydantic schemas for Investigations, Assets, and Reports.
"""
from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from app.schemas.finding import FindingResponse

# ─── Asset Schemas ───────────────────────────────────────────
class AssetBase(BaseModel):
    asset_type: str
    url: str
    technology: Optional[str] = None

class AssetCreate(AssetBase):
    pass

class AssetResponse(AssetBase):
    id: str
    investigation_id: str

    model_config = ConfigDict(from_attributes=True)


# ─── Threat Intelligence Report Schemas ───────────────────────
class TIReportResponse(BaseModel):
    id: str
    investigation_id: str
    overall_risk: float
    risk_summary: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── Threat Modeling Report Schemas ───────────────────────────
class TMReportResponse(BaseModel):
    id: str
    investigation_id: str
    stride_summary: Dict[str, Any]
    mitigations: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─── Investigation Schemas ────────────────────────────────────
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
    tm_mode: Optional[str] = "enhanced"  # "enhanced" or "standalone"

class InvestigationResponse(InvestigationBase):
    id: str
    scan_id: str
    status: str
    risk_score: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    include_ti: bool
    tm_mode: str
    current_stage: str
    progress_percent: float
    pipeline_state: Optional[Dict[str, Any]] = None
    final_result: Optional[Dict[str, Any]] = None
    findings: List[FindingResponse] = []
    assets: List[AssetResponse] = []
    ti_reports: List[TIReportResponse] = []
    tm_reports: List[TMReportResponse] = []

    model_config = ConfigDict(from_attributes=True)

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
