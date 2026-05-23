"""
Pydantic schemas representing raw scanner outputs.
"""
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any, Optional

class RawFinding(BaseModel):
    title: str
    module: Optional[str] = None
    classification: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    sev: Optional[str] = None
    confidence: Optional[str] = None
    url: Optional[str] = None
    affected_url: Optional[str] = None
    evidence: Optional[Any] = None
    details: Optional[Any] = None
    recommendation: Optional[str] = None
    tags: Optional[List[str]] = None
    finding_id: Optional[str] = None

    model_config = ConfigDict(extra="ignore")

class RawScannerOutput(BaseModel):
    scan_id: str
    target: str
    findings: List[RawFinding] = []
    detected_technologies: List[Dict[str, Any]] = []
    detected_assets: List[Dict[str, Any]] = []
    technology_metadata: List[Dict[str, Any]] = []

    model_config = ConfigDict(extra="ignore")
