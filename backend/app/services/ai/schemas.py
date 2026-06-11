from __future__ import annotations
from pydantic import BaseModel, Field
from typing import List, Optional

class MalwareScanInput(BaseModel):
    file_name: str = Field(..., description="Original uploaded file name")
    file_type: str = Field(default="Unknown", description="Detected file type")
    detections: List[str] = Field(default_factory=list, description="Malice AV detection labels")
    detection_count: int = Field(default=0, description="Number of AV engines that flagged the file")
    yara_matches: List[str] = Field(default_factory=list, description="YARA rule names that matched")
    capa_behaviors: List[str] = Field(default_factory=list, description="CAPA-identified behaviors")
    threat_score: int = Field(default=0, ge=0, le=100, description="Computed threat score 0-100")

class BehaviorFinding(BaseModel):
    source: str = Field(..., description="Source: CAPA, YARA, or MALICE")
    finding: str = Field(..., description="Human-readable finding description")

class AIExplanationResponse(BaseModel):
    risk_level: str = Field(..., description="Risk level: Critical, High, Medium, Low, or None")
    risk_score: int = Field(default=0, ge=0, le=100, description="Risk score 0-100")
    summary: str = Field(..., description="Detailed threat summary")
    what_it_does: List[str] = Field(default_factory=list, description="Simple behavioral descriptions")
    attack_impact: List[str] = Field(default_factory=list, description="Potential attack impacts")
    behavior_analysis: List[BehaviorFinding] = Field(default_factory=list, description="Source-mapped findings")
    recommended_actions: List[str] = Field(default_factory=list, description="Prioritized remediation steps")
    technical_notes: str = Field(default="", description="Detailed technical analysis")
    confidence: int = Field(default=50, ge=0, le=100, description="AI confidence percentage")

class RiskAssessment(BaseModel):
    risk_score: int = Field(...)
    risk_level: str = Field(...)
    justification: str = Field(...)

class SOCReport(BaseModel):
    executive_summary: str = Field(...)
    detection_summary: str = Field(...)
    final_verdict: str = Field(...)
    malware_classification: str = Field(...)
    confidence_assessment: str = Field(...)
    technical_findings: str = Field(...)
    indicators_of_compromise: List[str] = Field(default_factory=list)
    risk_assessment: RiskAssessment = Field(...)
    potential_impact: str = Field(...)
    recommended_actions: List[str] = Field(default_factory=list)
    analyst_conclusion: str = Field(...)

class GeminiReportResponse(BaseModel):
    """
    Structured response mapping exactly to the Gemini AI report requirements.
    """
    soc_report: SOCReport = Field(..., description="SOC Report for UI Dashboard")
    pdf_report: str = Field(..., description="PDF Report formatted as enterprise cybersecurity text")

