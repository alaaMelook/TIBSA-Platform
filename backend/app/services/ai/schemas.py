"""
Pydantic schemas for the AI Malware Explanation feature.

MalwareScanInput:  structured payload built internally after Malice/YARA/CAPA analysis.
AIExplanationResponse: the strict JSON returned to the frontend.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from typing import List


class MalwareScanInput(BaseModel):
    """Aggregated scan results sent to the AI for explanation."""

    file_name: str = Field(..., description="Original uploaded file name")
    file_type: str = Field(default="Unknown", description="Detected file type")

    detections: List[str] = Field(default_factory=list, description="Malice AV detection labels")
    detection_count: int = Field(default=0, description="Number of AV engines that flagged the file")

    yara_matches: List[str] = Field(default_factory=list, description="YARA rule names that matched")
    capa_behaviors: List[str] = Field(default_factory=list, description="CAPA-identified behaviors")

    threat_score: int = Field(default=0, ge=0, le=100, description="Computed threat score 0-100")


class BehaviorFinding(BaseModel):
    """A single behavior finding from a specific analysis source."""
    source: str = Field(..., description="Source: CAPA, YARA, or MALICE")
    finding: str = Field(..., description="Human-readable finding description")


class AIExplanationResponse(BaseModel):
    """Full AI analysis response returned to the frontend."""

    risk_level: str = Field(..., description="Risk level: Critical, High, Medium, Low, or None")
    risk_score: int = Field(default=0, ge=0, le=100, description="Risk score 0-100")
    summary: str = Field(..., description="Detailed threat summary")
    what_it_does: List[str] = Field(default_factory=list, description="Simple behavioral descriptions")
    attack_impact: List[str] = Field(default_factory=list, description="Potential attack impacts")
    behavior_analysis: List[BehaviorFinding] = Field(default_factory=list, description="Source-mapped findings")
    recommended_actions: List[str] = Field(default_factory=list, description="Prioritized remediation steps")
    technical_notes: str = Field(default="", description="Detailed technical analysis")
    confidence: int = Field(default=50, ge=0, le=100, description="AI confidence percentage")
