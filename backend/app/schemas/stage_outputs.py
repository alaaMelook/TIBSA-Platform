"""
Stage Output Schemas for Investigation Pipeline Stages 4-6.

Represents outputs from:
- Stage 4: Threat Correlation
- Stage 5: STRIDE Threat Modeling
- Stage 6: AI Security Reporter & Report Export
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


# ─── Enums ───────────────────────────────────────────────────────


class STRIDEType(str, Enum):
    """STRIDE threat categories."""
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ─── Stage 4: Correlation Output Schemas ───────────────────────


class AttackChainStep(BaseModel):
    """Represents a single step in an attack chain."""
    order: int = Field(..., description="Sequential step number")
    description: str = Field(..., description="Description of this attack step")
    finding_ids: List[str] = Field(
        default_factory=list,
        description="IDs of findings involved in this step"
    )
    severity: ThreatSeverity = Field(..., description="Severity of this step")
    evidence_source: Optional[str] = Field("pentest", description="Evidence source type for UI badge")
    affected_endpoint: Optional[str] = Field("", description="Affected URL or endpoint for the step")


class CorrelatedThreat(BaseModel):
    """Represents a correlated threat from multiple findings."""
    threat_id: str = Field(..., description="Unique threat correlation ID")
    title: str = Field(..., description="Human-readable threat title")
    description: str = Field(..., description="Detailed description")
    
    # Source findings
    source_findings: List[str] = Field(
        ..., description="IDs of correlated findings"
    )
    correlation_rule: str = Field(
        ..., description="Rule name that triggered correlation"
    )
    
    # Risk assessment
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence in correlation (0-1)"
    )
    severity: ThreatSeverity = Field(..., description="Overall threat severity")
    risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Risk score (0-100)"
    )
    
    # Attack chain
    attack_chain: List[AttackChainStep] = Field(
        default_factory=list, description="Step-by-step attack scenario"
    )
    
    # Additional context
    affected_endpoints: List[str] = Field(
        default_factory=list, description="URLs/endpoints affected"
    )
    tags: List[str] = Field(default_factory=list, description="Correlation tags")

    # Upgraded Investigation Fields
    impact: Optional[str] = Field(None, description="Impact analysis")
    exploitation_scenario: Optional[str] = Field(None, description="Exploitation scenario")
    recommended_mitigation: Optional[str] = Field(None, description="Recommended mitigation")
    global_chain_risk: Optional[float] = Field(None, description="Escalated chain risk score (0-100)")
    chain_confidence: Optional[float] = Field(None, description="Escalated chain confidence score (0-100)")
    attack_complexity: Optional[str] = Field(None, description="Attack complexity (low/medium/high)")
    sources: List[str] = Field(default_factory=list, description="Attributing source engines")

    # Frontend Compatibility Fallbacks
    id: Optional[str] = Field(None, description="Alias for threat_id")
    combined_risk: Optional[str] = Field("info", description="Alias for severity")
    confidence: Optional[float] = Field(0.5, description="Alias for confidence_score")
    contributing_finding_ids: List[str] = Field(default_factory=list, description="Alias for source_findings")
    contributing_ioc_values: List[str] = Field(default_factory=list, description="Associated IOC indicators")
    risk_label: Optional[str] = Field("Low", description="Risk level label")


class CorrelationStageOutput(BaseModel):
    """Complete output from Stage 4: Threat Correlation."""
    stage_id: str = Field("stage_4_correlation", description="Stage identifier")
    investigation_id: str = Field(..., description="Investigation ID")
    
    # Correlation results
    correlated_threats: List[CorrelatedThreat] = Field(
        default_factory=list, description="All correlated threats"
    )
    
    # Global risk metrics
    global_risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Overall investigation risk (0-100)"
    )
    risk_summary: Dict[str, Any] = Field(
        default_factory=dict, description="Risk breakdown by category"
    )
    
    # Deduplication stats
    total_findings_input: int = Field(..., description="Total findings analyzed")
    unique_threats_identified: int = Field(
        ..., description="Number of unique correlated threats"
    )
    duplicates_removed: int = Field(..., description="Duplicate findings removed")
    
    # Timing
    started_at: datetime = Field(..., description="Stage start time")
    completed_at: Optional[datetime] = Field(None, description="Stage completion time")
    duration_seconds: Optional[float] = Field(None, description="Execution duration")

    # Frontend Compatibility Counts
    total_correlations: int = Field(0, description="Total number of correlations")
    escalated_risks: int = Field(0, description="Count of escalated risk items")
    escalated_risks_count: int = Field(0, description="Count of escalated risk items")


# ─── Stage 5: STRIDE Threat Modeling Output Schemas ───────────────


class STRIDEThreat(BaseModel):
    """Represents a single STRIDE threat."""
    stride_id: str = Field(..., description="Unique STRIDE threat ID")
    category: STRIDEType = Field(..., description="STRIDE category")
    
    # Threat details
    affected_asset: str = Field(..., description="Asset or component affected")
    attack_scenario: str = Field(..., description="Description of attack scenario")
    
    # Risk assessment
    severity: ThreatSeverity = Field(..., description="Threat severity")
    likelihood: ThreatSeverity = Field(..., description="Likelihood of exploitation")
    
    # Mitigations
    mitigations: List[str] = Field(
        default_factory=list, description="Recommended mitigations"
    )
    
    # Mapping
    related_findings: List[str] = Field(
        default_factory=list, description="Related correlated threat IDs"
    )

    # Extended STRIDE threat model fields
    attack_prerequisites: Optional[str] = Field(None, description="Attack prerequisites")
    business_impact: Optional[str] = Field(None, description="Business impact")
    mitigation_priority: Optional[str] = Field(None, description="Mitigation priority (Low/Medium/High/Critical)")
    detection_recommendations: Optional[List[str]] = Field(default_factory=list, description="Detection recommendations")
    sources: List[str] = Field(default_factory=list, description="Originating engine sources")


class STRIDEMatrix(BaseModel):
    """STRIDE threat matrix summary."""
    spoofing_count: int = Field(default=0)
    tampering_count: int = Field(default=0)
    repudiation_count: int = Field(default=0)
    information_disclosure_count: int = Field(default=0)
    denial_of_service_count: int = Field(default=0)
    elevation_of_privilege_count: int = Field(default=0)
    
    def total_threats(self) -> int:
        """Get total threat count."""
        return (
            self.spoofing_count +
            self.tampering_count +
            self.repudiation_count +
            self.information_disclosure_count +
            self.denial_of_service_count +
            self.elevation_of_privilege_count
        )


class STRIDEStageOutput(BaseModel):
    """Complete output from Stage 5: STRIDE Threat Modeling."""
    stage_id: str = Field("stage_5_stride", description="Stage identifier")
    investigation_id: str = Field(..., description="Investigation ID")
    
    # Threats
    stride_threats: List[STRIDEThreat] = Field(
        default_factory=list, description="All identified STRIDE threats"
    )
    
    # Summary
    stride_matrix: STRIDEMatrix = Field(
        ..., description="Threat distribution across STRIDE categories"
    )
    
    # Timing
    started_at: datetime = Field(..., description="Stage start time")
    completed_at: Optional[datetime] = Field(None, description="Stage completion time")
    duration_seconds: Optional[float] = Field(None, description="Execution duration")


# ─── Stage 6: AI Reporter & Export Output Schemas ───────────────


class RemediationStep(BaseModel):
    """A single remediation step."""
    priority: int = Field(..., ge=1, le=5, description="Priority level 1-5")
    title: str = Field(..., description="Remediation title")
    description: str = Field(..., description="Detailed description")
    estimated_effort: str = Field(..., description="e.g., 'Low', 'Medium', 'High'")
    estimated_cost: Optional[str] = Field(None, description="Estimated cost")


class AISummary(BaseModel):
    """AI-generated security summary."""
    executive_summary: str = Field(
        ..., description="Non-technical summary for executives"
    )
    technical_summary: str = Field(
        ..., description="Technical summary for engineers"
    )
    remediation_plan: List[RemediationStep] = Field(
        default_factory=list, description="Prioritized remediation steps"
    )
    risk_explanation: str = Field(
        ..., description="Plain-language explanation of overall risk"
    )

    # Advanced SOC investigation report fields
    risk_overview: Optional[str] = None
    investigation_timeline: Optional[List[Dict[str, Any]]] = None
    attack_surface_summary: Optional[str] = None
    threat_intelligence_summary: Optional[str] = None
    correlated_attack_chains: Optional[List[Dict[str, Any]]] = None
    stride_threat_matrix: Optional[Dict[str, Any]] = None
    high_risk_findings: Optional[List[Dict[str, Any]]] = None
    exploitation_scenarios: Optional[List[Dict[str, Any]]] = None
    business_impact_analysis: Optional[str] = None
    mitigation_roadmap: Optional[List[Dict[str, Any]]] = None
    immediate_actions: Optional[List[str]] = []
    long_term_improvements: Optional[List[str]] = []
    technical_appendix: Optional[str] = None


class ExportMetadata(BaseModel):
    """Metadata for exported report."""
    investigation_id: str
    target: str
    scan_date: datetime
    global_risk_score: float
    total_findings: int
    total_threats: int


class ReporterStageOutput(BaseModel):
    """Complete output from Stage 6: AI Reporter & Export."""
    stage_id: str = Field("stage_6_reporter", description="Stage identifier")
    investigation_id: str = Field(..., description="Investigation ID")
    
    # AI summaries
    ai_summary: AISummary = Field(
        ..., description="AI-generated summary (or rule-based fallback)"
    )
    
    # Export metadata
    export_metadata: ExportMetadata = Field(
        ..., description="Metadata for exports"
    )
    
    # Export paths/status
    json_export_path: Optional[str] = Field(
        None, description="Path to JSON export"
    )
    pdf_export_path: Optional[str] = Field(
        None, description="Path to PDF export"
    )
    export_status: str = Field(
        default="pending", description="e.g., 'pending', 'completed', 'failed'"
    )
    
    # Timing
    started_at: datetime = Field(..., description="Stage start time")
    completed_at: Optional[datetime] = Field(None, description="Stage completion time")
    duration_seconds: Optional[float] = Field(None, description="Execution duration")


# ─── Complete Investigation Output ───────────────────────────────


class FullInvestigationOutput(BaseModel):
    """Complete investigation output including all stages."""
    investigation_id: str
    target: str
    status: str
    
    # All stage outputs
    correlation_output: Optional[CorrelationStageOutput] = None
    stride_output: Optional[STRIDEStageOutput] = None
    reporter_output: Optional[ReporterStageOutput] = None
    
    # Final metrics
    global_risk_score: float
    completed_at: Optional[datetime] = None
