"""
Threat Modeling – Pydantic request / response models.

Matches the FormState + ThreatItem + AnalysisResult interfaces
used by the frontend at /dashboard/threat-modeling.
"""
from __future__ import annotations

from typing import List, Literal, Optional, Dict, Any
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


# ─── Enums / Literals ────────────────────────────────────────

AppType      = Literal["Web", "Mobile", "API", "Cloud"]
RiskLevel    = Literal["Low", "Medium", "High"]
RiskLabel    = Literal["Low", "Medium", "High", "Critical"]
DeployEnv    = Literal[
    "On-Premise",
    "Cloud (AWS / GCP / Azure)",
    "Hybrid",
    "Serverless",
    "Containerized (Docker / K8s)",
    "Edge",
]
DeployType   = Literal["SaaS", "Internal Tool", "Open Source", "Enterprise", "B2C Product", "IoT / Embedded"]
DatabaseType = Literal[
    "PostgreSQL", "MySQL / MariaDB", "MongoDB", "Redis", "SQLite",
    "Elasticsearch", "Firebase / Firestore", "DynamoDB", "MSSQL", "Oracle",
]
ProtocolType = Literal[
    "HTTPS", "HTTP (plain)", "WebSocket / WSS", "gRPC", "GraphQL",
    "REST", "MQTT", "AMQP", "FTP / SFTP", "SSH",
]
FrameworkType = Literal[
    "React", "Next.js", "Vue", "Angular", "Svelte",
    "Django", "FastAPI", "Flask", "Express", "NestJS",
    "Spring Boot", "Laravel", "Rails", "ASP.NET",
]
LanguageType = Literal[
    "TypeScript", "JavaScript", "Python", "Java", "Go",
    "PHP", "Ruby", "C#", "Rust", "C / C++",
]

# New enums for enhanced threat modeling
class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

class ThreatStatus(str, Enum):
    OPEN = "Open"
    MITIGATED = "Mitigated"
    ACCEPTED = "Accepted"
    CLOSED = "Closed"

class MitigationPriority(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ExportFormat(str, Enum):
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    XML = "xml"


# ─── Sub-models ───────────────────────────────────────────────

class ThreatItem(BaseModel):
    """A single generated threat entry – mirrors ThreatItem in the frontend."""
    id:          str
    title:       str
    risk:        RiskLevel
    category:    str
    description: str
    mitigation:  str
    stride_category: Optional[STRIDECategory] = None
    capec_id: Optional[str] = None
    asvs_controls: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    entry_points: List[str] = Field(default_factory=list)
    trust_boundaries: List[str] = Field(default_factory=list)
    priority_score: int = Field(default=0, ge=0, le=100)
    status: ThreatStatus = ThreatStatus.OPEN
    llm_summary: Optional[str] = None


class Asset(BaseModel):
    """Represents a system asset in the threat model."""
    id: str
    name: str
    type: str  # e.g., "Database", "API", "User Interface"
    description: str
    sensitivity_level: RiskLevel
    data_classification: str  # e.g., "Public", "Internal", "Confidential", "Restricted"


class EntryPoint(BaseModel):
    """Represents an entry point into the system."""
    id: str
    name: str
    type: str  # e.g., "API Endpoint", "User Input", "File Upload"
    description: str
    authentication_required: bool
    exposed_to_internet: bool


class TrustBoundary(BaseModel):
    """Represents a trust boundary in the system."""
    id: str
    name: str
    type: str  # e.g., "Network", "Process", "Data"
    description: str
    source_zone: str
    target_zone: str


class DataFlow(BaseModel):
    """Represents data flow in the DFD."""
    id: str
    name: str
    source: str  # Asset ID
    destination: str  # Asset ID
    data_type: str
    encryption: bool
    authentication: bool


class ArchitectureDiagram(BaseModel):
    """Represents the system architecture/DDF."""
    assets: List[Asset]
    entry_points: List[EntryPoint]
    trust_boundaries: List[TrustBoundary]
    data_flows: List[DataFlow]


class Mitigation(BaseModel):
    """Represents a mitigation for a threat."""
    id: str
    threat_id: str
    title: str
    description: str
    priority: MitigationPriority
    estimated_effort: str  # e.g., "Low", "Medium", "High"
    estimated_cost: str
    implementation_status: str  # e.g., "Not Started", "In Progress", "Completed"
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None


class BacklogTicket(BaseModel):
    """Represents a backlog ticket for mitigation."""
    id: str
    title: str
    description: str
    priority: MitigationPriority
    story_points: Optional[int] = None
    labels: List[str] = Field(default_factory=list)
    assignee: Optional[str] = None
    created_at: datetime
    due_date: Optional[datetime] = None


class HeatmapData(BaseModel):
    """Data for visual threat heatmap."""
    threat_id: str
    x_coordinate: float  # Position on heatmap
    y_coordinate: float  # Position on heatmap
    risk_score: int
    category: str


class ExportableReport(BaseModel):
    """Complete exportable threat modeling report."""
    id: str
    project_name: str
    created_at: datetime
    executive_summary: str
    threat_register: List[ThreatItem]
    prioritized_mitigations: List[Mitigation]
    architecture_diagram: ArchitectureDiagram
    risk_heatmap: List[HeatmapData]
    recommendations: List[str]
    generated_by: str

class ThreatModelCreateRequest(BaseModel):
    """
    Payload sent by the frontend when the user clicks 'Save Report'.
    Matches FormState exactly.
    """
    # Section 1 – Basic
    project_name:          str  = Field(..., min_length=1, max_length=200)
    app_type:              AppType
    uses_auth:             bool = False
    uses_database:         bool = False
    has_admin_panel:       bool = False
    uses_external_apis:    bool = False
    stores_sensitive_data: bool = False

    # Section 2 – Stack
    frameworks: List[str] = Field(default_factory=list)
    languages:  List[str] = Field(default_factory=list)

    # Section 3 – Environment
    deploy_envs:  List[str] = Field(default_factory=list)
    deploy_types: List[str] = Field(default_factory=list)

    # Section 4 – Data & Protocols
    databases: List[str] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)

    # Enhanced inputs for automated pipeline
    system_metadata: Dict[str, Any] = Field(default_factory=dict)
    architecture_diagram: Optional[ArchitectureDiagram] = None
    assets: List[Asset] = Field(default_factory=list)
    entry_points: List[EntryPoint] = Field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)
    auth_questions: Dict[str, Any] = Field(default_factory=dict)
    data_questions: Dict[str, Any] = Field(default_factory=dict)
    control_questions: Dict[str, Any] = Field(default_factory=dict)


# ─── Response Models ──────────────────────────────────────────

class ThreatModelAnalysisResponse(BaseModel):
    """Full analysis result returned by the API."""
    id:         str
    user_id:    Optional[str] = None

    # Inputs (echoed back)
    project_name:          str
    app_type:              str
    uses_auth:             bool
    uses_database:         bool
    has_admin_panel:       bool
    uses_external_apis:    bool
    stores_sensitive_data: bool
    frameworks:            List[str]
    languages:             List[str]
    deploy_envs:           List[str]
    deploy_types:          List[str]
    databases:             List[str]
    protocols:             List[str]

    # Enhanced inputs
    system_metadata: Dict[str, Any]
    architecture_diagram: Optional[ArchitectureDiagram]
    assets: List[Asset]
    entry_points: List[EntryPoint]
    trust_boundaries: List[TrustBoundary]
    auth_questions: Dict[str, Any]
    data_questions: Dict[str, Any]
    control_questions: Dict[str, Any]

    # Results
    risk_score: int                   # 0 – 100
    risk_label: RiskLabel             # Low / Medium / High / Critical
    threats:    List[ThreatItem]
    mitigations: List[Mitigation]
    heatmap_data: List[HeatmapData]

    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ThreatModelAnalysis(BaseModel):
    """Complete threat model analysis with all enhanced features."""
    id: str
    title: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    system_metadata: Optional[Dict[str, Any]] = None
    architecture_diagram: Optional[ArchitectureDiagram] = None
    assets: Optional[List[Asset]] = None
    entry_points: Optional[List[EntryPoint]] = None
    trust_boundaries: Optional[List[TrustBoundary]] = None
    auth_questions: Optional[Dict[str, Any]] = None
    data_questions: Optional[Dict[str, Any]] = None
    control_questions: Optional[Dict[str, Any]] = None
    threats: Optional[List[ThreatItem]] = None
    mitigations: Optional[List[Mitigation]] = None
    heatmap_data: Optional[HeatmapData] = None


class ThreatModelListItem(BaseModel):
    """Lightweight summary used in the list endpoint."""
    id:           str
    project_name: str
    app_type:     str
    risk_score:   int
    risk_label:   str
    threat_count: int
    mitigation_count: int
    created_at:   Optional[datetime] = None


class ThreatModelAnalyzeResponse(BaseModel):
    """
    Returned by POST /analyze (stateless analysis, no DB write).
    Identical shape to AnalysisResult on the frontend.
    """
    threats:    List[ThreatItem]
    risk_score: int
    risk_label: RiskLabel
    mitigations: List[Mitigation]
    heatmap_data: List[HeatmapData]


class ExportRequest(BaseModel):
    """Request to export a threat model report."""
    format: ExportFormat
    include_mitigations: bool = True
    include_architecture: bool = True
    include_heatmap: bool = True


class ExportResponse(BaseModel):
    """Response containing exported report data."""
    format: ExportFormat
    content: str  # Base64 encoded content or URL
    filename: str


class BacklogSyncRequest(BaseModel):
    """Request to sync mitigations with backlog system."""
    system: str  # e.g., "Jira", "GitHub", "Azure DevOps"
    project_key: str
    api_token: str
    base_url: str


class BacklogSyncResponse(BaseModel):
    """Response from backlog sync operation."""
    synced_tickets: List[BacklogTicket]
    errors: List[str]


class DeleteResponse(BaseModel):
    message: str
    id:      str
