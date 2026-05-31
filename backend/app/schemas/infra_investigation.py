"""
Pydantic schemas for the Threat Infrastructure Intelligence Flow.
Mirrors frontend types in src/types/infra_investigation.ts exactly.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


# ─── Request ─────────────────────────────────────────────────────────────────

class InfraCreateRequest(BaseModel):
    target: str
    enable_passive_dns: bool = True
    enable_ai_summary: bool = True


# ─── Reputation Results ───────────────────────────────────────────────────────

class AbuseIPDBResult(BaseModel):
    is_public: bool = False
    abuse_confidence_score: int = 0
    country_code: str = ""
    isp: str = ""
    domain: str = ""
    total_reports: int = 0
    last_reported_at: Optional[str] = None
    error: Optional[str] = None


class URLhausResult(BaseModel):
    query_status: str = "no_results"
    urlhaus_reference: Optional[str] = None
    blacklists: Optional[Dict[str, str]] = None
    urls_on_this_host: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None


class ThreatFoxResult(BaseModel):
    query_status: str = "no_results"
    iocs: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None


class OTXPulsesResult(BaseModel):
    pulse_count: int = 0
    pulses: List[Dict[str, Any]] = []
    error: Optional[str] = None


class ReputationResults(BaseModel):
    abuseipdb: Optional[AbuseIPDBResult] = None
    urlhaus: Optional[URLhausResult] = None
    threatfox: Optional[ThreatFoxResult] = None
    otx: Optional[OTXPulsesResult] = None


# ─── Enrichment Results ───────────────────────────────────────────────────────

class DNSRecord(BaseModel):
    type: str
    value: str
    ttl: Optional[int] = None


class DNSResult(BaseModel):
    records: List[DNSRecord] = []
    error: Optional[str] = None


class WHOISResult(BaseModel):
    registrar: Optional[str] = None
    registrant_org: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    is_newly_registered: bool = False
    status: List[str] = []
    error: Optional[str] = None


class SSLCertResult(BaseModel):
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_expired: bool = False
    is_self_signed: bool = False
    san_domains: List[str] = []
    error: Optional[str] = None


class GeoIPResult(BaseModel):
    ip: str = ""
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    timezone: Optional[str] = None
    error: Optional[str] = None


class EnrichmentResults(BaseModel):
    dns: Optional[DNSResult] = None
    whois: Optional[WHOISResult] = None
    ssl: Optional[SSLCertResult] = None
    geoip: Optional[GeoIPResult] = None


# ─── Passive DNS ──────────────────────────────────────────────────────────────

class PassiveDNSEntry(BaseModel):
    hostname: str
    address: str
    first: str
    last: str
    asn: Optional[str] = None
    country_code: Optional[str] = None


class PassiveDNSResult(BaseModel):
    passive_dns: List[PassiveDNSEntry] = []
    count: int = 0
    error: Optional[str] = None


# ─── Threat Indicators ────────────────────────────────────────────────────────

class ThreatIndicatorCheck(BaseModel):
    id: str
    name: str
    description: str
    triggered: bool
    severity: str  # low | medium | high | critical | info
    detail: Optional[str] = None


class ThreatIndicatorsResult(BaseModel):
    checks: List[ThreatIndicatorCheck] = []
    phishing_score: float = 0.0
    total_triggered: int = 0


# ─── Correlation ──────────────────────────────────────────────────────────────

class InfraCorrelationRule(BaseModel):
    rule_id: str
    rule_name: str
    triggered: bool
    confidence: str  # low | medium | high
    description: str
    evidence: List[str] = []
    relationship_type: str


class InfraCorrelationResult(BaseModel):
    rules_evaluated: int = 0
    rules_triggered: int = 0
    relationships: List[InfraCorrelationRule] = []
    overall_confidence: str = "low"


# ─── Risk Score ───────────────────────────────────────────────────────────────

class InfraRiskBreakdown(BaseModel):
    reputation_score: float = 0.0
    infrastructure_score: float = 0.0
    phishing_score: float = 0.0
    weighted_total: float = 0.0
    risk_label: str = "Clean"  # Clean | Low | Medium | High | Critical
    contributing_factors: List[str] = []


# ─── Graph ───────────────────────────────────────────────────────────────────

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # target | ip | domain | asn | registrar | campaign | malware
    risk_level: str  # clean | low | medium | high | critical
    metadata: Optional[Dict[str, Any]] = None


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    confidence: str  # low | medium | high


class InfraGraph(BaseModel):
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []


# ─── AI Summary ───────────────────────────────────────────────────────────────

class InfraAISummary(BaseModel):
    executive_summary: str = ""
    threat_classification: str = ""
    why_suspicious: str = ""
    recommended_actions: List[str] = []
    confidence: float = 0.0
    error: Optional[str] = None


# ─── Full Results Payload ─────────────────────────────────────────────────────

class InfraInvestigationResults(BaseModel):
    target: str
    target_type: str
    normalized_target: str
    reputation: Optional[ReputationResults] = None
    enrichment: Optional[EnrichmentResults] = None
    passive_dns: Optional[PassiveDNSResult] = None
    threat_indicators: Optional[ThreatIndicatorsResult] = None
    correlation: Optional[InfraCorrelationResult] = None
    risk: Optional[InfraRiskBreakdown] = None
    graph: Optional[InfraGraph] = None
    ai_summary: Optional[InfraAISummary] = None


# ─── API Response Models ──────────────────────────────────────────────────────

class InfraInvestigationListItem(BaseModel):
    id: str
    target: str
    target_type: str
    status: str
    current_stage: str
    progress_percent: float
    risk_score: float
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class InfraInvestigationDetail(BaseModel):
    id: str
    target: str
    target_type: str
    status: str
    current_stage: str
    progress_percent: float
    risk_score: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    results: Optional[InfraInvestigationResults] = None
    error: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
