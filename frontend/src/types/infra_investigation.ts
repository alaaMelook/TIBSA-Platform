// ─── Infra Investigation Status ─────────────────────────────────────────────

export type InfraTargetType = "url" | "domain" | "ip" | "hash" | "email";

export type InfraStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "stopped";

// ─── Pipeline Stage ──────────────────────────────────────────────────────────

export interface InfraPipelineStage {
  key: string;
  name: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  error?: string | null;
}

// ─── Reputation Results ───────────────────────────────────────────────────────

export interface AbuseIPDBResult {
  is_public: boolean;
  abuse_confidence_score: number;
  country_code: string;
  isp: string;
  domain: string;
  total_reports: number;
  last_reported_at: string | null;
  error?: string;
}

export interface URLhausResult {
  query_status: string; // "is_listed" | "no_results"
  urlhaus_reference: string | null;
  blacklists?: Record<string, string>;
  urls_on_this_host?: Array<{
    url: string;
    url_status: string;
    threat: string;
    date_added: string;
  }>;
  error?: string;
}

export interface ThreatFoxResult {
  query_status: string; // "ok" | "no_results"
  iocs?: Array<{
    ioc: string;
    ioc_type: string;
    threat_type: string;
    malware: string;
    malware_printable: string;
    confidence_level: number;
    first_seen: string;
    last_seen: string;
  }>;
  error?: string;
}

export interface OTXPulsesResult {
  pulse_count: number;
  pulses: Array<{
    name: string;
    description: string;
    tags: string[];
    malware_families: string[];
    targeted_countries: string[];
  }>;
  error?: string;
}

// ─── Enrichment Results ───────────────────────────────────────────────────────

export interface DNSRecord {
  type: string; // "A" | "MX" | "NS" | "TXT" | "CNAME"
  value: string;
  ttl?: number;
}

export interface DNSResult {
  records: DNSRecord[];
  error?: string;
}

export interface WHOISResult {
  registrar: string | null;
  registrant_org: string | null;
  creation_date: string | null;
  expiration_date: string | null;
  updated_date: string | null;
  domain_age_days: number | null;
  is_newly_registered: boolean;
  status: string[];
  error?: string;
}

export interface SSLCertResult {
  subject_cn: string | null;
  issuer_cn: string | null;
  issuer_org: string | null;
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  is_expired: boolean;
  is_self_signed: boolean;
  san_domains: string[];
  error?: string;
}

export interface GeoIPResult {
  ip: string;
  country: string | null;
  country_code: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  org: string | null;  // ISP / Org name
  asn: string | null;
  timezone: string | null;
  error?: string;
}

// ─── Passive DNS ──────────────────────────────────────────────────────────────

export interface PassiveDNSEntry {
  hostname: string;
  address: string;
  first: string;
  last: string;
  asn: string | null;
  country_code: string | null;
}

export interface PassiveDNSResult {
  passive_dns: PassiveDNSEntry[];
  count: number;
  error?: string;
}

// ─── Threat Indicators ────────────────────────────────────────────────────────

export interface ThreatIndicatorCheck {
  id: string;
  name: string;
  description: string;
  triggered: boolean;
  severity: "low" | "medium" | "high" | "critical" | "info";
  detail?: string;
}

export interface ThreatIndicatorsResult {
  checks: ThreatIndicatorCheck[];
  phishing_score: number;
  total_triggered: number;
}

// ─── Correlation ──────────────────────────────────────────────────────────────

export interface InfraCorrelationRule {
  rule_id: string;
  rule_name: string;
  triggered: boolean;
  confidence: "low" | "medium" | "high";
  description: string;
  evidence: string[];
  relationship_type: string;
}

export interface InfraCorrelationResult {
  rules_evaluated: number;
  rules_triggered: number;
  relationships: InfraCorrelationRule[];
  overall_confidence: "low" | "medium" | "high";
}

// ─── Risk Score ───────────────────────────────────────────────────────────────

export interface InfraRiskBreakdown {
  reputation_score: number;
  infrastructure_score: number;
  phishing_score: number;
  weighted_total: number;
  risk_label: "Clean" | "Low" | "Medium" | "High" | "Critical";
  contributing_factors: string[];
}

// ─── Graph Nodes & Edges ─────────────────────────────────────────────────────

export interface GraphNode {
  id: string;
  label: string;
  type: "target" | "ip" | "domain" | "asn" | "registrar" | "campaign" | "malware";
  risk_level: "clean" | "low" | "medium" | "high" | "critical";
  metadata?: Record<string, string | number | boolean | null>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
  confidence: "low" | "medium" | "high";
}

export interface InfraGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// ─── AI Summary ───────────────────────────────────────────────────────────────

export interface InfraAISummary {
  executive_summary: string;
  threat_classification: string;
  why_suspicious: string;
  recommended_actions: string[];
  confidence: number;
  error?: string;
}

// ─── Full Results Payload (stored in Supabase `results` JSONB) ────────────────

export interface InfraInvestigationResults {
  target: string;
  target_type: InfraTargetType;
  normalized_target: string;
  // Stage results
  reputation?: {
    abuseipdb?: AbuseIPDBResult;
    urlhaus?: URLhausResult;
    threatfox?: ThreatFoxResult;
    otx?: OTXPulsesResult;
  };
  enrichment?: {
    dns?: DNSResult;
    whois?: WHOISResult;
    ssl?: SSLCertResult;
    geoip?: GeoIPResult;
  };
  passive_dns?: PassiveDNSResult;
  threat_indicators?: ThreatIndicatorsResult;
  correlation?: InfraCorrelationResult;
  risk?: InfraRiskBreakdown;
  graph?: InfraGraph;
  ai_summary?: InfraAISummary;
}

// ─── Main Investigation Model ─────────────────────────────────────────────────

export interface InfraInvestigation {
  id: string;
  target: string;
  target_type: InfraTargetType;
  status: InfraStatus;
  current_stage: string;
  progress_percent: number;
  risk_score: number;
  started_at: string;
  completed_at: string | null;
  results: InfraInvestigationResults | null;
}

// ─── API Response Shapes ──────────────────────────────────────────────────────

export interface InfraInvestigationListItem {
  id: string;
  target: string;
  target_type: InfraTargetType;
  status: InfraStatus;
  current_stage: string;
  progress_percent: number;
  risk_score: number;
  started_at: string;
  completed_at: string | null;
}

export interface InfraCreateRequest {
  target: string;
  enable_passive_dns?: boolean;
  enable_ai_summary?: boolean;
}

// ─── Live Event (SOC Feed) ────────────────────────────────────────────────────

export interface InfraLiveEvent {
  id: string;
  timestamp: string;
  stage: string;
  message: string;
  severity: "info" | "success" | "warning" | "critical";
}
