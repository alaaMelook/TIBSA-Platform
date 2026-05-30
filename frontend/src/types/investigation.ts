// ── Enums ─────────────────────────────────────────────────

export type InvestigationStatus =
  | "created"
  | "pending"
  | "running"
  | "scanning"
  | "analyzing"
  | "correlating"
  | "modeling"
  | "explaining"
  | "completed"
  | "failed"
  | "stopped";

export type StageStatus = "pending" | "running" | "completed" | "failed" | "skipped";

// ── Stage Models ──────────────────────────────────────────

export interface InvestigationStage {
  stage: string;
  status: StageStatus;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  error: string | null;
}

export interface StructuredFinding {
  id: string;
  finding_id: string;
  title: string;
  severity: string;
  category: string;
  affected_url: string;
  evidence: string;
  tags: string[];
}

export interface SecurityContextItem {
  finding_id: string;
  finding_title: string;
  risk_interpretation: string;
  risk_category: string;
  severity_multiplier: number;
  contributing_factors: string[];
}

export interface IOCResult {
  indicator_type: string;
  value: string;
  source: string;
  reputation_score: number;
  threat_level: string;
  details: Record<string, any>;
  flagged: boolean;
}

export interface AttackChainStep {
  order: number;
  description: string;
  evidence_source: string;
}

export interface CorrelatedThreat {
  id: string;
  title: string;
  description: string;
  contributing_finding_ids: string[];
  contributing_ioc_values: string[];
  attack_chain: AttackChainStep[];
  combined_risk: string;
  confidence: number;
  severity?: string;
}

export interface CorrelationStageOutput {
  correlated_threats: CorrelatedThreat[];
  global_risk_score: number;
  total_correlations: number;
  escalated_risks: number;
}

export interface AutoThreatItem {
  stride_id: string;
  title: string;
  category: string;
  severity: string;
  likelihood: string;
  affected_asset: string;
  attack_scenario: string;
  mitigations: string[];
  related_findings: string[];
}

export interface ThreatModelStageOutput {
  stride_threats: AutoThreatItem[];
  stride_matrix: Record<string, any>;
  total_threats: number;
}

export interface AIExplainStageOutput {
  executive_summary: string;
  technical_summary: string;
  key_risks: string[];
  recommendations: string[];
  confidence: number;
}

// ── Master Investigation ──────────────────────────────────

export interface Investigation {
  id: string;
  scan_id: string;
  target: string;
  status: InvestigationStatus;
  risk_score: number;
  started_at: string;
  completed_at: string | null;
  include_ti: boolean;
  tm_mode: string;
  current_stage: string;
  progress_percent: number;
  pipeline_state: Record<string, any> | null;
  final_result: {
    scan_id: string;
    target: string;
    risk_score: number;
    findings_count: number;
    assets_count: number;
    ti_enriched: boolean;
    tm_mode: string;
    correlation?: {
      correlated_threats: CorrelatedThreat[];
      global_risk_score: number;
      unique_threats_identified: number;
      escalated_risks_count: number;
    };
    stride?: {
      stride_threats: AutoThreatItem[];
      stride_matrix: Record<string, any>;
    };
    reporter?: {
      investigation_id?: string;
      ai_summary?: {
        executive_summary: string;
        technical_summary: string;
        remediation_plan: Array<{
          priority: number;
          title: string;
          description: string;
          estimated_effort: string;
        }>;
        risk_explanation: string;
      };
      export_metadata?: Record<string, any>;
      export_status?: string;
      started_at?: string;
      completed_at?: string;
      duration_seconds?: number;
      confidence?: number;
    };
    status?: string;
    completed_at?: string;
  } | null;
}

export interface InvestigationStatusResponse {
  id: string;
  scan_id: string;
  target: string;
  status: InvestigationStatus;
  risk_score: number;
  started_at: string;
  completed_at: string | null;
  current_stage: string;
  progress_percent: number;
}

export interface InvestigationCreateRequest {
  target: string;
  mode?: string;
  tests?: string[];
  include_ti?: boolean;
  tm_mode?: string;
}

export interface LiveEvent {
  id: string;
  timestamp: string;
  stage: string;
  message: string;
  severity: "info" | "low" | "medium" | "high" | "critical" | "success" | "warning";
}
