import { useState, useEffect, useRef, useCallback } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/hooks/useAuth";
import {
  InfraInvestigation,
  InfraInvestigationResults,
  InfraPipelineStage,
  InfraLiveEvent,
  InfraStatus,
} from "@/types/infra_investigation";

// ─── Stage definitions ────────────────────────────────────────────────────────

const PIPELINE_STAGES = [
  { key: "intake",       name: "Intake & Normalization",    threshold: 12  },
  { key: "reputation",   name: "Reputation Analysis",       threshold: 30  },
  { key: "enrichment",   name: "DNS & Infrastructure",      threshold: 50  },
  { key: "passive_dns",  name: "Passive DNS Mapping",       threshold: 65  },
  { key: "indicators",   name: "Threat Indicators",         threshold: 78  },
  { key: "correlation",  name: "Correlation Engine",        threshold: 88  },
  { key: "ai_summary",   name: "AI Threat Summary",         threshold: 97  },
];

function buildStages(
  currentStage: string,
  progress: number,
  status: InfraStatus
): InfraPipelineStage[] {
  return PIPELINE_STAGES.map((stg) => {
    let stageStatus: InfraPipelineStage["status"] = "pending";

    if (status === "completed") {
      stageStatus = "completed";
    } else if (status === "failed" || status === "stopped") {
      if (currentStage === stg.name) stageStatus = "failed";
      else if (progress >= stg.threshold) stageStatus = "completed";
      else stageStatus = "skipped";
    } else {
      if (currentStage === stg.name) stageStatus = "running";
      else if (progress >= stg.threshold) stageStatus = "completed";
      else stageStatus = "pending";
    }

    return { key: stg.key, name: stg.name, status: stageStatus, error: null };
  });
}

// ─── SOC-style live event generator ──────────────────────────────────────────

function buildLiveEvents(inv: InfraInvestigation): InfraLiveEvent[] {
  const events: InfraLiveEvent[] = [];
  const base = new Date(inv.started_at).getTime();
  const add = (offset: number, stage: string, message: string, severity: InfraLiveEvent["severity"]) => {
    events.push({ id: `${stage}-${offset}`, timestamp: new Date(base + offset).toISOString(), stage, message, severity });
  };

  add(0,    "System",      `Infrastructure intelligence request submitted: ${inv.target}`, "info");
  add(500,  "System",      `IOC type identified: ${inv.target_type.toUpperCase()}`,         "info");

  const p = inv.progress_percent;
  if (p >= 12 || inv.status === "completed") {
    add(800,  "Normalization", "Target normalised and validated successfully",              "success");
  }
  if (p >= 30 || inv.status === "completed") {
    add(2000, "Reputation",    "Querying AbuseIPDB, URLhaus and ThreatFox feeds...",        "info");
    add(4000, "Reputation",    "Reputation lookups complete",                               "success");
  }
  if (p >= 50 || inv.status === "completed") {
    add(5000, "Enrichment",    "Resolving DNS records (A, MX, NS, TXT)...",                 "info");
    add(6200, "Enrichment",    "WHOIS / RDAP registration data retrieved",                  "success");
    add(7000, "Enrichment",    "SSL certificate metadata extracted",                         "success");
    add(7800, "Enrichment",    "GeoIP & ASN lookup complete",                               "success");
  }
  if (p >= 65 || inv.status === "completed") {
    add(9000, "Passive DNS",   "Querying AlienVault OTX passive DNS history...",             "info");
    add(10500,"Passive DNS",   "Passive DNS resolution complete",                            "success");
  }
  if (p >= 78 || inv.status === "completed") {
    add(11500,"Indicators",    "Evaluating phishing heuristics and typosquatting rules...", "info");
    add(13000,"Indicators",    "Threat indicator checks completed",                          "success");
  }
  if (p >= 88 || inv.status === "completed") {
    add(14000,"Correlation",   "Running infrastructure correlation engine...",               "info");
    add(15500,"Correlation",   "Correlation analysis complete",                              "success");
  }
  if (p >= 97 || inv.status === "completed") {
    add(16500,"AI Summary",    "Invoking AI threat summarization model...",                  "info");
  }
  if (inv.status === "completed") {
    add(18000,"Success",       `Analysis complete. Risk score: ${Math.round(inv.risk_score)}/100`, "success");
  } else if (inv.status === "failed") {
    add(18000,"Failure",       "Pipeline terminated due to an error",                       "critical");
  } else if (inv.status === "stopped") {
    add(18000,"Stopped",       "Pipeline stopped by user request",                         "critical");
  }

  return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

// ─── Progressive risk interpolation ──────────────────────────────────────────

function getProgressiveRisk(status: InfraStatus, progress: number, finalRisk: number): number {
  if (status === "completed" || status === "stopped") return finalRisk;
  if (status === "failed") return 0;
  if (progress <= 12)  return Math.round((progress / 12) * 5);
  if (progress <= 30)  return Math.round(5 + ((progress - 12) / 18) * 15);
  if (progress <= 50)  return Math.round(20 + ((progress - 30) / 20) * 20);
  if (progress <= 65)  return Math.round(40 + ((progress - 50) / 15) * 15);
  if (progress <= 78)  return Math.round(55 + ((progress - 65) / 13) * 15);
  if (progress <= 88)  return Math.round(70 + ((progress - 78) / 10) * 15);
  return Math.round(Math.max(70, finalRisk * 0.9));
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useInfraInvestigationProgress(investigationId: string | null) {
  const { token } = useAuth();
  const [investigation, setInvestigation] = useState<InfraInvestigation | null>(null);
  const [isLoading, setIsLoading]         = useState(false);
  const [error, setError]                 = useState<string | null>(null);
  const [stages, setStages]               = useState<InfraPipelineStage[]>([]);
  const [liveEvents, setLiveEvents]       = useState<InfraLiveEvent[]>([]);
  const [progressiveRisk, setProgressiveRisk] = useState<number>(0);

  const pollRef    = useRef<NodeJS.Timeout | null>(null);
  const pollingRef = useRef<boolean>(false);

  // ── Full fetch (completed) ─────────────────────────────────────────────────
  const fetchFull = useCallback(async (id: string) => {
    if (!token) return;
    try {
      const res = await api.infraInvestigations.get(id, token);
      if (res?.success && res?.data) {
        const d = res.data;
        const inv: InfraInvestigation = {
          id:               d.id,
          target:           d.target || "",
          target_type:      d.target_type || "domain",
          status:           d.status,
          current_stage:    d.current_stage || "Completed",
          progress_percent: d.progress_percent ?? 100,
          risk_score:       d.risk_score ?? 0,
          started_at:       d.started_at || new Date().toISOString(),
          completed_at:     d.completed_at || null,
          results:          d.results || null,
        };
        setInvestigation(inv);
        setStages(buildStages(inv.current_stage, inv.progress_percent, inv.status));
        setLiveEvents(buildLiveEvents(inv));
        setProgressiveRisk(inv.risk_score);
      }
    } catch (err: any) {
      setError(err.message || "Could not load details.");
    }
  }, [token]);

  // ── Polling (running) ──────────────────────────────────────────────────────
  const pollStatus = useCallback(async () => {
    if (!investigationId || !token) return;
    try {
      const res = await api.infraInvestigations.getStatus(investigationId, token);
      if (res?.success && res?.data) {
        const d = res.data;
        const stage    = d.current_stage || "Pending";
        const progress = d.progress_percent ?? 0;
        const status   = d.status as InfraStatus;

        setInvestigation((prev) => {
          const updated: InfraInvestigation = {
            id:               d.id,
            target:           prev?.target || "",
            target_type:      prev?.target_type || "domain",
            status,
            current_stage:    stage,
            progress_percent: progress,
            risk_score:       d.risk_score ?? 0,
            started_at:       d.started_at,
            completed_at:     d.completed_at,
            results:          prev?.results || null,
          };
          setStages(buildStages(stage, progress, status));
          setLiveEvents(buildLiveEvents(updated));
          setProgressiveRisk(getProgressiveRisk(status, progress, d.risk_score ?? 0));
          return updated;
        });

        if (status === "completed" || status === "failed" || status === "stopped") {
          if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
          pollingRef.current = false;
          await fetchFull(investigationId);
        }
      }
    } catch {
      // Network glitch — keep polling
    }
  }, [investigationId, token, fetchFull]);

  // ── Effect ─────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!investigationId || !token) {
      setInvestigation(null); setStages([]); setLiveEvents([]); setProgressiveRisk(0);
      return;
    }

    setIsLoading(true);
    setError(null);

    fetchFull(investigationId).then(() => setIsLoading(false));

    const startPolling = async () => {
      try {
        const check = await api.infraInvestigations.getStatus(investigationId, token);
        if (check?.success && check?.data) {
          const s = check.data.status;
          if (s !== "completed" && s !== "failed" && s !== "stopped") {
            if (!pollingRef.current) {
              pollingRef.current = true;
              pollRef.current = setInterval(pollStatus, 3500);
            }
          }
        }
      } catch { /* silent */ }
    };

    startPolling();

    return () => {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
      pollingRef.current = false;
    };
  }, [investigationId, token, pollStatus, fetchFull]);

  return {
    investigation,
    stages,
    liveEvents,
    progressiveRisk,
    isLoading,
    error,
    refresh: () => investigationId && fetchFull(investigationId),
  };
}
