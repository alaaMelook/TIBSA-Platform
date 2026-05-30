import { useState, useEffect, useRef, useCallback } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/hooks/useAuth";
import { Investigation, InvestigationStage, StageStatus, LiveEvent } from "@/types";

// Helper to map current_stage & progress_percent & status to 6 stages
const buildStagesList = (
  currentStage: string,
  progress: number,
  status: string
): InvestigationStage[] => {
  const stages = [
    { key: "pentest", name: "Pentest Scanning", threshold: 25 },
    { key: "context", name: "Finding Normalization & Context", threshold: 50 },
    { key: "ioc", name: "Threat Intelligence Enrichment", threshold: 75 },
    { key: "correlation", name: "Threat Correlation", threshold: 92 },
    { key: "threat_model", name: "STRIDE Modeling", threshold: 95 },
    { key: "ai_explain", name: "AI Analysis", threshold: 97 }
  ];

  return stages.map((stg) => {
    let stageStatus: StageStatus = "pending";

    if (status === "completed") {
      stageStatus = "completed";
    } else if (status === "failed" || status === "stopped") {
      // If it failed or was stopped at this stage or later
      if (currentStage === stg.name) {
        stageStatus = "failed";
      } else if (progress < stg.threshold) {
        stageStatus = "skipped";
      } else {
        stageStatus = "completed";
      }
    } else {
      // running status
      if (currentStage === stg.name) {
        stageStatus = "running";
      } else if (progress >= stg.threshold) {
        stageStatus = "completed";
      } else {
        stageStatus = "pending";
      }
    }

    return {
      stage: stg.name,
      status: stageStatus,
      started_at: null,
      completed_at: null,
      duration_seconds: null,
      error: stageStatus === "failed" ? "Pipeline execution error" : null
    };
  });
};

// Client-side SOC events generator based on investigation data
const generateEventsList = (inv: Investigation | null): LiveEvent[] => {
  if (!inv) return [];
  const events: LiveEvent[] = [];
  const baseTime = new Date(inv.started_at).getTime();

  const addEvent = (offsetMs: number, message: string, stage: string, severity: LiveEvent["severity"]) => {
    events.push({
      id: `${stage}-${message}`,
      timestamp: new Date(baseTime + offsetMs).toISOString(),
      stage,
      message,
      severity
    });
  };

  // 1. Initial actions
  addEvent(0, "Security investigation request received", "System", "info");
  addEvent(300, `Target website set to: ${inv.target}`, "System", "info");

  // 2. Pentest Stage
  const progress = inv.progress_percent;
  const isStarted = inv.status !== "pending";
  if (isStarted) {
    addEvent(800, "Phase 1: Starting Pentest Scanning...", "Pentest", "info");
    addEvent(1500, "Initializing automated vulnerability crawling...", "Pentest", "info");
  }

  if (progress >= 50 || inv.status === "completed") {
    addEvent(3000, "Completed technology detection & fingerprinting", "Pentest", "success");
    addEvent(5000, "Port check and security headers analysis complete", "Pentest", "success");
    
    // Extracted findings events
    const findings = inv.final_result?.findings_count || 0;
    if (findings > 0) {
      addEvent(5800, `Vulnerability crawler flagged ${findings} security warnings`, "Pentest", "warning");
    } else {
      addEvent(5800, "No raw vulnerabilities detected on landing endpoints", "Pentest", "success");
    }
  }

  // 3. Normalization & Context
  if (progress >= 75 || inv.status === "completed") {
    addEvent(6500, "Phase 2: Running Finding Normalization & Threat Context interpreter", "Context", "info");
    addEvent(7200, "Vulnerability findings mapped to CWE structure", "Context", "success");
    if (inv.final_result?.correlation?.unique_threats_identified) {
      addEvent(7900, "Calculated baseline security rating weights", "Context", "info");
    }
  }

  // 4. TI / IOC Enrichment
  if (progress >= 92 || inv.status === "completed") {
    addEvent(8500, "Phase 3: Launching Threat Intelligence Enrichment (IOC verification)", "Threat Intel", "info");
    addEvent(9200, "Querying VirusTotal reputation databases in background...", "Threat Intel", "info");
    
    const assets = inv.final_result?.assets_count || 1;
    addEvent(9800, `Reputation lookup finished for ${assets} host domains and IPs`, "Threat Intel", "success");
  }

  // 5. Threat Correlation
  if (progress >= 95 || inv.status === "completed") {
    addEvent(10500, "Phase 4: Running Threat Correlation Engine...", "Correlation", "info");
    addEvent(11000, "Mapping dependency indicators and XSS vector risks...", "Correlation", "info");
    
    const correlations = inv.final_result?.correlation?.correlated_threats?.length || 0;
    if (correlations > 0) {
      addEvent(11800, `Correlated ${correlations} multi-stage attack scenarios`, "Correlation", "warning");
    } else {
      addEvent(11800, "No combined attack paths detected.", "Correlation", "success");
    }
  }

  // 6. STRIDE Threat Model
  if (progress >= 97 || inv.status === "completed") {
    addEvent(12500, "Phase 5: Generating STRIDE Threat Matrix", "Threat Model", "info");
    addEvent(13200, "Drafting Spoofing, Tampering, and Elevation of Privilege mitigations", "Threat Model", "success");
  }

  // 7. AI Analysis
  if (progress >= 100 || inv.status === "completed") {
    addEvent(14000, "Phase 6: Invoking AI Security Reporter...", "AI Analysis", "info");
    addEvent(14800, "Constructing executive and engineering explanations...", "AI Analysis", "info");
  }

  // Final status
  if (inv.status === "completed") {
    addEvent(15500, `Security pipeline completed. Global Risk Score finalized: ${inv.risk_score}/100`, "Success", "success");
  } else if (inv.status === "failed") {
    addEvent(15500, "Security pipeline terminated due to failure", "Failure", "critical");
  } else if (inv.status === "stopped") {
    addEvent(15500, "Security pipeline stopped by user request", "Failure", "critical");
  }

  return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
};

// Dynamic client risk progression interpolator
const getProgressiveRisk = (
  status: string,
  progress: number,
  finalRisk: number
): number => {
  if (status === "completed" || status === "stopped") return finalRisk;
  if (status === "failed") return 0;

  // Recon: 0-25% progress -> Risk up to 10
  if (progress <= 25) {
    return Math.round((progress / 25) * 10);
  }
  // Vulnerability detection: 26-50% -> Risk up to 35
  if (progress <= 50) {
    return Math.round(10 + ((progress - 25) / 25) * 25);
  }
  // Context mapping: 51-75% -> Risk up to 55
  if (progress <= 75) {
    return Math.round(35 + ((progress - 50) / 25) * 20);
  }
  // IOC matches: 76-92% -> Risk up to 70
  if (progress <= 92) {
    return Math.round(55 + ((progress - 75) / 17) * 15);
  }
  // Correlation engine: 93-97% -> Risk up to 90% of final
  if (progress <= 97) {
    const minRisk = Math.max(70, finalRisk * 0.85);
    return Math.round(70 + ((progress - 92) / 5) * (minRisk - 70));
  }
  // Explaining: 98-99% -> Risk close to final
  return Math.round(finalRisk);
};

export function useInvestigationProgress(investigationId: string | null) {
  const { token } = useAuth();
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stages, setStages] = useState<InvestigationStage[]>([]);
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [progressiveRisk, setProgressiveRisk] = useState<number>(0);

  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const isPollingRef = useRef<boolean>(false);

  const fetchFullInvestigation = useCallback(async (id: string) => {
    if (!token) return;
    try {
      const response = await api.investigations.get(id, token);
      if (response && response.success && response.data) {
        const inv: Investigation = {
          id: response.data.investigation_id,
          scan_id: response.data.scan_id || `SCAN-${id.substring(0, 5)}`,
          target: response.data.target || "",
          status: response.data.status,
          risk_score: response.data.risk_score,
          started_at: response.data.started_at || new Date().toISOString(),
          completed_at: response.data.completed_at || null,
          include_ti: response.data.include_ti ?? true,
          tm_mode: response.data.tm_mode || "enhanced",
          current_stage: response.data.current_stage || "Completed",
          progress_percent: response.data.progress_percent ?? 100,
          pipeline_state: response.data.pipeline_state || null,
          final_result: response.data.final_result || null
        };

        setInvestigation(inv);
        setStages(buildStagesList(inv.current_stage, inv.progress_percent, inv.status));
        setLiveEvents(generateEventsList(inv));
        setProgressiveRisk(inv.risk_score);
      }
    } catch (err: any) {
      console.error("Failed to fetch full investigation details:", err);
      setError(err.message || "Could not load report details.");
    }
  }, [token]);

  const pollStatus = useCallback(async () => {
    if (!investigationId || !token) return;
    try {
      const response = await api.investigations.getStatus(investigationId, token);
      if (response && response.success && response.data) {
        const statusData = response.data;
        const currentStage = statusData.current_stage || "Pending";
        const progress = statusData.progress_percent ?? 0.0;
        const status = statusData.status;

        // Build simulated / wrapped Investigation object for hook state
        setInvestigation((prev) => {
          const updated: Investigation = {
            id: statusData.id,
            scan_id: statusData.scan_id,
            target: prev?.target || "",
            status: statusData.status,
            risk_score: statusData.risk_score,
            started_at: statusData.started_at,
            completed_at: statusData.completed_at,
            include_ti: prev?.include_ti ?? true,
            tm_mode: prev?.tm_mode ?? "enhanced",
            current_stage: currentStage,
            progress_percent: progress,
            pipeline_state: prev?.pipeline_state || null,
            final_result: prev?.final_result || null
          };
          
          setStages(buildStagesList(currentStage, progress, status));
          setLiveEvents(generateEventsList(updated));
          setProgressiveRisk(getProgressiveRisk(status, progress, statusData.risk_score));
          return updated;
        });

        if (status === "completed" || status === "failed" || status === "stopped") {
          // Stop polling and load final details
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
          }
          isPollingRef.current = false;
          await fetchFullInvestigation(investigationId);
        }
      }
    } catch (err: any) {
      console.error("Error in status polling:", err);
      // Don't crash polling on network glitch, just record error
    }
  }, [investigationId, token, fetchFullInvestigation]);

  useEffect(() => {
    if (!investigationId || !token) {
      setInvestigation(null);
      setStages([]);
      setLiveEvents([]);
      setProgressiveRisk(0);
      return;
    }

    setIsLoading(true);
    setError(null);

    // Initial load
    fetchFullInvestigation(investigationId).then(() => {
      setIsLoading(false);
    });

    // Start polling if status isn't complete/failed
    const startPollingIfNeeded = async () => {
      try {
        const check = await api.investigations.getStatus(investigationId, token);
        if (check && check.success && check.data) {
          const currentStatus = check.data.status;
          if (currentStatus !== "completed" && currentStatus !== "failed" && currentStatus !== "stopped") {
            if (!isPollingRef.current) {
              isPollingRef.current = true;
              pollIntervalRef.current = setInterval(pollStatus, 3000);
            }
          }
        }
      } catch (err) {
        console.error("Error checking initial status for polling:", err);
      }
    };

    startPollingIfNeeded();

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
      isPollingRef.current = false;
    };
  }, [investigationId, token, pollStatus, fetchFullInvestigation]);

  return {
    investigation,
    stages,
    liveEvents,
    progressiveRisk,
    isLoading,
    error,
    refresh: () => investigationId && fetchFullInvestigation(investigationId)
  };
}
