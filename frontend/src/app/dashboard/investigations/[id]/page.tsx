"use client";

import React, { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { useInvestigationProgress } from "@/hooks/useInvestigationProgress";
import { api } from "@/lib/api";
import { RiskGauge } from "@/components/investigation/RiskGauge";
import { InvestigationTimeline } from "@/components/investigation/InvestigationTimeline";
import { SOCEventFeed } from "@/components/investigation/SOCEventFeed";
import { FindingsTable } from "@/components/investigation/FindingsTable";
import { PentestFindingsView } from "@/components/investigation/PentestFindingsView";
import { IOCTable } from "@/components/investigation/IOCTable";
import { AttackChainCard } from "@/components/investigation/AttackChainCard";
import { Card, Button } from "@/components/ui";
import {
  ArrowLeft,
  FileCode,
  FileText,
  Lock,
  Loader2,
  Clock,
  Sparkles,
  Terminal,
  Activity,
  UserCheck,
  AlertOctagon,
  Shield,
  HelpCircle,
  FileJson
} from "lucide-react";
import ReactMarkdown from "react-markdown";

const LoadingDotsRing = () => (
  <div className="relative flex items-center justify-center select-none" style={{ width: 180, height: 180 }}>
    {/* Inner glowing pulse */}
    <div className="absolute w-24 h-24 rounded-full bg-[var(--primary)]/5 border border-[var(--primary)] animate-pulse flex items-center justify-center">
      <div className="flex space-x-1.5 justify-center items-center">
        <span className="w-2.5 h-2.5 rounded-full bg-[#0f9d76] animate-bounce [animation-delay:-0.3s] shadow-lg shadow-[var(--primary-soft)]" />
        <span className="w-2.5 h-2.5 rounded-full bg-[#0f9d76] animate-bounce [animation-delay:-0.15s] shadow-lg shadow-[var(--primary-soft)]" />
        <span className="w-2.5 h-2.5 rounded-full bg-[#0f9d76] animate-bounce shadow-lg shadow-[var(--primary-soft)]" />
      </div>
    </div>

    {/* Spinning dotted orbits */}
    <div className="absolute inset-0 animate-spin [animation-duration:8s] rounded-full border border-dashed border-[var(--primary)]" />
    <div className="absolute inset-2.5 animate-spin [animation-duration:12s] [animation-direction:reverse] rounded-full border border-dotted border-[var(--primary)]" />

    {/* Sonar sweep SVG dots */}
    <svg className="absolute w-full h-full animate-spin [animation-duration:4s]" viewBox="0 0 100 100">
      <circle cx="50" cy="10" r="3.5" className="fill-[#0f9d76] shadow-md shadow-[#0f9d76]" />
      <circle cx="78" cy="22" r="3" className="fill-[#0f9d76]/80" />
      <circle cx="90" cy="50" r="2.5" className="fill-[#0f9d76]/60" />
      <circle cx="78" cy="78" r="2" className="fill-[#0f9d76]/40" />
      <circle cx="50" cy="90" r="1.5" className="fill-[#0f9d76]/20" />
    </svg>
  </div>
);

export default function LiveInvestigationWorkspace() {
  const params = useParams();
  const router = useRouter();
  const { token } = useAuth();
  const id = typeof params.id === "string" ? params.id : null;

  const {
    investigation,
    stages,
    liveEvents,
    progressiveRisk,
    isLoading,
    error
  } = useInvestigationProgress(id);

  const [activeTab, setActiveTab] = useState("findings");
  const [exportLoading, setExportLoading] = useState<string | null>(null);
  const [stopLoading, setStopLoading] = useState(false);

  // Active duration counter
  const [activeDuration, setActiveDuration] = useState<string>("00:00");

  const handleStop = async () => {
    if (!id || !token) return;
    if (!confirm("Are you sure you want to stop this investigation scan?")) return;
    try {
      setStopLoading(true);
      const response = await api.investigations.stop(id, token);
      if (response && response.success) {
        window.location.reload();
      } else {
        alert("Failed to stop investigation: invalid response.");
      }
    } catch (err: any) {
      console.error(err);
      alert(err.message || "An error occurred while stopping the scan.");
    } finally {
      setStopLoading(false);
    }
  };

  useEffect(() => {
    if (!investigation) return;

    const started = new Date(investigation.started_at).getTime();

    const updateTime = () => {
      let diffMs = 0;
      if (investigation.status === "completed" || investigation.status === "failed" || investigation.status === "stopped") {
        const completed = investigation.completed_at
          ? new Date(investigation.completed_at).getTime()
          : Date.now();
        diffMs = completed - started;
      } else {
        diffMs = Date.now() - started;
      }

      if (diffMs < 0) diffMs = 0;

      const totalSec = Math.floor(diffMs / 1000);
      const min = Math.floor(totalSec / 60).toString().padStart(2, "0");
      const sec = (totalSec % 60).toString().padStart(2, "0");
      setActiveDuration(`${min}:${sec}`);
    };

    updateTime();

    // Only poll clock if investigation is still running
    if (investigation.status !== "completed" && investigation.status !== "failed" && investigation.status !== "stopped") {
      const interval = setInterval(updateTime, 1000);
      return () => clearInterval(interval);
    }
  }, [investigation]);

  // Tab unlocking criteria
  const isTabUnlocked = (tab: string): boolean => {
    if (!investigation) return false;
    const progress = investigation.progress_percent;
    const status = investigation.status as string;

    if (status === "completed" || status === "stopped") return true;

    switch (tab) {
      case "findings":
        return progress >= 50; // Unlocked after normalization completed
      case "intel":
        return progress >= 75; // Unlocked after threat intel completed
      case "correlations":
        return progress >= 92; // Unlocked after correlation complete
      case "threat_model":
        return progress >= 95; // Unlocked after STRIDE modeling complete
      case "ai_summary":
        return progress >= 97; // Unlocked after AI analysis complete
      case "export":
        return status === "completed";
      default:
        return false;
    }
  };

  const getTabLabel = (tab: string, label: string) => {
    const unlocked = isTabUnlocked(tab);
    if (!unlocked) {
      return (
        <span className="flex items-center gap-1.5 opacity-60 text-[var(--text-muted)]">
          <Lock className="w-3.5 h-3.5" />
          {label}
        </span>
      );
    }

    // Add pulsing green dot if completed and just unlocked
    return (
      <span className="flex items-center gap-1.5">
        {label}
      </span>
    );
  };

  const handleExport = async (format: "json" | "pdf") => {
    if (!id || !token) return;
    try {
      setExportLoading(format);

      const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${API_BASE_URL}/api/v1/investigations/${id}/export/${format}`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });

      if (!res.ok) {
        throw new Error("Failed to export report files.");
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `TIBSA_Investigation_${investigation?.scan_id || id}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error(err);
      alert(err.message || "Failed to download report.");
    } finally {
      setExportLoading(null);
    }
  };

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-40 text-[var(--text-muted)] gap-3">
        <Loader2 className="w-8 h-8 animate-spin text-[var(--primary)]" />
        <p className="text-sm font-semibold uppercase tracking-wider">Loading Investigation Workspace...</p>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="space-y-4">
        <Button onClick={() => router.push("/dashboard/investigations")} variant="ghost" size="sm" className="gap-2">
          <ArrowLeft className="w-4 h-4" /> Back to Dashboard
        </Button>
        <Card className="border border-red-500/20 bg-red-950/10 text-center py-12">
          <AlertOctagon className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h3 className="text-lg font-bold text-[var(--text-primary)]">Workspace Loading Error</h3>
          <p className="text-sm text-[var(--text-muted)] mt-2 max-w-md mx-auto">
            {error || "We could not fetch details for this investigation. Please check if it exists or try again."}
          </p>
        </Card>
      </div>
    );
  }

  const displayRiskScore = (() => {
    if (investigation.progress_percent < 92) {
      if (investigation.pipeline_state?.pentest_summary?.risk_score != null) {
        return investigation.pipeline_state.pentest_summary.risk_score;
      }
      return progressiveRisk;
    }
    return progressiveRisk;
  })();

  const statusColors: Record<string, string> = {
    completed: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20",
    failed: "bg-red-500/10 text-red-400 border border-red-500/20",
    pending: "bg-[var(--bg-elevated)] text-[var(--text-muted)] border border-[var(--border-strong)]",
    running: "bg-[var(--primary)]/10 text-[var(--primary)] border border-[var(--primary)] animate-pulse",
    stopped: "bg-amber-500/10 text-amber-400 border border-amber-500/20"
  };

  const getStatusText = (status: string) => {
    if (status === "running") return "Active Scanning";
    if (status === "completed") return "Completed";
    if (status === "failed") return "Failed";
    if (status === "stopped") return "Stopped";
    return "Queued";
  };

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      {/* Top Identity Header */}
      <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] py-3 px-5 shadow-lg flex flex-col md:flex-row justify-between items-stretch md:items-center gap-4">
        <div className="space-y-2">
          {/* Back CTA & Breadcrumbs */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => router.push("/dashboard/investigations")}
              className="text-xs text-[var(--text-muted)] hover:text-[var(--text-secondary)] font-bold uppercase tracking-widest flex items-center gap-1 transition-colors cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" /> Workspace
            </button>
            <span className="text-[var(--text-muted)] font-mono text-xs">/</span>
            <span className="text-xs text-[var(--text-muted)] font-mono select-all">
              {investigation.scan_id}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-black text-[var(--text-primary)] tracking-tight break-all">
              Target: {investigation.target}
            </h1>
            <span className={`px-2.5 py-0.5 rounded text-[10px] font-extrabold uppercase ${statusColors[investigation.status] || statusColors.running}`}>
              {getStatusText(investigation.status)}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-xs text-[var(--text-muted)] font-mono">
            <div className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-[var(--text-muted)]" />
              Runtime: <span className="text-[var(--text-secondary)] font-bold">{activeDuration}</span>
            </div>
            <div>
              Stage: <span className="text-[var(--text-secondary)] font-semibold">{investigation.current_stage}</span>
            </div>
            <div className="hidden sm:block">
              ID: <span className="text-[var(--text-muted)] select-all">{investigation.id}</span>
            </div>
          </div>
        </div>

        {/* Global actions */}
        {investigation.status === "completed" ? (
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => handleExport("json")}
              disabled={!!exportLoading}
              className="gap-2"
            >
              {exportLoading === "json" ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <FileJson className="w-3.5 h-3.5" />
              )}
              JSON
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => handleExport("pdf")}
              disabled={!!exportLoading}
              className="gap-2"
            >
              {exportLoading === "pdf" ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <FileText className="w-3.5 h-3.5" />
              )}
              PDF Report
            </Button>
          </div>
        ) : (investigation.status === "running" || investigation.status === "pending") && (
          <div className="flex items-center gap-2">
            <Button
              variant="danger"
              size="sm"
              onClick={handleStop}
              disabled={stopLoading}
              className="gap-2 bg-red-600 hover:bg-red-500 border border-red-500/20 text-[var(--text-primary)] font-bold"
            >
              {stopLoading ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <AlertOctagon className="w-3.5 h-3.5" />
              )}
              Stop Scan
            </Button>
          </div>
        )}
      </div>

      {/* Progress timeline */}
      <InvestigationTimeline stages={stages} />

      {/* Live Activity & Gauge */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Progressive Risk Score */}
        <div className="lg:col-span-4 flex flex-col justify-center items-center bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] p-4 shadow-md min-h-[260px]">
          <h3 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-widest mb-3">
            Live Risk Progression
          </h3>
          {investigation.status === "completed" || investigation.status === "failed" || investigation.status === "stopped" ? (
            <RiskGauge score={displayRiskScore} />
          ) : (
            <LoadingDotsRing />
          )}
          {investigation.status !== "completed" && investigation.status !== "failed" && investigation.status !== "stopped" && (
            <p className="text-[10px] text-[var(--primary)] font-semibold uppercase tracking-wider mt-4 animate-pulse flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5" /> Calculating global threats...
            </p>
          )}
        </div>

        {/* Right: SOC Log Feed */}
        <div className="lg:col-span-8">
          <SOCEventFeed events={liveEvents} />
        </div>
      </div>

      {/* Progressive Results Tabs */}
      <div className="space-y-4">
        {/* Tabs Bar */}
        <div className="flex border-b border-[var(--border-soft)] overflow-x-auto whitespace-nowrap scrollbar-none gap-2">
          {[
            { key: "findings", label: "Findings" },
            { key: "intel", label: "Threat Intel" },
            { key: "correlations", label: "Correlations" },
            { key: "threat_model", label: "Threat Model" },
            { key: "ai_summary", label: "AI Summary" }
          ].map((tab) => {
            const unlocked = isTabUnlocked(tab.key);
            const active = activeTab === tab.key;

            return (
              <button
                key={tab.key}
                disabled={!unlocked}
                onClick={() => setActiveTab(tab.key)}
                className={`py-3 px-4 text-xs font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${active
                    ? "border-[#0f9d76] bg-[#edf8f3] text-[#0f9d76]"
                    : unlocked
                      ? "border-transparent text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                      : "border-transparent text-[var(--text-muted)] cursor-not-allowed"
                  }`}
              >
                {getTabLabel(tab.key, tab.label)}
              </button>
            );
          })}
        </div>

        {/* Tab content panel */}
        <div className="min-h-[300px]">
          {!isTabUnlocked(activeTab) ? (
            <Card className="border border-[var(--border-strong)] bg-[var(--bg-card)]/10 text-center py-20">
              <Lock className="w-12 h-12 text-[var(--text-muted)] mx-auto mb-4" />
              <h4 className="text-[var(--text-muted)] font-bold uppercase tracking-widest text-xs">
                Pipeline Stage Pending
              </h4>
              <p className="text-xs text-[var(--text-muted)] mt-2.5 max-w-sm mx-auto leading-relaxed">
                This analytical model is currently queued. Results will populate automatically as the active pipeline runs and processes this phase.
              </p>
            </Card>
          ) : (
            <>
              {/* Tab: Findings */}
              {activeTab === "findings" && (
                <PentestFindingsView
                  findings={investigation.pipeline_state?.pentest_findings || []}
                  summary={investigation.pipeline_state?.pentest_summary || null}
                  fallbackFindings={
                    investigation.final_result?.correlation?.correlated_threats
                      ? investigation.pipeline_state?.normalized_findings || []
                      : investigation.pipeline_state?.ti_findings || []
                  }
                />
              )}

              {/* Tab: Threat Intel */}
              {activeTab === "intel" && (
                <IOCTable
                  iocResults={
                    investigation.pipeline_state?.reputation_context?.ioc_results ||
                    investigation.pipeline_state?.ti_findings?.reduce((acc: any[], f: any) => {
                      const val = f.affected_asset || investigation.target;
                      if (!acc.some(x => x.value === val)) {
                        acc.push({
                          indicator_type: val.startsWith("http") ? "js_resource" : (val.includes(".") ? "domain" : "js_resource"),
                          value: val,
                          source: "virustotal",
                          reputation_score: f.risk_score || 55.0,
                          threat_level: f.severity === "critical" || f.severity === "high" ? "malicious" : "clean",
                          details: {},
                          flagged: f.severity === "critical" || f.severity === "high"
                        });
                      }
                      return acc;
                    }, []) ||
                    investigation.final_result?.correlation?.correlated_threats?.reduce((acc: any[], t) => {
                      // fallback mapping IOCs from final_result structure
                      (t.contributing_ioc_values || []).forEach((val) => {
                        if (!acc.some(x => x.value === val)) {
                          acc.push({
                            indicator_type: val.startsWith("http") ? "js_resource" : (val.includes(".") ? "domain" : "js_resource"),
                            value: val,
                            source: "virustotal",
                            reputation_score: 55.0,
                            threat_level: "malicious",
                            details: {},
                            flagged: true
                          });
                        }
                      });
                      return acc;
                    }, []) || []
                  }
                />
              )/* tab: threat intel end */}

              {/* Tab: Correlations */}
              {activeTab === "correlations" && (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="!p-5 bg-[var(--bg-card)]/20 border border-[var(--border-soft)]">
                      <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider block">
                        Correlation Analysis Summary
                      </span>
                      <div className="text-3xl font-black text-[var(--text-primary)] mt-1">
                        {investigation.final_result?.correlation?.unique_threats_identified || 0}
                      </div>
                      <p className="text-xs text-[var(--text-muted)] mt-2 leading-relaxed">
                        The correlation engine reviews Cross-Site Scripting (XSS), missing configurations, server configurations, and VirusTotal IOC indicator checks. When vulnerabilities compile together, high-priority alarms trigger.
                      </p>
                    </Card>

                    <Card className="!p-5 bg-[var(--bg-card)]/20 border border-[var(--border-soft)]">
                      <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider block">
                        Escalated Risk Counts
                      </span>
                      <div className="text-3xl font-black text-orange-400 mt-1">
                        {investigation.final_result?.correlation?.escalated_risks_count || 0}
                      </div>
                      <p className="text-xs text-[var(--text-muted)] mt-2 leading-relaxed">
                        Risks that escalated due to compounding parameters. A simple vulnerability multiplied because no defence-in-depth mitigations (e.g. CSP policies) were present.
                      </p>
                    </Card>
                  </div>

                  <div className="space-y-4">
                    <h4 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-widest">
                      Correlated Attack Chain Maps
                    </h4>
                    {(!investigation.final_result?.correlation?.correlated_threats ||
                      investigation.final_result.correlation.correlated_threats.length === 0) ? (
                      <Card className="py-12 text-center text-[var(--text-muted)]">
                        No combined threat indicators triggered the correlation engine filters.
                      </Card>
                    ) : (
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        {investigation.final_result.correlation.correlated_threats.map((threat, idx) => (
                          <AttackChainCard key={threat.id || idx} threat={threat} />
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Tab: Threat Model */}
              {activeTab === "threat_model" && (() => {
                const allThreats = investigation.final_result?.stride?.stride_threats || [];

                const isConfirmed = (t: any) => {
                  const status = (t.status || "").toLowerCase();
                  const evidenceType = (t.evidence_type || "").toLowerCase();
                  const classification = (t.classification || "").toLowerCase();
                  const confidence = (t.confidence || "").toLowerCase();

                  return (
                    status === "confirmed" ||
                    evidenceType === "vulnerability" ||
                    classification === "vulnerability" ||
                    confidence === "verified" ||
                    confidence === "high"
                  );
                };

                const confirmedThreats = allThreats.filter(isConfirmed);
                const potentialScenarios = allThreats.filter((t: any) => !isConfirmed(t));

                const parseScenario = (scenarioStr: string) => {
                  const parts = (scenarioStr || "").split("[Evidence Tracing]");
                  const mainDesc = parts[0].trim();
                  const evidence = parts.slice(1).join("[Evidence Tracing]").trim();
                  return { mainDesc, evidence };
                };

                const groupThreats = (threatsList: any[]) => {
                  const map = new Map<string, any>();
                  threatsList.forEach((t) => {
                    const { mainDesc } = parseScenario(t.attack_scenario);
                    const key = `${mainDesc}::${t.affected_asset || ""}`;
                    if (!map.has(key)) {
                      map.set(key, {
                        ...t,
                        categories: [t.category],
                        originalThreats: [t],
                      });
                    } else {
                      const existing = map.get(key);
                      existing.originalThreats.push(t);
                      if (!existing.categories.includes(t.category)) {
                        existing.categories.push(t.category);
                      }
                      const severityOrder: Record<string, number> = {
                        info: 0, low: 1, medium: 2, high: 3, critical: 4
                      };
                      const tSev = (t.severity || "info").toLowerCase();
                      const eSev = (existing.severity || "info").toLowerCase();
                      if ((severityOrder[tSev] ?? 0) > (severityOrder[eSev] ?? 0)) {
                        existing.severity = t.severity;
                      }
                      const existingMitigations = Array.isArray(existing.mitigations) 
                        ? existing.mitigations 
                        : [existing.mitigations];
                      const newMitigations = Array.isArray(t.mitigations) 
                        ? t.mitigations 
                        : [t.mitigations];
                      newMitigations.forEach((m: string) => {
                        if (m && !existingMitigations.includes(m)) {
                          existingMitigations.push(m);
                        }
                      });
                      existing.mitigations = existingMitigations;
                    }
                  });
                  return Array.from(map.values());
                };

                const groupedConfirmed = groupThreats(confirmedThreats);
                const groupedPotential = groupThreats(potentialScenarios);

                // ── Summary Metrics ──
                const uniqueCategories = new Set(allThreats.map((t: any) => t.category)).size;
                const getHighestRisk = () => {
                  const severities = allThreats.map((t: any) => (t.severity || "").toLowerCase());
                  if (severities.includes("critical")) return "Critical";
                  if (severities.includes("high")) return "High";
                  if (severities.includes("medium")) return "Medium";
                  if (severities.includes("low")) return "Low";
                  return "Info";
                };

                const getShortWhyGenerated = (t: any) => {
                  const whyStr = t.why_generated || "";
                  const notConfStr = t.why_not_confirmed || "";
                  const text = (whyStr || notConfStr).trim();
                  
                  if (!text) {
                    return "Generated from correlated security hardening findings.";
                  }
                  
                  if (text.toLowerCase().includes("csp") || text.toLowerCase().includes("content-security-policy")) {
                    return "Generated from hardening evidence related to Content-Security-Policy.";
                  }
                  
                  if (text.toLowerCase().includes("cors") || text.toLowerCase().includes("cross-origin")) {
                    return "Generated from hardening evidence related to CORS policy.";
                  }

                  if (text.toLowerCase().includes("security header") || text.toLowerCase().includes("x-frame-options") || text.toLowerCase().includes("x-content-type-options")) {
                    return "Generated from correlated security header hardening recommendations.";
                  }

                  if (text.toLowerCase().includes("auth") || text.toLowerCase().includes("jwt") || text.toLowerCase().includes("session")) {
                    return "Generated from authorization boundary indicators.";
                  }

                  const sentence = text.split(/[.!?]/)[0].trim();
                  if (sentence && sentence.length > 5 && !sentence.includes("{") && !sentence.includes("[")) {
                    const cleanText = sentence + ".";
                    return cleanText.length > 85 ? cleanText.slice(0, 82) + "..." : cleanText;
                  }

                  return "Generated from correlated security hardening findings.";
                };

                return (
                  <div className="space-y-6">
                    {/* Header Summary Row */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                      {/* Confirmed Threats Card */}
                      <Card className="!p-4 bg-[var(--bg-card)] border border-red-500/10 shadow-sm hover:shadow-md transition-all duration-200 flex flex-col justify-between">
                        <div>
                          <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider block">
                            Confirmed Threats
                          </span>
                          <div className="text-3xl font-black text-red-500 mt-1">
                            {confirmedThreats.length}
                          </div>
                        </div>
                        <p className="text-[11px] text-[var(--text-muted)] mt-2">
                          Active vulnerabilities verified by scan evidence.
                        </p>
                      </Card>

                      {/* Potential Scenarios Card */}
                      <Card className="!p-4 bg-[var(--bg-card)] border border-amber-500/10 shadow-sm hover:shadow-md transition-all duration-200 flex flex-col justify-between">
                        <div>
                          <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider block">
                            Potential Scenarios
                          </span>
                          <div className="text-3xl font-black text-amber-500 mt-1">
                            {potentialScenarios.length}
                          </div>
                        </div>
                        <p className="text-[11px] text-[var(--text-muted)] mt-2">
                          Architectural hardening and security advisories.
                        </p>
                      </Card>

                      {/* Highest Risk Card */}
                      <Card className="!p-4 bg-[var(--bg-card)] border border-[var(--border-soft)] shadow-sm hover:shadow-md transition-all duration-200 flex flex-col justify-between">
                        <div>
                          <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider block">
                            Highest Threat Risk
                          </span>
                          <div className={`text-3xl font-black mt-1 ${
                            getHighestRisk() === "Critical" || getHighestRisk() === "High" ? "text-red-500" : "text-[var(--primary)]"
                          }`}>
                            {getHighestRisk()}
                          </div>
                        </div>
                        <p className="text-[11px] text-[var(--text-muted)] mt-2">
                          Maximum threat level detected on target.
                        </p>
                      </Card>

                      {/* STRIDE Categories Card */}
                      <Card className="!p-4 bg-[var(--bg-card)] border border-[var(--border-soft)] shadow-sm hover:shadow-md transition-all duration-200 flex flex-col justify-between">
                        <div>
                          <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider block">
                            STRIDE Mappings
                          </span>
                          <div className="text-3xl font-black text-[var(--primary)] mt-1">
                            {uniqueCategories} / 6
                          </div>
                        </div>
                        <p className="text-[11px] text-[var(--text-muted)] mt-2">
                          Standard security threat model categories.
                        </p>
                      </Card>
                    </div>

                    {/* Section 1: Confirmed Threats */}
                    <Card title="Confirmed Threats" description="Security vulnerabilities requiring immediate remediation action">
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                          <thead>
                            <tr className="border-b border-[var(--border-strong)] text-[var(--text-muted)] font-semibold bg-[var(--bg-card)]/10">
                              <th className="py-3 px-4 w-40">STRIDE Category</th>
                              <th className="py-3 px-4">Threat Description</th>
                              <th className="py-3 px-4 w-32">Risk Level</th>
                              <th className="py-3 px-4 w-60">Evidence</th>
                              <th className="py-3 px-4">Recommended Mitigation</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-white/[0.04]">
                            {groupedConfirmed.length === 0 ? (
                              <tr>
                                <td colSpan={5} className="py-12 text-center text-[var(--text-muted)] font-medium">
                                  No confirmed threats found. Potential hardening scenarios are listed below.
                                </td>
                              </tr>
                            ) : (
                              groupedConfirmed.map((t: any, idx: number) => {
                                const { mainDesc, evidence } = parseScenario(t.attack_scenario);
                                return (
                                  <tr key={t.stride_id || idx} className="hover:bg-[var(--bg-elevated)] transition-colors duration-150">
                                    <td className="py-4 px-4 vertical-top">
                                      <div className="space-y-2">
                                        <div className="flex flex-wrap gap-1.5">
                                          {t.categories.map((cat: string, cIdx: number) => (
                                            <span key={cIdx} className="inline-block text-[10px] bg-red-500/10 border border-red-500/20 text-red-500 font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                                              {cat}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    </td>
                                    <td className="py-4 px-4 font-semibold text-[var(--text-primary)] text-xs leading-relaxed max-w-sm vertical-top">
                                      <p className="font-normal text-[var(--text-secondary)]">{mainDesc}</p>
                                    </td>
                                    <td className="py-4 px-4 vertical-top">
                                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                                        (t.severity ?? "").toLowerCase() === "high" || (t.severity ?? "").toLowerCase() === "critical"
                                          ? "border-red-500/25 bg-red-500/10 text-red-400"
                                          : (t.severity ?? "").toLowerCase() === "medium"
                                            ? "border-orange-500/25 bg-orange-500/10 text-orange-400"
                                            : "border-emerald-500/25 bg-emerald-500/10 text-emerald-400"
                                      }`}>
                                        {t.severity}
                                      </span>
                                    </td>
                                    <td className="py-4 px-4 text-xs text-[var(--text-secondary)] vertical-top">
                                      {evidence ? (
                                        <details className="group">
                                          <summary className="text-[11px] text-[var(--primary)]/80 hover:text-[var(--primary)] cursor-pointer select-none font-semibold outline-none flex items-center gap-1">
                                            <span className="inline-block transition-transform duration-200 group-open:rotate-90">▶</span>
                                            View Technical Evidence
                                          </summary>
                                          <pre className="mt-1.5 p-2.5 rounded bg-[var(--bg-page)]/50 border border-[var(--border-soft)] text-[10px] text-[var(--text-muted)] font-mono overflow-x-auto max-w-md whitespace-pre-wrap leading-relaxed">
                                            {evidence.startsWith("-") || evidence.startsWith(":") ? evidence.replace(/^[:\s\-]+/, "") : evidence}
                                          </pre>
                                        </details>
                                      ) : (
                                        <span className="text-[var(--text-muted)] italic">No trace log available</span>
                                      )}
                                    </td>
                                    <td className="py-4 px-4 text-xs text-[var(--text-secondary)] leading-relaxed font-sans max-w-xs vertical-top">
                                      {Array.isArray(t.mitigations) ? t.mitigations.join("; ") : t.mitigations || "N/A"}
                                    </td>
                                  </tr>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>
                    </Card>

                    {/* Section 2: Potential Scenarios */}
                    <Card title="Potential Scenarios" description="Architectural hardening opportunities and defensive recommendations">
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm">
                          <thead>
                            <tr className="border-b border-[var(--border-strong)] text-[var(--text-muted)] font-semibold bg-[var(--bg-card)]/10">
                              <th className="py-3 px-4 w-40">STRIDE Category</th>
                              <th className="py-3 px-4">Scenario Description</th>
                              <th className="py-3 px-4 w-32">Advisory Risk</th>
                              <th className="py-3 px-4 w-60">Why Generated</th>
                              <th className="py-3 px-4">Recommended Hardening</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-white/[0.04]">
                            {groupedPotential.length === 0 ? (
                              <tr>
                                <td colSpan={5} className="py-12 text-center text-[var(--text-muted)] font-medium">
                                  No potential hardening scenarios generated.
                                </td>
                              </tr>
                            ) : (
                              groupedPotential.map((t: any, idx: number) => {
                                const { mainDesc, evidence } = parseScenario(t.attack_scenario);
                                return (
                                  <tr key={t.stride_id || idx} className="hover:bg-[var(--bg-elevated)] transition-colors duration-150">
                                    <td className="py-4 px-4 vertical-top">
                                      <div className="space-y-2">
                                        <div className="flex flex-wrap gap-1.5">
                                          {t.categories.map((cat: string, cIdx: number) => (
                                            <span key={cIdx} className="inline-block text-[10px] bg-amber-500/10 border border-amber-500/20 text-amber-600 font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                                              {cat}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    </td>
                                    <td className="py-4 px-4 font-semibold text-[var(--text-primary)] text-xs leading-relaxed max-w-sm vertical-top">
                                      <p className="font-normal text-[var(--text-secondary)]">{mainDesc}</p>
                                    </td>
                                    <td className="py-4 px-4 vertical-top">
                                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                                        (t.severity ?? "").toLowerCase() === "high" || (t.severity ?? "").toLowerCase() === "critical"
                                          ? "border-amber-500/25 bg-amber-500/10 text-amber-600"
                                          : (t.severity ?? "").toLowerCase() === "medium"
                                            ? "border-blue-500/25 bg-blue-500/10 text-blue-400"
                                            : "border-emerald-500/25 bg-emerald-500/10 text-emerald-400"
                                      }`}>
                                        {t.severity || "Low"}
                                      </span>
                                    </td>
                                    <td className="py-4 px-4 text-xs text-[var(--text-secondary)] max-w-xs leading-relaxed vertical-top">
                                      <div className="line-clamp-2" title={getShortWhyGenerated(t)}>
                                        {getShortWhyGenerated(t)}
                                      </div>
                                      <div className="mt-2">
                                        <details className="group">
                                          <summary className="text-[11px] text-[var(--primary)]/80 hover:text-[var(--primary)] cursor-pointer select-none font-semibold outline-none flex items-center gap-1">
                                            <span className="inline-block transition-transform duration-200 group-open:rotate-90">▶</span>
                                            View Technical Evidence
                                          </summary>
                                          <div className="mt-2 p-3 rounded bg-[var(--bg-page)]/50 border border-[var(--border-soft)] text-[10px] text-[var(--text-muted)] font-mono overflow-x-auto max-w-md whitespace-pre-wrap leading-relaxed space-y-1">
                                            <div>
                                              <span className="text-[var(--text-primary)] font-semibold">Finding ID:</span> {t.related_findings?.join(", ") || t.stride_id || "N/A"}
                                            </div>
                                            <div>
                                              <span className="text-[var(--text-primary)] font-semibold">Source Module:</span> {t.source_module || "pentest_engine_module"}
                                            </div>
                                            {t.related_findings && t.related_findings.length > 0 && (
                                              <div>
                                                <span className="text-[var(--text-primary)] font-semibold">Related Findings:</span> {t.related_findings.join(", ")}
                                              </div>
                                            )}
                                            <div>
                                              <span className="text-[var(--text-primary)] font-semibold">Confidence:</span> {t.confidence || "advisory"}
                                            </div>
                                            {t.why_generated && (
                                              <div>
                                                <span className="text-[var(--text-primary)] font-semibold">Why Generated:</span> {t.why_generated}
                                              </div>
                                            )}
                                            {t.why_not_confirmed && (
                                              <div>
                                                <span className="text-[var(--text-primary)] font-semibold">Why Not Confirmed:</span> {t.why_not_confirmed}
                                              </div>
                                            )}
                                            {evidence && (
                                              <div className="mt-2 pt-2 border-t border-[var(--border-soft)]">
                                                <span className="text-[var(--text-primary)] font-semibold block mb-1">Raw Evidence:</span>
                                                <pre className="whitespace-pre-wrap font-mono leading-relaxed">{evidence.startsWith("-") || evidence.startsWith(":") ? evidence.replace(/^[:\s\-]+/, "") : evidence}</pre>
                                              </div>
                                            )}
                                          </div>
                                        </details>
                                      </div>
                                    </td>
                                    <td className="py-4 px-4 text-xs text-[var(--text-secondary)] leading-relaxed font-sans max-w-xs vertical-top">
                                      {Array.isArray(t.mitigations) ? t.mitigations.join("; ") : t.mitigations || "N/A"}
                                    </td>
                                  </tr>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>
                    </Card>
                  </div>
                );
              })()}

              {/* Tab: AI Summary */}
              {activeTab === "ai_summary" && (
                <div className="space-y-6">
                  {/* Confidence Gauge */}
                  <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                    <Card className="lg:col-span-3 !p-6 flex flex-col justify-center bg-[var(--bg-card)]/15 border border-[var(--border-soft)]">
                      <div className="flex items-center gap-2 text-[var(--primary)] font-semibold text-sm">
                        <Sparkles className="w-4 h-4 animate-bounce" />
                        AI Executive Summary
                      </div>
                      <div className="text-[var(--text-primary)] text-sm leading-relaxed mt-4 whitespace-pre-line font-sans">
                        <div className="markdown-content">
                          <ReactMarkdown>
                            {investigation.final_result?.reporter?.ai_summary?.executive_summary || "Generating summaries..."}
                          </ReactMarkdown>
                        </div>
                      </div>
                    </Card>

                    <Card className="lg:col-span-1 !p-6 flex flex-col items-center justify-center bg-[var(--bg-card)]/15 border border-[var(--border-soft)] text-center">
                      <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider block">
                        AI Confidence Index
                      </span>
                      <div className="text-5xl font-black text-[var(--text-primary)] tracking-tight mt-3">
                        {investigation.final_result?.reporter?.confidence || 85}%
                      </div>
                      <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-widest mt-2">
                        High Confidence
                      </span>
                      <p className="text-[10px] text-[var(--text-muted)] mt-4 leading-normal font-sans">
                        Calculated by the LLM based on findings, technology profiles, and verified reputation indices.
                      </p>
                    </Card>
                  </div>

                  {/* Technical & Risks */}
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                    {/* Technical details */}
                    <div className="lg:col-span-7">
                      <Card title="Technical Investigation Summary">
                        <div className="text-[var(--text-secondary)] text-xs leading-relaxed whitespace-pre-line font-sans">
                          <div className="markdown-content">
                            <ReactMarkdown>
                              {investigation.final_result?.reporter?.ai_summary?.technical_summary || "Generating technical summaries..."}
                            </ReactMarkdown>
                          </div>
                        </div>
                      </Card>
                    </div>

                    {/* Key Risks & Recommendations */}
                    <div className="lg:col-span-5 space-y-6">
                      <Card title="Prioritized Recommendations">
                        <ol className="list-decimal list-inside space-y-2.5 text-xs text-[var(--text-secondary)] font-sans">
                          {investigation.final_result?.reporter?.ai_summary?.remediation_plan?.map((rec: any, idx: number) => (
                            <li key={idx} className="leading-relaxed pl-1 text-[var(--text-secondary)]">
                              <span className="text-[var(--text-primary)] font-bold">{rec.title}:</span>{" "}
                              {rec.description}{" "}
                              <span className="text-[var(--text-muted)] font-mono text-[10px] ml-1">({rec.estimated_effort})</span>
                            </li>
                          )) || <li className="text-[var(--text-muted)] font-sans">No recommendations drafted.</li>}
                        </ol>
                      </Card>

                      <Card title="AI Risk Explanation">
                        <p className="text-xs text-[var(--text-secondary)] leading-relaxed font-sans">
                          {investigation.final_result?.reporter?.ai_summary?.risk_explanation || "No risk explanation drafted."}
                        </p>
                      </Card>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
