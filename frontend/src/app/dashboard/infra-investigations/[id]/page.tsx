"use client";

import React, { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { useInfraInvestigationProgress } from "@/hooks/useInfraInvestigationProgress";
import { api } from "@/lib/api";
import { RiskGauge } from "@/components/investigation/RiskGauge";
import { InfraPipelineTimeline } from "@/components/infra-investigation/InfraPipelineTimeline";
import { InfraSOCFeed } from "@/components/infra-investigation/InfraSOCFeed";
import { ReputationFeedTab } from "@/components/infra-investigation/ReputationFeedTab";
import { DNSWhoisTab } from "@/components/infra-investigation/DNSWhoisTab";
import { PassiveDNSTab } from "@/components/infra-investigation/PassiveDNSTab";
import { ThreatIndicatorsTab } from "@/components/infra-investigation/ThreatIndicatorsTab";
import { CorrelationTab } from "@/components/infra-investigation/CorrelationTab";
import { AIReportTab } from "@/components/infra-investigation/AIReportTab";
import { Button } from "@/components/ui";
import {
  ArrowLeft, Globe, AlertOctagon, Clock, RefreshCw, StopCircle,
  ShieldAlert, Search, GitBranch, AlertTriangle, Sparkles, Network,
  Loader2, CheckCircle, XCircle,
} from "lucide-react";

// ─── Loading animation ─────────────────────────────────────────────────────────

const IntelPulse = () => (
  <div className="relative flex items-center justify-center select-none" style={{ width: 180, height: 180 }}>
    <div className="absolute w-24 h-24 rounded-full bg-cyan-500/5 border border-cyan-500/10 animate-pulse flex items-center justify-center">
      <div className="flex space-x-1.5 justify-center items-center">
        <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-bounce [animation-delay:-0.3s] shadow-lg shadow-cyan-400/50" />
        <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-bounce [animation-delay:-0.15s] shadow-lg shadow-cyan-400/50" />
        <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-bounce shadow-lg shadow-cyan-400/50" />
      </div>
    </div>
    <div className="absolute inset-0 animate-spin [animation-duration:8s] rounded-full border border-dashed border-cyan-500/20" />
    <div className="absolute inset-2.5 animate-spin [animation-duration:12s] [animation-direction:reverse] rounded-full border border-dotted border-cyan-500/30" />
    <svg className="absolute w-full h-full animate-spin [animation-duration:4s]" viewBox="0 0 100 100">
      <circle cx="50" cy="10" r="3.5" className="fill-cyan-500 shadow-md shadow-cyan-500" />
      <circle cx="78" cy="22" r="3"   className="fill-cyan-400/80" />
      <circle cx="90" cy="50" r="2.5" className="fill-cyan-400/60" />
      <circle cx="78" cy="78" r="2"   className="fill-cyan-400/40" />
      <circle cx="50" cy="90" r="1.5" className="fill-cyan-400/20" />
    </svg>
  </div>
);

// ─── Tab definitions ───────────────────────────────────────────────────────────

const TABS = [
  { key: "reputation",  label: "Reputation",     icon: <ShieldAlert className="w-3.5 h-3.5" /> },
  { key: "dns",         label: "DNS & Infra",     icon: <Globe className="w-3.5 h-3.5" /> },
  { key: "passive_dns", label: "Passive DNS",     icon: <GitBranch className="w-3.5 h-3.5" /> },
  { key: "indicators",  label: "Threat Signals",  icon: <AlertTriangle className="w-3.5 h-3.5" /> },
  { key: "correlation", label: "Correlation",     icon: <Network className="w-3.5 h-3.5" /> },
  { key: "ai_report",   label: "AI Report",       icon: <Sparkles className="w-3.5 h-3.5" /> },
];

// ─── Target type badge ─────────────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  return (
    <span className="text-[9px] font-extrabold uppercase px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 tracking-wider">
      {type}
    </span>
  );
}

// ─── Status badge ──────────────────────────────────────────────────────────────

function StatusIndicator({ status }: { status: string }) {
  const map: Record<string, { label: string; cls: string; dot: string }> = {
    completed: { label: "Completed",  cls: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20", dot: "bg-emerald-400" },
    failed:    { label: "Failed",     cls: "text-red-400 bg-red-500/10 border-red-500/20",             dot: "bg-red-400"     },
    stopped:   { label: "Stopped",    cls: "text-amber-400 bg-amber-500/10 border-amber-500/20",       dot: "bg-amber-400"   },
    pending:   { label: "Pending",    cls: "text-slate-400 bg-slate-800 border-slate-700",              dot: "bg-slate-500"   },
  };
  const cfg = map[status] || { label: status || "Running", cls: "text-blue-400 bg-blue-500/10 border-blue-500/20 animate-pulse", dot: "bg-blue-400 animate-ping" };
  return (
    <span className={`flex items-center gap-1.5 text-[10px] font-extrabold uppercase px-2.5 py-1 rounded-full border ${cfg.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────────

export default function InfraInvestigationWorkspace() {
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
    error,
    refresh,
  } = useInfraInvestigationProgress(id);

  const [activeTab, setActiveTab] = useState("reputation");
  const [stopLoading, setStopLoading] = useState(false);
  const [activeDuration, setActiveDuration] = useState("00:00");

  // Relational tab state
  const [relIndicators, setRelIndicators] = useState<any[] | null>(null);
  const [relIndicatorsTotal, setRelIndicatorsTotal] = useState(0);
  const [relIndicatorsLoading, setRelIndicatorsLoading] = useState(false);
  const [relReport, setRelReport] = useState<any | null>(null);
  const [relReportLoading, setRelReportLoading] = useState(false);

  // Duration counter
  useEffect(() => {
    if (!investigation?.started_at) return;
    const update = () => {
      let diffMs = 0;
      if (
        investigation.status === "completed" ||
        investigation.status === "failed" ||
        investigation.status === "stopped"
      ) {
        const end = investigation.completed_at
          ? new Date(investigation.completed_at).getTime()
          : Date.now();
        diffMs = end - new Date(investigation.started_at).getTime();
      } else {
        diffMs = Date.now() - new Date(investigation.started_at).getTime();
      }
      const totalSec = Math.max(0, Math.floor(diffMs / 1000));
      const m = String(Math.floor(totalSec / 60)).padStart(2, "0");
      const s = String(totalSec % 60).padStart(2, "0");
      setActiveDuration(`${m}:${s}`);
    };
    update();
    const t = setInterval(update, 1000);
    return () => clearInterval(t);
  }, [investigation]);

  const handleStop = async () => {
    if (!id || !token) return;
    setStopLoading(true);
    try { await api.infraInvestigations.stop(id, token); refresh(); }
    catch { /* ignore */ }
    finally { setStopLoading(false); }
  };

  const isTerminal = investigation?.status === "completed" ||
                     investigation?.status === "failed"    ||
                     investigation?.status === "stopped";

  // Fetch relational indicators when tab is active and pipeline is done
  useEffect(() => {
    if (activeTab !== "indicators" || !isTerminal || !id || !token) return;
    if (relIndicators !== null) return; // already loaded
    setRelIndicatorsLoading(true);
    api.infraInvestigations.getIndicators(id, token, { maliciousOnly: false, limit: 200 })
      .then((res) => {
        if (res?.success && res?.data) {
          setRelIndicators(res.data.items ?? []);
          setRelIndicatorsTotal(res.data.total ?? 0);
        }
      })
      .catch(() => { /* fall back to JSONB */ })
      .finally(() => setRelIndicatorsLoading(false));
  }, [activeTab, isTerminal, id, token, relIndicators]);

  // Fetch relational AI report when tab is active and pipeline is done
  useEffect(() => {
    if (activeTab !== "ai_report" || !isTerminal || !id || !token) return;
    if (relReport !== null) return; // already loaded
    setRelReportLoading(true);
    api.infraInvestigations.getReport(id, token)
      .then((res) => {
        if (res?.success && res?.data) setRelReport(res.data);
      })
      .catch(() => { /* fall back to JSONB */ })
      .finally(() => setRelReportLoading(false));
  }, [activeTab, isTerminal, id, token, relReport]);

  const results = investigation?.results;

  // ── Loading screen ─────────────────────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-6">
        <IntelPulse />
        <div className="text-center">
          <p className="text-sm font-bold text-slate-300">Loading Investigation</p>
          <p className="text-xs text-slate-600 mt-1">Fetching intelligence pipeline status...</p>
        </div>
      </div>
    );
  }

  // ── Error screen ───────────────────────────────────────────────────────────
  if (error || !investigation) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <AlertOctagon className="w-12 h-12 text-red-400 opacity-60" />
        <p className="text-slate-300 font-semibold">{error || "Investigation not found"}</p>
        <Button variant="secondary" size="sm" onClick={() => router.back()}>
          <ArrowLeft className="w-4 h-4 mr-2" /> Go back
        </Button>
      </div>
    );
  }

  // ── Running screen (no results yet) ────────────────────────────────────────
  if (!isTerminal) {
    return (
      <div className="space-y-6">
        {/* Back + title */}
        <div className="flex items-center gap-3">
          <button onClick={() => router.push("/dashboard/infra-investigations")}
            className="p-2 rounded-lg border border-white/[0.08] text-slate-400 hover:text-white hover:bg-white/[0.04] transition-all">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-bold text-slate-200 font-mono truncate max-w-[300px]">{investigation.target}</span>
            <TypeBadge type={investigation.target_type} />
            <StatusIndicator status={investigation.status} />
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span className="text-xs text-slate-500 font-mono flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" />{activeDuration}
            </span>
            <Button variant="danger" size="sm" isLoading={stopLoading} onClick={handleStop}>
              <StopCircle className="w-4 h-4 mr-1" /> Stop
            </Button>
          </div>
        </div>

        {/* Pipeline timeline */}
        <InfraPipelineTimeline stages={stages} />

        {/* Central loading area */}
        <div className="flex flex-col items-center justify-center py-12 space-y-6">
          <IntelPulse />
          <div className="text-center">
            <p className="text-base font-bold text-white">{investigation.current_stage}</p>
            <p className="text-sm text-slate-500 mt-1">Gathering intelligence… {Math.round(investigation.progress_percent)}%</p>
          </div>
          <div className="w-full max-w-sm bg-white/[0.04] rounded-full h-1.5 overflow-hidden">
            <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-700"
              style={{ width: `${investigation.progress_percent}%` }} />
          </div>
        </div>

        {/* SOC Feed */}
        <InfraSOCFeed events={liveEvents} />
      </div>
    );
  }

  // ── Completed workspace ─────────────────────────────────────────────────────
  return (
    <div className="space-y-6">

      {/* Header row */}
      <div className="flex items-center gap-3 flex-wrap">
        <button
          onClick={() => router.push("/dashboard/infra-investigations")}
          className="p-2 rounded-lg border border-white/[0.08] text-slate-400 hover:text-white hover:bg-white/[0.04] transition-all"
        >
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-2 flex-wrap min-w-0">
          <span className="text-sm font-bold text-slate-200 font-mono truncate max-w-[320px]">{investigation.target}</span>
          <TypeBadge type={investigation.target_type} />
          <StatusIndicator status={investigation.status} />
        </div>
        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-slate-500 font-mono flex items-center gap-1">
            <Clock className="w-3.5 h-3.5" />{activeDuration}
          </span>
          <button onClick={() => refresh()} className="p-2 rounded-lg border border-white/[0.08] text-slate-400 hover:text-white hover:bg-white/[0.04] transition-all">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Pipeline timeline */}
      <InfraPipelineTimeline stages={stages} />

      {/* Metrics row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          {
            label: "Risk Score",
            value: `${Math.round(investigation.risk_score)}/100`,
            color: investigation.risk_score >= 70 ? "text-red-400" : investigation.risk_score >= 40 ? "text-amber-400" : "text-emerald-400",
            icon: <ShieldAlert className="w-4 h-4" />,
          },
          {
            label: "Target Type",
            value: investigation.target_type.toUpperCase(),
            color: "text-cyan-400",
            icon: <Search className="w-4 h-4" />,
          },
          {
            label: "Duration",
            value: activeDuration,
            color: "text-slate-200",
            icon: <Clock className="w-4 h-4" />,
          },
          {
            label: "Status",
            value: investigation.status,
            color: investigation.status === "completed" ? "text-emerald-400" : investigation.status === "failed" ? "text-red-400" : "text-amber-400",
            icon: investigation.status === "completed"
              ? <CheckCircle className="w-4 h-4 text-emerald-400" />
              : <XCircle className="w-4 h-4 text-red-400" />,
          },
        ].map((m) => (
          <div key={m.label} className="bg-[#1e293b]/50 border border-white/[0.06] rounded-xl p-3 flex items-center gap-3">
            <div className="text-slate-500">{m.icon}</div>
            <div>
              <p className={`text-sm font-black capitalize ${m.color}`}>{m.value}</p>
              <p className="text-[10px] text-slate-500">{m.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Main content */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5 items-start">

        {/* Risk gauge + SOC feed */}
        <div className="lg:col-span-1 flex flex-col gap-4" style={{ minHeight: 520 }}>
          <div className="bg-[#1e293b]/50 border border-white/[0.06] rounded-xl p-4 flex flex-col items-center justify-center flex-shrink-0">
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Threat Risk Score</p>
            <RiskGauge score={progressiveRisk} size={160} />
          </div>
          <div className="flex-1 min-h-0">
            <InfraSOCFeed events={liveEvents} />
          </div>
        </div>

        {/* Tabbed results */}
        <div className="lg:col-span-3 space-y-0">

          {/* Tabs */}
          <div className="flex gap-0.5 overflow-x-auto scrollbar-none border-b border-white/[0.05] mb-5">
            {TABS.map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex items-center gap-1.5 px-3 py-2.5 text-xs font-bold transition-all duration-200 border-b-2 whitespace-nowrap ${
                  activeTab === tab.key
                    ? "border-cyan-500 text-cyan-400"
                    : "border-transparent text-slate-500 hover:text-slate-300"
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="min-h-[400px]">
            {results ? (
              <>
                {/* Reputation — from JSONB */}
                {activeTab === "reputation"  && <ReputationFeedTab results={results} />}

                {/* DNS & Infra — from JSONB */}
                {activeTab === "dns"         && <DNSWhoisTab results={results} />}

                {/* Passive DNS — from JSONB */}
                {activeTab === "passive_dns" && <PassiveDNSTab results={results} />}

                {/* Threat Signals — relational primary, JSONB fallback */}
                {activeTab === "indicators"  && (
                  relIndicatorsLoading ? (
                    <div className="flex items-center justify-center py-20 gap-3 text-slate-500 text-sm">
                      <Loader2 className="w-5 h-5 animate-spin text-cyan-500" />
                      Loading threat signals from database…
                    </div>
                  ) : relIndicators !== null && relIndicators.length > 0 ? (
                    <ThreatIndicatorsTab results={results} relIndicators={relIndicators} relTotal={relIndicatorsTotal} />
                  ) : (
                    <ThreatIndicatorsTab results={results} />
                  )
                )}

                {/* Correlation — from JSONB */}
                {activeTab === "correlation" && <CorrelationTab results={results} />}

                {/* AI Report — relational primary, JSONB fallback */}
                {activeTab === "ai_report"   && (
                  relReportLoading ? (
                    <div className="flex items-center justify-center py-20 gap-3 text-slate-500 text-sm">
                      <Loader2 className="w-5 h-5 animate-spin text-purple-500" />
                      Loading AI report from database…
                    </div>
                  ) : (
                    <AIReportTab
                      results={results}
                      riskScore={investigation.risk_score}
                      relReport={relReport ?? undefined}
                    />
                  )
                )}
              </>
            ) : investigation.status === "failed" ? (
              <div className="flex flex-col items-center justify-center py-20 space-y-3 text-center">
                <XCircle className="w-10 h-10 text-red-400 opacity-60" />
                <p className="text-sm font-semibold text-slate-300">Pipeline terminated with an error</p>
                <p className="text-xs text-slate-500">Partial results may not be available.</p>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-20 space-y-3 text-center">
                <Loader2 className="w-8 h-8 text-slate-600 animate-spin" />
                <p className="text-sm text-slate-500">Results loading...</p>
              </div>
            )}
          </div>

        </div>

      </div>
    </div>
  );
}
