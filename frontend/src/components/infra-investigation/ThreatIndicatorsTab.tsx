"use client";

import { InfraInvestigationResults } from "@/types/infra_investigation";
import { AlertTriangle, CheckCircle, ShieldAlert, Minus } from "lucide-react";

interface Props {
  results: InfraInvestigationResults;
  relIndicators?: any[];   // from infra_indicators table (optional, relational)
  relTotal?: number;       // total count from relational table
}

const severityConfig = {
  critical: { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/25",    dot: "bg-red-400" },
  high:     { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/25", dot: "bg-orange-400" },
  medium:   { color: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/25",  dot: "bg-amber-400" },
  low:      { color: "text-[var(--primary)]",   bg: "bg-[var(--primary)]/10",   border: "border-[var(--primary)]",   dot: "bg-blue-400" },
  info:     { color: "text-[var(--text-muted)]",  bg: "bg-[var(--bg-elevated)]/40",  border: "border-[var(--border-strong)]",      dot: "bg-[var(--bg-elevated)]" },
};

export function ThreatIndicatorsTab({ results, relIndicators, relTotal }: Props) {
  const ti = results.threat_indicators;
  if (!ti) return <Empty />;

  // Prefer relational count if available
  const triggeredCount = relIndicators ? relIndicators.filter((i) => i.is_malicious).length : ti.total_triggered;
  const totalCount     = relTotal ?? ti.checks.length;

  const triggered = ti.checks.filter((c) => c.triggered);
  const clean     = ti.checks.filter((c) => !c.triggered);

  const phishingColor =
    ti.phishing_score >= 70 ? "text-red-400" :
    ti.phishing_score >= 40 ? "text-amber-400" : "text-emerald-400";

  const phishingBg =
    ti.phishing_score >= 70 ? "bg-red-500/10 border-red-500/20" :
    ti.phishing_score >= 40 ? "bg-amber-500/10 border-amber-500/20" :
    "bg-emerald-500/10 border-emerald-500/20";

  return (
    <div className="space-y-5">

      {/* Phishing score banner */}
      <div className={`flex items-center justify-between p-4 rounded-xl border ${phishingBg}`}>
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)]">Phishing Likelihood Score</p>
          <p className={`text-3xl font-black mt-1 ${phishingColor}`}>{ti.phishing_score}<span className="text-lg font-semibold text-[var(--text-muted)]">/100</span></p>
        </div>
        <div className="text-right">
          <p className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Indicators Triggered</p>
          <p className="text-2xl font-black text-[var(--text-primary)]">{ti.total_triggered} <span className="text-sm font-medium text-[var(--text-muted)]">/ {ti.checks.length}</span></p>
        </div>
      </div>

      {/* Phishing bar */}
      <div className="h-2 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{
            width: `${ti.phishing_score}%`,
            background: ti.phishing_score >= 70 ? "#ef4444" : ti.phishing_score >= 40 ? "#f59e0b" : "#10b981",
          }}
        />
      </div>

      {/* Triggered checks */}
      {triggered.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] mb-3 flex items-center gap-2">
            <ShieldAlert className="w-3 h-3" /> Triggered Indicators
          </p>
          <div className="space-y-2">
            {triggered.map((check) => {
              const cfg = severityConfig[check.severity] || severityConfig.info;
              return (
                <div key={check.id} className={`flex items-start gap-3 p-3 rounded-xl border ${cfg.bg} ${cfg.border}`}>
                  <div className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-xs font-bold ${cfg.color}`}>{check.name}</span>
                      <span className={`text-[9px] font-extrabold uppercase px-1.5 py-0.5 rounded border ${cfg.bg} ${cfg.border} ${cfg.color}`}>
                        {check.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-[var(--text-muted)] mt-0.5">{check.description}</p>
                    {check.detail && (
                      <p className="text-[11px] text-[var(--text-muted)] mt-1 font-mono bg-[var(--bg-card)]/40 px-2 py-1 rounded">
                        {check.detail}
                      </p>
                    )}
                  </div>
                  <AlertTriangle className={`w-4 h-4 flex-shrink-0 ${cfg.color}`} />
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Clean checks */}
      {clean.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] mb-3 flex items-center gap-2">
            <CheckCircle className="w-3 h-3 text-emerald-500" /> Passed Checks
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {clean.map((check) => (
              <div key={check.id} className="flex items-center gap-2.5 p-3 rounded-xl border border-[var(--border-soft)] bg-emerald-500/[0.03]">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-500 flex-shrink-0" />
                <div>
                  <p className="text-[11px] font-semibold text-[var(--text-secondary)]">{check.name}</p>
                  <p className="text-[10px] text-[var(--text-muted)]">{check.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Empty() {
  return (
    <div className="py-20 text-center text-[var(--text-muted)]">
      <Minus className="w-6 h-6 mx-auto mb-2 opacity-40" />
      <p className="text-sm">Threat indicator data not yet available</p>
    </div>
  );
}
