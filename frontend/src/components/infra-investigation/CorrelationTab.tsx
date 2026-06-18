"use client";

import { InfraInvestigationResults } from "@/types/infra_investigation";
import { Network, Zap, AlertCircle, Minus } from "lucide-react";

interface Props {
  results: InfraInvestigationResults;
}

const confidenceStyle = {
  high:   { text: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/20" },
  medium: { text: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/20" },
  low:    { text: "text-[var(--primary)]",   bg: "bg-[var(--primary)]/10",   border: "border-[var(--primary)]" },
};

export function CorrelationTab({ results }: Props) {
  const corr = results.correlation;
  if (!corr) return <Empty />;

  const triggered  = corr.relationships.filter((r) => r.triggered);
  const untriggered = corr.relationships.filter((r) => !r.triggered);

  const overallCfg = confidenceStyle[corr.overall_confidence] || confidenceStyle.low;

  return (
    <div className="space-y-5">

      {/* Summary banner */}
      <div className="grid grid-cols-3 gap-3">
        <StatBox label="Rules Evaluated" value={String(corr.rules_evaluated)} color="text-[var(--text-primary)]" />
        <StatBox label="Rules Triggered"  value={String(corr.rules_triggered)}  color="text-red-400" />
        <div className={`flex flex-col items-center justify-center p-4 rounded-xl border ${overallCfg.bg} ${overallCfg.border}`}>
          <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Confidence</span>
          <span className={`text-2xl font-black capitalize mt-1 ${overallCfg.text}`}>{corr.overall_confidence}</span>
        </div>
      </div>

      {/* Triggered rules */}
      {triggered.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] mb-3 flex items-center gap-2">
            <Zap className="w-3 h-3 text-red-400" /> Triggered Correlation Rules
          </p>
          <div className="space-y-3">
            {triggered.map((rule) => {
              const cfg = confidenceStyle[rule.confidence] || confidenceStyle.low;
              return (
                <div key={rule.rule_id} className={`p-4 rounded-xl border ${cfg.bg} ${cfg.border}`}>
                  <div className="flex items-start justify-between gap-4 mb-2">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <AlertCircle className={`w-3.5 h-3.5 ${cfg.text}`} />
                        <span className={`text-xs font-bold ${cfg.text}`}>{rule.rule_name}</span>
                      </div>
                      <p className="text-[11px] text-[var(--text-muted)]">{rule.description}</p>
                    </div>
                    <div className="flex flex-col items-end gap-1 flex-shrink-0">
                      <span className={`text-[9px] font-extrabold uppercase px-2 py-0.5 rounded border ${cfg.bg} ${cfg.border} ${cfg.text}`}>
                        {rule.confidence}
                      </span>
                      <span className="text-[9px] text-[var(--text-muted)] uppercase font-bold">{rule.relationship_type}</span>
                    </div>
                  </div>
                  {rule.evidence.length > 0 && (
                    <div className="mt-3 space-y-1">
                      <p className="text-[9px] font-bold uppercase tracking-wider text-[var(--text-muted)] mb-1">Evidence</p>
                      {rule.evidence.map((ev, i) => (
                        <div key={i} className="flex items-start gap-2">
                          <span className="text-[var(--text-muted)] text-xs mt-0.5">›</span>
                          <span className="text-[11px] text-[var(--text-muted)] font-mono">{ev}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Un-triggered rules summary */}
      {untriggered.length > 0 && (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest text-[var(--text-muted)] mb-3 flex items-center gap-2">
            <Network className="w-3 h-3" /> Evaluated But Not Triggered
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {untriggered.map((rule) => (
              <div key={rule.rule_id} className="flex items-center gap-3 p-3 rounded-xl border border-[var(--border-soft)] bg-[var(--bg-card)]/20">
                <div className="w-1.5 h-1.5 rounded-full bg-[var(--bg-elevated)] flex-shrink-0" />
                <span className="text-[11px] text-[var(--text-muted)]">{rule.rule_name}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatBox({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="flex flex-col items-center justify-center p-4 rounded-xl border border-[var(--border-strong)] bg-[var(--bg-card)]">
      <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">{label}</span>
      <span className={`text-2xl font-black mt-1 ${color}`}>{value}</span>
    </div>
  );
}

function Empty() {
  return (
    <div className="py-20 text-center text-[var(--text-muted)]">
      <Minus className="w-6 h-6 mx-auto mb-2 opacity-40" />
      <p className="text-sm">Correlation data not yet available</p>
    </div>
  );
}
