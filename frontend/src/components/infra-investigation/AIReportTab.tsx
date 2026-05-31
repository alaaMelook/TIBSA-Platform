"use client";

import { InfraInvestigationResults } from "@/types/infra_investigation";
import { Sparkles, ShieldAlert, CheckCircle, ArrowRight, Minus, AlertTriangle } from "lucide-react";
import ReactMarkdown from "react-markdown";

interface Props {
  results: InfraInvestigationResults;
  riskScore: number;
}

export function AIReportTab({ results, riskScore }: Props) {
  const ai = results.ai_summary;

  const risk = results.risk;

  const riskColor =
    riskScore >= 80 ? "text-red-400" :
    riskScore >= 60 ? "text-orange-400" :
    riskScore >= 40 ? "text-amber-400" : "text-emerald-400";

  const riskBg =
    riskScore >= 80 ? "from-red-900/20 to-[#1e293b]/0" :
    riskScore >= 60 ? "from-orange-900/20 to-[#1e293b]/0" :
    riskScore >= 40 ? "from-amber-900/20 to-[#1e293b]/0" :
    "from-emerald-900/20 to-[#1e293b]/0";

  return (
    <div className="space-y-5">

      {/* Risk breakdown */}
      {risk && (
        <div className={`bg-gradient-to-br ${riskBg} border border-white/[0.06] rounded-xl p-5`}>
          <div className="flex items-start justify-between mb-4">
            <div>
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Composite Risk Score</p>
              <p className={`text-5xl font-black mt-1 ${riskColor}`}>
                {Math.round(riskScore)}<span className="text-xl text-slate-500 font-semibold">/100</span>
              </p>
              <span className={`inline-block mt-2 text-[10px] font-extrabold uppercase px-2.5 py-1 rounded-full border ${
                riskScore >= 80 ? "text-red-400 bg-red-500/10 border-red-500/25" :
                riskScore >= 60 ? "text-orange-400 bg-orange-500/10 border-orange-500/25" :
                riskScore >= 40 ? "text-amber-400 bg-amber-500/10 border-amber-500/25" :
                "text-emerald-400 bg-emerald-500/10 border-emerald-500/25"
              }`}>{risk.risk_label}</span>
            </div>

            {/* Score breakdown bars */}
            <div className="space-y-2 min-w-[180px]">
              {[
                { label: "Reputation",      value: risk.reputation_score,     color: "#ef4444" },
                { label: "Infrastructure",  value: risk.infrastructure_score,  color: "#f97316" },
                { label: "Phishing",        value: risk.phishing_score,        color: "#eab308" },
              ].map((b) => (
                <div key={b.label}>
                  <div className="flex justify-between text-[10px] mb-0.5">
                    <span className="text-slate-500">{b.label}</span>
                    <span className="text-slate-300 font-bold">{Math.round(b.value)}</span>
                  </div>
                  <div className="h-1 bg-white/[0.06] rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${Math.min(100, b.value)}%`, backgroundColor: b.color }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Contributing factors */}
          {risk.contributing_factors.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-3 border-t border-white/[0.04]">
              {risk.contributing_factors.map((f, i) => (
                <span key={i} className="flex items-center gap-1 text-[10px] text-slate-400 bg-slate-900/40 px-2 py-1 rounded-lg border border-white/[0.05]">
                  <AlertTriangle className="w-3 h-3 text-amber-500" /> {f}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* AI Summary */}
      {ai && !ai.error ? (
        <div className="space-y-4">
          {/* Header */}
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-bold text-white">AI Threat Analysis</span>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 ml-auto">
              {Math.round(ai.confidence * 100)}% confidence
            </span>
          </div>

          {/* Threat classification */}
          <div className="flex items-center gap-3 p-3 rounded-xl border border-purple-500/20 bg-purple-500/5">
            <ShieldAlert className="w-5 h-5 text-purple-400 flex-shrink-0" />
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Threat Classification</p>
              <p className="text-sm font-bold text-purple-300 mt-0.5">{ai.threat_classification}</p>
            </div>
          </div>

          {/* Executive summary */}
          <div className="bg-[#1e293b]/60 border border-white/[0.06] rounded-xl p-4">
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3">Executive Summary</p>
            <div className="prose prose-invert prose-sm max-w-none text-slate-300 text-[13px] leading-relaxed">
              <ReactMarkdown>{ai.executive_summary}</ReactMarkdown>
            </div>
          </div>

          {/* Why suspicious */}
          {ai.why_suspicious && (
            <div className="bg-amber-500/[0.04] border border-amber-500/[0.15] rounded-xl p-4">
              <p className="text-[10px] font-bold uppercase tracking-widest text-amber-500/80 mb-3">Why This Is Suspicious</p>
              <div className="prose prose-invert prose-sm max-w-none text-slate-300 text-[13px] leading-relaxed">
                <ReactMarkdown>{ai.why_suspicious}</ReactMarkdown>
              </div>
            </div>
          )}

          {/* Recommended actions */}
          {ai.recommended_actions.length > 0 && (
            <div className="bg-[#1e293b]/60 border border-white/[0.06] rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Recommended Actions</p>
              </div>
              <ul className="space-y-2">
                {ai.recommended_actions.map((action, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <ArrowRight className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0 mt-0.5" />
                    <span className="text-[12px] text-slate-300">{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : ai?.error ? (
        <div className="p-4 rounded-xl border border-red-500/20 bg-red-500/5 text-red-400 text-sm">
          AI summary failed: {ai.error}
        </div>
      ) : (
        <div className="py-16 text-center text-slate-600">
          <Sparkles className="w-8 h-8 mx-auto mb-2 opacity-30" />
          <p className="text-sm">AI analysis not yet available</p>
        </div>
      )}
    </div>
  );
}
