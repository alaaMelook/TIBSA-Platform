import { CorrelatedThreat } from "@/types";
import { Card } from "@/components/ui";
import { GitCommit, ArrowDown, Sparkles } from "lucide-react";

interface AttackChainCardProps {
  threat: CorrelatedThreat;
}

export function AttackChainCard({ threat }: AttackChainCardProps) {
  const getRiskBadgeColor = (risk?: string) => {
    switch ((risk ?? '').toLowerCase()) {
      case "critical":
        return "border-red-950 bg-red-950/40 text-red-500";
      case "high":
        return "border-red-800 bg-red-900/20 text-red-400";
      case "medium":
        return "border-orange-800 bg-orange-900/10 text-orange-400";
      default:
        return "border-yellow-800 bg-yellow-900/10 text-yellow-400";
    }
  };

  const getSourceBadgeColor = (source?: string) => {
    switch ((source ?? '').toLowerCase()) {
      case "pentest":
        return "bg-blue-500/15 border-blue-500/30 text-blue-400";
      case "ioc":
        return "bg-purple-500/15 border-purple-500/30 text-purple-400";
      case "context":
      default:
        return "bg-orange-500/15 border-orange-500/30 text-orange-400";
    }
  };

  const displayRisk = threat.combined_risk || threat.severity || 'info';

  return (
    <Card className="!p-0 border border-white/[0.08] bg-slate-900/10 shadow-lg shadow-black/30 overflow-hidden hover:border-slate-700/50 transition-all duration-300">
      {/* Card Header */}
      <div className="px-5 py-4 border-b border-white/[0.06] bg-slate-900/30 flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold text-slate-500 font-mono tracking-widest uppercase">
              {threat.id || (threat as any).threat_id}
            </span>
            <span className="flex items-center gap-1 text-[10px] font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/25 uppercase tracking-wider">
              <Sparkles className="w-3 h-3 animate-spin" style={{ animationDuration: "3s" }} />
              Correlated Alarms
            </span>
          </div>
          <h4 className="text-base font-bold text-white tracking-wide">
            {threat.title}
          </h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            {threat.description}
          </p>
        </div>

        {/* Severity Badge */}
        <span className={`px-2.5 py-0.5 border rounded text-[10px] font-bold uppercase flex-shrink-0 tracking-wider ${getRiskBadgeColor(displayRisk)}`}>
          {displayRisk} Risk
        </span>
      </div>

      {/* Attack Chain Timeline Flow */}
      <div className="p-5 bg-slate-950/20">
        <h5 className="text-[10px] font-bold uppercase text-slate-500 tracking-wider mb-4">
          Visualized Attack Chain Steps
        </h5>

        <div className="space-y-3 relative pl-4 before:absolute before:left-[21px] before:top-2 before:bottom-2 before:w-[2px] before:bg-slate-800">
          {(threat.attack_chain || []).map((step, idx) => {
            const isLast = idx === (threat.attack_chain || []).length - 1;
            const displaySource = step.evidence_source || (step as any).severity || 'pentest';

            return (
              <div key={`${step.order}-${idx}`} className="space-y-2 relative">
                {/* Visual Connector Dot */}
                <div className="absolute -left-[5px] top-1.5 w-3 h-3 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center z-10">
                  <div className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                </div>

                {/* Step Content */}
                <div className="bg-[#263554]/30 border border-white/[0.04] p-3 rounded-lg flex items-start gap-4">
                  {/* Step Order Bubble */}
                  <span className="w-6 h-6 rounded-full bg-slate-800 border border-white/[0.08] text-white flex items-center justify-center font-mono font-bold text-xs flex-shrink-0">
                    {step.order}
                  </span>

                  {/* Step Description & Source */}
                  <div className="flex-1 space-y-1">
                    <p className="text-xs text-slate-200 leading-relaxed">
                      {step.description}
                    </p>
                    <div className="flex items-center gap-1.5">
                      <span className="text-[9px] text-slate-500 uppercase font-semibold">
                        Evidence Base:
                      </span>
                      <span className={`px-1.5 py-0.5 rounded text-[8px] font-extrabold uppercase border ${getSourceBadgeColor(displaySource)}`}>
                        {displaySource}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Down Arrow separator */}
                {!isLast && (
                  <div className="flex justify-center w-6 opacity-30 mt-1">
                    <ArrowDown className="w-3.5 h-3.5 text-slate-400" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </Card>
  );
}
