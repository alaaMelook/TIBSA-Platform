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
        return "border-[#EF4444]/20 bg-[#EF4444]/10 text-[#EF4444]";
      case "high":
        return "border-[#EF4444]/20 bg-[#EF4444]/10 text-[#EF4444]";
      case "medium":
        return "border-[#F97316]/20 bg-[#F97316]/10 text-[#F97316]";
      default:
        return "border-yellow-500/20 bg-yellow-500/10 text-yellow-600";
    }
  };

  const getSourceBadgeColor = (source?: string) => {
    switch ((source ?? '').toLowerCase()) {
      case "pentest":
        return "bg-[#10B981]/10 border-[#10B981]/20 text-[#10B981]";
      case "ioc":
        return "bg-[#2F80ED]/10 border-[#2F80ED]/20 text-[#2F80ED]";
      case "context":
      default:
        return "bg-orange-500/10 border-orange-500/20 text-orange-600";
    }
  };

  const displayRisk = threat.combined_risk || threat.severity || 'info';

  return (
    <div className="border border-[#E6DDD2] bg-white rounded-[20px] shadow-sm overflow-hidden hover:border-[#10B981]/50 transition-all duration-300">
      {/* Card Header */}
      <div className="px-5 py-4 border-b border-[#E6DDD2] bg-[#FAF7F1] flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold text-[#7C6F64] font-mono tracking-widest uppercase">
              {threat.id || (threat as any).threat_id}
            </span>
            <span className="flex items-center gap-1 text-[10px] font-bold text-[#10B981] bg-[#10B981]/10 px-2 py-0.5 rounded border border-[#10B981]/20 uppercase tracking-wider">
              <Sparkles className="w-3 h-3 animate-spin" style={{ animationDuration: "3s" }} />
              Correlated Alarms
            </span>
          </div>
          <h4 className="text-base font-bold text-[#1F2933] tracking-wide">
            {threat.title}
          </h4>
          <p className="text-xs text-[#7C6F64] leading-relaxed">
            {threat.description}
          </p>
        </div>

        {/* Severity Badge */}
        <span className={`px-2.5 py-0.5 border rounded text-[10px] font-bold uppercase flex-shrink-0 tracking-wider ${getRiskBadgeColor(displayRisk)}`}>
          {displayRisk} Risk
        </span>
      </div>

      {/* Attack Chain Timeline Flow */}
      <div className="p-5 bg-white">
        <h5 className="text-[10px] font-bold uppercase text-[#7C6F64] tracking-wider mb-4">
          Visualized Attack Chain Steps
        </h5>

        <div className="space-y-3 relative pl-4 before:absolute before:left-[21px] before:top-2 before:bottom-2 before:w-[2px] before:bg-[#E6DDD2]">
          {(threat.attack_chain || []).map((step, idx) => {
            const isLast = idx === (threat.attack_chain || []).length - 1;
            const displaySource = step.evidence_source || (step as any).severity || 'pentest';

            return (
              <div key={`${step.order}-${idx}`} className="space-y-2 relative">
                {/* Visual Connector Dot */}
                <div className="absolute -left-[5px] top-1.5 w-3 h-3 rounded-full bg-white border border-[#E6DDD2] flex items-center justify-center z-10">
                  <div className="w-1.5 h-1.5 rounded-full bg-[#10B981]" />
                </div>

                {/* Step Content */}
                <div className="bg-white border border-[#E6DDD2] p-3 rounded-lg flex items-start gap-4">
                  {/* Step Order Bubble */}
                  <span className="w-6 h-6 rounded-full bg-[#FAF7F1] border border-[#E6DDD2] text-[#1F2933] flex items-center justify-center font-mono font-bold text-xs flex-shrink-0">
                    {step.order}
                  </span>

                  {/* Step Description & Source */}
                  <div className="flex-1 space-y-1">
                    <p className="text-xs text-[#1F2933] leading-relaxed">
                      {step.description}
                    </p>
                    <div className="flex items-center gap-1.5">
                      <span className="text-[9px] text-[#7C6F64] uppercase font-semibold">
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
                    <ArrowDown className="w-3.5 h-3.5 text-[#7C6F64]" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
