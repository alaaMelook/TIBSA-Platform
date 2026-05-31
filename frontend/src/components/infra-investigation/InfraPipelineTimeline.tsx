"use client";

import { InfraPipelineStage } from "@/types/infra_investigation";
import { CheckCircle, AlertCircle, Clock, Loader2 } from "lucide-react";

interface Props {
  stages: InfraPipelineStage[];
}

export function InfraPipelineTimeline({ stages }: Props) {
  return (
    <div className="bg-[#1e293b]/30 rounded-xl border border-white/[0.04] px-5 py-4 shadow-lg">
      <div className="flex items-center justify-between overflow-x-auto gap-0 scrollbar-none">
        {stages.map((stage, idx) => {
          const isLast = idx === stages.length - 1;
          const statusColor = {
            completed: "text-emerald-400",
            running:   "text-blue-400",
            failed:    "text-red-400",
            skipped:   "text-slate-600",
            pending:   "text-slate-600",
          }[stage.status];

          const dotBg = {
            completed: "bg-emerald-500/20 border-emerald-500/40",
            running:   "bg-blue-500/20 border-blue-500/50 animate-pulse",
            failed:    "bg-red-500/20 border-red-500/40",
            skipped:   "bg-slate-800 border-slate-700",
            pending:   "bg-slate-800 border-slate-700",
          }[stage.status];

          const connectorColor =
            stage.status === "completed" ? "bg-emerald-500/40" : "bg-white/[0.06]";

          return (
            <div key={stage.key} className="flex items-center flex-shrink-0">
              {/* Stage node */}
              <div className="flex flex-col items-center gap-1.5 min-w-[80px]">
                <div className={`w-7 h-7 rounded-full border flex items-center justify-center ${dotBg}`}>
                  {stage.status === "completed" && <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />}
                  {stage.status === "running"   && <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />}
                  {stage.status === "failed"    && <AlertCircle className="w-3.5 h-3.5 text-red-400" />}
                  {(stage.status === "pending" || stage.status === "skipped") && (
                    <Clock className="w-3 h-3 text-slate-600" />
                  )}
                </div>
                <span className={`text-[9px] font-bold uppercase tracking-wider text-center leading-tight max-w-[70px] ${statusColor}`}>
                  {stage.name}
                </span>
              </div>

              {/* Connector line */}
              {!isLast && (
                <div className={`h-px w-8 flex-shrink-0 mx-1 transition-colors duration-500 ${connectorColor}`} />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
