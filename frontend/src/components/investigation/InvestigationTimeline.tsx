import React from "react";
import { InvestigationStage } from "@/types";
import {
  Search,
  RefreshCw,
  Globe,
  GitBranch,
  ShieldCheck,
  Cpu,
  CheckCircle2,
  XCircle,
  Clock
} from "lucide-react";

interface InvestigationTimelineProps {
  stages: InvestigationStage[];
}

export function InvestigationTimeline({ stages }: InvestigationTimelineProps) {
  // Map stage name to icons
  const getStageIcon = (name: string, status: string) => {
    const iconClass = `w-5 h-5 ${
      status === "running"
        ? "animate-pulse text-[#2F80ED]"
        : status === "completed"
        ? "text-[#10B981]"
        : status === "failed"
        ? "text-[#EF4444]"
        : "text-[#7C6F64]"
    }`;

    if (name.includes("Pentest")) return <Search className={iconClass} />;
    if (name.includes("Normalization")) return <RefreshCw className={iconClass} />;
    if (name.includes("Intelligence")) return <Globe className={iconClass} />;
    if (name.includes("Correlation")) return <GitBranch className={iconClass} />;
    if (name.includes("STRIDE")) return <ShieldCheck className={iconClass} />;
    return <Cpu className={iconClass} />; // AI Analysis
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "border-[#10B981]/20 bg-[#10B981]/10 text-[#10B981]";
      case "running":
        return "border-[#2F80ED]/50 bg-[#2F80ED]/5 text-[#2F80ED] border-dashed animate-pulse";
      case "failed":
        return "border-[#EF4444]/20 bg-[#EF4444]/10 text-[#EF4444]";
      case "skipped":
        return "border-[#E6DDD2] bg-[#FAF7F1] text-[#7C6F64]";
      default:
        return "border-[#E6DDD2] bg-[#FAF7F1]/50 text-[#7C6F64]";
    }
  };

  return (
    <div className="w-full bg-white rounded-[20px] border border-[#E6DDD2] p-6 shadow-sm">
      <h3 className="text-xs font-semibold text-[#7C6F64] uppercase tracking-widest mb-6">
        Investigation Progress Pipeline
      </h3>

      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4 relative">
        {stages.map((stage, idx) => {
          const isLast = idx === stages.length - 1;
          const status = stage.status;
          const statusClass = getStatusColor(status);

          return (
            <React.Fragment key={stage.stage}>
              {/* Stage Node */}
              <div className="flex-1 flex flex-col items-center text-center p-4 rounded-[16px] border border-[#E6DDD2] bg-white hover:border-[#10B981]/50 hover:shadow-md hover:-translate-y-1 relative transition-all duration-300">
                {/* Node Top Icon */}
                <div
                  className={`w-10 h-10 rounded-lg flex items-center justify-center border ${
                    status === "running"
                      ? "border-[#2F80ED]/30 bg-[#2F80ED]/10 shadow-sm"
                      : status === "completed"
                      ? "border-[#10B981]/30 bg-[#10B981]/10"
                      : status === "failed"
                      ? "border-[#EF4444]/30 bg-[#EF4444]/10"
                      : "border-[#E6DDD2] bg-[#FAF7F1]"
                  } mb-3`}
                >
                  {getStageIcon(stage.stage, status)}
                </div>

                {/* Info */}
                <span className="text-sm font-semibold text-[#1F2933] block truncate max-w-full">
                  {stage.stage}
                </span>

                <div className={`mt-2.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase ${statusClass}`}>
                  {status === "running" ? (
                    <span className="flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-ping" />
                      Active
                    </span>
                  ) : (
                    status
                  )}
                </div>
              </div>

              {/* Connecting line */}
              {!isLast && (
                <div className="hidden md:block w-8 h-[2px] bg-[#E6DDD2] relative self-center">
                  {status === "completed" && (
                    <div className="absolute inset-0 bg-[#10B981] transition-all duration-500" />
                  )}
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
