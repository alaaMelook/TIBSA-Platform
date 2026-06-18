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
        ? "animate-pulse text-[var(--primary)]"
        : status === "completed"
        ? "text-emerald-400"
        : status === "failed"
        ? "text-red-400"
        : "text-[var(--text-muted)]"
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
        return "border-emerald-500/30 bg-emerald-950/20 text-emerald-400";
      case "running":
        return "border-[var(--primary)] bg-blue-950/20 text-[var(--primary)] border-dashed animate-pulse";
      case "failed":
        return "border-red-500/30 bg-red-950/20 text-red-400";
      case "skipped":
        return "border-[var(--border-strong)] bg-[var(--bg-card)]/50 text-[var(--text-muted)]";
      default:
        return "border-[var(--border-strong)] bg-[var(--bg-card)]/10 text-[var(--text-muted)]";
    }
  };

  return (
    <div className="w-full bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] p-6 shadow-md">
      <h3 className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-widest mb-6">
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
              <div className="flex-1 flex flex-col items-center text-center p-3 rounded-xl border bg-[var(--bg-card)]/25 relative transition-all duration-300">
                {/* Node Top Icon */}
                <div
                  className={`w-10 h-10 rounded-lg flex items-center justify-center border ${
                    status === "running"
                      ? "border-blue-500 bg-blue-950/50 shadow-md shadow-[var(--primary-soft)]"
                      : status === "completed"
                      ? "border-emerald-500 bg-emerald-950/30"
                      : status === "failed"
                      ? "border-red-500 bg-red-950/30"
                      : "border-[var(--border-strong)] bg-[var(--bg-card)]/60"
                  } mb-3`}
                >
                  {getStageIcon(stage.stage, status)}
                </div>

                {/* Info */}
                <span className="text-sm font-semibold text-[var(--text-primary)] block truncate max-w-full">
                  {stage.stage}
                </span>

                <div className={`mt-2.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${statusClass}`}>
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
                <div className="hidden md:block w-8 h-[2px] bg-[var(--bg-elevated)] relative self-center">
                  {status === "completed" && (
                    <div className="absolute inset-0 bg-emerald-500/50 transition-all duration-500" />
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
