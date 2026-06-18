"use client";

import { InfraLiveEvent } from "@/types/infra_investigation";

interface Props {
  events: InfraLiveEvent[];
}

const severityStyle: Record<string, string> = {
  info:     "text-[var(--primary)]  bg-[var(--primary)]/10  border-[var(--primary)]",
  success:  "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  warning:  "text-amber-400 bg-amber-500/10  border-amber-500/20",
  critical: "text-red-400   bg-red-500/10   border-red-500/20",
};

const severityDot: Record<string, string> = {
  info:     "bg-blue-400",
  success:  "bg-emerald-400",
  warning:  "bg-amber-400",
  critical: "bg-red-400",
};

export function InfraSOCFeed({ events }: Props) {
  const reversed = [...events].reverse();

  return (
    <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] h-full shadow-lg overflow-hidden flex flex-col">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-[var(--border-soft)]">
        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-widest">
          Intelligence SOC Feed
        </span>
        <span className="ml-auto text-[10px] text-[var(--text-muted)] font-mono">{events.length} events</span>
      </div>

      <div className="flex-1 overflow-y-auto font-mono text-[11px] divide-y divide-white/[0.03]">
        {reversed.length === 0 ? (
          <div className="py-10 text-center text-[var(--text-muted)] text-xs">Awaiting pipeline events...</div>
        ) : (
          reversed.map((ev) => (
            <div key={ev.id} className="flex items-start gap-3 px-4 py-2.5 hover:bg-[var(--bg-elevated)] transition-colors">
              <div className={`mt-0.5 w-1.5 h-1.5 rounded-full flex-shrink-0 ${severityDot[ev.severity] || "bg-[var(--bg-elevated)]"}`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${severityStyle[ev.severity] || ""}`}>
                    {ev.stage}
                  </span>
                  <span className="text-[9px] text-[var(--text-muted)] font-mono">
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-[var(--text-secondary)] mt-0.5 leading-snug">{ev.message}</p>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
