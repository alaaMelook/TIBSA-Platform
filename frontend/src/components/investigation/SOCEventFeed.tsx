import { useEffect, useRef } from "react";
import { LiveEvent } from "@/types";
import { Shield, AlertTriangle, CheckCircle, Info, Terminal } from "lucide-react";

interface SOCEventFeedProps {
  events: LiveEvent[];
}

export function SOCEventFeed({ events }: SOCEventFeedProps) {
  const logContainerRef = useRef<HTMLDivElement | null>(null);

  // Scroll to bottom of log feed when events update
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [events]);

  const getEventIcon = (severity: LiveEvent["severity"]) => {
    const sizeClass = "w-3.5 h-3.5";
    switch (severity) {
      case "critical":
      case "high":
        return <AlertTriangle className={`${sizeClass} text-red-400`} />;
      case "warning":
      case "medium":
        return <AlertTriangle className={`${sizeClass} text-orange-400`} />;
      case "success":
        return <CheckCircle className={`${sizeClass} text-emerald-400`} />;
      case "info":
      default:
        return <Info className={`${sizeClass} text-blue-400`} />;
    }
  };

  const getEventBg = (severity: LiveEvent["severity"]) => {
    switch (severity) {
      case "critical":
      case "high":
        return "bg-red-500/10 border-red-500/20 text-red-200";
      case "warning":
      case "medium":
        return "bg-orange-500/10 border-orange-500/20 text-orange-200";
      case "success":
        return "bg-emerald-500/10 border-emerald-500/20 text-emerald-200";
      case "info":
      default:
        return "bg-blue-500/10 border-blue-500/20 text-blue-200";
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-950/70 rounded-xl border border-white/[0.06] shadow-inner">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06] bg-slate-900/40">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-blue-400 animate-pulse" />
          <span className="text-xs font-bold text-slate-300 uppercase tracking-widest">
            SOC Live Stream
          </span>
        </div>
        <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono">
          {events.length} logs
        </span>
      </div>

      {/* Log Feed */}
      <div 
        ref={logContainerRef}
        className="flex-1 p-4 overflow-y-auto font-mono text-xs space-y-2.5 max-h-[260px]"
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-600 py-12">
            <Shield className="w-8 h-8 mb-2 opacity-20" />
            <p className="text-[11px] uppercase tracking-wider">Awaiting pipeline trigger...</p>
          </div>
        ) : (
          events.map((evt, idx) => {
            const timeStr = new Date(evt.timestamp).toLocaleTimeString([], {
              hour12: false,
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit"
            });

            return (
              <div
                key={evt.id + idx}
                className={`flex items-start gap-2.5 p-2 rounded border transition-all duration-200 hover:bg-slate-900/50 ${getEventBg(
                  evt.severity
                )}`}
              >
                {/* Time stamp */}
                <span className="text-slate-500 font-semibold select-none flex-shrink-0">
                  [{timeStr}]
                </span>

                {/* Tag label */}
                <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-900/60 border border-white/[0.04] text-slate-400 flex-shrink-0">
                  {evt.stage}
                </span>

                {/* Message */}
                <div className="flex-1 flex items-center gap-1.5 leading-relaxed">
                  {getEventIcon(evt.severity)}
                  <span className="break-all">{evt.message}</span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
