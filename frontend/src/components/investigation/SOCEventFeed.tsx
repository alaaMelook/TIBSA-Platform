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
        return <AlertTriangle className={`${sizeClass} text-[#EF4444]`} />;
      case "warning":
      case "medium":
        return <AlertTriangle className={`${sizeClass} text-[#F97316]`} />;
      case "success":
        return <CheckCircle className={`${sizeClass} text-[#10B981]`} />;
      case "info":
      default:
        return <Info className={`${sizeClass} text-[#2F80ED]`} />;
    }
  };

  const getEventBg = (severity: LiveEvent["severity"]) => {
    switch (severity) {
      case "critical":
      case "high":
        return "bg-[#EF4444]/5 border-[#EF4444]/20 text-[#1F2933]";
      case "warning":
      case "medium":
        return "bg-[#F97316]/5 border-[#F97316]/20 text-[#1F2933]";
      case "success":
        return "bg-[#10B981]/5 border-[#10B981]/20 text-[#1F2933]";
      case "info":
      default:
        return "bg-[#2F80ED]/5 border-[#2F80ED]/20 text-[#1F2933]";
    }
  };

  return (
    <div className="flex flex-col h-full bg-white rounded-[20px] border border-[#E6DDD2] shadow-sm overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#E6DDD2] bg-[#FAF7F1]">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-[#10B981] animate-pulse" />
          <span className="text-xs font-bold text-[#1F2933] uppercase tracking-widest">
            SOC Live Stream
          </span>
        </div>
        <span className="text-[10px] bg-white border border-[#E6DDD2] text-[#7C6F64] px-2 py-0.5 rounded-md font-mono font-semibold">
          {events.length} logs
        </span>
      </div>

      {/* Log Feed */}
      <div 
        ref={logContainerRef}
        className="flex-1 p-4 overflow-y-auto font-mono text-xs space-y-2.5 max-h-[260px]"
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-[#7C6F64] py-12">
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
                className={`flex items-start gap-2.5 p-2.5 rounded-lg border transition-all duration-200 hover:brightness-95 ${getEventBg(
                  evt.severity
                )}`}
              >
                {/* Time stamp */}
                <span className="text-[#7C6F64] font-semibold select-none flex-shrink-0">
                  [{timeStr}]
                </span>

                {/* Tag label */}
                <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-white border border-[#E6DDD2] text-[#7C6F64] flex-shrink-0">
                  {evt.stage}
                </span>

                {/* Message */}
                <div className="flex-1 flex items-center gap-1.5 leading-relaxed font-sans font-medium text-[#1F2933]">
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
