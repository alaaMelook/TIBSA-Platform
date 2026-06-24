import React, { useState } from "react";
import { StructuredFinding } from "@/types";
import { Card } from "@/components/ui";
import { ChevronDown, ChevronUp, AlertCircle, ShieldAlert, AlertTriangle, Info, Tag } from "lucide-react";

interface FindingsTableProps {
  findings: StructuredFinding[];
}

export function FindingsTable({ findings }: FindingsTableProps) {
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});
  const [filterSeverity, setFilterSeverity] = useState<string>("all");

  const toggleRow = (id: string) => {
    setExpandedRows((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const getSeverityBadge = (severity: string) => {
    const norm = severity.toLowerCase();
    const commonStyles = "px-2.5 py-0.5 rounded-full text-xs font-bold uppercase border";
    
    switch (norm) {
      case "critical":
        return (
          <span className={`${commonStyles} border-[#EF4444]/20 bg-[#EF4444]/10 text-[#EF4444] flex items-center gap-1 w-fit`}>
            <ShieldAlert className="w-3.5 h-3.5" />
            Critical
          </span>
        );
      case "high":
        return (
          <span className={`${commonStyles} border-[#EF4444]/20 bg-[#EF4444]/10 text-[#EF4444] flex items-center gap-1 w-fit`}>
            <AlertCircle className="w-3.5 h-3.5" />
            High
          </span>
        );
      case "medium":
        return (
          <span className={`${commonStyles} border-[#F97316]/20 bg-[#F97316]/10 text-[#F97316] flex items-center gap-1 w-fit`}>
            <AlertTriangle className="w-3.5 h-3.5" />
            Medium
          </span>
        );
      case "low":
        return (
          <span className={`${commonStyles} border-yellow-500/20 bg-yellow-500/10 text-yellow-600 flex items-center gap-1 w-fit`}>
            <AlertTriangle className="w-3.5 h-3.5" />
            Low
          </span>
        );
      case "info":
      default:
        return (
          <span className={`${commonStyles} border-[#2F80ED]/20 bg-[#2F80ED]/5 text-[#2F80ED] flex items-center gap-1 w-fit`}>
            <Info className="w-3.5 h-3.5" />
            Info
          </span>
        );
    }
  };

  // Severity counts
  const counts = {
    critical: findings.filter(f => f.severity.toLowerCase() === "critical").length,
    high: findings.filter(f => f.severity.toLowerCase() === "high").length,
    medium: findings.filter(f => f.severity.toLowerCase() === "medium").length,
    low: findings.filter(f => f.severity.toLowerCase() === "low").length,
    info: findings.filter(f => f.severity.toLowerCase() === "info").length,
  };

  const filteredFindings = findings.filter(
    (f) => filterSeverity === "all" || f.severity.toLowerCase() === filterSeverity
  );

  return (
    <div className="space-y-4">
      {/* Counts Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
          const count = counts[sev];
          const active = filterSeverity === sev;
          const bgClass =
            sev === "critical"
              ? "bg-[#EF4444]/5 border-[#EF4444]/20 text-[#EF4444] hover:bg-[#EF4444]/10"
              : sev === "high"
              ? "bg-orange-600/5 border-orange-600/20 text-orange-600 hover:bg-orange-600/10"
              : sev === "medium"
              ? "bg-[#F97316]/5 border-[#F97316]/20 text-[#F97316] hover:bg-[#F97316]/10"
              : sev === "low"
              ? "bg-yellow-500/5 border-yellow-500/20 text-yellow-600 hover:bg-yellow-500/10"
              : "bg-[#2F80ED]/5 border-[#2F80ED]/20 text-[#2F80ED] hover:bg-[#2F80ED]/10";

          return (
            <button
              key={sev}
              onClick={() => setFilterSeverity(active ? "all" : sev)}
              className={`p-3 rounded-xl border text-center transition-all cursor-pointer ${bgClass} ${
                active ? "ring-2 ring-[#10B981] border-transparent shadow-sm" : ""
              }`}
            >
              <div className="text-xs uppercase font-bold tracking-widest">{sev}</div>
              <div className="text-2xl font-extrabold mt-1">{count}</div>
            </button>
          );
        })}
      </div>

      {/* Main Table */}
      <div className="bg-white border border-[#E6DDD2] rounded-[20px] shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="bg-[#FAF7F1] text-[#7C6F64] font-medium border-b border-[#E6DDD2]">
                <th className="py-3.5 px-4 w-10"></th>
                <th className="py-3.5 px-4 w-32">Severity</th>
                <th className="py-3.5 px-4">Finding Details</th>
                <th className="py-3.5 px-4">Affected URL</th>
                <th className="py-3.5 px-4 w-40">Category</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E6DDD2]">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-[#7C6F64] font-medium">
                    No findings match the selected filter.
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding, idx) => {
                  const fid = finding.id || finding.finding_id || `finding-${idx}`;
                  const isExpanded = !!expandedRows[fid];
                  return (
                    <React.Fragment key={fid}>
                      {/* Row Header */}
                      <tr
                        onClick={() => toggleRow(fid)}
                        className="hover:bg-[#FAF7F1] cursor-pointer transition-colors"
                      >
                        <td className="py-4 px-4 text-center">
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 text-[#7C6F64]" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-[#7C6F64]" />
                          )}
                        </td>
                        <td className="py-4 px-4">{getSeverityBadge(finding.severity)}</td>
                        <td className="py-4 px-4 font-semibold text-[#1F2933]">{finding.title}</td>
                        <td className="py-4 px-4 text-[#7C6F64] font-mono text-xs max-w-xs truncate">
                          {finding.affected_url}
                        </td>
                        <td className="py-4 px-4">
                          <span className="text-[10px] bg-white border border-[#E6DDD2] text-[#7C6F64] font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                            {finding.category || "General"}
                          </span>
                        </td>
                      </tr>

                      {/* Row Details Drawer */}
                      {isExpanded && (
                        <tr className="bg-[#FAF7F1]/50">
                          <td colSpan={5} className="p-4 border-t border-[#E6DDD2] text-[#1F2933]">
                            <div className="space-y-3 font-sans text-xs">
                              {/* Evidence */}
                              {finding.evidence && (
                                <div className="space-y-1">
                                  <span className="text-[10px] font-bold uppercase text-[#7C6F64] tracking-wider">
                                    Evidence Details
                                  </span>
                                  <pre className="bg-white p-3 rounded-lg border border-[#E6DDD2] font-mono text-[#1F2933] overflow-x-auto max-w-full shadow-sm">
                                    {finding.evidence}
                                  </pre>
                                </div>
                              )}

                              {/* Tags */}
                              {finding.tags && finding.tags.length > 0 && (
                                <div className="flex flex-wrap items-center gap-2 mt-2">
                                  <Tag className="w-3.5 h-3.5 text-[#7C6F64]" />
                                  {finding.tags.map((tag) => (
                                    <span
                                      key={tag}
                                      className="px-2 py-0.5 bg-white border border-[#E6DDD2] text-[#7C6F64] rounded-full text-[10px] font-medium"
                                    >
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
