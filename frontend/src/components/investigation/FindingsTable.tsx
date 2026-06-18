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
          <span className={`${commonStyles} border-red-950 bg-red-950/40 text-red-500 flex items-center gap-1 w-fit`}>
            <ShieldAlert className="w-3.5 h-3.5" />
            Critical
          </span>
        );
      case "high":
        return (
          <span className={`${commonStyles} border-red-800 bg-red-900/20 text-red-400 flex items-center gap-1 w-fit`}>
            <AlertCircle className="w-3.5 h-3.5" />
            High
          </span>
        );
      case "medium":
        return (
          <span className={`${commonStyles} border-orange-800 bg-orange-900/10 text-orange-400 flex items-center gap-1 w-fit`}>
            <AlertTriangle className="w-3.5 h-3.5" />
            Medium
          </span>
        );
      case "low":
        return (
          <span className={`${commonStyles} border-yellow-800 bg-yellow-900/10 text-yellow-400 flex items-center gap-1 w-fit`}>
            <AlertTriangle className="w-3.5 h-3.5" />
            Low
          </span>
        );
      case "info":
      default:
        return (
          <span className={`${commonStyles} border-blue-900 bg-blue-950/20 text-[var(--primary)] flex items-center gap-1 w-fit`}>
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
              ? "bg-red-950/30 border-red-500/30 text-red-400 hover:bg-red-950/50"
              : sev === "high"
              ? "bg-red-900/20 border-red-500/20 text-red-400 hover:bg-red-900/30"
              : sev === "medium"
              ? "bg-orange-950/20 border-orange-500/20 text-orange-400 hover:bg-orange-950/30"
              : sev === "low"
              ? "bg-yellow-950/20 border-yellow-500/20 text-yellow-400 hover:bg-yellow-950/30"
              : "bg-blue-950/20 border-[var(--primary)] text-[var(--primary)] hover:bg-blue-950/30";

          return (
            <button
              key={sev}
              onClick={() => setFilterSeverity(active ? "all" : sev)}
              className={`p-3 rounded-xl border text-center transition-all cursor-pointer ${bgClass} ${
                active ? "ring-2 ring-blue-500 border-transparent shadow-lg" : ""
              }`}
            >
              <div className="text-xs uppercase font-bold tracking-widest">{sev}</div>
              <div className="text-2xl font-extrabold mt-1">{count}</div>
            </button>
          );
        })}
      </div>

      {/* Main Table */}
      <Card className="overflow-hidden !p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="bg-[var(--bg-card)]/40 text-[var(--text-muted)] font-medium border-b border-[var(--border-strong)]">
                <th className="py-3.5 px-4 w-10"></th>
                <th className="py-3.5 px-4 w-32">Severity</th>
                <th className="py-3.5 px-4">Finding Details</th>
                <th className="py-3.5 px-4">Affected URL</th>
                <th className="py-3.5 px-4 w-40">Category</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.06]">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-[var(--text-muted)] font-medium">
                    No findings matches the selected filter.
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
                        className="hover:bg-[var(--bg-elevated)] cursor-pointer transition-colors"
                      >
                        <td className="py-4 px-4 text-center">
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 text-[var(--text-muted)]" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-[var(--text-muted)]" />
                          )}
                        </td>
                        <td className="py-4 px-4">{getSeverityBadge(finding.severity)}</td>
                        <td className="py-4 px-4 font-semibold text-[var(--text-muted)]">{finding.title}</td>
                        <td className="py-4 px-4 text-[var(--text-muted)] font-mono text-xs max-w-xs truncate">
                          {finding.affected_url}
                        </td>
                        <td className="py-4 px-4">
                          <span className="text-[10px] bg-[var(--bg-card)] border border-[var(--border-soft)] text-[var(--text-secondary)] font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                            {finding.category || "General"}
                          </span>
                        </td>
                      </tr>

                      {/* Row Details Drawer */}
                      {isExpanded && (
                        <tr className="bg-[var(--bg-page)]/20">
                          <td colSpan={5} className="p-4 border-t border-[var(--border-soft)] text-[var(--text-secondary)]">
                            <div className="space-y-3 font-sans text-xs">
                              {/* Evidence */}
                              {finding.evidence && (
                                <div className="space-y-1">
                                  <span className="text-[10px] font-bold uppercase text-[var(--text-muted)] tracking-wider">
                                    Evidence Details
                                  </span>
                                  <pre className="bg-[var(--bg-page)]/80 p-3 rounded-lg border border-[var(--border-strong)] font-mono text-[var(--text-secondary)] overflow-x-auto max-w-full">
                                    {finding.evidence}
                                  </pre>
                                </div>
                              )}

                              {/* Tags */}
                              {finding.tags && finding.tags.length > 0 && (
                                <div className="flex flex-wrap items-center gap-2 mt-2">
                                  <Tag className="w-3.5 h-3.5 text-[var(--text-muted)]" />
                                  {finding.tags.map((tag) => (
                                    <span
                                      key={tag}
                                      className="px-2 py-0.5 bg-[var(--bg-elevated)] text-[var(--text-muted)] rounded-full text-[10px] font-medium"
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
      </Card>
    </div>
  );
}
