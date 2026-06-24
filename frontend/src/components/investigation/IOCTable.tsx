import { useState, Fragment } from "react";
import { IOCResult } from "@/types";
import { Card } from "@/components/ui";
import { ShieldCheck, ShieldAlert, Globe, Server, Code, ChevronDown, ChevronUp } from "lucide-react";

interface IOCTableProps {
  iocResults: IOCResult[];
}

export function IOCTable({ iocResults }: IOCTableProps) {
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  const getIndicatorIcon = (type: string) => {
    const size = "w-4 h-4 text-[#7C6F64]";
    if (type === "domain") return <Globe className={size} />;
    if (type === "ip") return <Server className={size} />;
    return <Code className={size} />; // JS resource
  };

  const getSourceBadge = (source: string) => {
    const common = "px-2 py-0.5 rounded text-[9px] font-extrabold uppercase border tracking-wider";
    const srcLower = source.toLowerCase();
    if (srcLower === "both" || srcLower.includes("+ otx")) {
      return (
        <span className={`${common} border-indigo-500/20 bg-indigo-500/5 text-indigo-600`}>
          VirusTotal + OTX Context
        </span>
      );
    }
    if (srcLower === "alienvault" || srcLower === "otx") {
      return (
        <span className={`${common} border-[#10B981]/20 bg-[#10B981]/5 text-[#10B981]`}>
          AlienVault OTX
        </span>
      );
    }
    return (
      <span className={`${common} border-[#2F80ED]/20 bg-[#2F80ED]/5 text-[#2F80ED]`}>
        {source}
      </span>
    );
  };

  const getThreatBadge = (level: string, flagged: boolean) => {
    const common = "px-2 py-0.5 rounded text-[10px] font-bold uppercase border";
    if (level === "malicious") {
      return (
        <span className={`${common} border-[#EF4444]/20 bg-[#EF4444]/10 text-[#EF4444] flex items-center gap-1 w-fit`}>
          <ShieldAlert className="w-3.5 h-3.5" />
          Malicious
        </span>
      );
    }
    if (level === "suspicious") {
      return (
        <span className={`${common} border-[#F97316]/20 bg-[#F97316]/10 text-[#F97316] flex items-center gap-1 w-fit`}>
          <ShieldAlert className="w-3.5 h-3.5" />
          Suspicious
        </span>
      );
    }
    if (level === "unknown") {
      return (
        <span className={`${common} border-[#9CA3AF]/20 bg-[#9CA3AF]/10 text-[#6B7280] flex items-center gap-1 w-fit`}>
          <ShieldAlert className="w-3.5 h-3.5" />
          Unknown
        </span>
      );
    }

    return (
      <span className={`${common} border-[#10B981]/20 bg-[#10B981]/10 text-[#10B981] flex items-center gap-1 w-fit`}>
        <ShieldCheck className="w-3.5 h-3.5" />
        Clean
      </span>
    );
  };

  const toggleRow = (idx: number) => {
    setExpandedRow(expandedRow === idx ? null : idx);
  };

  return (
    <div className="bg-white border border-[#E6DDD2] rounded-[20px] shadow-sm overflow-hidden">
      <div className="px-6 py-4 border-b border-[#E6DDD2] bg-[#FAF7F1] flex items-center justify-between">
        <h3 className="text-sm font-bold text-[#1F2933] uppercase tracking-wider">
          External Reputation Checks & IOCs
        </h3>
        <span className="text-xs text-[#7C6F64] font-medium">
          Source: VirusTotal & AlienVault OTX Enrichment
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm border-collapse">
          <thead>
            <tr className="bg-[#FAF7F1] text-[#7C6F64] font-medium border-b border-[#E6DDD2]">
              <th className="py-3 px-6 w-24">Type</th>
              <th className="py-3 px-6">Indicator Value</th>
              <th className="py-3 px-6 w-36">Sources</th>
              <th className="py-3 px-6 w-24 text-center">Score</th>
              <th className="py-3 px-6 w-36">Threat Status</th>
              <th className="py-3 px-6 w-12"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#E6DDD2]">
            {iocResults.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-[#7C6F64] font-medium">
                  No external domains or IP indicators discovered to perform reputation lookups.
                </td>
              </tr>
            ) : (
              iocResults.map((ioc, idx) => {
                const isThreat = ioc.flagged || ioc.threat_level === "malicious" || ioc.threat_level === "suspicious";
                const isExpanded = expandedRow === idx;

                return (
                  <Fragment key={ioc.value + idx}>
                    <tr
                      onClick={() => toggleRow(idx)}
                      className={`transition-colors hover:bg-[#FAF7F1] cursor-pointer select-none ${
                        isThreat ? "bg-[#EF4444]/5" : ""
                      } ${isExpanded ? "bg-[#FAF7F1]" : ""}`}
                    >
                      <td className="py-3.5 px-6">
                        <div className="flex items-center gap-2">
                          {getIndicatorIcon(ioc.indicator_type)}
                          <span className="text-xs text-[#7C6F64] font-bold uppercase tracking-wider">
                            {ioc.indicator_type}
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-6 font-mono text-xs text-[#1F2933] break-all font-semibold">
                        {ioc.value}
                      </td>
                      <td className="py-3.5 px-6">
                        {getSourceBadge(ioc.source || "virustotal")}
                      </td>
                      <td className="py-3.5 px-6 text-center font-mono font-bold">
                        <span className={ioc.threat_level === "unknown" ? "text-[#6B7280]" : (isThreat ? "text-[#EF4444]" : "text-[#10B981]")}>
                          {ioc.threat_level === "unknown" ? "N/A" : (ioc.reputation_score ? `${ioc.reputation_score}%` : "0%")}
                        </span>
                      </td>
                      <td className="py-3.5 px-6">
                        {getThreatBadge(ioc.threat_level, ioc.flagged)}
                      </td>
                      <td className="py-3.5 px-6 text-right">
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4 text-[#7C6F64]" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-[#7C6F64]" />
                        )}
                      </td>
                    </tr>

                    {isExpanded && (
                      <tr className="bg-[#FAF7F1]/50 border-t border-[#E6DDD2]">
                        <td colSpan={6} className="py-5 px-8">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 text-xs">
                            {/* Summary Column */}
                            <div className="space-y-4">
                              <div>
                                <h4 className="font-bold text-[#7C6F64] uppercase tracking-widest text-[9px] mb-1.5">
                                  Reputation Summary
                                </h4>
                                <p className="text-[#1F2933] leading-relaxed font-sans text-sm">
                                  {ioc.details?.risk_reason || "No detailed explanation returned from intelligence providers."}
                                </p>
                              </div>
                              {ioc.details?.recommended_action && (
                                <div>
                                  <h4 className="font-bold text-[#7C6F64] uppercase tracking-widest text-[9px] mb-1">
                                    Analyst Recommended Action
                                  </h4>
                                  <p className="text-[#10B981] font-sans font-bold leading-relaxed">
                                    {ioc.details.recommended_action}
                                  </p>
                                </div>
                              )}
                            </div>

                            {/* Threat Intelligence Pulses Column */}
                            <div className="space-y-4">
                              <div>
                                <h4 className="font-bold text-[#7C6F64] uppercase tracking-widest text-[9px] mb-1.5">
                                  AlienVault OTX Context
                                </h4>
                                {ioc.details?.otx_pulses && ioc.details.otx_pulses.length > 0 ? (
                                  <div className="space-y-2">
                                    <span className="text-[10px] text-[#7C6F64] font-bold uppercase tracking-wider block">
                                      Active Threat Pulses ({ioc.details.otx_pulses.length})
                                    </span>
                                    <ul className="list-disc list-inside text-[#1F2933] pl-1 space-y-1 font-sans">
                                      {ioc.details.otx_pulses.map((pulse: string, pIdx: number) => (
                                        <li key={pIdx} className="text-[#1F2933]">{pulse}</li>
                                      ))}
                                    </ul>
                                  </div>
                                ) : (
                                  <p className="text-[#7C6F64] italic font-sans">
                                    No associated AlienVault OTX pulses were found for this indicator.
                                  </p>
                                )}
                              </div>

                              {ioc.details?.threat_tags && ioc.details.threat_tags.length > 0 && (
                                <div>
                                  <h4 className="font-bold text-[#7C6F64] uppercase tracking-widest text-[9px] mb-1.5">
                                    Intelligence Tags
                                  </h4>
                                  <div className="flex flex-wrap gap-1">
                                    {ioc.details.threat_tags.map((tag: string, tIdx: number) => (
                                      <span
                                        key={tIdx}
                                        className="bg-white border border-[#10B981]/50 text-[#10B981] px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider"
                                      >
                                        {tag}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {ioc.details?.related_malware_families && ioc.details.related_malware_families.length > 0 && (
                                <div>
                                  <h4 className="font-bold text-[#EF4444] uppercase tracking-widest text-[9px] mb-1">
                                    Malware Families Linked
                                  </h4>
                                  <p className="text-[#EF4444] font-semibold font-mono">
                                    {ioc.details.related_malware_families.join(", ")}
                                  </p>
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
