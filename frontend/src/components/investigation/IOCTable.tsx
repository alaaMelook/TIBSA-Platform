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
    const size = "w-4 h-4 text-slate-400";
    if (type === "domain") return <Globe className={size} />;
    if (type === "ip") return <Server className={size} />;
    return <Code className={size} />; // JS resource
  };

  const getSourceBadge = (source: string) => {
    const common = "px-2 py-0.5 rounded text-[9px] font-extrabold uppercase border tracking-wider";
    if (source === "both") {
      return (
        <span className={`${common} border-indigo-500/20 bg-indigo-500/10 text-indigo-400`}>
          Both VT & OTX
        </span>
      );
    }
    if (source === "alienvault") {
      return (
        <span className={`${common} border-purple-500/20 bg-purple-500/10 text-purple-400`}>
          AlienVault OTX
        </span>
      );
    }
    return (
      <span className={`${common} border-blue-500/20 bg-blue-500/10 text-blue-400`}>
        VirusTotal
      </span>
    );
  };

  const getThreatBadge = (level: string, flagged: boolean) => {
    const common = "px-2 py-0.5 rounded text-[10px] font-bold uppercase border";
    if (level === "malicious" || flagged) {
      return (
        <span className={`${common} border-red-500/20 bg-red-500/10 text-red-400 flex items-center gap-1 w-fit`}>
          <ShieldAlert className="w-3.5 h-3.5" />
          Malicious
        </span>
      );
    }
    if (level === "suspicious") {
      return (
        <span className={`${common} border-orange-500/20 bg-orange-500/10 text-orange-400 flex items-center gap-1 w-fit`}>
          <ShieldAlert className="w-3.5 h-3.5" />
          Suspicious
        </span>
      );
    }
    return (
      <span className={`${common} border-emerald-500/20 bg-emerald-500/10 text-emerald-400 flex items-center gap-1 w-fit`}>
        <ShieldCheck className="w-3.5 h-3.5" />
        Clean
      </span>
    );
  };

  const toggleRow = (idx: number) => {
    setExpandedRow(expandedRow === idx ? null : idx);
  };

  return (
    <Card className="!p-0 overflow-hidden">
      <div className="px-6 py-4 border-b border-white/[0.06] bg-slate-900/20 flex items-center justify-between">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider">
          External Reputation Checks & IOCs
        </h3>
        <span className="text-xs text-slate-400 font-medium">
          Source: VirusTotal & AlienVault OTX Enrichment
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm border-collapse">
          <thead>
            <tr className="bg-slate-950/20 text-slate-400 font-medium border-b border-white/[0.06]">
              <th className="py-3 px-6 w-24">Type</th>
              <th className="py-3 px-6">Indicator Value</th>
              <th className="py-3 px-6 w-36">Sources</th>
              <th className="py-3 px-6 w-24 text-center">Score</th>
              <th className="py-3 px-6 w-36">Threat Status</th>
              <th className="py-3 px-6 w-12"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.06]">
            {iocResults.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-slate-500 font-medium">
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
                      className={`transition-colors hover:bg-white/[0.02] cursor-pointer select-none ${
                        isThreat ? "bg-red-500/[0.02]" : ""
                      } ${isExpanded ? "bg-white/[0.01]" : ""}`}
                    >
                      <td className="py-3.5 px-6">
                        <div className="flex items-center gap-2">
                          {getIndicatorIcon(ioc.indicator_type)}
                          <span className="text-xs text-slate-400 font-bold uppercase tracking-wider">
                            {ioc.indicator_type}
                          </span>
                        </div>
                      </td>
                      <td className="py-3.5 px-6 font-mono text-xs text-slate-300 break-all">
                        {ioc.value}
                      </td>
                      <td className="py-3.5 px-6">
                        {getSourceBadge(ioc.source || "virustotal")}
                      </td>
                      <td className="py-3.5 px-6 text-center font-mono font-bold">
                        <span className={isThreat ? "text-red-400" : "text-emerald-400"}>
                          {ioc.reputation_score ? `${ioc.reputation_score}%` : "0%"}
                        </span>
                      </td>
                      <td className="py-3.5 px-6">
                        {getThreatBadge(ioc.threat_level, ioc.flagged)}
                      </td>
                      <td className="py-3.5 px-6 text-right">
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4 text-slate-500" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-slate-500" />
                        )}
                      </td>
                    </tr>

                    {isExpanded && (
                      <tr className="bg-slate-950/30">
                        <td colSpan={6} className="py-5 px-8 border-t border-white/[0.04]">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 text-xs">
                            {/* Summary Column */}
                            <div className="space-y-4">
                              <div>
                                <h4 className="font-bold text-slate-500 uppercase tracking-widest text-[9px] mb-1.5">
                                  Reputation Summary
                                </h4>
                                <p className="text-slate-300 leading-relaxed font-sans text-sm">
                                  {ioc.details?.risk_reason || "No detailed explanation returned from intelligence providers."}
                                </p>
                              </div>
                              {ioc.details?.recommended_action && (
                                <div>
                                  <h4 className="font-bold text-slate-500 uppercase tracking-widest text-[9px] mb-1">
                                    Analyst Recommended Action
                                  </h4>
                                  <p className="text-blue-400 font-sans leading-relaxed">
                                    {ioc.details.recommended_action}
                                  </p>
                                </div>
                              )}
                            </div>

                            {/* Threat Intelligence Pulses Column */}
                            <div className="space-y-4">
                              <div>
                                <h4 className="font-bold text-slate-500 uppercase tracking-widest text-[9px] mb-1.5">
                                  AlienVault OTX Context
                                </h4>
                                {ioc.details?.otx_pulses && ioc.details.otx_pulses.length > 0 ? (
                                  <div className="space-y-2">
                                    <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider block">
                                      Active Threat Pulses ({ioc.details.otx_pulses.length})
                                    </span>
                                    <ul className="list-disc list-inside text-slate-300 pl-1 space-y-1 font-sans">
                                      {ioc.details.otx_pulses.map((pulse: string, pIdx: number) => (
                                        <li key={pIdx} className="text-slate-200">{pulse}</li>
                                      ))}
                                    </ul>
                                  </div>
                                ) : (
                                  <p className="text-slate-500 italic font-sans">
                                    No associated AlienVault OTX pulses were found for this indicator.
                                  </p>
                                )}
                              </div>

                              {ioc.details?.threat_tags && ioc.details.threat_tags.length > 0 && (
                                <div>
                                  <h4 className="font-bold text-slate-500 uppercase tracking-widest text-[9px] mb-1.5">
                                    Intelligence Tags
                                  </h4>
                                  <div className="flex flex-wrap gap-1">
                                    {ioc.details.threat_tags.map((tag: string, tIdx: number) => (
                                      <span
                                        key={tIdx}
                                        className="bg-purple-500/10 border border-purple-500/20 text-purple-400 px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider"
                                      >
                                        {tag}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {ioc.details?.related_malware_families && ioc.details.related_malware_families.length > 0 && (
                                <div>
                                  <h4 className="font-bold text-red-500/80 uppercase tracking-widest text-[9px] mb-1">
                                    Malware Families Linked
                                  </h4>
                                  <p className="text-red-400 font-semibold font-mono">
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
    </Card>
  );
}
