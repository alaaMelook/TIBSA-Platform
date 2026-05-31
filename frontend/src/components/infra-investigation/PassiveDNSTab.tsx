"use client";

import { InfraInvestigationResults } from "@/types/infra_investigation";
import { GitBranch, Clock, Minus } from "lucide-react";

interface Props {
  results: InfraInvestigationResults;
}

export function PassiveDNSTab({ results }: Props) {
  const pDNS = results.passive_dns;
  if (!pDNS || pDNS.error) return (
    <div className="py-20 text-center text-slate-600">
      <Minus className="w-6 h-6 mx-auto mb-2 opacity-40" />
      <p className="text-sm">Passive DNS data not yet available</p>
    </div>
  );

  const entries = pDNS.passive_dns || [];

  return (
    <div className="space-y-4">
      {/* Header bar */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-cyan-400" />
          <span className="text-sm font-bold text-white">Passive DNS History</span>
        </div>
        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
          {pDNS.count} records
        </span>
      </div>

      {entries.length === 0 ? (
        <div className="py-16 text-center">
          <Clock className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="text-sm text-slate-500">No passive DNS history found for this target</p>
        </div>
      ) : (
        <div className="bg-[#1e293b]/40 border border-white/[0.05] rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/[0.05] bg-slate-900/30 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                  <th className="px-4 py-3">Hostname</th>
                  <th className="px-4 py-3">IP Address</th>
                  <th className="px-4 py-3">ASN</th>
                  <th className="px-4 py-3">Country</th>
                  <th className="px-4 py-3">First Seen</th>
                  <th className="px-4 py-3">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.03]">
                {entries.map((entry, i) => (
                  <tr key={i} className="hover:bg-white/[0.02] transition-colors group">
                    <td className="px-4 py-3 font-mono text-xs text-slate-200 max-w-[220px] truncate">
                      {entry.hostname}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-cyan-400 font-semibold">
                      {entry.address}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {entry.asn || "—"}
                    </td>
                    <td className="px-4 py-3">
                      {entry.country_code ? (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 border border-white/[0.05] text-slate-300">
                          {entry.country_code}
                        </span>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-3 text-[11px] text-slate-500 font-mono">
                      {entry.first ? new Date(entry.first).toLocaleDateString() : "—"}
                    </td>
                    <td className="px-4 py-3 text-[11px] text-slate-400 font-mono">
                      {entry.last ? new Date(entry.last).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
