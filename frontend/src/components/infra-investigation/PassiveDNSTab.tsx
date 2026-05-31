"use client";

import { InfraInvestigationResults } from "@/types/infra_investigation";
import { GitBranch } from "lucide-react";

interface Props {
  results: InfraInvestigationResults;
}

export function PassiveDNSTab({ results }: Props) {
  const pDNS = results.passive_dns;

  // ── Differentiated empty states ────────────────────────────────────────────
  if (!pDNS) {
    return <InfoState icon="🌐" title="Not Applicable" detail="Passive DNS is only available for domain and URL targets." />;
  }

  if (pDNS.error) {
    const isKeyMissing   = pDNS.error.toLowerCase().includes("key not configured");
    const isNotApplicable = pDNS.error.toLowerCase().includes("not applicable");
    if (isNotApplicable) {
      return <InfoState icon="🌐" title="Not Applicable" detail={pDNS.error} />;
    }
    if (isKeyMissing) {
      return (
        <InfoState
          icon="🔑"
          title="OTX API Key Not Configured"
          detail="Add your AlienVault OTX API key to the backend .env file as OTX_API_KEY= to enable passive DNS history lookups."
          isWarning
        />
      );
    }
    return <InfoState icon="⚠️" title="Passive DNS Error" detail={pDNS.error} isWarning />;
  }

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
        <InfoState icon="🕒" title="No Data Found" detail="No passive DNS history found for this target." />
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

function InfoState({
  icon,
  title,
  detail,
  isWarning = false,
}: {
  icon: string;
  title: string;
  detail: string;
  isWarning?: boolean;
}) {
  return (
    <div className="py-20 text-center flex flex-col items-center gap-3">
      <span className="text-3xl select-none">{icon}</span>
      <p className={`text-sm font-semibold ${isWarning ? "text-amber-400" : "text-slate-400"}`}>
        {title}
      </p>
      <p className="text-xs text-slate-500 max-w-xs leading-relaxed">{detail}</p>
    </div>
  );
}
