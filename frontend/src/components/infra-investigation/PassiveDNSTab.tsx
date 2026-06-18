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
    const isKeyMissing    = pDNS.error.toLowerCase().includes("key not configured");
    const isNotApplicable = pDNS.error.toLowerCase().includes("not applicable");
    const isTimeout       = pDNS.error.toLowerCase().includes("timed out") ||
                            pDNS.error.toLowerCase().includes("timeout");

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
    if (isTimeout) {
      return (
        <InfoState
          icon="⏱️"
          title="OTX Passive DNS Timed Out"
          detail="The AlienVault OTX passive_dns endpoint did not respond in time. This endpoint is sometimes slow or restricted from certain networks. Try using a VPN or re-running the investigation."
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
          <span className="text-sm font-bold text-[var(--text-primary)]">Passive DNS History</span>
        </div>
        <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
          {pDNS.count} records
        </span>
      </div>

      {entries.length === 0 ? (
        <InfoState icon="🕒" title="No Data Found" detail="No passive DNS history found for this target." />
      ) : (
        <div className="bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[var(--border-soft)] bg-[var(--bg-card)]/30 text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
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
                  <tr key={i} className="hover:bg-[var(--bg-elevated)] transition-colors group">
                    <td className="px-4 py-3 font-mono text-xs text-[var(--text-primary)] max-w-[220px] truncate">
                      {entry.hostname}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-cyan-400 font-semibold">
                      {entry.address}
                    </td>
                    <td className="px-4 py-3 text-xs text-[var(--text-muted)]">
                      {entry.asn || "—"}
                    </td>
                    <td className="px-4 py-3">
                      {entry.country_code ? (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] border border-[var(--border-soft)] text-[var(--text-secondary)]">
                          {entry.country_code}
                        </span>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-3 text-[11px] text-[var(--text-muted)] font-mono">
                      {entry.first ? new Date(entry.first).toLocaleDateString() : "—"}
                    </td>
                    <td className="px-4 py-3 text-[11px] text-[var(--text-muted)] font-mono">
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
      <p className={`text-sm font-semibold ${isWarning ? "text-amber-400" : "text-[var(--text-muted)]"}`}>
        {title}
      </p>
      <p className="text-xs text-[var(--text-muted)] max-w-xs leading-relaxed">{detail}</p>
    </div>
  );
}
