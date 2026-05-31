"use client";

import { InfraInvestigationResults } from "@/types/infra_investigation";
import { ShieldAlert, Globe, AlertCircle, CheckCircle } from "lucide-react";

interface Props {
  results: InfraInvestigationResults;
}

// ── Shared primitives ─────────────────────────────────────────────────────────

function RatioBar({ value, max = 100, color = "#3b82f6" }: { value: number; max?: number; color?: string }) {
  const pct = Math.min(100, Math.round((value / max) * 100));
  return (
    <div className="h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: color }} />
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-200 font-medium">{value}</span>
    </div>
  );
}

function FeedCard({
  title, icon, badge, children,
}: {
  title: string;
  icon: React.ReactNode;
  badge?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-[#1e293b]/60 border border-white/[0.06] rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.04]">
        <div className="flex items-center gap-2">
          {icon}
          <span className="text-xs font-bold text-slate-200">{title}</span>
        </div>
        {badge}
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  const isKey = message.toLowerCase().includes("key not configured") ||
                message.toLowerCase().includes("api key");
  return (
    <div className={`flex items-start gap-2 text-xs rounded-lg p-3 border ${
      isKey
        ? "text-amber-400 bg-amber-500/5 border-amber-500/15"
        : "text-slate-500 bg-slate-900/30 border-white/[0.04]"
    }`}>
      <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
      <span>{isKey ? "API key not configured — add it to backend .env" : message}</span>
    </div>
  );
}

function NotApplicable({ reason }: { reason: string }) {
  return (
    <p className="text-xs text-slate-600 italic">{reason}</p>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function ReputationFeedTab({ results }: Props) {
  const r = results.reputation;
  const targetType = results.target_type;

  // reputation object itself missing = pipeline didn't run stage 2 yet
  if (!r) {
    return (
      <div className="py-20 text-center text-slate-600">
        <ShieldAlert className="w-6 h-6 mx-auto mb-2 opacity-30" />
        <p className="text-sm">Reputation data not yet available</p>
      </div>
    );
  }

  const abuse   = r.abuseipdb;
  const urlhaus = r.urlhaus;
  const tfox    = r.threatfox;
  const otx     = r.otx;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

      {/* ── AbuseIPDB ───────────────────────────────────────────────────────── */}
      <FeedCard
        title="AbuseIPDB"
        icon={<ShieldAlert className="w-4 h-4 text-orange-400" />}
        badge={
          abuse && !abuse.error ? (
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
              abuse.abuse_confidence_score > 60
                ? "text-red-400 bg-red-500/10 border-red-500/20"
                : abuse.abuse_confidence_score > 20
                ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
                : "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
            }`}>{abuse.abuse_confidence_score}% confidence</span>
          ) : abuse?.error ? (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border text-slate-500 bg-slate-800 border-slate-700">Error</span>
          ) : (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border text-slate-600 bg-slate-800/50 border-slate-700/50">N/A</span>
          )
        }
      >
        {!abuse ? (
          <NotApplicable reason="AbuseIPDB only applies to IP address targets." />
        ) : abuse.error ? (
          <ErrorState message={abuse.error} />
        ) : (
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-400">Abuse Confidence</span>
                <span className="font-bold text-white">{abuse.abuse_confidence_score}%</span>
              </div>
              <RatioBar value={abuse.abuse_confidence_score} color={
                abuse.abuse_confidence_score > 60 ? "#ef4444" :
                abuse.abuse_confidence_score > 20 ? "#f59e0b" : "#10b981"
              } />
            </div>
            <Row label="Country"       value={abuse.country_code || "Unknown"} />
            <Row label="ISP"           value={abuse.isp || "—"} />
            <Row label="Domain"        value={abuse.domain || "—"} />
            <Row label="Total Reports" value={String(abuse.total_reports)} />
            <Row label="Last Reported" value={abuse.last_reported_at ? new Date(abuse.last_reported_at).toLocaleDateString() : "—"} />
          </div>
        )}
      </FeedCard>

      {/* ── URLhaus ─────────────────────────────────────────────────────────── */}
      <FeedCard
        title="URLhaus"
        icon={<Globe className="w-4 h-4 text-blue-400" />}
        badge={
          !urlhaus ? (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border text-slate-600 bg-slate-800/50 border-slate-700/50">N/A</span>
          ) : urlhaus && !urlhaus.error ? (
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
              urlhaus.query_status === "is_host" || urlhaus.query_status === "is_listed"
                ? "text-red-400 bg-red-500/10 border-red-500/20"
                : "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
            }`}>
              {urlhaus.query_status === "is_host" || urlhaus.query_status === "is_listed" ? "LISTED" : "CLEAN"}
            </span>
          ) : urlhaus?.error ? (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border text-slate-500 bg-slate-800 border-slate-700">Error</span>
          ) : null
        }
      >
        {!urlhaus ? (
          <NotApplicable reason="URLhaus does not support hash lookups — only IPs, domains, and URLs." />
        ) : urlhaus.error ? (
          <ErrorState message={urlhaus.error} />
        ) : urlhaus.query_status === "is_host" || urlhaus.query_status === "is_listed" ? (
          <div className="space-y-2">
            {urlhaus.urls_on_this_host?.slice(0, 5).map((u, i) => (
              <div key={i} className="flex justify-between text-xs border-b border-white/[0.04] pb-2">
                <span className="text-slate-400 truncate max-w-[200px]">{u.url}</span>
                <span className="text-red-400 font-bold ml-2 flex-shrink-0">{u.threat}</span>
              </div>
            ))}
            {(urlhaus.urls_on_this_host?.length ?? 0) === 0 && (
              <p className="text-slate-500 text-xs">Listed but no URL details returned.</p>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2 text-emerald-400 text-sm">
            <CheckCircle className="w-4 h-4" /> Not found in URLhaus database
          </div>
        )}
      </FeedCard>

      {/* ── ThreatFox ───────────────────────────────────────────────────────── */}
      <FeedCard
        title="ThreatFox IOCs"
        icon={<AlertCircle className="w-4 h-4 text-purple-400" />}
        badge={
          tfox && !tfox.error ? (
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
              (tfox.iocs?.length ?? 0) > 0
                ? "text-red-400 bg-red-500/10 border-red-500/20"
                : "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
            }`}>{tfox.iocs?.length ?? 0} IOCs</span>
          ) : tfox?.error ? (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border text-slate-500 bg-slate-800 border-slate-700">Error</span>
          ) : null
        }
      >
        {!tfox ? (
          <NotApplicable reason="ThreatFox data unavailable." />
        ) : tfox.error ? (
          <ErrorState message={tfox.error} />
        ) : (tfox.iocs?.length ?? 0) > 0 ? (
          <div className="space-y-2">
            {tfox.iocs?.slice(0, 4).map((ioc, i) => (
              <div key={i} className="bg-slate-900/40 rounded-lg p-2.5 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200">{ioc.malware_printable}</span>
                  <span className="text-[10px] text-purple-400 font-bold">{ioc.confidence_level}%</span>
                </div>
                <div className="flex gap-2 text-[10px] text-slate-500">
                  <span>{ioc.threat_type}</span>
                  <span>·</span>
                  <span>{ioc.ioc_type}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-2 text-emerald-400 text-sm">
            <CheckCircle className="w-4 h-4" /> No ThreatFox IOC matches
          </div>
        )}
      </FeedCard>

      {/* ── AlienVault OTX ──────────────────────────────────────────────────── */}
      <FeedCard
        title="AlienVault OTX"
        icon={<ShieldAlert className="w-4 h-4 text-cyan-400" />}
        badge={
          !otx ? (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border text-slate-600 bg-slate-800/50 border-slate-700/50">N/A</span>
          ) : otx && !otx.error ? (
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
              otx.pulse_count > 0
                ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
                : "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
            }`}>{otx.pulse_count} pulses</span>
          ) : otx?.error ? (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border text-slate-500 bg-slate-800 border-slate-700">Error</span>
          ) : (
            <span className="text-[10px] font-bold px-2 py-0.5 rounded border text-slate-600 bg-slate-800/50 border-slate-700/50">N/A</span>
          )
        }
      >
        {!otx ? (
          <NotApplicable reason="AlienVault OTX pulse lookup is only available for IPs, domains, and URLs — not hash values." />
        ) : otx.error ? (
          <ErrorState message={otx.error} />
        ) : otx.pulse_count > 0 ? (
          <div className="space-y-2">
            {otx.pulses.slice(0, 3).map((p, i) => (
              <div key={i} className="bg-slate-900/40 rounded-lg p-2.5">
                <p className="text-xs font-semibold text-slate-200 mb-1">{p.name}</p>
                <div className="flex flex-wrap gap-1">
                  {p.tags.slice(0, 4).map((tag: string, j: number) => (
                    <span key={j} className="text-[9px] bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded font-bold">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-2 text-emerald-400 text-sm">
            <CheckCircle className="w-4 h-4" /> No OTX threat pulses found
          </div>
        )}
      </FeedCard>

    </div>
  );
}
