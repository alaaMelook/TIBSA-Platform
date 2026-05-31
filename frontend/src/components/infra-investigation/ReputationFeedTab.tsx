"use client";

import { InfraInvestigationResults } from "@/types/infra_investigation";
import { ShieldAlert, Globe, AlertCircle, CheckCircle, Minus } from "lucide-react";

interface Props {
  results: InfraInvestigationResults;
}

function RatioBar({ value, max = 100, color = "#3b82f6" }: { value: number; max?: number; color?: string }) {
  const pct = Math.min(100, Math.round((value / max) * 100));
  return (
    <div className="h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: color }} />
    </div>
  );
}

export function ReputationFeedTab({ results }: Props) {
  const r = results.reputation;
  if (!r) return <Empty />;

  const abuse   = r.abuseipdb;
  const urlhaus = r.urlhaus;
  const tfox    = r.threatfox;
  const otx     = r.otx;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

      {/* AbuseIPDB */}
      {abuse && !abuse.error && (
        <FeedCard title="AbuseIPDB" icon={<ShieldAlert className="w-4 h-4 text-orange-400" />} badge={
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
            abuse.abuse_confidence_score > 60
              ? "text-red-400 bg-red-500/10 border-red-500/20"
              : abuse.abuse_confidence_score > 20
              ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
              : "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
          }`}>{abuse.abuse_confidence_score}% confidence</span>
        }>
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
            <Row label="Country"        value={abuse.country_code || "Unknown"} />
            <Row label="ISP"            value={abuse.isp || "—"} />
            <Row label="Domain"         value={abuse.domain || "—"} />
            <Row label="Total Reports"  value={String(abuse.total_reports)} />
            <Row label="Last Reported"  value={abuse.last_reported_at ? new Date(abuse.last_reported_at).toLocaleDateString() : "—"} />
          </div>
        </FeedCard>
      )}

      {/* URLhaus */}
      {urlhaus && !urlhaus.error && (
        <FeedCard title="URLhaus" icon={<Globe className="w-4 h-4 text-blue-400" />} badge={
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
            urlhaus.query_status === "is_listed"
              ? "text-red-400 bg-red-500/10 border-red-500/20"
              : "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
          }`}>{urlhaus.query_status === "is_listed" ? "LISTED" : "CLEAN"}</span>
        }>
          {urlhaus.query_status === "is_listed" ? (
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
      )}

      {/* ThreatFox */}
      {tfox && !tfox.error && (
        <FeedCard title="ThreatFox IOCs" icon={<AlertCircle className="w-4 h-4 text-purple-400" />} badge={
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
            (tfox.iocs?.length ?? 0) > 0
              ? "text-red-400 bg-red-500/10 border-red-500/20"
              : "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
          }`}>{tfox.iocs?.length ?? 0} IOCs</span>
        }>
          {(tfox.iocs?.length ?? 0) > 0 ? (
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
      )}

      {/* OTX */}
      {otx && !otx.error && (
        <FeedCard title="AlienVault OTX" icon={<ShieldAlert className="w-4 h-4 text-cyan-400" />} badge={
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
            otx.pulse_count > 0
              ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
              : "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
          }`}>{otx.pulse_count} pulses</span>
        }>
          {otx.pulse_count > 0 ? (
            <div className="space-y-2">
              {otx.pulses.slice(0, 3).map((p, i) => (
                <div key={i} className="bg-slate-900/40 rounded-lg p-2.5">
                  <p className="text-xs font-semibold text-slate-200 mb-1">{p.name}</p>
                  <div className="flex flex-wrap gap-1">
                    {p.tags.slice(0, 4).map((tag, j) => (
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
      )}
    </div>
  );
}

function FeedCard({
  title, icon, badge, children
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

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-200 font-medium">{value}</span>
    </div>
  );
}

function Empty() {
  return (
    <div className="py-20 text-center text-slate-600">
      <Minus className="w-6 h-6 mx-auto mb-2 opacity-40" />
      <p className="text-sm">Reputation data not yet available</p>
    </div>
  );
}
