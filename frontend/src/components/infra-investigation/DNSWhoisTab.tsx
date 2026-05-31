"use client";

import { InfraInvestigationResults } from "@/types/infra_investigation";
import { Globe, Server, Lock, MapPin, Minus } from "lucide-react";

interface Props {
  results: InfraInvestigationResults;
}

function InfoRow({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="flex items-start justify-between py-2 border-b border-white/[0.03] last:border-0 gap-4">
      <span className="text-xs text-slate-500 flex-shrink-0">{label}</span>
      <span className="text-xs text-slate-200 font-medium text-right break-all">{value || "—"}</span>
    </div>
  );
}

function SectionCard({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="bg-[#1e293b]/60 border border-white/[0.06] rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.04]">
        {icon}
        <span className="text-xs font-bold text-slate-200">{title}</span>
      </div>
      <div className="px-4 py-2">{children}</div>
    </div>
  );
}

export function DNSWhoisTab({ results }: Props) {
  const enrichment = results.enrichment;
  if (!enrichment) return <Empty />;

  const { dns, whois, ssl, geoip } = enrichment;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

      {/* DNS Records */}
      {dns && !dns.error && (
        <SectionCard title="DNS Records" icon={<Globe className="w-4 h-4 text-blue-400" />}>
          {dns.records.length === 0 ? (
            <p className="text-slate-500 text-xs py-4">No DNS records retrieved</p>
          ) : (
            <div className="divide-y divide-white/[0.03]">
              {dns.records.map((rec, i) => (
                <div key={i} className="flex items-center gap-3 py-2">
                  <span className="text-[9px] font-extrabold px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 tracking-wider flex-shrink-0">
                    {rec.type}
                  </span>
                  <span className="text-xs text-slate-200 font-mono truncate">{rec.value}</span>
                  {rec.ttl && <span className="text-[10px] text-slate-600 ml-auto flex-shrink-0">TTL {rec.ttl}</span>}
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      )}

      {/* WHOIS */}
      {whois && !whois.error && (
        <SectionCard title="WHOIS / Registration" icon={<Server className="w-4 h-4 text-purple-400" />}>
          <InfoRow label="Registrar"        value={whois.registrar} />
          <InfoRow label="Registrant Org"   value={whois.registrant_org} />
          <InfoRow label="Created"          value={whois.creation_date ? new Date(whois.creation_date).toLocaleDateString() : null} />
          <InfoRow label="Expires"          value={whois.expiration_date ? new Date(whois.expiration_date).toLocaleDateString() : null} />
          <InfoRow label="Updated"          value={whois.updated_date ? new Date(whois.updated_date).toLocaleDateString() : null} />
          <InfoRow label="Domain Age"       value={whois.domain_age_days !== null ? `${whois.domain_age_days} days` : null} />
          <div className="py-2 flex items-center justify-between">
            <span className="text-xs text-slate-500">Newly Registered</span>
            {whois.is_newly_registered ? (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">
                YES – HIGH RISK
              </span>
            ) : (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                NO
              </span>
            )}
          </div>
          {whois.status.length > 0 && (
            <div className="flex flex-wrap gap-1 pt-2">
              {whois.status.slice(0, 4).map((s, i) => (
                <span key={i} className="text-[9px] font-semibold bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded border border-white/[0.04]">
                  {s.split(" ")[0]}
                </span>
              ))}
            </div>
          )}
        </SectionCard>
      )}

      {/* SSL Certificate */}
      {ssl && !ssl.error && (
        <SectionCard title="SSL Certificate" icon={<Lock className="w-4 h-4 text-emerald-400" />}>
          <InfoRow label="Subject CN"    value={ssl.subject_cn} />
          <InfoRow label="Issuer"        value={ssl.issuer_cn} />
          <InfoRow label="Issuer Org"    value={ssl.issuer_org} />
          <InfoRow label="Valid From"    value={ssl.not_before ? new Date(ssl.not_before).toLocaleDateString() : null} />
          <InfoRow label="Valid Until"   value={ssl.not_after ? new Date(ssl.not_after).toLocaleDateString() : null} />
          <InfoRow label="Serial"        value={ssl.serial_number} />
          <div className="flex gap-2 mt-2">
            {ssl.is_expired && (
              <span className="text-[9px] font-bold px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">EXPIRED</span>
            )}
            {ssl.is_self_signed && (
              <span className="text-[9px] font-bold px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400">SELF-SIGNED</span>
            )}
          </div>
          {ssl.san_domains.length > 0 && (
            <div className="mt-3 pt-2 border-t border-white/[0.04]">
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">SAN Domains</p>
              <div className="flex flex-wrap gap-1">
                {ssl.san_domains.slice(0, 8).map((d, i) => (
                  <span key={i} className="text-[9px] font-mono bg-slate-900/60 text-slate-400 px-1.5 py-0.5 rounded border border-white/[0.04]">
                    {d}
                  </span>
                ))}
              </div>
            </div>
          )}
        </SectionCard>
      )}

      {/* GeoIP */}
      {geoip && !geoip.error && (
        <SectionCard title="GeoIP & ASN" icon={<MapPin className="w-4 h-4 text-cyan-400" />}>
          <InfoRow label="IP"          value={geoip.ip} />
          <InfoRow label="Country"     value={geoip.country_code ? `${geoip.country || ""} (${geoip.country_code})` : null} />
          <InfoRow label="Region"      value={geoip.region} />
          <InfoRow label="City"        value={geoip.city} />
          <InfoRow label="ISP / Org"   value={geoip.org} />
          <InfoRow label="ASN"         value={geoip.asn} />
          <InfoRow label="Timezone"    value={geoip.timezone} />
          {geoip.latitude && geoip.longitude && (
            <InfoRow label="Coordinates" value={`${geoip.latitude.toFixed(4)}, ${geoip.longitude.toFixed(4)}`} />
          )}
        </SectionCard>
      )}
    </div>
  );
}

function Empty() {
  return (
    <div className="py-20 text-center text-slate-600">
      <Minus className="w-6 h-6 mx-auto mb-2 opacity-40" />
      <p className="text-sm">DNS & infrastructure data not yet available</p>
    </div>
  );
}
