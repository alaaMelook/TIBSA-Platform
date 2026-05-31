"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card, Button, Input } from "@/components/ui";
import { InfraSubHeader } from "@/components/infra-investigation/InfraSubHeader";
import {
  Globe,
  Search,
  Play,
  Database,
  Clock,
  ArrowRight,
  Sparkles,
  Cpu,
  Network,
  AlertTriangle,
  ShieldCheck,
} from "lucide-react";
import { InfraInvestigationListItem, InfraTargetType } from "@/types/infra_investigation";

const TARGET_TYPES: { key: InfraTargetType; label: string; desc: string; example: string }[] = [
  { key: "domain",  label: "Domain",  desc: "Resolve, enumerate and correlate domain infrastructure", example: "evil-domain.com"     },
  { key: "ip",      label: "IP",      desc: "Reputation lookup, GeoIP, ASN, and abuse reports",       example: "185.220.101.45"     },
  { key: "url",     label: "URL",     desc: "Full URL analysis including domain + path heuristics",    example: "http://phish.xyz/r" },
  { key: "hash",    label: "Hash",    desc: "IOC hash lookup across threat intelligence feeds",        example: "a3f8c..."            },
  { key: "email",   label: "Email",   desc: "Email domain reputation and spoofing vector analysis",    example: "ceo@evil-corp.ru"   },
];

function StatusBadge({ status }: { status: string }) {
  const base = "px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border tracking-wider";
  switch (status) {
    case "completed": return <span className={`${base} border-emerald-500/20 bg-emerald-500/10 text-emerald-400`}>Completed</span>;
    case "failed":    return <span className={`${base} border-red-500/20 bg-red-500/10 text-red-400`}>Failed</span>;
    case "stopped":   return <span className={`${base} border-amber-500/20 bg-amber-500/10 text-amber-400`}>Stopped</span>;
    case "pending":   return <span className={`${base} border-slate-700 bg-slate-800 text-slate-400`}>Pending</span>;
    default:          return <span className={`${base} border-blue-500/20 bg-blue-500/10 text-blue-400 animate-pulse`}>{status || "Running"}</span>;
  }
}

export default function InfraInvestigationsPage() {
  const router = useRouter();
  const { token } = useAuth();

  const [target, setTarget]             = useState("");
  const [targetType, setTargetType]     = useState<InfraTargetType>("domain");
  const [enablePassiveDns, setPassiveDns] = useState(true);
  const [enableAiSummary, setAiSummary]   = useState(true);

  const [history, setHistory]               = useState<InfraInvestigationListItem[]>([]);
  const [isHistoryLoading, setHistoryLoad]  = useState(true);
  const [isLaunching, setIsLaunching]       = useState(false);
  const [launchError, setLaunchError]       = useState<string | null>(null);

  const fetchHistory = useCallback(async () => {
    if (!token) return;
    try {
      setHistoryLoad(true);
      const res = await api.infraInvestigations.list(token);
      if (res?.success && res?.data) setHistory(res.data);
    } catch {
      // silent
    } finally {
      setHistoryLoad(false);
    }
  }, [token]);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim() || !token) return;
    setIsLaunching(true);
    setLaunchError(null);
    try {
      const res = await api.infraInvestigations.create({
        target: target.trim(),
        enable_passive_dns: enablePassiveDns,
        enable_ai_summary:  enableAiSummary,
      }, token);
      if (res?.success && res?.data) {
        router.push(`/dashboard/infra-investigations/${res.data.id}`);
      } else {
        setLaunchError("Failed to start — invalid response.");
      }
    } catch (err: any) {
      setLaunchError(err.message || "An error occurred.");
    } finally {
      setIsLaunching(false);
    }
  };

  const selectedType = TARGET_TYPES.find((t) => t.key === targetType);

  return (
    <div className="space-y-6">

      {/* Shared Sub-navigation Hero Header */}
      <InfraSubHeader />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* ── Launch Form ── */}
        <div className="lg:col-span-1 space-y-4">
          <Card title="New Investigation" description="Submit an IOC or infrastructure indicator">
            <form onSubmit={handleSubmit} className="space-y-4">

              {/* Target type selector */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                  Target Type
                </label>
                <div className="grid grid-cols-5 gap-1">
                  {TARGET_TYPES.map((t) => (
                    <button
                      key={t.key}
                      type="button"
                      onClick={() => setTargetType(t.key)}
                      className={`py-1.5 rounded-lg border text-[10px] font-bold capitalize transition-all cursor-pointer ${
                        targetType === t.key
                          ? "border-cyan-500 bg-cyan-950/30 text-cyan-400"
                          : "border-white/[0.06] bg-slate-950/20 text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
                {selectedType && (
                  <p className="text-[10px] text-slate-500 leading-tight">{selectedType.desc}</p>
                )}
              </div>

              {/* Target input */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                  Target Value
                </label>
                <div className="relative">
                  <Search className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                  <Input
                    placeholder={selectedType?.example || "Enter indicator..."}
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    required
                    className="pl-9 bg-slate-950/40 border-white/[0.08]"
                  />
                </div>
              </div>

              {/* Options */}
              <div className="border-t border-white/[0.06] pt-3 space-y-3">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">
                  Pipeline Options
                </span>

                {[
                  {
                    id: "passive-dns",
                    label: "Enable Passive DNS",
                    desc:  "Map historical resolution data via OTX",
                    state: enablePassiveDns,
                    set:   setPassiveDns,
                    icon:  <Network className="w-3.5 h-3.5" />,
                  },
                  {
                    id: "ai-summary",
                    label: "Enable AI Summary",
                    desc:  "Generate AI-powered threat classification",
                    state: enableAiSummary,
                    set:   setAiSummary,
                    icon:  <Sparkles className="w-3.5 h-3.5" />,
                  },
                ].map((opt) => (
                  <div
                    key={opt.id}
                    onClick={() => opt.set(!opt.state)}
                    className={`flex items-center justify-between p-2.5 rounded-xl border cursor-pointer select-none transition-all duration-200 ${
                      opt.state
                        ? "border-cyan-500/40 bg-cyan-500/[0.03]"
                        : "border-white/[0.05] bg-slate-950/20 hover:bg-slate-900/30"
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className={`p-1.5 rounded-lg border transition-colors ${
                        opt.state
                          ? "text-cyan-400 bg-cyan-500/10 border-cyan-500/20"
                          : "text-slate-500 bg-slate-900/40 border-white/[0.04]"
                      }`}>
                        {opt.icon}
                      </div>
                      <div>
                        <p className="text-[11px] font-bold text-slate-200">{opt.label}</p>
                        <p className="text-[9px] text-slate-500">{opt.desc}</p>
                      </div>
                    </div>
                    <div className={`relative inline-flex h-4 w-7 rounded-full border-transparent transition-colors duration-200 ease-in-out ${
                      opt.state ? "bg-cyan-600" : "bg-slate-800"
                    }`}>
                      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out ${
                        opt.state ? "translate-x-3" : "translate-x-0"
                      }`} />
                    </div>
                  </div>
                ))}
              </div>

              {launchError && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-xs font-medium">
                  {launchError}
                </div>
              )}

              <Button
                type="submit"
                variant="primary"
                isLoading={isLaunching}
                className="w-full justify-center gap-2 mt-2 !bg-cyan-600 hover:!bg-cyan-500 !shadow-cyan-600/20"
              >
                <Play className="w-4 h-4" /> Launch Intelligence Scan
              </Button>
            </form>
          </Card>

          {/* Info cards */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Data Sources", value: "5+",     icon: <Database className="w-4 h-4 text-cyan-400" />,    color: "text-cyan-400" },
              { label: "Pipeline Stages", value: "7",   icon: <Cpu className="w-4 h-4 text-purple-400" />,       color: "text-purple-400" },
              { label: "AI-Powered",   value: "Yes",    icon: <Sparkles className="w-4 h-4 text-blue-400" />,    color: "text-blue-400" },
              { label: "No VT Used",   value: "True",   icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />, color: "text-emerald-400" },
            ].map((s) => (
              <div key={s.label} className="bg-[#263554]/50 border border-white/[0.06] rounded-xl p-3 flex items-center gap-3">
                {s.icon}
                <div>
                  <p className={`text-sm font-black ${s.color}`}>{s.value}</p>
                  <p className="text-[10px] text-slate-500">{s.label}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ── History ── */}
        <div className="lg:col-span-2">
          <Card title="Investigation History" description="Browse and resume past infra investigations">
            {isHistoryLoading ? (
              <div className="py-20 text-center text-slate-500 font-medium">
                <span className="inline-block animate-spin mr-2 h-4 w-4 border-2 border-cyan-500 border-t-transparent rounded-full" />
                Loading history...
              </div>
            ) : history.length === 0 ? (
              <div className="py-20 text-center text-slate-500 flex flex-col items-center justify-center">
                <Globe className="w-8 h-8 mb-2 opacity-20" />
                <p className="text-sm font-semibold">No investigations started yet.</p>
                <p className="text-xs text-slate-600 mt-1">Submit an IOC or domain to run your first intelligence scan.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-slate-400 font-semibold bg-slate-900/10 text-[11px] uppercase tracking-wider">
                      <th className="py-3 px-4">Target</th>
                      <th className="py-3 px-4">Type</th>
                      <th className="py-3 px-4">Risk</th>
                      <th className="py-3 px-4">Stage</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Date</th>
                      <th className="py-3 px-4" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.04]">
                    {history.map((inv) => {
                      const isFailed    = inv.status === "failed";
                      const riskColor   =
                        isFailed        ? "text-slate-500" :
                        inv.risk_score > 60 ? "text-red-400" :
                        inv.risk_score > 30 ? "text-orange-400" : "text-emerald-400";

                      return (
                        <tr
                          key={inv.id}
                          onClick={() => router.push(`/dashboard/infra-investigations/${inv.id}`)}
                          className="hover:bg-white/[0.02] cursor-pointer transition-colors group"
                        >
                          <td className="py-4 px-4 text-slate-200 font-medium max-w-[180px] truncate">
                            <div className="flex items-center gap-2">
                              <Globe className="w-3.5 h-3.5 text-cyan-500/60 flex-shrink-0" />
                              <span className="truncate">{inv.target}</span>
                            </div>
                          </td>
                          <td className="py-4 px-4">
                            <span className="text-[9px] font-extrabold uppercase px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                              {inv.target_type}
                            </span>
                          </td>
                          <td className="py-4 px-4">
                            <span className={`font-bold font-mono text-xs ${riskColor}`}>
                              {isFailed ? "—" : Math.round(inv.risk_score)}
                            </span>
                          </td>
                          <td className="py-4 px-4 text-xs text-slate-400 font-medium">
                            {inv.current_stage || "Queued"}
                          </td>
                          <td className="py-4 px-4">
                            <StatusBadge status={inv.status} />
                          </td>
                          <td className="py-4 px-4 text-[10px] text-slate-500 font-medium">
                            <div className="flex items-center gap-1">
                              <Clock className="w-3.5 h-3.5" />
                              {new Date(inv.started_at).toLocaleDateString()}
                            </div>
                          </td>
                          <td className="py-4 px-4 text-right">
                            <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>

      </div>
    </div>
  );
}
