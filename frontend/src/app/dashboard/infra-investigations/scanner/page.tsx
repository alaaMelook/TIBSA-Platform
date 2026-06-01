"use client";

import { useState } from "react";
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
  Sparkles,
  Cpu,
  Network,
  ShieldCheck,
  Zap,
  Server,
  Layers,
} from "lucide-react";
import { InfraTargetType } from "@/types/infra_investigation";

const TARGET_TYPES: { key: InfraTargetType; label: string; desc: string; example: string }[] = [
  { key: "domain",  label: "Domain",  desc: "Resolve, enumerate and correlate domain infrastructure", example: "evil-domain.com"     },
  { key: "ip",      label: "IP",      desc: "Reputation lookup, GeoIP, ASN, and abuse reports",       example: "185.220.101.45"     },
  { key: "url",     label: "URL",     desc: "Full URL analysis including domain + path heuristics",    example: "http://phish.xyz/r" },
  { key: "hash",    label: "Hash",    desc: "IOC hash lookup across threat intelligence feeds",        example: "a3f8c..."            },
  { key: "email",   label: "Email",   desc: "Email domain reputation and spoofing vector analysis",    example: "ceo@evil-corp.ru"   },
];

const PIPELINE_STAGES = [
  { step: "01", name: "Target Parsing", desc: "Validate target schema and extract indicators" },
  { step: "02", name: "DNS Resolution", desc: "A, AAAA, MX, NS and TXT record resolution" },
  { step: "03", name: "WHOIS & RDAP", desc: "Registrar details, creation date, and ownership" },
  { step: "04", name: "SSL Certificate", desc: "Enrich Certificate Authority and issuer dates" },
  { step: "05", name: "GeoIP & ASN", desc: "Lookup physical location, ISP, and network routing" },
  { step: "06", name: "Passive DNS", desc: "Map historical IP-to-domain mapping graphs" },
  { step: "07", name: "Reputation Feeds", desc: "Cross-reference IOC against threat intelligence lists" },
  { step: "08", name: "AI Categorization", desc: "Summarize findings and attribute campaigns" },
];

export default function InfraScannerPage() {
  const router = useRouter();
  const { token } = useAuth();

  const [target, setTarget]             = useState("");
  const [targetType, setTargetType]     = useState<InfraTargetType>("domain");
  const [enablePassiveDns, setPassiveDns] = useState(true);
  const [enableAiSummary, setAiSummary]   = useState(true);

  const [isLaunching, setIsLaunching]       = useState(false);
  const [launchError, setLaunchError]       = useState<string | null>(null);

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
      {/* SubHeader Component */}
      <InfraSubHeader />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Launch Form */}
        <div className="lg:col-span-1 space-y-4">
          <Card title="New Investigation" description="Submit an IOC or infrastructure indicator">
            <form onSubmit={handleSubmit} className="space-y-4 mt-2">

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
                          ? "border-cyan-500 bg-cyan-950/30 text-cyan-400 font-extrabold shadow-sm"
                          : "border-white/[0.06] bg-slate-950/20 text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
                {selectedType && (
                  <p className="text-[10px] text-slate-500 leading-tight transition-all duration-300 mt-1">
                    {selectedType.desc}
                  </p>
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
                    className="pl-9 bg-slate-950/40 border-white/[0.08] focus:border-cyan-500/50"
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
                        <p className="text-[9px] text-slate-500 leading-none mt-0.5">{opt.desc}</p>
                      </div>
                    </div>
                    <div className={`relative inline-flex h-4 w-7 rounded-full border-transparent transition-colors duration-200 ease-in-out ${
                      opt.state ? "bg-cyan-600" : "bg-slate-800"
                    }`}>
                      <span className={`inline-block h-3 w-3 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out mt-[2px] ml-[2px] ${
                        opt.state ? "translate-x-3.5" : "translate-x-0"
                      }`} />
                    </div>
                  </div>
                ))}
              </div>

              {launchError && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-xs font-medium animate-shake">
                  {launchError}
                </div>
              )}

              <Button
                type="submit"
                variant="primary"
                isLoading={isLaunching}
                className="w-full justify-center gap-2 mt-2 !bg-cyan-600 hover:!bg-cyan-500 !shadow-cyan-600/20 text-xs font-bold transition-all duration-200"
              >
                <Play className="w-3.5 h-3.5" /> Launch Intelligence Scan
              </Button>
            </form>
          </Card>

          {/* Quick Stats Grid */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Data Sources", value: "8+",     icon: <Database className="w-4 h-4 text-cyan-400" />,    color: "text-cyan-400" },
              { label: "Pipeline Stages", value: "8 Steps",   icon: <Layers className="w-4 h-4 text-purple-400" />,       color: "text-purple-400" },
              { label: "AI Analysis",   value: "Llama 3.1",    icon: <Sparkles className="w-4 h-4 text-blue-400" />,    color: "text-blue-400" },
              { label: "No VT API Keys",   value: "Zero Cost",   icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />, color: "text-emerald-400" },
            ].map((s) => (
              <div key={s.label} className="bg-slate-900/40 border border-white/[0.04] rounded-xl p-3 flex items-center gap-3">
                <div className="p-2 bg-slate-950/60 rounded-lg border border-white/[0.04]">{s.icon}</div>
                <div>
                  <p className={`text-xs font-extrabold ${s.color}`}>{s.value}</p>
                  <p className="text-[9px] text-slate-500 uppercase font-semibold">{s.label}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Pipeline Steps & Description */}
        <div className="lg:col-span-2 space-y-4">
          <Card title="Investigation Pipeline Architecture" description="Multi-stage profiling runs sequentially in the background">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
              {PIPELINE_STAGES.map((stage) => (
                <div 
                  key={stage.step} 
                  className="p-3 rounded-xl border border-white/[0.04] bg-slate-950/20 hover:bg-slate-900/10 hover:border-cyan-500/20 transition-all duration-200 flex items-start gap-3 group"
                >
                  <div className="text-xs font-black text-cyan-500 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded-lg">
                    {stage.step}
                  </div>
                  <div>
                    <h4 className="text-xs font-extrabold text-slate-200 group-hover:text-cyan-400 transition-colors">
                      {stage.name}
                    </h4>
                    <p className="text-[10px] text-slate-500 mt-0.5 leading-snug">
                      {stage.desc}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-4 p-4 rounded-xl border border-cyan-500/10 bg-cyan-500/[0.01] flex gap-3.5 items-start">
              <Zap className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-slate-200">Continuous Enrichment</h4>
                <p className="text-[10px] text-slate-400 leading-relaxed">
                  The infrastructure pipeline correlates indicators using free open-source threat intelligence datasets, reverse lookup databases, and passive DNS records. Once completed, a relational graph is compiled to show connections between entities.
                </p>
              </div>
            </div>
          </Card>
        </div>

      </div>
    </div>
  );
}
