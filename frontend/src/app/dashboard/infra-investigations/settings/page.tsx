"use client";

import { useState, useEffect } from "react";
import { Card, Button, Input } from "@/components/ui";
import { InfraSubHeader } from "@/components/infra-investigation/InfraSubHeader";
import {
  Sliders,
  ToggleLeft,
  ToggleRight,
  Database,
  Cpu,
  AlertTriangle,
  Plus,
  Trash,
  CheckCircle,
  HelpCircle,
  Save,
} from "lucide-react";

interface ScorerWeights {
  reputation: number;
  infrastructure: number;
  phishing: number;
}

interface FeedConfiguration {
  abuseipdb: boolean;
  urlhaus: boolean;
  threatfox: boolean;
  otx_pdns: boolean;
  rdap_whois: boolean;
  ssl_socket: boolean;
  ipapi_geoip: boolean;
}

export default function InfraSettingsPage() {
  // ── Scorer Weights state ──
  const [weights, setWeights] = useState<ScorerWeights>({
    reputation: 40,
    infrastructure: 35,
    phishing: 25,
  });

  // ── Feeds activation state ──
  const [feeds, setFeeds] = useState<FeedConfiguration>({
    abuseipdb: true,
    urlhaus: true,
    threatfox: true,
    otx_pdns: true,
    rdap_whois: true,
    ssl_socket: true,
    ipapi_geoip: true,
  });

  // ── Brand Keywords watchlist ──
  const [keywords, setKeywords] = useState<string[]>(["tibsa", "secure-auth", "paypal", "microsoft"]);
  const [newKeyword, setNewKeyword] = useState("");

  // ── Alert thresholds ──
  const [thresholds, setThresholds] = useState({
    critical: 75,
    high: 50,
    medium: 25,
  });

  // Notifications
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Load from localStorage on mount
  useEffect(() => {
    try {
      const storedWeights = localStorage.getItem("tibsa_infra_weights");
      if (storedWeights) setWeights(JSON.parse(storedWeights));

      const storedFeeds = localStorage.getItem("tibsa_infra_feeds");
      if (storedFeeds) setFeeds(JSON.parse(storedFeeds));

      const storedKeywords = localStorage.getItem("tibsa_infra_keywords");
      if (storedKeywords) setKeywords(JSON.parse(storedKeywords));

      const storedThresholds = localStorage.getItem("tibsa_infra_thresholds");
      if (storedThresholds) setThresholds(JSON.parse(storedThresholds));
    } catch {
      // Ignore
    }
  }, []);

  // Save settings handler
  const handleSave = () => {
    try {
      localStorage.setItem("tibsa_infra_weights", JSON.stringify(weights));
      localStorage.setItem("tibsa_infra_feeds", JSON.stringify(feeds));
      localStorage.setItem("tibsa_infra_keywords", JSON.stringify(keywords));
      localStorage.setItem("tibsa_infra_thresholds", JSON.stringify(thresholds));

      setSuccessMsg("Configuration parameters updated and saved successfully.");
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err) {
      console.error("Save config failed:", err);
    }
  };

  // Keyword operations
  const handleAddKeyword = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyword.trim()) return;
    const clean = newKeyword.trim().toLowerCase();
    if (!keywords.includes(clean)) {
      setKeywords((prev) => [...prev, clean]);
    }
    setNewKeyword("");
  };

  const handleRemoveKeyword = (keyword: string) => {
    setKeywords((prev) => prev.filter((k) => k !== keyword));
  };

  // Live total sum validator
  const totalWeight = weights.reputation + weights.infrastructure + weights.phishing;
  const isWeightValid = totalWeight === 100;

  return (
    <div className="space-y-6">
      {/* SubHeader Layout component */}
      <InfraSubHeader />

      {/* Backend Integration Pending Banner */}
      <div className="p-3 bg-amber-500/5 border border-amber-500/20 text-amber-400 rounded-xl text-xs font-semibold flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
        <span><strong>Configuration Scope:</strong> Settings parameters are persisted locally in browser session memory (localStorage) pending integration of backend configuration persistence APIs.</span>
      </div>

      {/* Dynamic Success Notice Banner */}
      {successMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl text-xs font-semibold flex items-center gap-2 animate-bounce">
          <CheckCircle className="w-4 h-4 text-emerald-400" />
          {successMsg}
        </div>
      )}

      {/* Main Settings Panel Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* 1. Scorer Risk Weights Card */}
        <Card
          title="Weighted Risk Scorer Settings"
          description="Establish custom coefficients for the threat index scoring algorithm (Must sum to 100%)"
        >
          <div className="space-y-6">
            
            {/* Live visual summation dial */}
            <div className={`p-4 rounded-xl border flex items-center justify-between transition-colors ${
              isWeightValid
                ? "bg-cyan-500/[0.02] border-cyan-500/20"
                : "bg-red-500/[0.02] border-red-500/20"
            }`}>
              <div className="space-y-1">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">Model Validation Sum</span>
                <p className={`text-xl font-black ${isWeightValid ? "text-cyan-400" : "text-red-400"}`}>
                  {totalWeight}% <span className="text-slate-500 text-xs font-normal">/ 100%</span>
                </p>
              </div>
              <div>
                {isWeightValid ? (
                  <span className="px-2.5 py-1 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-[10px] font-extrabold uppercase tracking-wide">
                    Valid Weights
                  </span>
                ) : (
                  <span className="px-2.5 py-1 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] font-extrabold uppercase tracking-wide animate-pulse">
                    Sum Must Equals 100%
                  </span>
                )}
              </div>
            </div>

            {/* Reputation Weight Slider */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                  Reputation Feeds ({weights.reputation}%)
                </label>
                <span className="text-[10px] text-slate-500 font-medium">AbuseIPDB, URLhaus, ThreatFox</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.reputation}
                onChange={(e) => setWeights((prev) => ({ ...prev, reputation: parseInt(e.target.value) }))}
                className="w-full h-1.5 bg-slate-900 border border-white/[0.04] rounded-lg appearance-none cursor-pointer accent-cyan-500"
              />
            </div>

            {/* Infrastructure Weight Slider */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                  Infrastructure Integrity ({weights.infrastructure}%)
                </label>
                <span className="text-[10px] text-slate-500 font-medium">DNS record sets, SSL expiry, WHOIS</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.infrastructure}
                onChange={(e) => setWeights((prev) => ({ ...prev, infrastructure: parseInt(e.target.value) }))}
                className="w-full h-1.5 bg-slate-900 border border-white/[0.04] rounded-lg appearance-none cursor-pointer accent-cyan-500"
              />
            </div>

            {/* Phishing Heuristics Weight Slider */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                  Heuristics & Phishing ({weights.phishing}%)
                </label>
                <span className="text-[10px] text-slate-500 font-medium">Cybersquatting, TLDs, keyword matches</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.phishing}
                onChange={(e) => setWeights((prev) => ({ ...prev, phishing: parseInt(e.target.value) }))}
                className="w-full h-1.5 bg-slate-900 border border-white/[0.04] rounded-lg appearance-none cursor-pointer accent-cyan-500"
              />
            </div>

          </div>
        </Card>

        {/* 2. Feed Pipeline Configurations Card */}
        <Card
          title="Aggregator Threat Feeds Configuration"
          description="Enable or disable specific network query pipelines during intelligence runs"
        >
          <div className="space-y-3.5 max-h-[340px] overflow-y-auto pr-1">
            
            {[
              {
                id: "abuseipdb",
                label: "AbuseIPDB IP Reputation",
                desc: "Check malicious reports and ISP abuse classifications",
                state: feeds.abuseipdb,
                set: (s: boolean) => setFeeds((f) => ({ ...f, abuseipdb: s })),
                icon: <Database className="w-4 h-4" />
              },
              {
                id: "urlhaus",
                label: "URLhaus Active Payloads",
                desc: "Identify C2 servers delivering malware payloads",
                state: feeds.urlhaus,
                set: (s: boolean) => setFeeds((f) => ({ ...f, urlhaus: s })),
                icon: <Database className="w-4 h-4" />
              },
              {
                id: "threatfox",
                label: "ThreatFox IOC Classifications",
                desc: "Identify matches against malware campaigns and botnet tags",
                state: feeds.threatfox,
                set: (s: boolean) => setFeeds((f) => ({ ...f, threatfox: s })),
                icon: <Database className="w-4 h-4" />
              },
              {
                id: "otx_pdns",
                label: "OTX Passive DNS Mapping",
                desc: "Resolve historical resolutions and sibling domains",
                state: feeds.otx_pdns,
                set: (s: boolean) => setFeeds((f) => ({ ...f, otx_pdns: s })),
                icon: <Cpu className="w-4 h-4" />
              },
              {
                id: "rdap_whois",
                label: "RDAP Registrar (WHOIS) Lookups",
                desc: "Verify domain creation dates, registrars, and status",
                state: feeds.rdap_whois,
                set: (s: boolean) => setFeeds((f) => ({ ...f, rdap_whois: s })),
                icon: <Cpu className="w-4 h-4" />
              },
              {
                id: "ssl_socket",
                label: "Direct SSL Socket Handshake",
                desc: "Verify SSL certificates validity, chain, and issuers",
                state: feeds.ssl_socket,
                set: (s: boolean) => setFeeds((f) => ({ ...f, ssl_socket: s })),
                icon: <Cpu className="w-4 h-4" />
              },
              {
                id: "ipapi_geoip",
                label: "ipapi.co GeoIP & ASN Enrichment",
                desc: "Lookup geo coordinates, country parameters, and ASNs",
                state: feeds.ipapi_geoip,
                set: (s: boolean) => setFeeds((f) => ({ ...f, ipapi_geoip: s })),
                icon: <Database className="w-4 h-4" />
              }
            ].map((feed) => (
              <div
                key={feed.id}
                onClick={() => feed.set(!feed.state)}
                className={`flex items-center justify-between p-2 rounded-lg border cursor-pointer select-none transition-all duration-200 ${
                  feed.state
                    ? "border-cyan-500/30 bg-cyan-500/[0.02]"
                    : "border-white/[0.04] bg-slate-950/20 hover:bg-slate-900/30"
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <div className={`p-1.5 rounded border transition-colors ${
                    feed.state
                      ? "text-cyan-400 bg-cyan-500/10 border-cyan-500/20"
                      : "text-slate-500 bg-slate-900/40 border-white/[0.04]"
                  }`}>
                    {feed.icon}
                  </div>
                  <div>
                    <p className="text-[10px] font-bold text-slate-200 leading-none">{feed.label}</p>
                    <p className="text-[9px] text-slate-500 mt-1 font-medium leading-none">{feed.desc}</p>
                  </div>
                </div>
                <div>
                  {feed.state ? (
                    <ToggleRight className="w-6 h-6 text-cyan-400" />
                  ) : (
                    <ToggleLeft className="w-6 h-6 text-slate-600" />
                  )}
                </div>
              </div>
            ))}

          </div>
        </Card>

        {/* 3. Phishing Watchlist & Keywords */}
        <Card
          title="Cybersquatting Keywords Watchlist"
          description="Add key brand tags matched during heuristic checks to detect spoofing target domains"
        >
          <div className="space-y-4">
            
            {/* Add Keyword Form */}
            <form onSubmit={handleAddKeyword} className="flex gap-2">
              <Input
                placeholder="Enter custom brand keyword (e.g. microsoft)..."
                value={newKeyword}
                onChange={(e) => setNewKeyword(e.target.value)}
                className="bg-slate-950/40 border-white/[0.08]"
              />
              <Button type="submit" className="!px-3 flex items-center justify-center gap-1 !bg-cyan-600 hover:!bg-cyan-500 shadow-lg shadow-cyan-600/20 font-bold text-xs whitespace-nowrap">
                <Plus className="w-3.5 h-3.5" /> Add Tag
              </Button>
            </form>

            {/* Keyword tag list display */}
            <div className="flex flex-wrap gap-2 border border-white/[0.04] p-3 rounded-xl min-h-[100px] bg-slate-950/20 max-h-[150px] overflow-y-auto">
              {keywords.length === 0 ? (
                <p className="text-[10px] text-slate-600 m-auto">No brand tags added yet.</p>
              ) : (
                keywords.map((kw) => (
                  <div
                    key={kw}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#263554]/50 border border-white/[0.06] text-[10px] font-bold text-slate-300 font-mono"
                  >
                    <span>{kw}</span>
                    <button
                      type="button"
                      onClick={() => handleRemoveKeyword(kw)}
                      className="text-slate-500 hover:text-red-400 transition-colors"
                    >
                      <Trash className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>

          </div>
        </Card>

        {/* 4. Alert Threshold Boundaries */}
        <Card
          title="Threat Classification Limits"
          description="Adjust index scores governing risk ratings"
        >
          <div className="space-y-4">
            
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1.5">
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                  Critical Score Limit
                </label>
                <Input
                  type="number"
                  min="50"
                  max="100"
                  value={thresholds.critical}
                  onChange={(e) => setThresholds((t) => ({ ...t, critical: parseInt(e.target.value) || 0 }))}
                  className="bg-slate-950/40 border-white/[0.08] text-xs font-mono font-bold"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                  High Score Limit
                </label>
                <Input
                  type="number"
                  min="20"
                  max="80"
                  value={thresholds.high}
                  onChange={(e) => setThresholds((t) => ({ ...t, high: parseInt(e.target.value) || 0 }))}
                  className="bg-slate-950/40 border-white/[0.08] text-xs font-mono font-bold"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                  Medium Score Limit
                </label>
                <Input
                  type="number"
                  min="0"
                  max="50"
                  value={thresholds.medium}
                  onChange={(e) => setThresholds((t) => ({ ...t, medium: parseInt(e.target.value) || 0 }))}
                  className="bg-slate-950/40 border-white/[0.08] text-xs font-mono font-bold"
                />
              </div>
            </div>

            {/* Quick alert reminder */}
            <div className="bg-amber-500/5 border border-amber-500/10 p-3 rounded-lg flex gap-2">
              <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0" />
              <p className="text-[10px] text-slate-500 leading-normal">
                These thresholds govern visual status indicators, badge styling, and SOC alerts generated inside threat workspaces. Changing limits applies locally in this session immediately.
              </p>
            </div>

          </div>
        </Card>

      </div>

      {/* Unified Save Panel */}
      <div className="flex justify-end p-4 bg-slate-950/20 border border-white/[0.05] rounded-xl">
        <Button
          type="button"
          disabled={!isWeightValid}
          onClick={handleSave}
          className="flex items-center justify-center gap-2 !bg-cyan-600 hover:!bg-cyan-500 shadow-lg shadow-cyan-600/20 font-black text-xs !px-5 !py-2.5"
        >
          <Save className="w-4 h-4" /> Save Configuration Parameters
        </Button>
      </div>

    </div>
  );
}
