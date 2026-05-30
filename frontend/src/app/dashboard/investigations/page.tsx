"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card, Button, Input } from "@/components/ui";
import { Shield, Search, ArrowRight, Play, Database, ServerCrash, Clock, Sparkles, Code, Globe, Cookie, Sliders, FolderOpen, Lock, AlertTriangle } from "lucide-react";
import { InvestigationStatusResponse } from "@/types";

export default function InvestigationsDashboard() {
  const router = useRouter();
  const { token } = useAuth();
  
  // Launch parameters
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("safe");
  const [includeTi, setIncludeTi] = useState(true);
  const [tmMode, setTmMode] = useState("enhanced");
  
  const [enableSqlmap, setEnableSqlmap] = useState(false);
  const [authBrowserAnalysis, setAuthBrowserAnalysis] = useState(false);
  const [authorizedAuthMode, setAuthorizedAuthMode] = useState(false);
  const [authLifecycleChecks, setAuthLifecycleChecks] = useState(false);
  const [authzTransitionChecks, setAuthzTransitionChecks] = useState(false);
  const [sessionCookie, setSessionCookie] = useState("");
  
  const [tests, setTests] = useState<string[]>([
    "security_headers",
    "xss",
    "sqli",
    "endpoint_crawling",
    "cookie_analysis",
    "misconfiguration",
    "directory_discovery",
    "auth_security"
  ]);

  const [history, setHistory] = useState<InvestigationStatusResponse[]>([]);
  const [isHistoryLoading, setIsHistoryLoading] = useState(true);
  const [isLaunching, setIsLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);

  // Available tests options
  const testOptions = [
    { key: "security_headers", label: "Security Headers", desc: "Scan security headers & policy configurations" },
    { key: "xss", label: "Cross-Site Scripting (XSS)", desc: "Detect injection risks & reflection vectors" },
    { key: "sqli", label: "SQL Injection (SQLi)", desc: "Identify active database escapement flaws" },
    { key: "endpoint_crawling", label: "Endpoint Crawling", desc: "Map directories, assets, and active URLs" },
    { key: "cookie_analysis", label: "Cookie Analysis", desc: "Validate flags, session configs, and expiry" },
    { key: "misconfiguration", label: "Server Misconfiguration", desc: "Detect SSL/TLS faults & header leaks" },
    { key: "directory_discovery", label: "Directory Discovery", desc: "Uncover hidden directories & configs" },
    { key: "auth_security", label: "Auth & Identity Security", desc: "Probe login surfaces & credential forms" }
  ];

  const fetchHistory = useCallback(async () => {
    if (!token) return;
    try {
      setIsHistoryLoading(true);
      const response = await api.investigations.list(token);
      if (response && response.success && response.data) {
        setHistory(response.data);
      }
    } catch (err) {
      console.error("Failed to load investigation history:", err);
    } finally {
      setIsHistoryLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const handleTestToggle = (key: string) => {
    setTests((prev) => {
      const isRemoving = prev.includes(key);
      if (key === "sqli" && isRemoving) {
        setEnableSqlmap(false);
      }
      if (key === "auth_security" && isRemoving) {
        setAuthBrowserAnalysis(false);
        setAuthorizedAuthMode(false);
        setAuthLifecycleChecks(false);
        setAuthzTransitionChecks(false);
        setSessionCookie("");
      }
      return isRemoving ? prev.filter((t) => t !== key) : [...prev, key];
    });
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim() || !token) return;

    setIsLaunching(true);
    setLaunchError(null);

    try {
      const response = await api.investigations.create(
        {
          target: target.trim(),
          mode,
          tests,
          include_ti: includeTi,
          tm_mode: tmMode,
          enable_sqlmap: enableSqlmap,
          auth_browser_analysis: authBrowserAnalysis,
          authorized_auth_mode: authorizedAuthMode,
          auth_lifecycle_checks: authLifecycleChecks,
          authz_transition_checks: authzTransitionChecks,
          session_cookie: sessionCookie ? sessionCookie.trim() : null
        },
        token
      );

      if (response && response.success && response.data) {
        const newId = response.data.investigation_id;
        router.push(`/dashboard/investigations/${newId}`);
      } else {
        setLaunchError("Failed to initialize pipeline: invalid response.");
      }
    } catch (err: any) {
      console.error("Failed to start investigation:", err);
      setLaunchError(err.message || "An error occurred during launcher dispatch.");
    } finally {
      setIsLaunching(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const common = "px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border tracking-wider";
    switch (status) {
      case "completed":
        return <span className={`${common} border-emerald-500/20 bg-emerald-500/10 text-emerald-400`}>Completed</span>;
      case "failed":
        return <span className={`${common} border-red-500/20 bg-red-500/10 text-red-400`}>Failed</span>;
      case "stopped":
        return <span className={`${common} border-amber-500/20 bg-amber-500/10 text-amber-400`}>Stopped</span>;
      case "pending":
      case "created":
        return <span className={`${common} border-slate-700 bg-slate-800 text-slate-400`}>Pending</span>;
      default:
        return <span className={`${common} border-blue-500/20 bg-blue-500/10 text-blue-400 animate-pulse`}>{status || "Running"}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Hero Header */}
      <div className="bg-gradient-to-r from-blue-900/20 via-[#263554]/30 to-[#0f172a] border border-white/[0.04] p-6 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6 shadow-md">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-ping" />
            <span className="text-[10px] font-bold text-blue-400 uppercase tracking-widest">
              AI Security Ingestion
            </span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">
            Security Investigations
          </h1>
          <p className="text-slate-400 max-w-xl text-sm leading-relaxed">
            Run automated endpoint intelligence pipelines. Discover assets, normalise vulnerabilities, run external reputation lookups, build STRIDE models, and compose AI analysis.
          </p>
        </div>
        <Shield className="w-12 h-12 text-blue-500/20 hidden md:block" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Launch Config Form Card */}
        <div className="lg:col-span-1 space-y-6">
          <Card title="Start Investigation" description="Deploy an ingestion scan against a target">
            <form onSubmit={handleStartScan} className="space-y-4">
              {/* Target URL */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                  Target Endpoint
                </label>
                <div className="relative">
                  <Search className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                  <Input
                    placeholder="https://example.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    required
                    className="pl-9 bg-slate-950/40 border-white/[0.08]"
                  />
                </div>
              </div>

              {/* Mode Selector */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                  Scan Mode
                </label>
                <div className="grid grid-cols-3 gap-2">
                  {["passive", "safe", "aggressive"].map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setMode(m)}
                      className={`py-1.5 px-3 rounded-lg border text-xs font-bold capitalize transition-all cursor-pointer ${
                        mode === m
                          ? "border-blue-500 bg-blue-950/30 text-blue-400"
                          : "border-white/[0.06] bg-slate-950/20 text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              {/* Options */}
              <div className="pt-2 space-y-3">
                <label className="flex items-center gap-2.5 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={includeTi}
                    onChange={(e) => setIncludeTi(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-700 bg-slate-950 text-blue-500 focus:ring-blue-500"
                  />
                  <div className="text-xs font-semibold text-slate-300">
                    Enable Threat Intel Integration
                  </div>
                </label>

                <div className="space-y-1.5">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
                    STRIDE Modeling Mode
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    {["standard", "enhanced"].map((tm) => (
                      <button
                        key={tm}
                        type="button"
                        onClick={() => setTmMode(tm)}
                        className={`py-1 px-2.5 rounded border text-[10px] font-bold capitalize transition-all cursor-pointer ${
                          tmMode === tm
                            ? "border-blue-500/50 bg-blue-950/20 text-blue-400"
                            : "border-white/[0.06] bg-slate-950/20 text-slate-500"
                        }`}
                      >
                        {tm}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Scans config block */}
              <div className="border-t border-white/[0.06] pt-4 space-y-3">
                <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">
                  Select Vulnerability Scans
                </span>
                <div className="grid grid-cols-1 gap-2 max-h-[280px] overflow-y-auto pr-1">
                  {testOptions.map((opt) => {
                    const isSelected = tests.includes(opt.key);
                    
                    const getOptionIcon = (key: string, selected: boolean) => {
                      const colorClass = selected 
                        ? "text-blue-400 bg-blue-500/10 border-blue-500/20" 
                        : "text-slate-500 bg-slate-900/40 border-white/[0.04]";
                      
                      switch (key) {
                        case "security_headers":
                          return <div className={`p-1.5 rounded-lg border transition-colors ${colorClass}`}><Shield className="w-3.5 h-3.5" /></div>;
                        case "xss":
                          return <div className={`p-1.5 rounded-lg border transition-colors ${colorClass}`}><Code className="w-3.5 h-3.5" /></div>;
                        case "sqli":
                          return <div className={`p-1.5 rounded-lg border transition-colors ${colorClass}`}><Database className="w-3.5 h-3.5" /></div>;
                        case "endpoint_crawling":
                          return <div className={`p-1.5 rounded-lg border transition-colors ${colorClass}`}><Globe className="w-3.5 h-3.5" /></div>;
                        case "cookie_analysis":
                          return <div className={`p-1.5 rounded-lg border transition-colors ${colorClass}`}><Cookie className="w-3.5 h-3.5" /></div>;
                        case "misconfiguration":
                          return <div className={`p-1.5 rounded-lg border transition-colors ${colorClass}`}><Sliders className="w-3.5 h-3.5" /></div>;
                        case "directory_discovery":
                          return <div className={`p-1.5 rounded-lg border transition-colors ${colorClass}`}><FolderOpen className="w-3.5 h-3.5" /></div>;
                        case "auth_security":
                          return <div className={`p-1.5 rounded-lg border transition-colors ${colorClass}`}><Lock className="w-3.5 h-3.5" /></div>;
                        default:
                          return <div className={`p-1.5 rounded-lg border transition-colors ${colorClass}`}><Shield className="w-3.5 h-3.5" /></div>;
                      }
                    };

                    return (
                      <div
                        key={opt.key}
                        onClick={() => handleTestToggle(opt.key)}
                        className={`flex flex-col p-2.5 rounded-xl border transition-all duration-200 select-none cursor-pointer ${
                          isSelected 
                            ? "border-blue-500/40 bg-blue-500/[0.03] shadow-md shadow-blue-500/[0.02]" 
                            : "border-white/[0.05] bg-slate-950/20 hover:bg-slate-900/30"
                        }`}
                      >
                        <div className="flex items-center justify-between w-full">
                          <div className="flex items-center gap-3">
                            {getOptionIcon(opt.key, isSelected)}
                            <div className="flex flex-col text-left">
                              <span className="text-[11px] font-bold text-slate-200">{opt.label}</span>
                              <span className="text-[9px] text-slate-500 mt-0.5 leading-tight font-medium max-w-[190px]">{opt.desc}</span>
                            </div>
                          </div>
                          
                          {/* iOS-like Custom Switch */}
                          <div className={`relative inline-flex h-4 w-7 flex-shrink-0 cursor-pointer rounded-full border border-transparent transition-colors duration-200 ease-in-out ${
                            isSelected ? "bg-blue-600 border-blue-500" : "bg-slate-800 border-slate-700"
                          }`}>
                            <span className={`pointer-events-none inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out ${
                              isSelected ? "translate-x-3" : "translate-x-0"
                            }`} />
                          </div>
                        </div>

                        {opt.key === "sqli" && isSelected && (
                          <div
                            onClick={(e) => {
                              e.stopPropagation();
                            }}
                            className="mt-3 pt-3 border-t border-white/5 space-y-3 text-left w-full"
                          >
                            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Advanced SQLI Checks</div>
                            
                            <div className="flex items-center justify-between gap-3">
                              <div>
                                <div className="text-[11px] font-medium text-slate-300">
                                  SQLMap Verification
                                </div>
                                <div className="text-[10px] text-slate-500">
                                  Confirm findings using sqlmap API
                                </div>
                              </div>

                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setEnableSqlmap(!enableSqlmap);
                                }}
                                className={`relative inline-flex h-4 w-7 flex-shrink-0 cursor-pointer rounded-full border border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                  enableSqlmap ? "bg-blue-600 border-blue-500" : "bg-slate-800 border-slate-700"
                                }`}
                              >
                                <span
                                  className={`pointer-events-none inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out ${
                                    enableSqlmap ? "translate-x-3" : "translate-x-0"
                                  }`}
                                />
                              </button>
                            </div>
                          </div>
                        )}

                        {opt.key === "auth_security" && isSelected && (
                          <div
                            onClick={(e) => {
                              e.stopPropagation();
                            }}
                            className="mt-3 pt-3 border-t border-white/5 space-y-3 text-left w-full"
                          >
                            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-2">Advanced Auth Checks</div>
                            
                            {/* Browser Auth Analysis */}
                            <div className="flex items-center justify-between gap-3">
                              <div>
                                <div className="text-[11px] font-medium text-slate-300">Browser Auth Analysis</div>
                                <div className="text-[10px] text-slate-500">Inspect storage, cookies, network auth signals</div>
                              </div>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setAuthBrowserAnalysis(!authBrowserAnalysis);
                                }}
                                className={`relative inline-flex h-4 w-7 flex-shrink-0 cursor-pointer rounded-full border border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                  authBrowserAnalysis ? "bg-blue-600 border-blue-500" : "bg-slate-800 border-slate-700"
                                }`}
                              >
                                <span className={`pointer-events-none inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out ${
                                  authBrowserAnalysis ? "translate-x-3" : "translate-x-0"
                                }`} />
                              </button>
                            </div>

                            {/* Authorized Auth Flow Checks */}
                            <div className="flex items-center justify-between gap-3">
                              <div>
                                <div className="text-[11px] font-medium text-slate-300">Authorized Auth Flow Checks</div>
                                <div className="text-[10px] text-slate-500">Uses supplied auth/session for safe GET/HEAD checks only</div>
                              </div>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  const next = !authorizedAuthMode;
                                  setAuthorizedAuthMode(next);
                                  if (!next) {
                                    setAuthLifecycleChecks(false);
                                    setAuthzTransitionChecks(false);
                                    setSessionCookie("");
                                  }
                                }}
                                className={`relative inline-flex h-4 w-7 flex-shrink-0 cursor-pointer rounded-full border border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                  authorizedAuthMode ? "bg-blue-600 border-blue-500" : "bg-slate-800 border-slate-700"
                                }`}
                              >
                                <span className={`pointer-events-none inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out ${
                                  authorizedAuthMode ? "translate-x-3" : "translate-x-0"
                                }`} />
                              </button>
                            </div>

                            {/* Authorized Warning */}
                            {authorizedAuthMode && (
                              <div className="bg-amber-500/10 border border-amber-500/20 text-amber-400 p-2 rounded-lg text-[9px] leading-tight flex items-start gap-2">
                                <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
                                <span>Authorized checks may use supplied authenticated cookies/session and will only perform safe GET/HEAD requests unless explicitly configured.</span>
                              </div>
                            )}

                            {/* Session Cookie Option */}
                            {authorizedAuthMode && (
                              <div className="flex flex-col gap-1 mt-1 border-b border-white/5 pb-3">
                                <label className="text-[11px] font-medium text-slate-300">Session Cookie</label>
                                <input
                                  type="text"
                                  value={sessionCookie}
                                  onChange={(e) => setSessionCookie(e.target.value)}
                                  placeholder="session=abc123xyz; csrftoken=..."
                                  className="w-full bg-slate-950/40 border border-white/[0.08] rounded-lg px-3 py-1.5 text-[10px] text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50 transition-colors"
                                  onClick={(e) => e.stopPropagation()}
                                />
                                <div className="text-[10px] text-slate-500">Used for authenticated GET/HEAD authorization checks.</div>
                              </div>
                            )}

                            {/* Token Lifecycle Checks */}
                            <div className={`flex items-center justify-between gap-3 ${authorizedAuthMode ? "" : "opacity-50"}`}>
                              <div>
                                <div className="text-[11px] font-medium text-slate-300">Token Lifecycle Checks</div>
                                <div className="text-[10px] text-slate-500">Logout invalidation and refresh-token rotation checks</div>
                              </div>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (authorizedAuthMode) setAuthLifecycleChecks(!authLifecycleChecks);
                                }}
                                disabled={!authorizedAuthMode}
                                className={`relative inline-flex h-4 w-7 flex-shrink-0 cursor-pointer rounded-full border border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                  authLifecycleChecks ? "bg-blue-600 border-blue-500" : "bg-slate-800 border-slate-700"
                                }`}
                              >
                                <span className={`pointer-events-none inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out ${
                                  authLifecycleChecks ? "translate-x-3" : "translate-x-0"
                                }`} />
                              </button>
                            </div>

                            {/* AuthZ Transition Checks */}
                            <div className={`flex items-center justify-between gap-3 ${authorizedAuthMode ? "" : "opacity-50"}`}>
                              <div>
                                <div className="text-[11px] font-medium text-slate-300">AuthZ Transition Checks</div>
                                <div className="text-[10px] text-slate-500">Compare unauthenticated vs authenticated protected routes</div>
                              </div>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (authorizedAuthMode) setAuthzTransitionChecks(!authzTransitionChecks);
                                }}
                                disabled={!authorizedAuthMode}
                                className={`relative inline-flex h-4 w-7 flex-shrink-0 cursor-pointer rounded-full border border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                  authzTransitionChecks ? "bg-blue-600 border-blue-500" : "bg-slate-800 border-slate-700"
                                }`}
                              >
                                <span className={`pointer-events-none inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out ${
                                  authzTransitionChecks ? "translate-x-3" : "translate-x-0"
                                }`} />
                              </button>
                            </div>

                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {launchError && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-xs font-medium">
                  {launchError}
                </div>
              )}

              {/* Launch CTA */}
              <Button
                type="submit"
                variant="primary"
                isLoading={isLaunching}
                disabled={tests.length === 0}
                className="w-full justify-center gap-2 mt-2"
              >
                <Play className="w-4 h-4" /> Launch Ingestion
              </Button>
            </form>
          </Card>
        </div>

        {/* History Listing Card */}
        <div className="lg:col-span-2">
          <Card title="Investigation Pipeline Logs" description="Review and monitor status logs">
            {isHistoryLoading ? (
              <div className="py-20 text-center text-slate-500 font-medium font-sans">
                <span className="inline-block animate-spin mr-2 h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full" />
                Loading logs...
              </div>
            ) : history.length === 0 ? (
              <div className="py-20 text-center text-slate-500 flex flex-col items-center justify-center">
                <Database className="w-8 h-8 mb-2 opacity-20" />
                <p className="text-sm font-semibold">No investigations started yet.</p>
                <p className="text-xs text-slate-500 mt-1">Configure parameters and start your first security scan.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-slate-400 font-semibold bg-slate-900/10">
                      <th className="py-3 px-4">Investigation ID / Scan</th>
                      <th className="py-3 px-4">Target</th>
                      <th className="py-3 px-4">Risk</th>
                      <th className="py-3 px-4">Active Stage</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Date</th>
                      <th className="py-3 px-4"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.04]">
                    {history.map((inv) => {
                      const idShort = inv.id.substring(0, 8);
                      const isFailed = inv.status === "failed";
                      const isCompleted = inv.status === "completed";

                      return (
                        <tr
                          key={inv.id}
                          onClick={() => router.push(`/dashboard/investigations/${inv.id}`)}
                          className="hover:bg-white/[0.02] cursor-pointer transition-colors group"
                        >
                          <td className="py-4 px-4 font-mono text-xs font-semibold text-slate-300">
                            <div>{inv.scan_id || "SCAN-INF"}</div>
                            <div className="text-[10px] text-slate-500 uppercase tracking-widest mt-0.5">
                              ID: {idShort}
                            </div>
                          </td>
                          <td className="py-4 px-4 text-slate-200 font-medium max-w-[180px] truncate">
                            {inv.target}
                          </td>
                          <td className="py-4 px-4">
                            <span
                              className={`font-bold font-mono text-xs ${
                                isFailed
                                  ? "text-slate-500"
                                  : inv.risk_score > 60
                                  ? "text-red-400"
                                  : inv.risk_score > 30
                                  ? "text-orange-400"
                                  : "text-emerald-400"
                              }`}
                            >
                              {isFailed ? "—" : Math.round(inv.risk_score)}
                            </span>
                          </td>
                          <td className="py-4 px-4 text-xs text-slate-400 font-medium">
                            {inv.current_stage || "Queued"}
                          </td>
                          <td className="py-4 px-4">{getStatusBadge(inv.status)}</td>
                          <td className="py-4 px-4 text-[10px] text-slate-500 font-medium">
                            <div className="flex items-center gap-1">
                              <Clock className="w-3.5 h-3.5" />
                              {new Date(inv.started_at).toLocaleDateString()}
                            </div>
                          </td>
                          <td className="py-4 px-4 text-right">
                            <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-blue-400 group-hover:translate-x-1 transition-all" />
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
