"use client";

import React, { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { api } from "@/lib/api";
import { supabase } from "@/lib/supabase";
import {
  ShieldAlert, ShieldCheck, Activity, Search, AlertTriangle, 
  Terminal, Server, Globe, FileKey, Layers, Radar, CheckCircle2,
  XCircle, Copy, Code, ArrowRight, Zap, Target, ChevronDown, ChevronUp, ExternalLink,
  Eye, EyeOff, Lock, Unlock, Command
} from "lucide-react";

// --- Types ---
interface Finding {
  id: string;
  title: string;
  module: string;
  classification: "vulnerability" | "misconfiguration" | "hardening" | "informational";
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "verified" | "high" | "medium" | "low" | "potential";
  confidence_label?: string;
  verified?: boolean;
  url: string;
  description: string;
  evidence: string;
  recommendation: string;
  severity_justification?: string;
  auto_fix?: string;
  cwe_id?: string;
  tags?: string[];
  reproduction_data?: Record<string, any>;
}

interface ScanSummary {
  scan_id: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  endpoints_found: number;
  attack_surface_endpoints_count: number;
  duration: number;
  started_at: string;
  risk_score: number;
  mode: string;
}

interface DetectedTech {
  name: string;
  category: string;
  confidence: string;
  evidence: string;
  source?: string;
}

interface DetectedAsset {
  type: string;
  url: string;
  confidence: string;
}

interface NormalizedFinding {
  finding_id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  affected_url: string;
  evidence: string;
  raw_value: any;
  recommendation: string;
}

interface ScannerJson {
  scan_id: string;
  target: { url: string; domain: string; ip: string; app_type: string; scan_mode: string; };
  detected_technologies: DetectedTech[];
  detected_assets: DetectedAsset[];
  technology_metadata?: DetectedTech[];
  findings: NormalizedFinding[];
}

interface ScanResult {
  scan_id: string;
  target: string;
  mode: string;
  started_at: string;
  duration: number;
  risk_score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  endpoints_found: number;
  attack_surface_endpoints_count: number;
  executions_confirmed?: number;
  findings: Finding[];
  error?: string;
  detected_technologies?: DetectedTech[];
  detected_assets?: DetectedAsset[];
  technology_metadata?: DetectedTech[];
  scanner_json?: ScannerJson;
}

interface HistoryItem {
  id: string;
  target: string;
  summary: ScanSummary;
  created_at: string;
}

// --- UI Components ---

const CollapsibleSection = ({ title, content, icon: Icon, defaultOpen = false, mono = true }: { title: string, content: string | null | undefined, icon: any, defaultOpen?: boolean, mono?: boolean }) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  if (!content) return null;

  return (
    <div className="border border-white/5 rounded-xl overflow-hidden bg-slate-950/20 mb-3">
      <button 
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-white/5 transition-all group"
      >
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 group-hover:text-slate-200">
          <Icon className="w-3.5 h-3.5" />
          {title}
        </div>
        {isOpen ? <ChevronUp className="w-3.5 h-3.5 text-slate-500" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-500" />}
      </button>
      {isOpen && (
        <div className="px-4 pb-4">
          <div className={`p-3 rounded-lg bg-black/40 border border-white/5 text-[11px] ${mono ? 'font-mono' : 'font-sans'} text-slate-300 break-all whitespace-pre-wrap relative group`}>
            {content}
            <button 
              onClick={(e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(content);
              }}
              className="absolute top-2 right-2 p-1.5 bg-slate-800/50 hover:bg-purple-600/50 rounded-md transition-all opacity-0 group-hover:opacity-100"
            >
              <Copy className="w-3 h-3 text-white" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

const ReproductionCurl = ({ url, method, data, cookies }: { url: string, method: string, data?: any, cookies?: string }) => {
  // Mask cookies: PHPSESSID=... -> PHPSESSID=<redacted>
  const maskCookies = (c: string | undefined) => {
    if (!c) return "PHPSESSID=<redacted>";
    return c.replace(/PHPSESSID=[^;]+/g, "PHPSESSID=<redacted>");
  };

  const curl = `curl -X ${method} "${url}" \\\n  -H "Cookie: ${maskCookies(cookies)}" \\\n  -H "User-Agent: TIBSA-Scanner/4.0" ${data ? `\\\n  -d '${JSON.stringify(data)}'` : ''}`;

  return (
    <CollapsibleSection title="Reproduction Command (Curl)" content={curl} icon={Command} />
  );
};

const severityColors = {
  critical: "bg-red-600/10 text-red-500 border-red-600/20",
  high: "bg-red-500/10 text-red-400 border-red-500/20",
  medium: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  low: "bg-yellow-500/10 text-yellow-400 border-yellow-400/20",
  info: "bg-slate-500/10 text-slate-400 border-slate-500/20"
};

const getSqlmapEvidence = (evidence: any) => {
  if (!evidence) return null;
  let obj = evidence;
  if (typeof evidence === "string") {
    try {
      obj = JSON.parse(evidence);
    } catch {
      return null;
    }
  }
  if (typeof obj === "object" && obj !== null && "sqlmap" in obj) {
    return obj.sqlmap;
  }
  return null;
};

const mapVerificationReason = (reason: string) => {
  const mapping: Record<string, string> = {
    sqlmap_negative_log: "SQLMap rejected exploitation",
    sqlmap_data_payload: "Confirmed via extracted sqlmap data",
    sqlmap_strong_positive_log: "Confirmed via sqlmap detection logs",
    no_vulnerability_indicators: "No reliable exploitation evidence",
  };
  return mapping[reason] || reason;
};

const TechnicalEvidenceTable = ({ evidence }: { evidence: any }) => {
  const [copiedKey, setCopiedKey] = React.useState<string | null>(null);
  const [expandedKeys, setExpandedKeys] = React.useState<Record<string, boolean>>({});

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleExpand = (key: string) => {
    setExpandedKeys(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const copyableFields = ['PAYLOAD', 'URL', 'VERIFICATION URL', 'TESTED URL', 'CURL', 'COMMAND', 'IMPLEMENTATION FIX', 'FIX', 'EVIDENCE', 'DATA'];

  // Parsing logic
  let rows: { key: string, value: string }[] = [];
  
  if (typeof evidence === 'object' && evidence !== null) {
    rows = Object.entries(evidence)
      .filter(([k]) => k !== "sqlmap")
      .map(([k, v]) => ({ 
        key: k.replace(/_/g, ' ').toUpperCase(), 
        value: typeof v === 'object' ? JSON.stringify(v) : String(v) 
      }));
  } else if (typeof evidence === 'string') {
    const lines = evidence.split(/\n/);
    lines.forEach(line => {
      const trimmed = line.trim();
      if (!trimmed) return;
      const match = trimmed.match(/^-?\s*([^:]+):\s*(.*)$/);
      if (match) {
        rows.push({ key: match[1].trim().toUpperCase(), value: match[2].trim() });
      } else {
        if (rows.length > 0 && !trimmed.includes(':')) {
           rows[rows.length - 1].value += "\n" + trimmed;
        } else {
           rows.push({ key: "DATA", value: trimmed });
        }
      }
    });
  }

  const renderValue = (key: string, value: string, rowKey: string) => {
    // Special handling for Preserved Parameters (JSON)
    if (key.includes('PRESERVED PARAMETERS') || (key.includes('PARAMETERS') && value.startsWith('{'))) {
      try {
        const parsed = JSON.parse(value);
        if (typeof parsed === 'object' && parsed !== null && Object.keys(parsed).length > 0) {
          return (
            <div className="space-y-1.5 py-1 w-full">
              {Object.entries(parsed).map(([pk, pv]) => (
                <div key={pk} className="flex flex-col sm:flex-row sm:gap-3 text-[10px] border-l border-emerald-500/20 pl-3">
                  <span className="text-slate-500 font-bold sm:min-w-[120px]">{pk}:</span>
                  <span className="text-emerald-300 break-all">{String(pv)}</span>
                </div>
              ))}
            </div>
          );
        }
      } catch (e) {}
    }

    const isLong = value.length > 100;
    const isExpanded = expandedKeys[rowKey];
    const displayValue = isLong && !isExpanded ? value.substring(0, 100) + "..." : value;

    return (
      <div className="flex-1 whitespace-pre-wrap leading-relaxed pr-10">
        {displayValue}
        {isLong && (
          <button 
            onClick={() => toggleExpand(rowKey)}
            className="ml-3 text-[9px] font-black text-purple-400/70 hover:text-purple-400 transition-colors uppercase underline underline-offset-2"
          >
            {isExpanded ? "[Collapse]" : "[Show Full]"}
          </button>
        )}
      </div>
    );
  };

  return (
    <div className="bg-[#050505]/40 border border-white/10 rounded-xl overflow-hidden shadow-2xl font-mono text-[11px]">
      <div className="flex flex-col divide-y divide-white/5">
        {rows.map((row, idx) => {
          const rowKey = `${row.key}-${idx}`;
          const isCopyable = copyableFields.some(f => row.key.includes(f));

          return (
            <div key={idx} className="flex flex-col md:grid md:grid-cols-[220px_1fr] group hover:bg-white/[0.02] transition-colors relative">
              {/* Key Column */}
              <div className="px-5 py-4 text-slate-500 bg-white/[0.01] border-b md:border-b-0 md:border-r border-white/5 font-sans uppercase text-[10px] font-black tracking-widest flex items-center whitespace-nowrap overflow-hidden text-ellipsis">
                {row.key}
              </div>
              
              {/* Value Column */}
              <div className="px-5 py-4 text-emerald-400/90 relative flex items-start group/val">
                {renderValue(row.key, row.value, rowKey)}
                
                {/* Copy Button on the right */}
                {isCopyable && (
                  <button 
                    onClick={() => copyToClipboard(row.value, rowKey)}
                    className="absolute right-4 top-4 p-1.5 bg-slate-800/80 hover:bg-emerald-600/50 border border-white/10 rounded-md text-white transition-all opacity-0 group-hover:opacity-100 flex items-center gap-1.5 z-10"
                    title="Copy Value"
                  >
                    {copiedKey === rowKey ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copiedKey === rowKey && <span className="text-[9px] font-bold">COPIED</span>}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const defaultTests = [
  { id: "security_headers", label: "Security Headers", icon: Layers, desc: "CSP, HSTS, X-Frame-Options" },
  { id: "cookie_analysis", label: "Cookie Security", icon: FileKey, desc: "Secure, HttpOnly, SameSite" },
  { id: "xss", label: "XSS Verification", icon: Code, desc: "Playwright DOM/Reflected Analysis" },
  { id: "sqli", label: "SQL Injection", icon: Server, desc: "sqlmap integration & boolean blind" },
  { id: "misconfiguration", label: "Misconfigurations", icon: AlertTriangle, desc: "CORS, Open Redirects, Exposed Files" },
  { id: "directory_discovery", label: "Directory Fuzzing", icon: Search, desc: "ffuf path discovery" },
  { id: "auth_security", label: "Auth Security", icon: ShieldCheck, desc: "Rate limits, session strength, MFA checks" },
  { id: "bac", label: "Access Control / IDOR", icon: Lock, desc: "IDOR, object access, role checks" },
  { id: "endpoint_crawling", label: "Deep Crawling", icon: Globe, desc: "Katana headless extraction" },
];

export default function WebsiteScannerPage() {
  const [targetUrl, setTargetUrl] = useState("");
  const [authMode, setAuthMode] = useState<"none" | "cookie" | "auto">("none");
  const [sessionCookie, setSessionCookie] = useState("");
  const [loginUrl, setLoginUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [securityLevel, setSecurityLevel] = useState("low");
  const [selectedTests, setSelectedTests] = useState<string[]>([]);
  const [scanMode, setScanMode] = useState("safe");
  const [enableSqlmap, setEnableSqlmap] = useState(false);
  const [authBrowserAnalysis, setAuthBrowserAnalysis] = useState(false);
  const [authorizedAuthMode, setAuthorizedAuthMode] = useState(false);
  const [authLifecycleChecks, setAuthLifecycleChecks] = useState(false);
  const [authzTransitionChecks, setAuthzTransitionChecks] = useState(false);
  
  const [isScanning, setIsScanning] = useState(false);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [showMetadata, setShowMetadata] = useState(false);
  const [assetSearch, setAssetSearch] = useState("");
  const [assetGrouped, setAssetGrouped] = useState(false);
  const [assetLimit, setAssetLimit] = useState(10);
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"findings" | "overview" | "technology">("overview");

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) return;
      const data = await api.get<HistoryItem[]>("/api/v1/website-scanner/history", session.access_token);
      setHistory(data || []);
    } catch (err: any) {
      console.error("Failed to fetch history", err);
    }
  };

  const loadPastScan = async (id: string) => {
    try {
      setIsScanning(true);
      setError("");
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) throw new Error("Not authenticated");
      const data = await api.get<any>(`/api/v1/website-scanner/history/${id}`, session.access_token);
      
      const hydrated = {
        detected_technologies: data.detected_technologies || data.summary?.detected_technologies || data.scanner_json?.detected_technologies || [],
        detected_assets: data.detected_assets || data.summary?.detected_assets || data.scanner_json?.detected_assets || [],
        technology_metadata: data.technology_metadata || data.summary?.technology_metadata || data.scanner_json?.technology_metadata || [],
        scanner_json: data.scanner_json || data.summary?.scanner_json || null
      };

      console.log("[HISTORY HYDRATION] technologies", hydrated.detected_technologies?.length);
      console.log("[HISTORY HYDRATION] assets", hydrated.detected_assets?.length);
      console.log("[HISTORY HYDRATION] metadata", hydrated.technology_metadata?.length);
      console.log("[HISTORY HYDRATION] scanner_json", !!hydrated.scanner_json);
      
      setCurrentResult({
        scan_id: data.summary?.scan_id || data.id,
        target: data.target,
        mode: data.summary?.mode || "unknown",
        started_at: data.summary?.started_at || data.created_at,
        duration: data.summary?.duration || 0,
        risk_score: data.summary?.risk_score || 0,
        critical: data.summary?.critical || 0,
        high: data.summary?.high || 0,
        medium: data.summary?.medium || 0,
        low: data.summary?.low || 0,
        info: data.summary?.info || 0,
        total: data.summary?.total || 0,
        endpoints_found: data.summary?.endpoints_found || 0,
        attack_surface_endpoints_count: data.summary?.attack_surface_endpoints_count || 0,
        executions_confirmed: data.executions_confirmed || 0,
        findings: data.findings || [],
        error: data.error,
        detected_technologies: hydrated.detected_technologies,
        detected_assets: hydrated.detected_assets,
        technology_metadata: hydrated.technology_metadata,
        scanner_json: hydrated.scanner_json,
      });
      setActiveTab("overview");
    } catch (err: any) {
      setError(err.message || "Failed to load scan details.");
    } finally {
      setIsScanning(false);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl) return;
    if (selectedTests.length === 0) {
      setError("Please select at least one test module.");
      return;
    }

    console.log("Selected tests:", selectedTests);

    setIsScanning(true);
    setCurrentResult(null);
    setError("");

    try {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) throw new Error("Not authenticated");

      const result = await api.post<ScanResult>("/api/v1/website-scanner/scan", {
        target: targetUrl,
        tests: selectedTests,
        mode: scanMode,
        enable_sqlmap: enableSqlmap,
        auth_browser_analysis: authBrowserAnalysis,
        authorized_auth_mode: authorizedAuthMode,
        auth_lifecycle_checks: authLifecycleChecks,
        authz_transition_checks: authzTransitionChecks,
        session_cookie: sessionCookie ? sessionCookie.trim() : null,
        auth: authMode === "auto" ? {
          type: "form_login",
          login_url: loginUrl,
          username: username,
          password: password,
          extra_fields: { security: securityLevel }
        } : { type: "none" }
      }, session.access_token);

      setCurrentResult(result);
      if (result.error) setError(result.error);
      fetchHistory();
      setActiveTab("overview");
      console.log("detected_technologies", result.detected_technologies || []);
      console.log("detected_assets", result.detected_assets || []);
    } catch (err: any) {
      setError(err.message || "An error occurred during scanning.");
    } finally {
      setIsScanning(false);
    }
  };

  const toggleTest = (id: string) => {
    setSelectedTests(prev => {
      const isRemoving = prev.includes(id);
      if (id === "sqli" && isRemoving) {
        setEnableSqlmap(false);
      }
      if (id === "auth_security" && isRemoving) {
        setAuthBrowserAnalysis(false);
        setAuthorizedAuthMode(false);
        setAuthLifecycleChecks(false);
        setAuthzTransitionChecks(false);
      }
      return isRemoving ? prev.filter(t => t !== id) : [...prev, id];
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="min-h-screen bg-[#050B14] text-slate-300 p-6 font-sans selection:bg-purple-500/30">
      
      {/* Header */}
      <div className="flex items-center justify-between mb-8 pb-6 border-b border-white/5">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <div className="p-2 bg-purple-500/10 rounded-lg border border-purple-500/20">
              <Radar className="w-8 h-8 text-purple-400" />
            </div>
            Enterprise Pentest Module
          </h1>
          <p className="text-slate-400 mt-2">Browser-verified vulnerability assessment and intelligence gathering.</p>
        </div>
      </div>

      <div className="grid lg:grid-cols-[1fr_350px] gap-6">
        
        {/* Main Content Area */}
        <div className="space-y-6">
          
          {/* Scanner Controls */}
          <div className="bg-[#0A101C] border border-white/5 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 w-96 h-96 bg-purple-500/5 blur-[100px] pointer-events-none" />
            
            <form onSubmit={handleScan} className="relative z-10">
              <div className="flex gap-4 mb-6">
                <div className="flex-1 relative group">
                  <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                    <Target className="w-5 h-5 text-slate-500 group-focus-within:text-purple-400 transition-colors" />
                  </div>
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full bg-slate-900/50 border border-white/10 rounded-xl py-4 pl-12 pr-4 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/50 transition-all"
                    disabled={isScanning}
                  />
                </div>
                <button
                  type="submit"
                  disabled={isScanning || !targetUrl || selectedTests.length === 0}
                  className="bg-purple-600 hover:bg-purple-500 text-white px-8 rounded-xl font-medium flex items-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(147,51,234,0.3)] hover:shadow-[0_0_30px_rgba(147,51,234,0.5)]"
                >
                  {isScanning ? (
                    <><Activity className="w-5 h-5 animate-pulse" /> Scanning...</>
                  ) : (
                    <><Zap className="w-5 h-5" /> Launch Scan</>
                  )}
                </button>
              </div>

              <div className="mb-6 p-4 bg-slate-900/30 border border-white/5 rounded-2xl">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-purple-400" /> Authentication Configuration
                  </h3>
                  <div className="flex bg-slate-950/50 p-1 rounded-lg border border-white/5">
                    {(["none", "cookie", "auto"] as const).map(mode => (
                      <button
                        key={mode}
                        type="button"
                        onClick={() => setAuthMode(mode)}
                        className={`px-3 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-all ${
                          authMode === mode ? "bg-purple-600 text-white shadow-lg" : "text-slate-500 hover:text-slate-300"
                        }`}
                      >
                        {mode === "none" ? "No Auth" : mode === "cookie" ? "Cookie" : "Auto Login"}
                      </button>
                    ))}
                  </div>
                </div>

                {authMode === "cookie" && (
                  <div className="relative group">
                    <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                      <FileKey className="w-4 h-4 text-slate-500" />
                    </div>
                    <input
                      type="text"
                      value={sessionCookie}
                      onChange={(e) => setSessionCookie(e.target.value)}
                      placeholder="PHPSESSID=...; security=low"
                      className="w-full bg-slate-950/50 border border-white/10 rounded-xl py-3 pl-12 pr-4 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500/50 transition-all text-xs"
                    />
                  </div>
                )}

                {authMode === "auto" && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="relative">
                        <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                          <Globe className="w-4 h-4 text-slate-500" />
                        </div>
                        <input
                          type="text"
                          value={loginUrl}
                          onChange={(e) => setLoginUrl(e.target.value)}
                          placeholder="Login URL"
                          className="w-full bg-slate-950/50 border border-white/10 rounded-xl py-3 pl-12 pr-4 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500/50 transition-all text-xs"
                        />
                      </div>
                      <div className="relative">
                        <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                          <CheckCircle2 className="w-4 h-4 text-slate-500" />
                        </div>
                        <select
                          value={securityLevel}
                          onChange={(e) => setSecurityLevel(e.target.value)}
                          className="w-full bg-slate-950/50 border border-white/10 rounded-xl py-3 pl-12 pr-4 text-white focus:outline-none focus:border-purple-500/50 transition-all text-xs appearance-none"
                        >
                          <option value="low">Security: Low</option>
                          <option value="medium">Security: Medium</option>
                          <option value="high">Security: High</option>
                          <option value="impossible">Security: Impossible</option>
                        </select>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="Username"
                        className="w-full bg-slate-950/50 border border-white/10 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500/50 transition-all text-xs"
                      />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Password"
                        className="w-full bg-slate-950/50 border border-white/10 rounded-xl py-3 px-4 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500/50 transition-all text-xs"
                      />
                    </div>
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-4 mb-6">
                <span className="text-sm font-medium text-slate-400">Scan Mode:</span>
                {(["passive", "safe", "aggressive"] as const).map(mode => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setScanMode(mode)}
                    disabled={isScanning}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all capitalize border ${
                      scanMode === mode 
                        ? mode === "aggressive" ? "bg-red-500/10 text-red-400 border-red-500/30" : "bg-purple-500/10 text-purple-400 border-purple-500/30"
                        : "bg-slate-900/50 text-slate-400 border-white/5 hover:bg-white/5"
                    }`}
                  >
                    {mode}
                  </button>
                ))}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 items-start">
                {defaultTests.map(test => {
                  const isSelected = selectedTests.includes(test.id);
                  const Icon = test.icon;
                  return (
                    <div
                      key={test.id}
                      onClick={() => {
                        if (!isScanning) {
                          toggleTest(test.id);
                        }
                      }}
                      className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                        isScanning ? "opacity-60 cursor-not-allowed" : ""
                      } ${
                        isSelected 
                          ? "bg-purple-500/5 border-purple-500/30" 
                          : "bg-slate-900/30 border-white/5 hover:bg-white/5"
                      }`}
                    >
                      <Icon className={`w-5 h-5 mb-2 ${isSelected ? "text-purple-400" : "text-slate-500"}`} />
                      <div className={`font-medium text-sm mb-1 ${isSelected ? "text-white" : "text-slate-400"}`}>
                        {test.label}
                      </div>
                      <div className="text-[10px] text-slate-500 line-clamp-1">{test.desc}</div>
                      
                      {test.id === "sqli" && isSelected && (
                        <div
                          onClick={(e) => {
                            e.stopPropagation();
                          }}
                          className={`mt-3 pt-3 border-t border-white/5 space-y-3 ${
                            isSelected ? "opacity-100" : "opacity-50"
                          }`}
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
                                if (!isScanning) {
                                  setEnableSqlmap(!enableSqlmap);
                                }
                              }}
                              disabled={isScanning}
                              className={`relative h-5 w-9 shrink-0 rounded-full transition-all ${
                                enableSqlmap ? "bg-purple-500" : "bg-slate-700"
                              }`}
                            >
                              <span
                                className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${
                                  enableSqlmap ? "left-4" : "left-0.5"
                                }`}
                              />
                            </button>
                          </div>
                        </div>
                      )}

                      {test.id === "auth_security" && isSelected && (
                        <div
                          onClick={(e) => {
                            e.stopPropagation();
                          }}
                          className={`mt-3 pt-3 border-t border-white/5 space-y-3 ${
                            isSelected ? "opacity-100" : "opacity-50"
                          }`}
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
                                if (!isScanning) setAuthBrowserAnalysis(!authBrowserAnalysis);
                              }}
                              disabled={isScanning}
                              className={`relative h-5 w-9 shrink-0 rounded-full transition-all ${authBrowserAnalysis ? "bg-purple-500" : "bg-slate-700"}`}
                            >
                              <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${authBrowserAnalysis ? "left-4" : "left-0.5"}`} />
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
                                if (!isScanning) {
                                  const next = !authorizedAuthMode;
                                  setAuthorizedAuthMode(next);
                                  if (!next) {
                                    setAuthLifecycleChecks(false);
                                    setAuthzTransitionChecks(false);
                                    setSessionCookie("");
                                  }
                                }
                              }}
                              disabled={isScanning}
                              className={`relative h-5 w-9 shrink-0 rounded-full transition-all ${authorizedAuthMode ? "bg-purple-500" : "bg-slate-700"}`}
                            >
                              <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${authorizedAuthMode ? "left-4" : "left-0.5"}`} />
                            </button>
                          </div>

                          {/* Authorized Warning */}
                          {authorizedAuthMode && (
                            <div className="bg-amber-500/10 border border-amber-500/20 text-amber-400 p-2 rounded-lg text-[10px] leading-tight flex items-start gap-2">
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
                                className="w-full bg-[#0A101C] border border-white/10 rounded-lg px-3 py-1.5 text-[10px] text-white placeholder-slate-600 focus:outline-none focus:border-purple-500/50 transition-colors"
                                disabled={isScanning}
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
                                if (!isScanning && authorizedAuthMode) setAuthLifecycleChecks(!authLifecycleChecks);
                              }}
                              disabled={isScanning || !authorizedAuthMode}
                              className={`relative h-5 w-9 shrink-0 rounded-full transition-all ${authLifecycleChecks ? "bg-purple-500" : "bg-slate-700"}`}
                            >
                              <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${authLifecycleChecks ? "left-4" : "left-0.5"}`} />
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
                                if (!isScanning && authorizedAuthMode) setAuthzTransitionChecks(!authzTransitionChecks);
                              }}
                              disabled={isScanning || !authorizedAuthMode}
                              className={`relative h-5 w-9 shrink-0 rounded-full transition-all ${authzTransitionChecks ? "bg-purple-500" : "bg-slate-700"}`}
                            >
                              <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${authzTransitionChecks ? "left-4" : "left-0.5"}`} />
                            </button>
                          </div>

                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </form>
          </div>

          {/* Results Area */}
          {currentResult && (
            <div className="bg-[#0A101C] border border-white/5 rounded-2xl shadow-2xl overflow-hidden">
              {/* Results Tabs + Export Button */}
              <div className="flex border-b border-white/5 bg-slate-900/30 items-center">
                <button
                  onClick={() => setActiveTab("overview")}
                  className={`px-6 py-4 font-medium text-sm flex items-center gap-2 border-b-2 transition-all ${
                    activeTab === "overview" ? "border-purple-500 text-white bg-purple-500/5" : "border-transparent text-slate-400 hover:text-white"
                  }`}
                >
                  <Activity className="w-4 h-4" /> Overview
                </button>
                <button
                  onClick={() => setActiveTab("technology")}
                  className={`px-6 py-4 font-medium text-sm flex items-center gap-2 border-b-2 transition-all ${
                    activeTab === "technology" ? "border-emerald-500 text-white bg-emerald-500/5" : "border-transparent text-slate-400 hover:text-white"
                  }`}
                >
                  <Server className="w-4 h-4" /> Technologies
                  {(currentResult.detected_technologies?.length ?? 0) > 0 && (
                    <span className="text-[10px] font-bold bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded-full">
                      {currentResult.detected_technologies?.length}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => setActiveTab("findings")}
                  className={`px-6 py-4 font-medium text-sm flex items-center gap-2 border-b-2 transition-all ${
                    activeTab === "findings" ? "border-purple-500 text-white bg-purple-500/5" : "border-transparent text-slate-400 hover:text-white"
                  }`}
                >
                  <ShieldAlert className="w-4 h-4" /> Findings ({currentResult.findings.length})
                </button>

                {/* Export Scanner JSON Button */}
                <div className="ml-auto pr-4 flex gap-2">
                  {currentResult.scanner_json && (
                    <>
                      <button
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(currentResult.scanner_json, null, 2)], { type: 'application/json' });
                          const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
                          a.download = `scanner_context_${currentResult.scan_id}.json`; a.click();
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600/10 hover:bg-emerald-600/20 border border-emerald-500/30 text-emerald-400 rounded-lg text-[11px] font-bold transition-all"
                        title="Download scanner_context.json"
                      >
                        <Zap className="w-3 h-3" /> Export JSON
                      </button>
                      <button
                        onClick={() => { navigator.clipboard.writeText(JSON.stringify(currentResult.scanner_json, null, 2)); }}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700/50 hover:bg-slate-600/50 border border-white/10 text-slate-300 rounded-lg text-[11px] font-bold transition-all"
                        title="Copy scanner JSON to clipboard"
                      >
                        <Copy className="w-3 h-3" /> Copy
                      </button>
                      <a
                        href={`/dashboard/website-scanner/review?scan_id=${currentResult.scan_id}`}
                        onClick={(e) => {
                          e.preventDefault();
                          localStorage.setItem('tibsa_scanner_json', JSON.stringify(currentResult.scanner_json));
                          window.location.href = `/dashboard/website-scanner/review`;
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-600/10 hover:bg-purple-600/20 border border-purple-500/30 text-purple-400 rounded-lg text-[11px] font-bold transition-all"
                      >
                        <Eye className="w-3 h-3" /> Client Review
                      </a>
                    </>
                  )}
                </div>
              </div>

              <div className="p-6">
                {activeTab === "overview" && (
                   <div className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <div className="bg-slate-900/50 border border-white/5 rounded-xl p-6 flex flex-col items-center justify-center relative overflow-hidden">
                        <div className={`absolute inset-0 opacity-20 ${
                          (currentResult.risk_score ?? 0) > 70 ? "bg-red-500" : (currentResult.risk_score ?? 0) > 40 ? "bg-orange-500" : "bg-emerald-500"
                        } blur-[50px]`} />
                        <div className="text-sm font-medium text-slate-400 mb-2 relative z-10">Risk Score</div>
                        <div className={`text-6xl font-bold relative z-10 ${
                          (currentResult.risk_score ?? 0) > 70 ? "text-red-400" : (currentResult.risk_score ?? 0) > 40 ? "text-orange-400" : "text-emerald-400"
                        }`}>
                          {(currentResult.risk_score ?? 0).toFixed(0)}
                        </div>
                      </div>

                      <div className="col-span-2 grid grid-cols-2 md:grid-cols-4 gap-4">
                         {(["critical", "high", "medium", "low"] as const).map(sev => (
                           <div key={sev} className="bg-slate-900/50 border border-white/5 rounded-xl p-4 flex flex-col items-center justify-center">
                             <div className="text-3xl font-bold text-white mb-1">{currentResult[sev as keyof ScanResult] as number}</div>
                             <div className={`text-[10px] font-bold uppercase tracking-widest ${
                               sev === "critical" ? "text-red-400" :
                               sev === "high" ? "text-orange-400" :
                               sev === "medium" ? "text-yellow-400" : "text-blue-400"
                             }`}>{sev}</div>
                           </div>
                         ))}
                      </div>

                      {currentResult.executions_confirmed !== undefined && (
                        <div className="md:col-span-3 bg-purple-500/5 border border-purple-500/20 rounded-xl p-4 flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div className="p-2 bg-purple-500/20 rounded-lg">
                              <Zap className="w-5 h-5 text-purple-400" />
                            </div>
                            <div>
                              <div className="text-xs text-slate-400 font-medium">Verified Browser Executions</div>
                              <div className="text-lg font-bold text-white">XSS Confirmation Signal</div>
                            </div>
                          </div>
                          <div className="text-4xl font-black text-purple-400 mr-4">
                            {currentResult.executions_confirmed}
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                      <div className="bg-slate-900/30 p-3 rounded-lg border border-white/5 flex justify-between">
                        <span className="text-slate-500">Target:</span>
                        <span className="text-slate-300 truncate ml-4">{currentResult.target}</span>
                      </div>
                      <div className="bg-slate-900/30 p-3 rounded-lg border border-white/5 flex justify-between">
                        <span className="text-slate-500">Mode:</span>
                        <span className="text-slate-300 uppercase">{currentResult.mode}</span>
                      </div>
                      <div className="bg-slate-900/30 p-3 rounded-lg border border-white/5 flex justify-between">
                        <span className="text-slate-500">Attack Surface:</span>
                        <span className="text-red-400 font-bold">{currentResult.attack_surface_endpoints_count ?? 0} endpoints</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Technology Detection Tab */}
                {activeTab === "technology" && (
                  <div className="space-y-6">

                    {/* Detected Technologies */}
                    {(currentResult.detected_technologies?.length ?? 0) > 0 ? (
                      <div>
                        <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                          <Server className="w-4 h-4 text-emerald-400" />
                          Detected Technologies
                          <span className="text-xs font-normal text-slate-500">— evidence-based only</span>
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {currentResult.detected_technologies?.map((tech, i) => (
                            <div key={i} className="bg-slate-900/50 border border-white/5 rounded-xl p-4 hover:border-emerald-500/20 transition-all group">
                              <div className="flex items-start justify-between mb-2">
                                <div>
                                  <div className="font-semibold text-white text-sm group-hover:text-emerald-400 transition-colors">{tech.name}</div>
                                  <div className="flex items-center gap-2 mt-0.5">
                                    <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{tech.category.replace(/_/g, ' ')}</div>
                                    <span className="text-[8px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded bg-white/5 text-slate-400">
                                      SRC: {tech.source || "custom_detector"}
                                    </span>
                                  </div>
                                </div>
                                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                                  tech.confidence === 'high' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                                  tech.confidence === 'medium' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30' :
                                  'bg-slate-500/10 text-slate-400 border-slate-500/30'
                                }`}>{tech.confidence}</span>
                              </div>
                              <div className="text-[11px] text-slate-400 font-mono leading-relaxed bg-black/20 rounded-lg p-2 border border-white/5">
                                {tech.evidence}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-8 text-slate-500">
                        <Server className="w-8 h-8 mx-auto mb-3 opacity-30" />
                        <p className="text-sm">No technologies detected — insufficient evidence in target response.</p>
                      </div>
                    )}

                    {/* Technical Metadata Collapsible Section */}
                    {(currentResult.technology_metadata?.length ?? 0) > 0 && (
                      <div className="bg-slate-950/40 border border-white/5 rounded-2xl overflow-hidden shadow-2xl transition-all hover:border-white/10">
                        <button
                          onClick={() => setShowMetadata(!showMetadata)}
                          className="w-full flex items-center justify-between px-6 py-4 hover:bg-white/[0.02] transition-all group/meta-btn"
                        >
                          <div className="flex items-center gap-2 text-sm font-bold text-white">
                            <Layers className="w-4 h-4 text-purple-400" />
                            Technical Metadata
                            <span className="text-[10px] font-bold text-slate-500 bg-white/5 px-2 py-0.5 rounded border border-white/5 ml-1">
                              {currentResult.technology_metadata?.length} items
                            </span>
                          </div>
                          {showMetadata ? (
                            <ChevronUp className="w-4 h-4 text-slate-400 group-hover/meta-btn:text-white transition-colors" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-slate-400 group-hover/meta-btn:text-white transition-colors" />
                          )}
                        </button>
                        
                        {showMetadata && (
                          <div className="px-6 pb-6 pt-2 border-t border-white/5 bg-slate-900/10">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              {currentResult.technology_metadata?.map((meta, i) => (
                                <div key={i} className="bg-slate-900/30 border border-white/5 rounded-xl p-4 hover:border-purple-500/20 transition-all group">
                                  <div className="flex items-start justify-between mb-2">
                                    <div>
                                      <div className="font-semibold text-white text-sm group-hover:text-purple-400 transition-colors">{meta.name}</div>
                                      <div className="flex items-center gap-2 mt-0.5">
                                        <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{meta.category}</div>
                                        <span className="text-[8px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded bg-white/5 text-slate-400">
                                          SRC: {meta.source || "wappalyzer"}
                                        </span>
                                      </div>
                                    </div>
                                  </div>
                                  <div className="text-[11px] text-slate-400 font-mono leading-relaxed bg-black/20 rounded-lg p-2 border border-white/5 break-all max-h-24 overflow-y-auto">
                                    {meta.evidence}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Attack Surface Assets */}
                    {(currentResult.detected_assets?.length ?? 0) > 0 && (() => {
                      const assets = currentResult.detected_assets || [];
                      const filteredAssets = assets.filter(asset => {
                        const query = assetSearch.toLowerCase();
                        return asset.url.toLowerCase().includes(query) || 
                               asset.type.toLowerCase().includes(query);
                      });

                      const groupedAssets: Record<string, typeof assets> = {};
                      if (assetGrouped) {
                        filteredAssets.forEach(asset => {
                          const typeLabel = asset.type.replace(/_/g, ' ').toUpperCase();
                          if (!groupedAssets[typeLabel]) {
                            groupedAssets[typeLabel] = [];
                          }
                          groupedAssets[typeLabel].push(asset);
                        });
                      }

                      const totalCount = assets.length;
                      const displayedAssets = assetGrouped ? [] : filteredAssets.slice(0, assetLimit);

                      return (
                        <div className="space-y-4">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/5 pb-4">
                            <h3 className="text-sm font-bold text-white flex items-center gap-2">
                              <Target className="w-4 h-4 text-orange-400" />
                              Attack Surface Assets
                              <span className="text-[10px] font-bold text-slate-500 bg-white/5 px-2 py-0.5 rounded border border-white/5">
                                {totalCount}
                              </span>
                            </h3>
                            
                            <div className="flex items-center gap-2">
                              <div className="relative">
                                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                                <input
                                  type="text"
                                  placeholder="Search assets..."
                                  value={assetSearch}
                                  onChange={(e) => setAssetSearch(e.target.value)}
                                  className="pl-9 pr-4 py-1.5 bg-slate-950/60 border border-white/5 rounded-lg text-xs text-white placeholder-slate-500 focus:border-orange-500/50 focus:outline-none transition-all w-48 sm:w-64 font-medium"
                                />
                              </div>

                              <button
                                onClick={() => setAssetGrouped(!assetGrouped)}
                                className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                                  assetGrouped 
                                    ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' 
                                    : 'bg-slate-900/50 text-slate-400 border-white/5 hover:border-white/10'
                                }`}
                              >
                                {assetGrouped ? "Ungroup" : "Group by Type"}
                              </button>
                            </div>
                          </div>

                          {!assetGrouped ? (
                            <div className="space-y-2">
                              <AnimatePresence initial={false}>
                                {displayedAssets.map((asset, i) => (
                                  <motion.div
                                    key={i}
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: "auto" }}
                                    exit={{ opacity: 0, height: 0 }}
                                    transition={{ duration: 0.2 }}
                                    className="flex items-center justify-between bg-slate-900/50 border border-white/5 rounded-lg px-4 py-3 hover:border-orange-500/20 transition-all group overflow-hidden"
                                  >
                                    <div className="flex items-center gap-3">
                                      <div className={`w-2 h-2 rounded-full ${
                                        asset.confidence === 'high' ? 'bg-orange-400' : 'bg-yellow-400'
                                      }`} />
                                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-white/5">
                                        {asset.type.replace(/_/g, ' ')}
                                      </span>
                                      <span className="text-xs font-mono text-slate-300 truncate max-w-xs sm:max-w-md md:max-w-lg">{asset.url}</span>
                                    </div>
                                    <span className={`text-[10px] font-bold ${
                                      asset.confidence === 'high' ? 'text-orange-400' : 'text-yellow-400'
                                    }`}>{asset.confidence}</span>
                                  </motion.div>
                                ))}
                              </AnimatePresence>

                              {filteredAssets.length > 10 && (
                                <div className="pt-2 flex justify-center">
                                  <button
                                    onClick={() => {
                                      if (assetLimit >= filteredAssets.length) {
                                        setAssetLimit(10);
                                      } else {
                                        setAssetLimit(prev => prev + 50);
                                      }
                                    }}
                                    className="px-4 py-2 bg-slate-950/60 border border-white/5 hover:border-orange-500/30 rounded-xl text-xs font-bold text-slate-400 hover:text-orange-400 transition-all flex items-center gap-2 shadow-lg cursor-pointer"
                                  >
                                    {assetLimit >= filteredAssets.length ? (
                                      <>
                                        Show Less <ChevronUp className="w-3.5 h-3.5 text-orange-400" />
                                      </>
                                    ) : (
                                      <>
                                        Show {filteredAssets.length - assetLimit} More Assets <ChevronDown className="w-3.5 h-3.5 text-orange-400" />
                                      </>
                                    )}
                                  </button>
                                </div>
                              )}

                              {filteredAssets.length === 0 && (
                                <div className="text-center py-8 text-slate-500 font-medium">
                                  No assets match your search filters.
                                </div>
                              )}
                            </div>
                          ) : (
                            <div className="space-y-4">
                              {Object.entries(groupedAssets).map(([groupTitle, groupItems]: [string, any]) => {
                                const isGroupExpanded = expandedGroups[groupTitle] !== false;
                                return (
                                  <div key={groupTitle} className="bg-slate-950/20 border border-white/5 rounded-xl overflow-hidden">
                                    <button
                                      onClick={() => setExpandedGroups(prev => ({ ...prev, [groupTitle]: !isGroupExpanded }))}
                                      className="w-full flex items-center justify-between px-4 py-3 bg-white/[0.01] hover:bg-white/[0.02] transition-colors border-b border-white/5 cursor-pointer"
                                    >
                                      <span className="text-xs font-bold text-white flex items-center gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full bg-orange-400" />
                                        {groupTitle}
                                        <span className="text-[9px] font-bold text-slate-500 bg-white/5 px-2 py-0.5 rounded border border-white/5 ml-1">
                                          {groupItems.length} items
                                        </span>
                                      </span>
                                      {isGroupExpanded ? <ChevronUp className="w-3.5 h-3.5 text-slate-500" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-500" />}
                                    </button>

                                    {isGroupExpanded && (
                                      <div className="p-3 space-y-2">
                                        {groupItems.map((asset: any, idx: number) => (
                                          <div key={idx} className="flex items-center justify-between bg-slate-900/30 border border-white/5 rounded-lg px-4 py-2 hover:border-orange-500/10 transition-all">
                                            <span className="text-xs font-mono text-slate-300 truncate max-w-xs sm:max-w-md md:max-w-lg">{asset.url}</span>
                                            <span className={`text-[10px] font-bold ${
                                              asset.confidence === 'high' ? 'text-orange-400' : 'text-yellow-400'
                                            }`}>{asset.confidence}</span>
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                );
                              })}

                              {Object.keys(groupedAssets).length === 0 && (
                                <div className="text-center py-8 text-slate-500 font-medium">
                                  No assets match your search filters.
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })()}

                    {/* Scanner JSON Preview */}
                    {currentResult.scanner_json && (
                      <div>
                        <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                          <Code className="w-4 h-4 text-purple-400" />
                          Scanner JSON Preview
                        </h3>
                        <div className="bg-black/60 border border-white/5 rounded-xl overflow-hidden">
                          <div className="flex items-center justify-between px-4 py-2 bg-white/5 border-b border-white/5">
                            <span className="text-[10px] font-bold text-slate-500 font-mono">scanner_context.json</span>
                            <button
                              onClick={() => navigator.clipboard.writeText(JSON.stringify(currentResult.scanner_json, null, 2))}
                              className="p-1 hover:bg-white/10 rounded transition-all"
                            >
                              <Copy className="w-3 h-3 text-slate-400" />
                            </button>
                          </div>
                          <pre className="text-[11px] font-mono text-slate-300 p-4 overflow-auto max-h-96 leading-relaxed">
                            {JSON.stringify(currentResult.scanner_json, null, 2)}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === "findings" && (
                  <div className="space-y-8">
                    {currentResult.findings.map((finding: any) => (
                      <div key={finding.id} className="bg-[#0D1525] border border-white/5 rounded-2xl overflow-hidden shadow-2xl relative group/card transition-all hover:border-white/10">
                        {/* Header Section */}
                        <div className="px-6 py-5 bg-gradient-to-r from-slate-900/80 to-transparent border-b border-white/5 flex items-center justify-between">
                          <div className="flex flex-col gap-1">
                            <div className="flex items-center gap-3">
                              <h3 className="text-lg font-bold text-white group-hover/card:text-purple-400 transition-colors">
                                {finding.title}
                              </h3>
                              <div className="flex gap-2">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${severityColors[finding.severity as keyof typeof severityColors] || severityColors.info}`}>
                                  {finding.severity}
                                </span>
                                {finding.verified ? (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/30 flex items-center gap-1 shadow-[0_0_10px_rgba(239,68,68,0.2)]">
                                    <ShieldCheck className="w-3 h-3" /> VERIFIED
                                  </span>
                                ) : finding.title.toLowerCase().includes("potential") ? (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-orange-500/10 text-orange-400 border border-orange-500/20 flex items-center gap-1">
                                    <AlertTriangle className="w-3 h-3" /> POTENTIAL
                                  </span>
                                ) : null}
                              </div>
                            </div>
                            <div className="text-xs font-mono text-slate-500 truncate max-w-md">
                              {finding.url}
                            </div>
                          </div>
                          
                          <div className="flex items-center gap-4">
                            {finding.cwe_id && (
                              <span className="text-[10px] font-bold font-mono text-slate-400 bg-slate-800/50 px-2 py-1 rounded border border-white/5">
                                {finding.cwe_id}
                              </span>
                            )}
                            <div className="p-2 rounded-lg bg-white/5 hover:bg-white/10 cursor-pointer transition-all" onClick={() => copyToClipboard(finding.url)}>
                              <ExternalLink className="w-4 h-4 text-slate-400" />
                            </div>
                          </div>
                        </div>

                        {/* Badges Ribbon */}
                        <div className="px-6 py-2 bg-slate-900/30 flex flex-wrap gap-2 border-b border-white/5">
                           {finding.tags?.map((tag: string) => (
                              <span key={tag} className={`px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-[0.1em] border ${
                                tag === "PLAYWRIGHT-VERIFIED" || tag === "VERIFIED"
                                  ? "bg-blue-600/10 text-blue-400 border-blue-500/20" 
                                  : "bg-slate-800/40 text-slate-500 border-white/5"
                              }`}>
                                {tag}
                              </span>
                            ))}
                        </div>

                        {/* Content Grid */}
                        <div className="grid lg:grid-cols-[1.2fr_1fr] gap-0">
                          
                          {/* Left Column: Evidence & Reproduction */}
                          <div className="p-6 border-r border-white/5 space-y-6">
                            <div>
                              <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-slate-500 mb-3 flex items-center gap-2">
                                <Search className="w-3 h-3" /> Summary
                              </h4>
                              <p className="text-sm text-slate-300 leading-relaxed bg-slate-950/20 p-4 rounded-xl border border-white/5 italic">
                                {finding.description}
                              </p>
                            </div>

                            {(() => {
                              const sqlmap = getSqlmapEvidence(finding.evidence);
                              if (!sqlmap || sqlmap.enabled !== true) return null;

                              return (
                                <div className="space-y-3">
                                  <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-slate-500 mb-2 flex items-center gap-2">
                                    <ShieldAlert className="w-3 h-3 text-purple-400" /> SQLMAP VERIFICATION
                                  </h4>
                                  <div className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 transition-all duration-300 ${
                                    sqlmap.verified
                                      ? "bg-emerald-950/20 border-emerald-500/30 shadow-[0_0_15px_rgba(16,185,129,0.05)]"
                                      : "bg-amber-950/20 border-amber-500/30 shadow-[0_0_15px_rgba(245,158,11,0.05)]"
                                  }`}>
                                    <div className="space-y-1">
                                      <div className="flex items-center gap-2.5">
                                        <span className={`w-2 h-2 rounded-full ${sqlmap.verified ? "bg-emerald-400" : "bg-amber-400"}`} />
                                        <div className={`text-sm font-bold uppercase tracking-wider ${sqlmap.verified ? "text-emerald-400" : "text-amber-400"}`}>
                                          {sqlmap.verified ? "SQLMap: Confirmed" : "SQLMap: Not Confirmed"}
                                        </div>
                                      </div>
                                      <div className="text-[11px] text-slate-400">
                                        {sqlmap.verified 
                                          ? "Verified by sqlmap exploitation checks" 
                                          : "Scanner detected a possible issue but sqlmap could not fully confirm exploitation."}
                                      </div>
                                    </div>
                                    {!sqlmap.verified && sqlmap.verification_reason && (
                                      <div className="text-left sm:text-right shrink-0">
                                        <div className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">REASON</div>
                                        <div className="text-xs font-mono font-semibold text-amber-300 mt-0.5">
                                          {mapVerificationReason(sqlmap.verification_reason)}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              );
                            })()}

                            <div>
                              <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-slate-500 mb-3 flex items-center gap-2">
                                <Terminal className="w-3 h-3" /> Technical Evidence
                              </h4>
                              <TechnicalEvidenceTable evidence={finding.evidence} />
                            </div>

                            {/* Reproduction Details */}
                            {finding.reproduction_data && (
                              <div>
                                <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-slate-500 mb-3 flex items-center gap-2">
                                  <Zap className="w-3 h-3" /> Reproduction Details
                                </h4>
                                <div className="space-y-3">
                                  {Object.entries(finding.reproduction_data).map(([key, value]) => {
                                    if (typeof value === 'object') return null;
                                    const isUrl = String(value).startsWith('http');
                                    const isPayload = key === 'payload';
                                    
                                    return (
                                      <CollapsibleSection 
                                        key={key}
                                        title={`${key.replace(/_/g, ' ').toUpperCase()}`}
                                        content={String(value)}
                                        icon={isUrl ? Globe : isPayload ? Code : Layers}
                                        defaultOpen={!isUrl && !isPayload}
                                      />
                                    );
                                  })}
                                  
                                  {/* Curl command */}
                                  <ReproductionCurl 
                                    url={finding.reproduction_data.verification_url || finding.reproduction_data.test_url || finding.url}
                                    method={finding.reproduction_data.method || "GET"}
                                    cookies={sessionCookie}
                                  />
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Right Column: Remediation & Implementation */}
                          <div className="p-6 bg-slate-950/10 space-y-8">
                            <div>
                              <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-purple-400 mb-4 flex items-center gap-2">
                                <ShieldCheck className="w-3 h-3" /> Remediation Plan
                              </h4>
                              <div className="space-y-3">
                                {finding.recommendation?.split('\n').filter((l: string) => l.trim()).map((line: string, i: number) => (
                                  <div key={i} className="flex gap-3 items-start bg-white/5 p-3 rounded-lg border border-white/5 hover:border-white/10 transition-all">
                                    <div className="w-1.5 h-1.5 rounded-full bg-purple-500 mt-1.5 shrink-0" />
                                    <span className="text-[13px] text-slate-300 leading-snug">{line.replace(/^- /, '').replace(/\*\*/g, '')}</span>
                                  </div>
                                ))}
                              </div>
                            </div>

                            {finding.auto_fix && (
                              <div>
                                <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-emerald-400 mb-4 flex items-center gap-2">
                                  <Code className="w-3 h-3" /> Implementation Fix
                                </h4>
                                <div className="bg-[#020202] border border-white/10 rounded-xl overflow-hidden shadow-2xl">
                                  <div className="flex items-center justify-between px-4 py-2 bg-white/5 border-b border-white/5">
                                    <div className="text-[10px] font-bold text-slate-500 font-mono">CODE SNIPPET</div>
                                    <button 
                                      onClick={() => copyToClipboard(finding.auto_fix)}
                                      className="p-1.5 bg-slate-800/50 hover:bg-emerald-600/50 rounded-md transition-all"
                                    >
                                      <Copy className="w-3 h-3 text-white" />
                                    </button>
                                  </div>
                                  <div className="p-4 overflow-x-auto">
                                    <pre className="text-[11px] font-mono text-slate-300 leading-relaxed">
                                      {finding.auto_fix.replace(/```[a-z]*\n/g, '').replace(/```/g, '')}
                                    </pre>
                                  </div>
                                </div>
                              </div>
                            )}

                            {/* Action Buttons */}
                            <div className="pt-4 flex gap-3">
                               <button 
                                 onClick={() => copyToClipboard(finding.reproduction_data?.payload || "")}
                                 className="flex-1 bg-white/5 hover:bg-white/10 border border-white/5 rounded-lg py-2.5 text-[11px] font-bold text-slate-400 flex items-center justify-center gap-2 transition-all"
                               >
                                 <Copy className="w-3 h-3" /> COPY PAYLOAD
                               </button>
                               <button 
                                 onClick={() => window.open(finding.reproduction_data?.verification_url || finding.url, '_blank')}
                                 className="flex-1 bg-purple-600/10 hover:bg-purple-600/20 border border-purple-500/20 rounded-lg py-2.5 text-[11px] font-bold text-purple-400 flex items-center justify-center gap-2 transition-all"
                               >
                                 <ExternalLink className="w-3 h-3" /> TEST MANUAL
                               </button>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Sidebar: History */}
        <div className="bg-[#0A101C] border border-white/5 rounded-2xl flex flex-col h-[calc(100vh-8rem)] sticky top-6">
          <div className="p-6 border-b border-white/5">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-purple-400" />
              Scan History
            </h2>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
            {history.length === 0 ? (
              <p className="text-center text-slate-500 text-sm mt-10">No past scans found.</p>
            ) : (
              history.map((item) => (
                <button
                  key={item.id}
                  onClick={() => loadPastScan(item.id)}
                  disabled={isScanning}
                  className="w-full text-left bg-slate-900/50 hover:bg-slate-800/50 border border-white/5 rounded-xl p-4 transition-all group"
                >
                  <div className="flex justify-between items-start mb-2">
                    <div className="font-medium text-white truncate pr-2 group-hover:text-purple-400 transition-colors">
                      {item.target.replace(/^https?:\/\//, '')}
                    </div>
                    {item.summary.risk_score != null && (
                      <div className={`text-xs font-bold px-2 py-0.5 rounded ${
                        (item.summary.risk_score ?? 0) > 70 ? "bg-red-500/20 text-red-400" : 
                        (item.summary.risk_score ?? 0) > 40 ? "bg-orange-500/20 text-orange-400" : 
                        "bg-emerald-500/20 text-emerald-400"
                      }`}>
                        {(item.summary.risk_score ?? 0).toFixed(0)}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-slate-500">
                    <span className="capitalize">{item.summary.mode}</span>
                    <span>{new Date(item.created_at).toLocaleDateString()}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>
        
      </div>
      
      <style dangerouslySetInnerHTML={{__html: `
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 10px; }
      `}} />
    </div>
  );
}
