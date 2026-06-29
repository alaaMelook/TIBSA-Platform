"use client";

import React, { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { api } from "@/lib/api";
import { supabase } from "@/lib/supabase";
import { useAuth } from "@/hooks/useAuth";
import {
  ShieldAlert, ShieldCheck, Activity, Search, AlertTriangle,
  Terminal, Server, Globe, FileKey, Layers, Radar, CheckCircle2,
  XCircle, Copy, Code, ArrowRight, Zap, Target, ChevronDown, ChevronUp, ExternalLink,
  Eye, EyeOff, Lock, Unlock, Command, Check
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
    <div className="border border-[var(--border-soft)] rounded-xl overflow-hidden bg-[var(--bg-page)]/20 mb-3">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-[var(--bg-elevated)] transition-all group"
      >
        <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text-muted)] group-hover:text-[var(--text-primary)]">
          <Icon className="w-3.5 h-3.5" />
          {title}
        </div>
        {isOpen ? <ChevronUp className="w-3.5 h-3.5 text-[var(--text-muted)]" /> : <ChevronDown className="w-3.5 h-3.5 text-[var(--text-muted)]" />}
      </button>
      {isOpen && (
        <div className="px-4 pb-4">
          <div className={`p-3 rounded-lg bg-black/40 border border-[var(--border-soft)] text-[11px] ${mono ? 'font-mono' : 'font-sans'} text-[var(--text-secondary)] break-all whitespace-pre-wrap relative group`}>
            {content}
            <button
              onClick={(e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(content);
              }}
              className="absolute top-2 right-2 p-1.5 bg-[var(--bg-elevated)]/50 hover:bg-[var(--primary-soft)] rounded-md transition-all opacity-0 group-hover:opacity-100"
            >
              <Copy className="w-3 h-3 text-[var(--text-primary)]" />
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
  info: "bg-[var(--bg-elevated)] text-[var(--text-muted)] border-[var(--border-soft)]"
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
                  <span className="text-[var(--text-muted)] font-bold sm:min-w-[120px]">{pk}:</span>
                  <span className="text-emerald-300 break-all">{String(pv)}</span>
                </div>
              ))}
            </div>
          );
        }
      } catch (e) { }
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
            className="ml-3 text-[9px] font-black text-[var(--primary)]/70 hover:text-[var(--primary)] transition-colors uppercase underline underline-offset-2"
          >
            {isExpanded ? "[Collapse]" : "[Show Full]"}
          </button>
        )}
      </div>
    );
  };

  return (
    <div className="bg-[var(--bg-card)]/40 border border-[var(--border-strong)] rounded-xl overflow-hidden shadow-2xl font-mono text-[11px]">
      <div className="flex flex-col divide-y divide-white/5">
        {rows.map((row, idx) => {
          const rowKey = `${row.key}-${idx}`;
          const isCopyable = copyableFields.some(f => row.key.includes(f));

          return (
            <div key={idx} className="flex flex-col md:grid md:grid-cols-[220px_1fr] group hover:bg-[var(--bg-elevated)] transition-colors relative">
              {/* Key Column */}
              <div className="px-5 py-4 text-[var(--text-muted)] bg-[var(--bg-elevated)] border-b md:border-b-0 md:border-r border-[var(--border-soft)] font-sans uppercase text-[10px] font-black tracking-widest flex items-center whitespace-nowrap overflow-hidden text-ellipsis">
                {row.key}
              </div>

              {/* Value Column */}
              <div className="px-5 py-4 text-emerald-400/90 relative flex items-start group/val">
                {renderValue(row.key, row.value, rowKey)}

                {/* Copy Button on the right */}
                {isCopyable && (
                  <button
                    onClick={() => copyToClipboard(row.value, rowKey)}
                    className="absolute right-4 top-4 p-1.5 bg-[var(--bg-elevated)]/80 hover:bg-emerald-600/50 border border-[var(--border-strong)] rounded-md text-[var(--text-primary)] transition-all opacity-0 group-hover:opacity-100 flex items-center gap-1.5 z-10"
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

const getColorizedJson = (jsonObj: any) => {
  if (!jsonObj) return "";
  const str = JSON.stringify(jsonObj, null, 2)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  return str.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
    let color = '#93c5fd'; // number
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        color = '#6ee7b7'; // key
      } else {
        color = '#fde68a'; // string
      }
    } else if (/true|false/.test(match)) {
      color = '#c084fc'; // boolean
    } else if (/null/.test(match)) {
      color = '#f87171'; // null
    }
    return `<span style="color: ${color}">${match}</span>`;
  });
};

export default function WebsiteScannerPage() {
  const { token } = useAuth();
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

  const [authDropdownOpen, setAuthDropdownOpen] = useState(false);
  const [scanDropdownOpen, setScanDropdownOpen] = useState(false);

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
    if (token) fetchHistory();
  }, [token]);

  const fetchHistory = async () => {
    try {
      if (!token) return;
      const data = await api.get<HistoryItem[]>("/api/v1/website-scanner/history", token);
      setHistory(data || []);
    } catch (err: any) {
      console.error("Failed to fetch history", err);
    }
  };

  const loadPastScan = async (id: string) => {
    try {
      setIsScanning(true);
      setError("");
      if (!token) throw new Error("Not authenticated");
      const data = await api.get<any>(`/api/v1/website-scanner/history/${id}`, token);

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
      if (!token) throw new Error("Not authenticated");

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
      }, token);

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
    <div className="space-y-6 text-[var(--text-secondary)] selection:bg-[var(--primary-soft)]">

      {/* Header */}
      <div
        style={{
          background: "linear-gradient(90deg, rgba(230,226,220,0.95) 0%, rgba(156,158,160,0.75) 55%, #0f172a 100%)"
        }}
        className="border border-[var(--border-soft)] p-[32px] rounded-[20px] shadow-xl relative overflow-hidden animate-[cardFadeIn_300ms_ease-out_forwards] motion-reduce:animate-none flex flex-col md:flex-row md:items-center justify-between gap-6"
      >
        <div className="flex items-start gap-4">
          <div className="p-2.5 bg-[#edf8f3] rounded-xl border border-[#0f9d76]/30 shadow-sm shrink-0 mt-1">
            <Radar className="w-8 h-8 text-[#0f9d76]" />
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-[10px] font-bold text-[#0f9d76] uppercase tracking-widest">
                PENETRATION TESTING
              </span>
            </div>
            <h1 className="text-2xl font-black text-[#1d1d1d] tracking-tight">Web Application Penetration Testing</h1>
            <p className="text-[#4f4a45] mt-1 max-w-xl text-sm leading-relaxed font-medium">
              Run safe web application security tests, verify vulnerabilities, analyze exposed attack surfaces, and generate actionable penetration testing insights.
            </p>
          </div>
        </div>
      </div>

      <div className="grid lg:grid-cols-[1fr_350px] gap-6">

        {/* Main Content Area */}
        <div className="space-y-6">

          {/* Scanner Controls */}
          <div className="bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-2xl p-6 shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 w-96 h-96 bg-[var(--primary-soft)] blur-[100px] pointer-events-none" />

            <form onSubmit={handleScan} className="relative z-10">
              <div className="flex gap-4 mb-6">
                <div className="flex-1 relative group">
                  <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                    <Target className="w-5 h-5 text-[var(--text-muted)] group-focus-within:text-[var(--primary)] transition-colors" />
                  </div>
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full bg-[var(--bg-card)]/50 border border-[var(--border-strong)] rounded-xl py-4 pl-12 pr-4 text-[var(--text-primary)] placeholder-slate-500 focus:outline-none focus:border-[var(--primary)] focus:ring-1 focus:ring-[var(--primary)] transition-all"
                    disabled={isScanning}
                  />
                </div>
                <button
                  type="submit"
                  disabled={isScanning || !targetUrl || selectedTests.length === 0}
                  className="btn-animated btn-primary-emerald w-full sm:w-auto px-8 py-3 rounded-xl font-medium flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isScanning ? (
                    <><Activity className="w-5 h-5 animate-pulse" /> Scanning...</>
                  ) : (
                    <><Zap className="w-5 h-5" /> Launch Scan</>
                  )}
                </button>
              </div>

              <div className="mb-6 p-4 bg-[var(--bg-card)]/30 border border-[var(--border-soft)] rounded-2xl">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-[var(--text-secondary)] flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-[var(--primary)]" /> Authentication Configuration
                  </h3>
                  <div className="relative" onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setAuthDropdownOpen(false) }}>
                    <button
                      type="button"
                      onClick={() => setAuthDropdownOpen(!authDropdownOpen)}
                      className="px-4 py-2 bg-[#ffffff] hover:bg-[#edf8f3] border border-[#e7ddd1] focus:border-[#0f9d76] focus:ring-2 focus:ring-[#0f9d76]/30 rounded-xl text-sm font-semibold text-[#1d1d1d] shadow-sm transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.98] flex items-center gap-2"
                    >
                      {authMode === "none" ? "No Auth" : authMode === "cookie" ? "Cookie" : "Auto Login"}
                      <ChevronDown className={`w-4 h-4 text-[#4f4a45] transition-transform duration-200 ${authDropdownOpen ? "rotate-180" : ""}`} />
                    </button>

                    {authDropdownOpen && (
                      <div className="absolute top-full right-0 mt-2 w-40 bg-[#ffffff] border border-[#e7ddd1] rounded-2xl shadow-lg shadow-[#0f9d76]/10 z-50 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200 ease-out">
                        {(["none", "cookie", "auto"] as const).map((mode) => (
                          <button
                            key={mode}
                            type="button"
                            onClick={() => {
                              setAuthMode(mode);
                              setAuthDropdownOpen(false);
                            }}
                            className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center justify-between ${authMode === mode
                              ? "bg-[#edf8f3] text-[#0f9d76] font-bold"
                              : "text-[#1d1d1d] hover:bg-[#edf8f3] hover:text-[#0f9d76]"
                              }`}
                          >
                            {mode === "none" ? "No Auth" : mode === "cookie" ? "Cookie" : "Auto Login"}
                            {authMode === mode && <CheckCircle2 className="w-4 h-4" />}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {authMode === "cookie" && (
                  <div className="relative group">
                    <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                      <FileKey className="w-4 h-4 text-[var(--text-muted)]" />
                    </div>
                    <input
                      type="text"
                      value={sessionCookie}
                      onChange={(e) => setSessionCookie(e.target.value)}
                      placeholder="PHPSESSID=...; security=low"
                      className="w-full bg-[var(--bg-page)]/50 border border-[var(--border-strong)] rounded-xl py-3 pl-12 pr-4 text-[var(--text-primary)] placeholder-slate-500 focus:outline-none focus:border-[var(--primary)] transition-all text-xs"
                    />
                  </div>
                )}

                {authMode === "auto" && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="relative">
                        <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                          <Globe className="w-4 h-4 text-[var(--text-muted)]" />
                        </div>
                        <input
                          type="text"
                          value={loginUrl}
                          onChange={(e) => setLoginUrl(e.target.value)}
                          placeholder="Login URL"
                          className="w-full bg-[var(--bg-page)]/50 border border-[var(--border-strong)] rounded-xl py-3 pl-12 pr-4 text-[var(--text-primary)] placeholder-slate-500 focus:outline-none focus:border-[var(--primary)] transition-all text-xs"
                        />
                      </div>
                      <div className="relative">
                        <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                          <CheckCircle2 className="w-4 h-4 text-[var(--text-muted)]" />
                        </div>
                        <select
                          value={securityLevel}
                          onChange={(e) => setSecurityLevel(e.target.value)}
                          className="w-full bg-[var(--bg-page)]/50 border border-[var(--border-strong)] rounded-xl py-3 pl-12 pr-4 text-[var(--text-primary)] focus:outline-none focus:border-[var(--primary)] transition-all text-xs appearance-none"
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
                        className="w-full bg-[var(--bg-page)]/50 border border-[var(--border-strong)] rounded-xl py-3 px-4 text-[var(--text-primary)] placeholder-slate-500 focus:outline-none focus:border-[var(--primary)] transition-all text-xs"
                      />
                      <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Password"
                        className="w-full bg-[var(--bg-page)]/50 border border-[var(--border-strong)] rounded-xl py-3 px-4 text-[var(--text-primary)] placeholder-slate-500 focus:outline-none focus:border-[var(--primary)] transition-all text-xs"
                      />
                    </div>
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-4 mb-6">
                <span className="text-sm font-medium text-[var(--text-muted)]">Scan Mode:</span>
                <div className="relative" onBlur={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) setScanDropdownOpen(false) }}>
                  <button
                    type="button"
                    onClick={() => setScanDropdownOpen(!scanDropdownOpen)}
                    disabled={isScanning}
                    className="px-4 py-2 bg-[#ffffff] hover:bg-[#edf8f3] border border-[#e7ddd1] focus:border-[#0f9d76] focus:ring-2 focus:ring-[#0f9d76]/30 rounded-xl text-sm font-semibold text-[#1d1d1d] shadow-sm transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.98] flex items-center gap-2 capitalize disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:transform-none"
                  >
                    {scanMode} Mode
                    <ChevronDown className={`w-4 h-4 text-[#4f4a45] transition-transform duration-200 ${scanDropdownOpen ? "rotate-180" : ""}`} />
                  </button>

                  {scanDropdownOpen && (
                    <div className="absolute top-full left-0 mt-2 w-44 bg-[#ffffff] border border-[#e7ddd1] rounded-2xl shadow-lg shadow-[#0f9d76]/10 z-50 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200 ease-out">
                      {(["passive", "safe", "aggressive"] as const).map((mode) => (
                        <button
                          key={mode}
                          type="button"
                          onClick={() => {
                            setScanMode(mode);
                            setScanDropdownOpen(false);
                          }}
                          className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center justify-between capitalize ${scanMode === mode
                            ? "bg-[#edf8f3] text-[#0f9d76] font-bold"
                            : "text-[#1d1d1d] hover:bg-[#edf8f3] hover:text-[#0f9d76]"
                            }`}
                        >
                          {mode}
                          {scanMode === mode && <CheckCircle2 className="w-4 h-4" />}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Scanner Modules Header */}
              <div className="mb-4 flex items-center justify-between">
                <div className="space-y-0.5">
                  <h3 className="text-sm font-semibold text-[var(--text-secondary)] flex items-center gap-2">
                    <Layers className="w-4.5 h-4.5 text-[#0f9d76]" /> Scanner Modules
                  </h3>
                  <p className="text-[11px] text-[#8a8178]">Select the scanning engines to deploy against target</p>
                </div>
                <span className="text-[11px] font-bold bg-[#edf8f3] text-[#0f9d76] px-2.5 py-1 rounded-full border border-[#0f9d76]/20">
                  {selectedTests.length} of {defaultTests.length} Selected
                </span>
              </div>

              {/* Main Scanner Modules Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
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
                      className={`p-5 rounded-2xl border text-left cursor-pointer transition-all duration-200 hover:-translate-y-[3px] active:scale-[0.98] flex flex-col justify-between h-full group ${
                        isScanning ? "opacity-60 cursor-not-allowed" : ""
                      } ${
                        isSelected
                          ? "bg-gradient-to-br from-[#edf8f3] to-[#dcf5e7] border-[#0f9d76] shadow-[0_4px_16px_rgba(15,157,118,0.08),_inset_0_1px_2px_rgba(255,255,255,0.7)] hover:shadow-[0_6px_20px_rgba(15,157,118,0.12)]"
                          : "bg-[#ffffff] border-[#e7ddd1] hover:bg-[#edf8f3]/30 hover:border-[#0f9d76]/30 hover:shadow-md"
                      }`}
                    >
                      <div className="flex flex-col h-full justify-between">
                        <div>
                          {/* Card Icon & Checkbox Badge */}
                          <div className="flex items-center justify-between mb-4">
                            <div className={`p-2 rounded-xl border transition-all duration-200 ${
                              isSelected
                                ? "bg-white border-[#0f9d76]/30 text-[#0f9d76] shadow-sm"
                                : "bg-[#ffffff] border-[#e7ddd1] text-[#4f4a45] group-hover:border-[#0f9d76]/20 group-hover:text-[#0f9d76]"
                            }`}>
                              <Icon className="w-5 h-5" />
                            </div>
                            
                            <div className="relative w-5 h-5 flex items-center justify-center">
                              {/* Outer ring for double-ring aesthetic */}
                              <div className={`absolute inset-0 rounded-full border transition-all duration-300 ${
                                isSelected 
                                  ? "border-[#0f9d76]/40 scale-125" 
                                  : "border-[#e7ddd1] group-hover:border-[#0f9d76]/40"
                              }`} />
                              
                              {/* Inner spring-animated badge */}
                              <AnimatePresence mode="wait">
                                {isSelected ? (
                                  <motion.div
                                    key="selected-badge"
                                    initial={{ scale: 0, opacity: 0 }}
                                    animate={{ scale: 1, opacity: 1 }}
                                    exit={{ scale: 0, opacity: 0 }}
                                    transition={{ type: "spring", stiffness: 450, damping: 22 }}
                                    className="absolute inset-0.5 rounded-full bg-[#0f9d76] flex items-center justify-center shadow-[0_2px_5px_rgba(15,157,118,0.25),_inset_0_1px_1px_rgba(255,255,255,0.4)]"
                                  >
                                    <Check className="w-3.5 h-3.5 text-white stroke-[3px]" />
                                  </motion.div>
                                ) : (
                                  <motion.div
                                    key="unselected-badge"
                                    initial={{ scale: 0.8, opacity: 0 }}
                                    animate={{ scale: 1, opacity: 1 }}
                                    exit={{ scale: 0.8, opacity: 0 }}
                                    className="absolute inset-0.5 rounded-full bg-transparent"
                                  />
                                )}
                              </AnimatePresence>
                            </div>
                          </div>

                          {/* Card Content */}
                          <div className={`font-bold text-sm mb-1.5 transition-colors ${
                            isSelected ? "text-[#0a5c44]" : "text-[#1d1d1d] group-hover:text-[#0f9d76]"
                          }`}>
                            {test.label}
                          </div>
                          <p className={`text-[11px] leading-relaxed transition-colors ${
                            isSelected ? "text-[#326f5e]" : "text-[#8a8178]"
                          }`}>
                            {test.desc}
                          </p>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Advanced Checks Section */}
              <div className="mt-8 pt-6 border-t border-[var(--border-soft)] space-y-4">
                <div className="flex items-center gap-2">
                  <Command className="w-4.5 h-4.5 text-[#0f9d76]" />
                  <h3 className="text-sm font-semibold text-[var(--text-secondary)]">Advanced Checks</h3>
                </div>

                <div className="bg-[#ffffff] border border-[#e7ddd1] rounded-2xl p-5 shadow-sm space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    
                    {/* SQL Injection Advanced Checks */}
                    <div className={`space-y-4 transition-all duration-200 ${
                      selectedTests.includes("sqli") 
                        ? "opacity-100" 
                        : "opacity-40 cursor-not-allowed select-none"
                    }`}>
                      <div className="flex items-center gap-2 pb-2 border-b border-[#e7ddd1]/60">
                        <Server className="w-4 h-4 text-[#0f9d76]" />
                        <span className="text-xs font-bold uppercase tracking-wider text-[#1d1d1d]">SQL Injection Engine</span>
                        {!selectedTests.includes("sqli") && (
                          <span className="text-[9px] font-bold bg-[#8a8178]/10 text-[#8a8178] px-2 py-0.5 rounded ml-auto">
                            Requires SQL Injection Module
                          </span>
                        )}
                      </div>

                      <div className="flex items-start justify-between gap-4 p-3 hover:bg-[#edf8f3]/10 rounded-xl transition-all duration-200">
                        <div className="space-y-0.5">
                          <div className="text-xs font-semibold text-[#1d1d1d]">SQLMap Verification</div>
                          <p className="text-[11px] text-[#8a8178] leading-relaxed">
                            Deploy sqlmap API to run deep validation and attempt safe exploitation checks.
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (!isScanning && selectedTests.includes("sqli")) {
                              setEnableSqlmap(!enableSqlmap);
                            }
                          }}
                          disabled={isScanning || !selectedTests.includes("sqli")}
                          className={`relative h-5 w-9 shrink-0 rounded-full shadow-inner transition-colors duration-180 ${
                            enableSqlmap ? "bg-[#0f9d76]" : "bg-[#d9cdbf]"
                          } ${isScanning || !selectedTests.includes("sqli") ? "cursor-not-allowed" : "cursor-pointer"}`}
                        >
                          <span
                            className={`absolute top-[2px] left-[2px] h-4 w-4 rounded-full bg-white transition-transform duration-180 shadow-sm ${
                              enableSqlmap ? "translate-x-4" : "translate-x-0"
                            }`}
                          />
                        </button>
                      </div>
                    </div>

                    {/* Auth Security Advanced Checks */}
                    <div className={`space-y-4 transition-all duration-200 ${
                      selectedTests.includes("auth_security") 
                        ? "opacity-100" 
                        : "opacity-40 cursor-not-allowed select-none"
                    }`}>
                      <div className="flex items-center gap-2 pb-2 border-b border-[#e7ddd1]/60">
                        <ShieldCheck className="w-4 h-4 text-[#0f9d76]" />
                        <span className="text-xs font-bold uppercase tracking-wider text-[#1d1d1d]">Auth Security Engine</span>
                        {!selectedTests.includes("auth_security") && (
                          <span className="text-[9px] font-bold bg-[#8a8178]/10 text-[#8a8178] px-2 py-0.5 rounded ml-auto">
                            Requires Auth Security Module
                          </span>
                        )}
                      </div>

                      <div className="space-y-4">
                        {/* Browser Auth Analysis */}
                        <div className="flex items-start justify-between gap-4 p-3 hover:bg-[#edf8f3]/10 rounded-xl transition-all duration-200">
                          <div className="space-y-0.5">
                            <div className="text-xs font-semibold text-[#1d1d1d]">Browser Auth Analysis</div>
                            <p className="text-[11px] text-[#8a8178] leading-relaxed">
                              Inspect browser storage, secure attributes, cookies, and network credentials.
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (!isScanning && selectedTests.includes("auth_security")) {
                                setAuthBrowserAnalysis(!authBrowserAnalysis);
                              }
                            }}
                            disabled={isScanning || !selectedTests.includes("auth_security")}
                            className={`relative h-5 w-9 shrink-0 rounded-full shadow-inner transition-colors duration-180 ${
                              authBrowserAnalysis ? "bg-[#0f9d76]" : "bg-[#d9cdbf]"
                            } ${isScanning || !selectedTests.includes("auth_security") ? "cursor-not-allowed" : "cursor-pointer"}`}
                          >
                            <span className={`absolute top-[2px] left-[2px] h-4 w-4 rounded-full bg-white transition-transform duration-180 shadow-sm ${authBrowserAnalysis ? "translate-x-4" : "translate-x-0"}`} />
                          </button>
                        </div>

                        {/* Authorized Auth Flow Checks */}
                        <div className="flex items-start justify-between gap-4 p-3 hover:bg-[#edf8f3]/10 rounded-xl transition-all duration-200">
                          <div className="space-y-0.5">
                            <div className="text-xs font-semibold text-[#1d1d1d]">Authorized Auth Flow Checks</div>
                            <p className="text-[11px] text-[#8a8178] leading-relaxed">
                              Inject supplied cookies to discover authenticated paths using read-only checks.
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (!isScanning && selectedTests.includes("auth_security")) {
                                const next = !authorizedAuthMode;
                                setAuthorizedAuthMode(next);
                                if (!next) {
                                  setAuthLifecycleChecks(false);
                                  setAuthzTransitionChecks(false);
                                  setSessionCookie("");
                                }
                              }
                            }}
                            disabled={isScanning || !selectedTests.includes("auth_security")}
                            className={`relative h-5 w-9 shrink-0 rounded-full shadow-inner transition-colors duration-180 ${
                              authorizedAuthMode ? "bg-[#0f9d76]" : "bg-[#d9cdbf]"
                            } ${isScanning || !selectedTests.includes("auth_security") ? "cursor-not-allowed" : "cursor-pointer"}`}
                          >
                            <span className={`absolute top-[2px] left-[2px] h-4 w-4 rounded-full bg-white transition-transform duration-180 shadow-sm ${authorizedAuthMode ? "translate-x-4" : "translate-x-0"}`} />
                          </button>
                        </div>

                        {/* Authorized warning details */}
                        {authorizedAuthMode && selectedTests.includes("auth_security") && (
                          <div className="p-3 bg-amber-500/10 border border-amber-500/20 text-amber-600 rounded-xl text-[11px] leading-relaxed flex items-start gap-2 animate-in fade-in slide-in-from-top-1 duration-150">
                            <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0 text-amber-500" />
                            <span>Warning: Authorized scans leverage the supplied active session cookies to check privilege boundaries.</span>
                          </div>
                        )}

                        {/* Session Cookie Option */}
                        {authorizedAuthMode && selectedTests.includes("auth_security") && (
                          <div className="flex flex-col gap-1.5 p-3.5 bg-[#f8f3eb]/50 border border-[#e7ddd1] rounded-xl animate-in fade-in slide-in-from-top-2 duration-200">
                            <label className="text-[10px] font-bold text-[#1d1d1d] uppercase tracking-wider">Session Cookie</label>
                            <input
                              type="text"
                              value={sessionCookie}
                              onChange={(e) => setSessionCookie(e.target.value)}
                              placeholder="session=abc123xyz; csrftoken=..."
                              className="w-full bg-[#ffffff] border border-[#e7ddd1] rounded-lg px-3 py-2 text-xs text-[#1d1d1d] placeholder-slate-400 focus:outline-none focus:border-[#0f9d76] transition-colors"
                              disabled={isScanning}
                              onClick={(e) => e.stopPropagation()}
                            />
                            <div className="text-[10px] text-[#8a8178]">Inject this cookie to perform authorized privilege boundary verification.</div>
                          </div>
                        )}

                        {/* Token Lifecycle Checks */}
                        <div className={`flex items-start justify-between gap-4 p-3 hover:bg-[#edf8f3]/10 rounded-xl transition-all duration-200 ${
                          authorizedAuthMode ? "opacity-100" : "opacity-40 cursor-not-allowed select-none pointer-events-none"
                        }`}>
                          <div className="space-y-0.5">
                            <div className="text-xs font-semibold text-[#1d1d1d]">Token Lifecycle Checks</div>
                            <p className="text-[11px] text-[#8a8178] leading-relaxed">
                              Test authorization timeouts, logout invalidations, and tokens lifecycle rotation.
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (!isScanning && selectedTests.includes("auth_security") && authorizedAuthMode) {
                                setAuthLifecycleChecks(!authLifecycleChecks);
                              }
                            }}
                            disabled={isScanning || !selectedTests.includes("auth_security") || !authorizedAuthMode}
                            className={`relative h-5 w-9 shrink-0 rounded-full shadow-inner transition-colors duration-180 ${
                              authLifecycleChecks ? "bg-[#0f9d76]" : "bg-[#d9cdbf]"
                            } ${isScanning || !selectedTests.includes("auth_security") || !authorizedAuthMode ? "cursor-not-allowed" : "cursor-pointer"}`}
                          >
                            <span className={`absolute top-[2px] left-[2px] h-4 w-4 rounded-full bg-white transition-transform duration-180 shadow-sm ${authLifecycleChecks ? "translate-x-4" : "translate-x-0"}`} />
                          </button>
                        </div>

                        {/* AuthZ Transition Checks */}
                        <div className={`flex items-start justify-between gap-4 p-3 hover:bg-[#edf8f3]/10 rounded-xl transition-all duration-200 ${
                          authorizedAuthMode ? "opacity-100" : "opacity-40 cursor-not-allowed select-none pointer-events-none"
                        }`}>
                          <div className="space-y-0.5">
                            <div className="text-xs font-semibold text-[#1d1d1d]">AuthZ Transition Checks</div>
                            <p className="text-[11px] text-[#8a8178] leading-relaxed">
                              Validate authorization boundaries by comparing public and privileged route responses.
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (!isScanning && selectedTests.includes("auth_security") && authorizedAuthMode) {
                                setAuthzTransitionChecks(!authzTransitionChecks);
                              }
                            }}
                            disabled={isScanning || !selectedTests.includes("auth_security") || !authorizedAuthMode}
                            className={`relative h-5 w-9 shrink-0 rounded-full shadow-inner transition-colors duration-180 ${
                              authzTransitionChecks ? "bg-[#0f9d76]" : "bg-[#d9cdbf]"
                            } ${isScanning || !selectedTests.includes("auth_security") || !authorizedAuthMode ? "cursor-not-allowed" : "cursor-pointer"}`}
                          >
                            <span className={`absolute top-[2px] left-[2px] h-4 w-4 rounded-full bg-white transition-transform duration-180 shadow-sm ${authzTransitionChecks ? "translate-x-4" : "translate-x-0"}`} />
                          </button>
                        </div>

                      </div>
                    </div>

                  </div>
                </div>
              </div>
            </form>
          </div>

          {/* Results Area */}
          {currentResult && (
            <div className="bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-2xl shadow-2xl overflow-hidden">
              {/* Results Tabs + Export Button */}
              <div className="flex border-b border-[var(--border-soft)] bg-[#f8f3eb] items-center p-2 gap-2">
                <button
                  onClick={() => setActiveTab("overview")}
                  className={`px-4 py-2 rounded-lg text-sm shadow-sm transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] flex items-center gap-2 motion-reduce:transition-colors motion-reduce:hover:transform-none ${activeTab === "overview" ? "bg-[#edf8f3] border border-[#0f9d76] text-[#0f9d76] font-bold" : "bg-[#ffffff] border border-[#e7ddd1] text-[#1d1d1d] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76]"
                    }`}
                >
                  <Activity className="w-4 h-4" /> Overview
                </button>
                <button
                  onClick={() => setActiveTab("technology")}
                  className={`px-4 py-2 rounded-lg text-sm shadow-sm transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] flex items-center gap-2 motion-reduce:transition-colors motion-reduce:hover:transform-none ${activeTab === "technology" ? "bg-[#edf8f3] border border-[#0f9d76] text-[#0f9d76] font-bold" : "bg-[#ffffff] border border-[#e7ddd1] text-[#1d1d1d] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76]"
                    }`}
                >
                  <Server className="w-4 h-4" /> Technologies
                  {(currentResult.detected_technologies?.length ?? 0) > 0 && (
                    <span className="text-[10px] font-bold bg-[#0f9d76]/10 text-[#0f9d76] px-1.5 py-0.5 rounded-full">
                      {currentResult.detected_technologies?.length}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => setActiveTab("findings")}
                  className={`px-4 py-2 rounded-lg text-sm shadow-sm transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] flex items-center gap-2 motion-reduce:transition-colors motion-reduce:hover:transform-none ${activeTab === "findings" ? "bg-[#edf8f3] border border-[#0f9d76] text-[#0f9d76] font-bold" : "bg-[#ffffff] border border-[#e7ddd1] text-[#1d1d1d] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76]"
                    }`}
                >
                  <ShieldAlert className="w-4 h-4" /> Findings ({currentResult.findings?.length || 0})
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
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-[#ffffff] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76] border border-[#e7ddd1] text-[#1d1d1d] rounded-lg text-[11px] font-bold transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] shadow-sm motion-reduce:transition-colors motion-reduce:hover:transform-none"
                        title="Download scanner_context.json"
                      >
                        <Zap className="w-3 h-3" /> Export JSON
                      </button>
                      <button
                        onClick={() => { navigator.clipboard.writeText(JSON.stringify(currentResult.scanner_json, null, 2)); }}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-[#ffffff] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76] border border-[#e7ddd1] text-[#1d1d1d] rounded-lg text-[11px] font-bold transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] shadow-sm motion-reduce:transition-colors motion-reduce:hover:transform-none"
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
                        className="btn-animated btn-primary-emerald flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold"
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
                      <div className="bg-[var(--bg-card)]/50 border border-[var(--border-soft)] rounded-xl p-6 flex flex-col items-center justify-center relative overflow-hidden">
                        <div className={`absolute inset-0 opacity-20 ${(currentResult.risk_score ?? 0) > 70 ? "bg-red-500" : (currentResult.risk_score ?? 0) > 40 ? "bg-orange-500" : "bg-emerald-500"
                          } blur-[50px]`} />
                        <div className="text-sm font-medium text-[var(--text-muted)] mb-2 relative z-10">Risk Score</div>
                        <div className={`text-6xl font-bold relative z-10 ${(currentResult.risk_score ?? 0) > 70 ? "text-red-400" : (currentResult.risk_score ?? 0) > 40 ? "text-orange-400" : "text-emerald-400"
                          }`}>
                          {(currentResult.risk_score ?? 0).toFixed(0)}
                        </div>
                      </div>

                      <div className="col-span-2 grid grid-cols-2 md:grid-cols-4 gap-4">
                        {(["critical", "high", "medium", "low"] as const).map(sev => (
                          <div key={sev} className="bg-[var(--bg-card)]/50 border border-[var(--border-soft)] rounded-xl p-4 flex flex-col items-center justify-center">
                            <div className="text-3xl font-bold text-[var(--text-primary)] mb-1">{currentResult[sev as keyof ScanResult] as number}</div>
                            <div className={`text-[10px] font-bold uppercase tracking-widest ${sev === "critical" ? "text-red-400" :
                              sev === "high" ? "text-orange-400" :
                                sev === "medium" ? "text-yellow-400" : "text-[var(--primary)]"
                              }`}>{sev}</div>
                          </div>
                        ))}
                      </div>

                      {currentResult.executions_confirmed !== undefined && (
                        <div className="md:col-span-3 bg-[var(--primary-soft)] border border-[var(--primary)] rounded-xl p-4 flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div className="p-2 bg-[var(--primary-soft)] rounded-lg">
                              <Zap className="w-5 h-5 text-[var(--primary)]" />
                            </div>
                            <div>
                              <div className="text-xs text-[var(--text-muted)] font-medium">Verified Browser Executions</div>
                              <div className="text-lg font-bold text-[var(--text-primary)]">XSS Confirmation Signal</div>
                            </div>
                          </div>
                          <div className="text-4xl font-black text-[var(--primary)] mr-4">
                            {currentResult.executions_confirmed}
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                      <div className="bg-[var(--bg-card)]/30 p-3 rounded-lg border border-[var(--border-soft)] flex justify-between">
                        <span className="text-[var(--text-muted)]">Target:</span>
                        <span className="text-[var(--text-secondary)] truncate ml-4">{currentResult.target}</span>
                      </div>
                      <div className="bg-[var(--bg-card)]/30 p-3 rounded-lg border border-[var(--border-soft)] flex justify-between">
                        <span className="text-[var(--text-muted)]">Mode:</span>
                        <span className="text-[var(--text-secondary)] uppercase">{currentResult.mode}</span>
                      </div>
                      <div className="bg-[var(--bg-card)]/30 p-3 rounded-lg border border-[var(--border-soft)] flex justify-between">
                        <span className="text-[var(--text-muted)]">Attack Surface:</span>
                        <span className="text-red-400 font-bold">{currentResult.attack_surface_endpoints_count ?? 0} endpoints</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Technology Detection Tab */}
                {activeTab === "technology" && (
                  <div className="space-y-6 min-w-0 w-full max-w-6xl mx-auto">

                    {/* Detected Technologies */}
                    {(currentResult.detected_technologies?.length ?? 0) > 0 ? (
                      <div className="min-w-0 max-w-full">
                        <h3 className="text-sm font-bold text-[var(--text-primary)] mb-4 flex items-center gap-2">
                          <Server className="w-4 h-4 text-emerald-400" />
                          Detected Technologies
                          <span className="text-xs font-normal text-[var(--text-muted)]">— evidence-based only</span>
                        </h3>
                        <div className="max-h-[520px] overflow-y-auto overflow-x-hidden custom-scrollbar pr-2 pb-2">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {currentResult.detected_technologies?.map((tech, i) => (
                              <div key={i} className="bg-[#ffffff] border border-[#e7ddd1] rounded-xl p-[12px] px-[14px] shadow-sm hover:border-[#0f9d76] transition-all duration-200 hover:-translate-y-[1px] group min-w-0 flex flex-col gap-2 min-h-0">
                                <div className="flex items-start justify-between gap-3 min-w-0">
                                  <div className="min-w-0 flex-1">
                                    <div className="font-semibold text-[#1d1d1d] text-sm group-hover:text-[#0f9d76] transition-colors truncate">{tech.name}</div>
                                    <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                                      <div className="text-[10px] font-bold uppercase tracking-wider text-[#4f4a45] truncate">{tech.category.replace(/_/g, ' ')}</div>
                                      <span className="text-[8px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded bg-[#f8f3eb] text-[#8a8178] border border-[#e7ddd1] truncate">
                                        SRC: {tech.source || "custom_detector"}
                                      </span>
                                    </div>
                                  </div>
                                  <span className={`shrink-0 text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${tech.confidence === 'high' ? 'bg-[#edf8f3] text-[#0f9d76] border-[#0f9d76]/30' :
                                    tech.confidence === 'medium' ? 'bg-amber-50 text-amber-600 border-amber-200' :
                                      'bg-[#f8f3eb] text-[#4f4a45] border-[#e7ddd1]'
                                    }`}>{tech.confidence}</span>
                                </div>
                                <div className="text-xs text-[#4f4a45] font-mono leading-[1.4] bg-[#f6f0e7] rounded-lg p-[8px] px-[10px] border border-[#e7ddd1] break-all break-words whitespace-pre-wrap overflow-y-auto max-h-28 custom-scrollbar min-w-0 w-full">
                                  {tech.evidence}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-8 text-[var(--text-muted)]">
                        <Server className="w-8 h-8 mx-auto mb-3 opacity-30" />
                        <p className="text-sm">No technologies detected — insufficient evidence in target response.</p>
                      </div>
                    )}

                    {/* Technical Metadata Collapsible Section */}
                    {(currentResult.technology_metadata?.length ?? 0) > 0 && (
                      <div className="bg-[var(--bg-page)]/40 border border-[var(--border-soft)] rounded-xl overflow-hidden shadow-sm transition-all hover:border-[var(--border-strong)] min-w-0 max-w-full">
                        <button
                          onClick={() => setShowMetadata(!showMetadata)}
                          className="w-full flex items-center justify-between px-6 py-4 hover:bg-[var(--bg-elevated)] transition-all group/meta-btn"
                        >
                          <div className="flex items-center gap-2 text-sm font-bold text-[var(--text-primary)]">
                            <Layers className="w-4 h-4 text-[var(--primary)]" />
                            Technical Metadata
                            <span className="text-[10px] font-bold text-[var(--text-muted)] bg-[var(--bg-elevated)] px-2 py-0.5 rounded border border-[var(--border-soft)] ml-1">
                              {currentResult.technology_metadata?.length} items
                            </span>
                          </div>
                          {showMetadata ? (
                            <ChevronUp className="w-4 h-4 text-[var(--text-muted)] group-hover/meta-btn:text-[var(--text-primary)] transition-colors" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-[var(--text-muted)] group-hover/meta-btn:text-[var(--text-primary)] transition-colors" />
                          )}
                        </button>

                        {showMetadata && (
                          <div className="px-6 pb-6 pt-2 border-t border-[var(--border-soft)] bg-[var(--bg-card)]/10 min-w-0 max-w-full">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[360px] overflow-y-auto overflow-x-hidden custom-scrollbar pr-2">
                              {currentResult.technology_metadata?.map((meta, i) => (
                                <div key={i} className="bg-[var(--bg-card)]/30 border border-[var(--border-soft)] rounded-xl p-[12px] px-[14px] hover:border-[var(--primary)] transition-all group min-w-0 flex flex-col gap-2 min-h-0">
                                  <div className="flex items-start justify-between gap-3 min-w-0">
                                    <div className="min-w-0 flex-1">
                                      <div className="font-semibold text-[var(--text-primary)] text-sm group-hover:text-[var(--primary)] transition-colors truncate">{meta.name}</div>
                                      <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                                        <div className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)] truncate">{meta.category}</div>
                                        <span className="text-[8px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--text-muted)] truncate">
                                          SRC: {meta.source || "wappalyzer"}
                                        </span>
                                      </div>
                                    </div>
                                  </div>
                                  <div className="text-xs text-[var(--text-muted)] font-mono leading-[1.4] bg-black/20 rounded-lg p-[8px] px-[10px] border border-[var(--border-soft)] break-all break-words whitespace-pre-wrap overflow-y-auto max-h-28 custom-scrollbar min-w-0 w-full">
                                    {meta.evidence}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}                    {/* Attack Surface Assets */}
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
                        <div className="space-y-3 min-w-0 max-w-full">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--border-soft)] pb-3 min-w-0">
                            <h3 className="text-sm font-bold text-[var(--text-primary)] flex items-center gap-2 min-w-0">
                              <Target className="w-4 h-4 text-orange-400 shrink-0" />
                              <span className="truncate">Attack Surface Assets</span>
                              <span className="shrink-0 text-[10px] font-bold text-[var(--text-muted)] bg-[var(--bg-elevated)] px-2 py-0.5 rounded border border-[var(--border-soft)]">
                                {totalCount}
                              </span>
                            </h3>

                            <div className="flex items-center gap-2 shrink-0">
                              <div className="relative">
                                <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-3 top-1/2 -translate-y-1/2" />
                                <input
                                  type="text"
                                  placeholder="Search assets..."
                                  value={assetSearch}
                                  onChange={(e) => setAssetSearch(e.target.value)}
                                  className="pl-9 pr-4 py-1.5 bg-[var(--bg-page)]/60 border border-[var(--border-soft)] rounded-lg text-xs text-[var(--text-primary)] placeholder-slate-500 focus:border-orange-500/50 focus:outline-none transition-all w-36 sm:w-48 font-medium"
                                />
                              </div>

                              <button
                                onClick={() => setAssetGrouped(!assetGrouped)}
                                className={`px-3 py-1.5 rounded-lg text-xs shadow-sm transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] motion-reduce:transition-colors motion-reduce:hover:transform-none ${assetGrouped
                                  ? 'bg-[#edf8f3] border border-[#0f9d76] text-[#0f9d76] font-bold'
                                  : 'bg-[#ffffff] border border-[#e7ddd1] text-[#1d1d1d] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76]'
                                  }`}
                              >
                                {assetGrouped ? "Ungroup" : "Group"}
                              </button>
                            </div>
                          </div>

                          {!assetGrouped ? (
                            <div className="space-y-1.5 max-h-[360px] overflow-y-auto overflow-x-hidden custom-scrollbar pr-2 min-w-0 max-w-full">
                              <AnimatePresence initial={false}>
                                {displayedAssets.map((asset, i) => (
                                  <motion.div
                                    key={i}
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: "auto" }}
                                    exit={{ opacity: 0, height: 0 }}
                                    transition={{ duration: 0.15 }}
                                    className="flex items-center justify-between bg-[var(--bg-card)]/50 border border-[var(--border-soft)] rounded-lg p-[8px] px-[12px] hover:border-orange-500/20 transition-all group min-w-0 flex-nowrap gap-[10px] overflow-hidden"
                                  >
                                    <div className="flex items-center gap-[10px] min-w-0 flex-1">
                                      <div className={`shrink-0 w-1.5 h-1.5 rounded-full ${asset.confidence === 'high' ? 'bg-orange-400' : 'bg-yellow-400'
                                        }`} />
                                      <span className="shrink-0 text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--text-muted)] border border-[var(--border-soft)] truncate">
                                        {asset.type.replace(/_/g, ' ')}
                                      </span>
                                      <span className="text-xs font-mono text-[var(--text-secondary)] truncate min-w-0 flex-1">{asset.url}</span>
                                    </div>
                                    <span className={`shrink-0 text-[10px] font-bold ${asset.confidence === 'high' ? 'text-orange-400' : 'text-yellow-400'
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
                                    className="px-3 py-1.5 bg-[#ffffff] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76] border border-[#e7ddd1] text-[#1d1d1d] rounded-lg text-[11px] font-bold transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] flex items-center gap-1.5 shadow-sm cursor-pointer motion-reduce:transition-colors motion-reduce:hover:transform-none"
                                  >
                                    {assetLimit >= filteredAssets.length ? (
                                      <>
                                        Show Less <ChevronUp className="w-3 h-3" />
                                      </>
                                    ) : (
                                      <>
                                        Show {filteredAssets.length - assetLimit} More Assets <ChevronDown className="w-3 h-3" />
                                      </>
                                    )}
                                  </button>
                                </div>
                              )}

                              {filteredAssets.length === 0 && (
                                <div className="text-center py-6 text-[var(--text-muted)] text-[11px] font-medium">
                                  No assets match your search filters.
                                </div>
                              )}
                            </div>
                          ) : (
                            <div className="space-y-3 max-h-[360px] overflow-y-auto overflow-x-hidden custom-scrollbar pr-2 min-w-0 max-w-full">
                              {Object.entries(groupedAssets).map(([groupTitle, groupItems]: [string, any]) => {
                                const isGroupExpanded = expandedGroups[groupTitle] !== false;
                                return (
                                  <div key={groupTitle} className="bg-[var(--bg-page)]/20 border border-[var(--border-soft)] rounded-lg overflow-hidden min-w-0 max-w-full">
                                    <button
                                      onClick={() => setExpandedGroups(prev => ({ ...prev, [groupTitle]: !isGroupExpanded }))}
                                      className="w-full flex items-center justify-between px-3 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--bg-elevated)] transition-colors border-b border-[var(--border-soft)] cursor-pointer"
                                    >
                                      <span className="text-[11px] font-bold text-[var(--text-primary)] flex items-center gap-2 min-w-0">
                                        <span className="w-1.5 h-1.5 rounded-full bg-orange-400 shrink-0" />
                                        <span className="truncate">{groupTitle}</span>
                                        <span className="shrink-0 text-[8px] font-bold text-[var(--text-muted)] bg-[var(--bg-elevated)] px-1.5 py-0.5 rounded border border-[var(--border-soft)] ml-1">
                                          {groupItems.length} items
                                        </span>
                                      </span>
                                      {isGroupExpanded ? <ChevronUp className="shrink-0 w-3 h-3 text-[var(--text-muted)]" /> : <ChevronDown className="shrink-0 w-3 h-3 text-[var(--text-muted)]" />}
                                    </button>

                                    {isGroupExpanded && (
                                      <div className="p-2 space-y-1.5 min-w-0">
                                        {groupItems.map((asset: any, idx: number) => (
                                          <div key={idx} className="flex items-center justify-between bg-[var(--bg-card)]/30 border border-[var(--border-soft)] rounded-lg p-[8px] px-[12px] hover:border-orange-500/10 transition-all min-w-0 flex-nowrap gap-[10px]">
                                            <span className="text-xs font-mono text-[var(--text-secondary)] truncate min-w-0 flex-1">{asset.url}</span>
                                            <span className={`shrink-0 text-[10px] font-bold ${asset.confidence === 'high' ? 'text-orange-400' : 'text-yellow-400'
                                              }`}>{asset.confidence}</span>
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                );
                              })}

                              {Object.keys(groupedAssets).length === 0 && (
                                <div className="text-center py-6 text-[var(--text-muted)] text-[11px] font-medium">
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
                        <h3 className="text-sm font-bold text-[var(--text-primary)] mb-3 flex items-center gap-2">
                          <Code className="w-4 h-4 text-[var(--primary)]" />
                          Scanner JSON Preview
                        </h3>
                        <div className="bg-[#0f172a] border border-[rgba(15,157,118,0.25)] rounded-[14px] overflow-hidden shadow-xl">
                          <div className="flex items-center justify-between px-4 py-3 bg-[#1e293b] border-b border-[rgba(15,157,118,0.2)]">
                            <span className="text-xs font-bold text-[#e2e8f0] font-mono">scanner_context.json</span>
                            <button
                              onClick={() => navigator.clipboard.writeText(JSON.stringify(currentResult.scanner_json, null, 2))}
                              className="p-1.5 hover:bg-[#334155] rounded-md transition-all text-[#cbd5e1] hover:text-[#ffffff]"
                            >
                              <Copy className="w-3.5 h-3.5" />
                            </button>
                          </div>
                          <div className="overflow-auto custom-scrollbar" style={{ maxHeight: "420px" }}>
                            <pre
                              className="text-[13px] font-mono p-4 leading-[1.6]"
                              style={{ color: "#e5e7eb" }}
                              dangerouslySetInnerHTML={{ __html: getColorizedJson(currentResult.scanner_json) }}
                            />
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === "findings" && (
                  <div className="space-y-8">
                    {(currentResult.findings || []).map((finding: any) => (
                      <div key={finding.id} className="bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-2xl overflow-hidden shadow-2xl relative group/card transition-all hover:border-[var(--border-strong)]">
                        {/* Header Section */}
                        <div className="px-6 py-5 bg-gradient-to-r from-slate-900/80 to-transparent border-b border-[var(--border-soft)] flex items-center justify-between">
                          <div className="flex flex-col gap-1">
                            <div className="flex items-center gap-3">
                              <h3 className="text-lg font-bold text-[var(--text-primary)] group-hover/card:text-[var(--primary)] transition-colors">
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
                            <div className="text-xs font-mono text-[var(--text-muted)] truncate max-w-md">
                              {finding.url}
                            </div>
                          </div>

                          <div className="flex items-center gap-4">
                            {finding.cwe_id && (
                              <span className="text-[10px] font-bold font-mono text-[var(--text-muted)] bg-[var(--bg-elevated)]/50 px-2 py-1 rounded border border-[var(--border-soft)]">
                                {finding.cwe_id}
                              </span>
                            )}
                            <div className="p-2 rounded-lg bg-[var(--bg-elevated)] hover:bg-[var(--bg-elevated)] cursor-pointer transition-all" onClick={() => copyToClipboard(finding.url)}>
                              <ExternalLink className="w-4 h-4 text-[var(--text-muted)]" />
                            </div>
                          </div>
                        </div>

                        {/* Badges Ribbon */}
                        <div className="px-6 py-2 bg-[var(--bg-card)]/30 flex flex-wrap gap-2 border-b border-[var(--border-soft)]">
                          {finding.tags?.map((tag: string) => (
                            <span key={tag} className={`px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-[0.1em] border ${tag === "PLAYWRIGHT-VERIFIED" || tag === "VERIFIED"
                              ? "bg-[var(--primary-hover)]/10 text-[var(--primary)] border-[var(--primary)]"
                              : "bg-[var(--bg-elevated)]/40 text-[var(--text-muted)] border-[var(--border-soft)]"
                              }`}>
                              {tag}
                            </span>
                          ))}
                        </div>

                        {/* Content Grid */}
                        <div className="grid lg:grid-cols-[1.2fr_1fr] gap-0">

                          {/* Left Column: Evidence & Reproduction */}
                          <div className="p-6 border-r border-[var(--border-soft)] space-y-6">
                            <div>
                              <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-[var(--text-muted)] mb-3 flex items-center gap-2">
                                <Search className="w-3 h-3" /> Summary
                              </h4>
                              <p className="text-sm text-[var(--text-secondary)] leading-relaxed bg-[var(--bg-page)]/20 p-4 rounded-xl border border-[var(--border-soft)] italic">
                                {finding.description}
                              </p>
                            </div>

                            {(() => {
                              const sqlmap = getSqlmapEvidence(finding.evidence);
                              if (!sqlmap || sqlmap.enabled !== true) return null;

                              return (
                                <div className="space-y-3">
                                  <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-[var(--text-muted)] mb-2 flex items-center gap-2">
                                    <ShieldAlert className="w-3 h-3 text-[var(--primary)]" /> SQLMAP VERIFICATION
                                  </h4>
                                  <div className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 transition-all duration-300 ${sqlmap.verified
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
                                      <div className="text-[11px] text-[var(--text-muted)]">
                                        {sqlmap.verified
                                          ? "Verified by sqlmap exploitation checks"
                                          : "Scanner detected a possible issue but sqlmap could not fully confirm exploitation."}
                                      </div>
                                    </div>
                                    {!sqlmap.verified && sqlmap.verification_reason && (
                                      <div className="text-left sm:text-right shrink-0">
                                        <div className="text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-widest">REASON</div>
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
                              <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-[var(--text-muted)] mb-3 flex items-center gap-2">
                                <Terminal className="w-3 h-3" /> Technical Evidence
                              </h4>
                              <TechnicalEvidenceTable evidence={finding.evidence} />
                            </div>

                            {/* Reproduction Details */}
                            {finding.reproduction_data && (
                              <div>
                                <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-[var(--text-muted)] mb-3 flex items-center gap-2">
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
                          <div className="p-6 bg-[var(--bg-page)]/10 space-y-8">
                            <div>
                              <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-[var(--primary)] mb-4 flex items-center gap-2">
                                <ShieldCheck className="w-3 h-3" /> Remediation Plan
                              </h4>
                              <div className="space-y-3">
                                {finding.recommendation?.split('\n').filter((l: string) => l.trim()).map((line: string, i: number) => (
                                  <div key={i} className="flex gap-3 items-start bg-[var(--bg-elevated)] p-3 rounded-lg border border-[var(--border-soft)] hover:border-[var(--border-strong)] transition-all">
                                    <div className="w-1.5 h-1.5 rounded-full bg-[var(--primary)] !text-white mt-1.5 shrink-0" />
                                    <span className="text-[13px] text-[var(--text-secondary)] leading-snug">{line.replace(/^- /, '').replace(/\*\*/g, '')}</span>
                                  </div>
                                ))}
                              </div>
                            </div>

                            {finding.auto_fix && (
                              <div>
                                <h4 className="text-[10px] uppercase tracking-[0.2em] font-black text-emerald-400 mb-4 flex items-center gap-2">
                                  <Code className="w-3 h-3" /> Implementation Fix
                                </h4>
                                <div className="bg-[var(--bg-elevated)] border border-[var(--border-strong)] rounded-xl overflow-hidden shadow-2xl">
                                  <div className="flex items-center justify-between px-4 py-2 bg-[var(--bg-elevated)] border-b border-[var(--border-soft)]">
                                    <div className="text-[10px] font-bold text-[var(--text-muted)] font-mono">CODE SNIPPET</div>
                                    <button
                                      onClick={() => copyToClipboard(finding.auto_fix)}
                                      className="p-1.5 bg-[var(--bg-elevated)]/50 hover:bg-emerald-600/50 rounded-md transition-all"
                                    >
                                      <Copy className="w-3 h-3 text-[var(--text-primary)]" />
                                    </button>
                                  </div>
                                  <div className="p-4 overflow-x-auto">
                                    <pre className="text-[11px] font-mono text-[var(--text-secondary)] leading-relaxed">
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
                                className="flex-1 bg-[#ffffff] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76] border border-[#e7ddd1] rounded-lg py-2.5 text-[11px] font-bold text-[#1d1d1d] flex items-center justify-center gap-2 transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] shadow-sm motion-reduce:transition-colors motion-reduce:hover:transform-none"
                              >
                                <Copy className="w-3 h-3" /> COPY PAYLOAD
                              </button>
                              <button
                                onClick={() => window.open(finding.reproduction_data?.verification_url || finding.url, '_blank')}
                                className="btn-animated btn-primary-emerald flex-1 rounded-lg py-2.5 text-[11px] font-bold flex items-center justify-center gap-2"
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
        <div className="bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-2xl flex flex-col h-[calc(100vh-8rem)] sticky top-6">
          <div className="p-6 border-b border-[var(--border-soft)]">
            <h2 className="text-lg font-semibold text-[var(--text-primary)] flex items-center gap-2">
              <Activity className="w-5 h-5 text-[var(--primary)]" />
              Scan History
            </h2>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
            {history.length === 0 ? (
              <p className="text-center text-[var(--text-muted)] text-sm mt-10">No past scans found.</p>
            ) : (
              history.map((item) => (
                <button
                  key={item.id}
                  onClick={() => loadPastScan(item.id)}
                  disabled={isScanning}
                  className="w-full text-left bg-[#ffffff] hover:bg-[#edf8f3] hover:border-[#0f9d76] border border-[#e7ddd1] rounded-xl p-4 transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] shadow-sm group motion-reduce:transition-colors motion-reduce:hover:transform-none"
                >
                  <div className="flex justify-between items-start mb-2">
                    <div className="font-semibold text-[#1d1d1d] truncate pr-2 group-hover:text-[#0f9d76] transition-colors">
                      {item.target.replace(/^https?:\/\//, '')}
                    </div>
                    {item.summary.risk_score != null && (
                      <div className={`text-xs font-bold px-2 py-0.5 rounded ${(item.summary.risk_score ?? 0) > 70 ? "bg-red-500/20 text-red-400" :
                        (item.summary.risk_score ?? 0) > 40 ? "bg-orange-500/20 text-orange-400" :
                          "bg-emerald-500/20 text-emerald-400"
                        }`}>
                        {(item.summary.risk_score ?? 0).toFixed(0)}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-[var(--text-muted)]">
                    <span className="capitalize">{item.summary.mode}</span>
                    <span>{new Date(item.created_at).toLocaleDateString()}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

      </div>

      <style dangerouslySetInnerHTML={{
        __html: `
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 10px; }
      `}} />
    </div>
  );
}
