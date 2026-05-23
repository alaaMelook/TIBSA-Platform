"use client";

import React, { useState, useEffect } from "react";
import { useAuthContext } from "@/contexts/AuthContext";
import { api } from "@/lib/api";

// Local Interfaces to ensure zero typescript build errors
interface TestFinding {
    id: string;
    finding_id: string;
    title: string;
    severity: string;
    category: string;
    affected_url: string;
    evidence: string;
    tags: string[];
}

interface TestAsset {
    id: string;
    asset_type: string;
    url: string;
    technology?: string | null;
}

interface TestTIReport {
    id: string;
    overall_risk: number;
    risk_summary?: string | null;
    created_at: string;
}

interface TestTMReport {
    id: string;
    stride_summary: Record<string, number>;
    mitigations: Record<string, string>;
    created_at: string;
}

interface InvestigationStatusData {
    id: string;
    scan_id: string;
    status: string;
    risk_score: number;
    started_at: string;
    completed_at?: string | null;
    current_stage: string;
    progress_percent: number;
}

interface InvestigationFullData extends InvestigationStatusData {
    target: string;
    include_ti: boolean;
    tm_mode: string;
    findings: TestFinding[];
    assets: TestAsset[];
    ti_reports: TestTIReport[];
    tm_reports: TestTMReport[];
}

interface ApiResponseWrapper<T> {
    success: boolean;
    message?: string;
    data: T;
}

export default function Dev1TestPage() {
    const { user, token, isAuthenticated, login, logout, isLoading: authLoading } = useAuthContext();
    
    // Auth Form State (initialized to user's known testing account for rapid testing)
    const [email, setEmail] = useState("kenzy.rasmy@gmail.com");
    const [password, setPassword] = useState("123456789");
    const [authError, setAuthError] = useState("");
    const [authSubmitting, setAuthSubmitting] = useState(false);

    // Scan parameters State
    const [targetUrl, setTargetUrl] = useState("https://example.com");
    const [scanMode, setScanMode] = useState("safe");
    const [includeTi, setIncludeTi] = useState(true);
    const [tmMode, setTmMode] = useState("enhanced");
    const [selectedTests, setSelectedTests] = useState<string[]>([
        "security_headers",
        "xss",
        "sqli",
        "cookie_analysis",
        "misconfiguration"
    ]);

    // Active pipeline state
    const [isLaunching, setIsLaunching] = useState(false);
    const [investigationId, setInvestigationId] = useState<string | null>(null);
    const [scanId, setScanId] = useState<string | null>(null);
    const [statusInfo, setStatusInfo] = useState<InvestigationStatusData | null>(null);
    const [fullResults, setFullResults] = useState<InvestigationFullData | null>(null);
    const [pollingError, setPollingError] = useState("");
    const [activeTab, setActiveTab] = useState<"findings" | "assets" | "reports" | "raw">("findings");
    const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

    // Run custom login with provided credentials
    const handleLoginSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setAuthError("");
        setAuthSubmitting(true);
        try {
            await login({ email, password });
        } catch (err: unknown) {
            setAuthError(err instanceof Error ? err.message : "Authentication failed");
        } finally {
            setAuthSubmitting(false);
        }
    };

    // Toggle specific pentest scan check
    const toggleTest = (testName: string) => {
        if (selectedTests.includes(testName)) {
            setSelectedTests(selectedTests.filter(t => t !== testName));
        } else {
            setSelectedTests([...selectedTests, testName]);
        }
    };

    // Dispatch background orchestrator investigation
    const launchInvestigation = async () => {
        if (!token) return;
        setIsLaunching(true);
        setPollingError("");
        setInvestigationId(null);
        setScanId(null);
        setStatusInfo(null);
        setFullResults(null);

        try {
            const res = await api.post<ApiResponseWrapper<InvestigationFullData>>(
                "/api/v1/investigations/start",
                {
                    target: targetUrl,
                    tests: selectedTests,
                    mode: scanMode,
                    include_ti: includeTi,
                    tm_mode: tmMode
                },
                token
            );
            
            if (res.success && res.data) {
                setInvestigationId(res.data.id);
                setScanId(res.data.scan_id);
                setStatusInfo(res.data);
            } else {
                throw new Error("Invalid response format from server");
            }
        } catch (err: unknown) {
            setPollingError(err instanceof Error ? err.message : "Failed to launch pipeline");
        } finally {
            setIsLaunching(false);
        }
    };

    // Poll live status until completed/failed
    useEffect(() => {
        if (!investigationId || !token) return;

        let isMounted = true;
        const intervalId = setInterval(async () => {
            try {
                const res = await api.get<ApiResponseWrapper<InvestigationStatusData>>(
                    `/api/v1/investigations/${investigationId}/status`,
                    token
                );
                
                if (!isMounted) return;
                
                if (res.success && res.data) {
                    setStatusInfo(res.data);
                    
                    // Stop polling if completed or failed
                    if (res.data.status === "completed" || res.data.status === "failed") {
                        clearInterval(intervalId);
                        
                        // Retrieve full results details
                        const fullRes = await api.get<ApiResponseWrapper<InvestigationFullData>>(
                            `/api/v1/investigations/${investigationId}`,
                            token
                        );
                        
                        if (isMounted && fullRes.success && fullRes.data) {
                            setFullResults(fullRes.data);
                        }
                    }
                }
            } catch (err: unknown) {
                if (isMounted) {
                    setPollingError(err instanceof Error ? err.message : "Error polling status");
                    clearInterval(intervalId);
                }
            }
        }, 3000);

        return () => {
            isMounted = false;
            clearInterval(intervalId);
        };
    }, [investigationId, token]);

    // Helpers to render colors
    const getSeverityColor = (sev: string) => {
        const s = sev.toLowerCase();
        if (s === "critical" || s === "high") return "bg-red-500/10 border-red-500/30 text-red-400";
        if (s === "medium") return "bg-amber-500/10 border-amber-500/30 text-amber-400";
        if (s === "low") return "bg-blue-500/10 border-blue-500/30 text-blue-400";
        return "bg-slate-500/10 border-slate-500/30 text-slate-400";
    };

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 p-6 font-sans">
            {/* Header */}
            <header className="max-w-7xl mx-auto flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">
                        TIBSA Security Workspace
                    </h1>
                    <p className="text-xs text-slate-400 mt-1">
                        Isolated Sandbox Sandbox for verifying Developer 1 tasks in real-time
                    </p>
                </div>
                {isAuthenticated && (
                    <div className="flex items-center gap-3">
                        <span className="text-xs text-slate-400 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-full">
                            👤 {user?.email}
                        </span>
                        <button
                            onClick={logout}
                            className="text-xs bg-red-950 hover:bg-red-900 border border-red-900/50 text-red-200 px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
                        >
                            Sign Out
                        </button>
                    </div>
                )}
            </header>

            <main className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Left Area: Setup & Control */}
                <section className="lg:col-span-4 space-y-6">
                    {/* Authenticator */}
                    {!isAuthenticated ? (
                        <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-5 shadow-2xl backdrop-blur-sm">
                            <h2 className="text-sm font-semibold text-cyan-400 uppercase tracking-wider mb-4">
                                🔐 Configure Session Credentials
                            </h2>
                            <form onSubmit={handleLoginSubmit} className="space-y-4">
                                <div>
                                    <label className="block text-xs text-slate-400 font-medium mb-1.5">Supabase Account Email</label>
                                    <input
                                        type="email"
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        required
                                    />
                                </div>
                                <div>
                                    <label className="block text-xs text-slate-400 font-medium mb-1.5">Account Password</label>
                                    <input
                                        type="password"
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                    />
                                </div>
                                {authError && (
                                    <div className="text-xs bg-red-950/40 border border-red-900/30 text-red-300 p-2.5 rounded-lg">
                                        ⚠️ {authError}
                                    </div>
                                )}
                                <button
                                    type="submit"
                                    disabled={authSubmitting || authLoading}
                                    className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs py-2.5 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                                >
                                    {authSubmitting ? "Authenticating Session..." : "Connect to Project DB"}
                                </button>
                            </form>
                        </div>
                    ) : (
                        /* Control Panel */
                        <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-5 shadow-2xl backdrop-blur-sm space-y-5">
                            <h2 className="text-sm font-semibold text-cyan-400 uppercase tracking-wider">
                                🕹️ Ingestion Parameters
                            </h2>
                            
                            {/* Target Input */}
                            <div className="space-y-1.5">
                                <label className="block text-xs text-slate-400 font-medium">Target Scan URL</label>
                                <input
                                    type="text"
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
                                    value={targetUrl}
                                    onChange={(e) => setTargetUrl(e.target.value)}
                                />
                            </div>

                            {/* Options */}
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-1.5">
                                    <label className="block text-xs text-slate-400 font-medium font-sans">Scanning Mode</label>
                                    <select
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
                                        value={scanMode}
                                        onChange={(e) => setScanMode(e.target.value)}
                                    >
                                        <option value="safe">Safe / Non-Intrusive</option>
                                        <option value="passive">Passive Scan</option>
                                        <option value="aggressive">Aggressive Audit</option>
                                    </select>
                                </div>
                                <div className="space-y-1.5">
                                    <label className="block text-xs text-slate-400 font-medium">Threat Modeler</label>
                                    <select
                                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 transition-colors"
                                        value={tmMode}
                                        onChange={(e) => setTmMode(e.target.value)}
                                    >
                                        <option value="enhanced">Enhanced (TI-Driven)</option>
                                        <option value="standalone">Standalone Rules</option>
                                    </select>
                                </div>
                            </div>

                            {/* Threat Intel Switch */}
                            <div className="flex items-center justify-between bg-slate-950/60 p-3 rounded-lg border border-slate-800/40">
                                <div>
                                    <span className="block text-xs font-semibold text-slate-200">Include Threat Intel</span>
                                    <span className="block text-[10px] text-slate-400">Flag malices via external API</span>
                                </div>
                                <button
                                    onClick={() => setIncludeTi(!includeTi)}
                                    className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                        includeTi ? "bg-cyan-500" : "bg-slate-700"
                                    }`}
                                >
                                    <span
                                        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                                            includeTi ? "translate-x-4" : "translate-x-0"
                                        }`}
                                    />
                                </button>
                            </div>

                            {/* Vulnerability Checks */}
                            <div className="space-y-2">
                                <label className="block text-xs text-slate-400 font-medium">Core Scan Modules</label>
                                <div className="space-y-1.5 max-h-[140px] overflow-y-auto pr-1">
                                    {[
                                        { key: "security_headers", label: "Missing Security Headers" },
                                        { key: "xss", label: "Cross-Site Scripting (XSS)" },
                                        { key: "sqli", label: "SQL Injection (SQLi)" },
                                        { key: "cookie_analysis", label: "Insecure Cookie Settings" },
                                        { key: "misconfiguration", label: "Server Misconfigurations" }
                                    ].map((test) => (
                                        <label
                                            key={test.key}
                                            className="flex items-center gap-2.5 bg-slate-950/30 border border-slate-800/30 px-3 py-1.5 rounded-lg text-xs hover:border-slate-700/60 cursor-pointer"
                                        >
                                            <input
                                                type="checkbox"
                                                checked={selectedTests.includes(test.key)}
                                                onChange={() => toggleTest(test.key)}
                                                className="rounded border-slate-800 text-cyan-500 focus:ring-cyan-500 bg-slate-950"
                                            />
                                            <span className="text-slate-300">{test.label}</span>
                                        </label>
                                    ))}
                                </div>
                            </div>

                            {/* Action Button */}
                            <button
                                onClick={launchInvestigation}
                                disabled={isLaunching || selectedTests.length === 0}
                                className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs py-3 rounded-lg shadow-lg hover:shadow-cyan-900/20 transition-all cursor-pointer disabled:opacity-40"
                            >
                                {isLaunching ? "Initiating Orchestrator..." : "Launch Investigation Flow"}
                            </button>
                        </div>
                    )}
                </section>

                {/* Right Area: Results & Tracking */}
                <section className="lg:col-span-8 space-y-6">
                    {/* Live Tracker (Shows when flow starts) */}
                    {(investigationId || pollingError) && (
                        <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-5 shadow-2xl backdrop-blur-sm space-y-5">
                            <div className="flex items-center justify-between">
                                <h2 className="text-sm font-semibold text-cyan-400 uppercase tracking-wider">
                                    🔄 Real-Time Pipeline tracker
                                </h2>
                                {statusInfo && (
                                    <span className={`text-[10px] uppercase font-semibold tracking-wider px-2 py-0.5 border rounded-full ${
                                        statusInfo.status === "completed" 
                                            ? "bg-green-500/10 border-green-500/30 text-green-400"
                                            : statusInfo.status === "failed"
                                            ? "bg-red-500/10 border-red-500/30 text-red-400"
                                            : "bg-cyan-500/10 border-cyan-500/30 text-cyan-400 animate-pulse"
                                    }`}>
                                        {statusInfo.status}
                                    </span>
                                )}
                            </div>

                            {/* Details Row */}
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-slate-950/60 p-4 rounded-xl border border-slate-800/40 text-xs">
                                <div>
                                    <span className="block text-slate-400">Investigation ID</span>
                                    <span className="font-mono text-slate-200 truncate block">{investigationId || "-"}</span>
                                </div>
                                <div>
                                    <span className="block text-slate-400">Scan Ingestion Ref</span>
                                    <span className="font-mono text-slate-200 block">{scanId || "-"}</span>
                                </div>
                                <div>
                                    <span className="block text-slate-400">Completed Level</span>
                                    <span className="font-semibold text-slate-200 block">
                                        {statusInfo ? `${statusInfo.progress_percent}%` : "0%"}
                                    </span>
                                </div>
                                <div>
                                    <span className="block text-slate-400">Initial Risk Score</span>
                                    <span className="font-semibold text-slate-200 block">
                                        {statusInfo ? statusInfo.risk_score.toFixed(1) : "-"}
                                    </span>
                                </div>
                            </div>

                            {/* Stepper Steps */}
                            <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                                {[
                                    { name: "Pentest Scanning", threshold: 25 },
                                    { name: "Finding Normalization", threshold: 50 },
                                    { name: "Threat Intel Enrichment", threshold: 75, condition: includeTi },
                                    { name: "Threat Modeling", threshold: 100 }
                                ].map((step, idx) => {
                                    if (step.condition === false) return null;
                                    const isDone = statusInfo && statusInfo.progress_percent >= step.threshold;
                                    const isActive = statusInfo && statusInfo.current_stage === step.name;
                                    
                                    return (
                                        <div
                                            key={step.name}
                                            className={`p-3 rounded-lg border text-xs transition-all ${
                                                isDone
                                                    ? "bg-green-950/20 border-green-500/20 text-green-400"
                                                    : isActive
                                                    ? "bg-cyan-950/40 border-cyan-500/40 text-cyan-300 shadow-md shadow-cyan-950/30"
                                                    : "bg-slate-950/30 border-slate-800 text-slate-500"
                                            }`}
                                        >
                                            <div className="flex items-center justify-between mb-1 font-semibold">
                                                <span>Stage {idx + 1}</span>
                                                {isDone ? (
                                                    <span>✓</span>
                                                ) : isActive ? (
                                                    <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-ping" />
                                                ) : null}
                                            </div>
                                            <span className="block text-[11px] truncate">{step.name}</span>
                                        </div>
                                    );
                                })}
                            </div>

                            {/* Progress bar */}
                            {statusInfo && (
                                <div className="space-y-1">
                                    <div className="w-full bg-slate-950 rounded-full h-1.5 border border-slate-800">
                                        <div
                                            className="bg-gradient-to-r from-cyan-500 to-indigo-500 h-full rounded-full transition-all duration-500"
                                            style={{ width: `${statusInfo.progress_percent}%` }}
                                        />
                                    </div>
                                    <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                                        <span>In Progress stage: {statusInfo.current_stage}</span>
                                        <span>{statusInfo.progress_percent}%</span>
                                    </div>
                                </div>
                            )}

                            {pollingError && (
                                <div className="text-xs bg-red-950/40 border border-red-900/30 text-red-300 p-3 rounded-lg">
                                    ⚠️ Connection Error: {pollingError}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Results Explorer (Shows when results exist) */}
                    {fullResults ? (
                        <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-5 shadow-2xl backdrop-blur-sm space-y-5">
                            {/* Tabs Header */}
                            <div className="flex border-b border-slate-800 gap-1 overflow-x-auto">
                                {[
                                    { key: "findings", label: `Normalized Findings (${fullResults.findings?.length || 0})` },
                                    { key: "assets", label: `Discovered Assets (${fullResults.assets?.length || 0})` },
                                    { key: "reports", label: "Compliance Reports" },
                                    { key: "raw", label: "Full JSON Payload" }
                                ].map((tab) => (
                                    <button
                                        key={tab.key}
                                        onClick={() => setActiveTab(tab.key as typeof activeTab)}
                                        className={`px-4 py-2 text-xs font-semibold border-b-2 whitespace-nowrap transition-colors cursor-pointer ${
                                            activeTab === tab.key
                                                ? "border-cyan-500 text-cyan-400"
                                                : "border-transparent text-slate-400 hover:text-slate-200"
                                        }`}
                                    >
                                        {tab.label}
                                    </button>
                                ))}
                            </div>

                            {/* Active Tab Panel */}
                            <div className="min-h-[300px]">
                                {/* ─── FINDINGS TAB ─── */}
                                {activeTab === "findings" && (
                                    <div className="space-y-3">
                                        {fullResults.findings && fullResults.findings.length > 0 ? (
                                            fullResults.findings.map((f) => {
                                                const isExpanded = expandedFinding === f.id;
                                                return (
                                                    <div
                                                        key={f.id}
                                                        className="bg-slate-950/60 rounded-xl border border-slate-800/60 overflow-hidden shadow-md"
                                                    >
                                                        {/* Accordion header */}
                                                        <div
                                                            onClick={() => setExpandedFinding(isExpanded ? null : f.id)}
                                                            className="p-4 flex items-center justify-between gap-3 cursor-pointer hover:bg-slate-950/90 transition-colors"
                                                        >
                                                            <div className="space-y-1">
                                                                <div className="flex items-center gap-2 flex-wrap">
                                                                    <span className={`text-[9px] uppercase font-bold px-2 py-0.5 border rounded-md ${getSeverityColor(f.severity)}`}>
                                                                        {f.severity}
                                                                    </span>
                                                                    <span className="text-[10px] font-semibold text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded-md">
                                                                        {f.category}
                                                                    </span>
                                                                </div>
                                                                <h3 className="text-xs font-bold text-slate-200 mt-1">{f.title}</h3>
                                                            </div>
                                                            <span className="text-slate-500 text-xs">{isExpanded ? "▲" : "▼"}</span>
                                                        </div>

                                                        {/* Accordion body */}
                                                        {isExpanded && (
                                                            <div className="p-4 border-t border-slate-900 bg-slate-950/40 space-y-3 text-xs">
                                                                <div>
                                                                    <span className="block text-[10px] text-slate-400 font-semibold mb-1">Affected Endpoint</span>
                                                                    <span className="font-mono text-slate-300 break-all">{f.affected_url}</span>
                                                                </div>
                                                                <div>
                                                                    <span className="block text-[10px] text-slate-400 font-semibold mb-1">Normalized Finding ID Slug</span>
                                                                    <span className="font-mono text-slate-300">{f.finding_id}</span>
                                                                </div>
                                                                {f.tags && f.tags.length > 0 && (
                                                                    <div>
                                                                        <span className="block text-[10px] text-slate-400 font-semibold mb-1">Tags</span>
                                                                        <div className="flex flex-wrap gap-1">
                                                                            {f.tags.map(t => (
                                                                                <span key={t} className="text-[10px] text-slate-400 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
                                                                                    {t}
                                                                                </span>
                                                                            ))}
                                                                        </div>
                                                                    </div>
                                                                )}
                                                                <div>
                                                                    <span className="block text-[10px] text-slate-400 font-semibold mb-1">Vulnerability Evidence Trace</span>
                                                                    <pre className="w-full bg-slate-950 border border-slate-900 rounded-lg p-3 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-[150px] whitespace-pre-wrap">
                                                                        {f.evidence || "No evidence details captured."}
                                                                    </pre>
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                );
                                            })
                                        ) : (
                                            <div className="text-center py-12 text-slate-500 text-xs">
                                                Zero vulnerability findings discovered for this target website.
                                            </div>
                                        )}
                                    </div>
                                )}

                                {/* ─── ASSETS TAB ─── */}
                                {activeTab === "assets" && (
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                        {fullResults.assets && fullResults.assets.length > 0 ? (
                                            fullResults.assets.map((asset) => (
                                                <div
                                                    key={asset.id}
                                                    className="bg-slate-950/60 p-4 rounded-xl border border-slate-800/60 space-y-2 text-xs"
                                                >
                                                    <div className="flex items-center justify-between">
                                                        <span className="text-[10px] uppercase font-bold text-cyan-400 bg-cyan-950/20 border border-cyan-800/30 px-2 py-0.5 rounded">
                                                            {asset.asset_type}
                                                        </span>
                                                    </div>
                                                    <div>
                                                        <span className="block text-[10px] text-slate-400">Endpoint/Asset Path</span>
                                                        <span className="font-mono text-slate-200 truncate block">{asset.url}</span>
                                                    </div>
                                                    {asset.technology && (
                                                        <div>
                                                            <span className="block text-[10px] text-slate-400">Detected Tech Stack</span>
                                                            <span className="font-bold text-indigo-300">{asset.technology}</span>
                                                        </div>
                                                    )}
                                                </div>
                                            ))
                                        ) : (
                                            <div className="text-center py-12 text-slate-500 text-xs col-span-2">
                                                No specific assets mapped in the database yet.
                                            </div>
                                        )}
                                    </div>
                                )}

                                {/* ─── REPORTS COMPLIANCE TAB ─── */}
                                {activeTab === "reports" && (
                                    <div className="space-y-6">
                                        {/* Threat Intelligence Report */}
                                        <div className="bg-slate-950/60 border border-slate-800/60 p-5 rounded-xl space-y-3">
                                            <div className="flex items-center justify-between border-b border-slate-900 pb-2">
                                                <h3 className="text-xs font-bold text-slate-200">🔍 Threat Intelligence (TI) Enrichment Report</h3>
                                                {fullResults.ti_reports && fullResults.ti_reports[0] && (
                                                    <span className="text-xs font-semibold text-cyan-400">
                                                        Risk Index: {fullResults.ti_reports[0].overall_risk.toFixed(1)}
                                                    </span>
                                                )}
                                            </div>
                                            {fullResults.ti_reports && fullResults.ti_reports.length > 0 ? (
                                                fullResults.ti_reports.map((ti) => (
                                                    <div key={ti.id} className="text-xs space-y-1">
                                                        <span className="block text-slate-400">Ingested Summary</span>
                                                        <p className="text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-900">
                                                            {ti.risk_summary}
                                                        </p>
                                                    </div>
                                                ))
                                            ) : (
                                                <p className="text-slate-500 text-xs py-2">
                                                    Threat intelligence report disabled or not populated.
                                                </p>
                                            )}
                                        </div>

                                        {/* Threat Modeling Report */}
                                        <div className="bg-slate-950/60 border border-slate-800/60 p-5 rounded-xl space-y-4">
                                            <div className="border-b border-slate-900 pb-2">
                                                <h3 className="text-xs font-bold text-slate-200">🧠 Automated STRIDE Threat Model</h3>
                                            </div>
                                            
                                            {fullResults.tm_reports && fullResults.tm_reports.length > 0 ? (
                                                fullResults.tm_reports.map((tm) => (
                                                    <div key={tm.id} className="space-y-4">
                                                        {/* STRIDE COUNTS */}
                                                        <div>
                                                            <span className="block text-[10px] text-slate-400 font-semibold mb-2">STRIDE Threat Vectors Discovered</span>
                                                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                                                                {Object.entries(tm.stride_summary).map(([category, count]) => (
                                                                    <div key={category} className="bg-slate-950 p-2 border border-slate-900 rounded-lg text-center">
                                                                        <span className="block text-[10px] text-slate-400">{category}</span>
                                                                        <span className={`text-base font-bold ${count > 0 ? "text-amber-400" : "text-slate-500"}`}>
                                                                            {count}
                                                                        </span>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>

                                                        {/* MITIGATION ROADMAP */}
                                                        <div>
                                                            <span className="block text-[10px] text-slate-400 font-semibold mb-2">Automated Remediation Roadmap</span>
                                                            <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
                                                                {Object.entries(tm.mitigations).map(([cat, mit]) => (
                                                                    <div key={cat} className="bg-slate-950/80 p-3 border border-slate-900 rounded-lg text-xs">
                                                                        <span className="font-bold text-cyan-400 block mb-0.5">{cat} Mitigation</span>
                                                                        <p className="text-slate-300">{mit}</p>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))
                                            ) : (
                                                <p className="text-slate-500 text-xs py-2">
                                                    Threat modeling report is not generated yet.
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                )}

                                {/* ─── RAW JSON TAB ─── */}
                                {activeTab === "raw" && (
                                    <div className="space-y-2">
                                        <span className="text-[10px] text-slate-400 block font-mono">Raw Investigation Schema Payload</span>
                                        <pre className="w-full bg-slate-950 border border-slate-900 rounded-xl p-4 text-[11px] font-mono text-cyan-400 overflow-x-auto max-h-[360px] whitespace-pre">
                                            {JSON.stringify(fullResults, null, 2)}
                                        </pre>
                                    </div>
                                )}
                            </div>
                        </div>
                    ) : (
                        /* Default state when not scanning */
                        !investigationId && (
                            <div className="bg-slate-900/30 border border-slate-800/60 rounded-xl py-20 text-center text-slate-400 flex flex-col items-center justify-center space-y-4">
                                <span className="text-4xl">🚀</span>
                                <div>
                                    <h3 className="text-sm font-bold text-slate-200">Investigation Sandbox Ready</h3>
                                    <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto leading-relaxed">
                                        Submit a website URL on the left panel to execute and inspect the live pipeline, translation, reputation enrichment, and threat modeling components.
                                    </p>
                                </div>
                            </div>
                        )
                    )}
                </section>
            </main>
        </div>
    );
}
