"use client";

import React, { useState, useEffect } from "react";
import { useAuthContext } from "@/contexts/AuthContext";
import { api } from "@/lib/api";

// Local Interfaces to ensure zero typescript build errors
interface TIFinding {
    id?: string;
    finding_id: string;
    title: string;
    severity: string;
    category: string;
    confidence: number;
    false_positive_probability: number;
    verification_status: string;
    exploitability: string;
    affected_asset: string;
    risk_score: number;
    risk_multiplier: number;
    evidence?: string;
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
    investigation_id: string;
    status: string;
    risk_score: number;
    summary: any;
    ti_findings: TIFinding[];
    reputation_context: any;
}

interface InvestigationFullData extends InvestigationStatusData {
    target?: string;
    include_ti?: boolean;
    tm_mode?: string;
    assets?: TestAsset[];
    ti_reports?: TestTIReport[];
    tm_reports?: TestTMReport[];
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

    // Scan parameters State (Removed manual target URL and manual tests)
    const [scanMode, setScanMode] = useState("safe");
    const [includeTi, setIncludeTi] = useState(true);
    const [tmMode, setTmMode] = useState("enhanced");

    // History selection state
    const [scanHistory, setScanHistory] = useState<any[]>([]);
    const [selectedHistoryId, setSelectedHistoryId] = useState<string>("");
    const [isLoadingHistory, setIsLoadingHistory] = useState(false);

    // Active pipeline state
    const [isLaunching, setIsLaunching] = useState(false);
    const [investigationId, setInvestigationId] = useState<string | null>(null);
    const [statusInfo, setStatusInfo] = useState<InvestigationStatusData | null>(null);
    const [fullResults, setFullResults] = useState<InvestigationFullData | null>(null);
    const [pollingError, setPollingError] = useState("");
    const [activeTab, setActiveTab] = useState<"findings" | "reports" | "raw">("findings");
    const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

    // Fetch history when user is authenticated
    useEffect(() => {
        if (!token || !isAuthenticated) return;
        
        const fetchHistory = async () => {
            setIsLoadingHistory(true);
            try {
                const res = await api.get<any[]>("/api/v1/website-scanner/history", token);
                // Based on standard FastAPI returning direct list or wrapped
                const data = Array.isArray(res) ? res : ((res as any).data || []);
                setScanHistory(data);
                if (data.length > 0) {
                    setSelectedHistoryId(data[0].id);
                }
            } catch (err: unknown) {
                console.error("Failed to load history:", err);
            } finally {
                setIsLoadingHistory(false);
            }
        };

        fetchHistory();
    }, [token, isAuthenticated]);

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

    // Generate TI Report from selected history
    const generateTIReport = async () => {
        if (!token || !selectedHistoryId) return;
        setIsLaunching(true);
        setPollingError("");
        setInvestigationId(null);
        setStatusInfo(null);
        setFullResults(null);
        setActiveTab("findings");

        try {
            // Hitting the history detail route which we refactored to apply TI Processing
            const res = await api.get<InvestigationFullData | ApiResponseWrapper<InvestigationFullData>>(
                `/api/v1/website-scanner/history/${selectedHistoryId}`,
                token
            );
            
            // Depending on if the API wraps in ApiResponseWrapper or returns direct object
            const data = ("success" in res && "data" in res) ? (res as ApiResponseWrapper<InvestigationFullData>).data : (res as InvestigationFullData);
            
            if (data && (data.investigation_id || (data as any).id)) {
                const iId = data.investigation_id || (data as any).id;
                setInvestigationId(iId);
                setStatusInfo(data);
                setFullResults(data);
            } else {
                throw new Error("Invalid response format from server");
            }
        } catch (err: unknown) {
            setPollingError(err instanceof Error ? err.message : "Failed to generate TI report");
        } finally {
            setIsLaunching(false);
        }
    };

    // Helpers to render colors
    const getSeverityColor = (sev: string) => {
        const s = sev.toLowerCase();
        if (s === "critical" || s === "high") return "bg-red-500/10 border-red-500/30 text-red-400";
        if (s === "medium") return "bg-amber-500/10 border-amber-500/30 text-amber-400";
        if (s === "low") return "bg-[var(--primary)]/10 border-[var(--primary)] text-[var(--primary)]";
        return "bg-[var(--bg-elevated)] border-[var(--border-soft)] text-[var(--text-muted)]";
    };

    return (
        <div className="min-h-screen bg-[var(--bg-page)] text-[var(--text-muted)] p-6 font-sans">
            {/* Header */}
            <header className="max-w-7xl mx-auto flex items-center justify-between border-b border-[var(--border-strong)] pb-4 mb-6">
                <div>
                    <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">
                        TIBSA Security Workspace
                    </h1>
                    <p className="text-xs text-[var(--text-muted)] mt-1">
                        Isolated Sandbox Sandbox for verifying Developer 1 tasks in real-time
                    </p>
                </div>
                {isAuthenticated && (
                    <div className="flex items-center gap-3">
                        <span className="text-xs text-[var(--text-muted)] bg-[var(--bg-card)] border border-[var(--border-strong)] px-3 py-1.5 rounded-full">
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
                        <div className="bg-[var(--bg-card)]/50 border border-[var(--border-strong)]/80 rounded-xl p-5 shadow-2xl backdrop-blur-sm">
                            <h2 className="text-sm font-semibold text-cyan-400 uppercase tracking-wider mb-4">
                                🔐 Configure Session Credentials
                            </h2>
                            <form onSubmit={handleLoginSubmit} className="space-y-4">
                                <div>
                                    <label className="block text-xs text-[var(--text-muted)] font-medium mb-1.5">Supabase Account Email</label>
                                    <input
                                        type="email"
                                        className="w-full bg-[var(--bg-page)] border border-[var(--border-strong)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-cyan-500 transition-colors"
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        required
                                    />
                                </div>
                                <div>
                                    <label className="block text-xs text-[var(--text-muted)] font-medium mb-1.5">Account Password</label>
                                    <input
                                        type="password"
                                        className="w-full bg-[var(--bg-page)] border border-[var(--border-strong)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-cyan-500 transition-colors"
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
                                    className="w-full bg-indigo-600 hover:bg-indigo-500 text-[var(--text-primary)] font-medium text-xs py-2.5 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                                >
                                    {authSubmitting ? "Authenticating Session..." : "Connect to Project DB"}
                                </button>
                            </form>
                        </div>
                    ) : (
                        /* Control Panel */
                        <div className="bg-[var(--bg-card)]/50 border border-[var(--border-strong)]/80 rounded-xl p-5 shadow-2xl backdrop-blur-sm space-y-5">
                            <h2 className="text-sm font-semibold text-cyan-400 uppercase tracking-wider">
                                🕹️ Threat Intelligence Pipeline
                            </h2>
                            
                            {/* History Selection */}
                            <div className="space-y-1.5">
                                <label className="block text-xs text-[var(--text-muted)] font-medium">Select Past Pentest Investigation</label>
                                {isLoadingHistory ? (
                                    <div className="w-full bg-[var(--bg-page)] border border-[var(--border-strong)] rounded-lg px-3 py-2 text-sm text-[var(--text-muted)] animate-pulse">
                                        Loading investigations...
                                    </div>
                                ) : (
                                    <select
                                        className="w-full bg-[var(--bg-page)] border border-[var(--border-strong)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-cyan-500 transition-colors"
                                        value={selectedHistoryId}
                                        onChange={(e) => setSelectedHistoryId(e.target.value)}
                                        disabled={scanHistory.length === 0}
                                    >
                                        {scanHistory.length === 0 ? (
                                            <option value="">No past investigations found</option>
                                        ) : (
                                            scanHistory.map((h) => (
                                                <option key={h.id} value={h.id}>
                                                    {new Date(h.created_at).toLocaleDateString()} - {h.target}
                                                </option>
                                            ))
                                        )}
                                    </select>
                                )}
                            </div>

                            {/* Options */}
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-1.5">
                                    <label className="block text-xs text-[var(--text-muted)] font-medium font-sans">Scanning Mode (SAFE overrides UI)</label>
                                    <select
                                        className="w-full bg-[var(--bg-page)]/50 border border-[var(--border-strong)]/50 rounded-lg px-2.5 py-2 text-xs text-[var(--text-muted)] cursor-not-allowed"
                                        value={scanMode}
                                        disabled
                                    >
                                        <option value="safe">Safe / Non-Intrusive</option>
                                    </select>
                                </div>
                                <div className="space-y-1.5">
                                    <label className="block text-xs text-[var(--text-muted)] font-medium">Threat Modeler</label>
                                    <select
                                        className="w-full bg-[var(--bg-page)] border border-[var(--border-strong)] rounded-lg px-2.5 py-2 text-xs text-[var(--text-primary)] focus:outline-none focus:border-cyan-500 transition-colors"
                                        value={tmMode}
                                        onChange={(e) => setTmMode(e.target.value)}
                                    >
                                        <option value="enhanced">Enhanced (TI-Driven)</option>
                                        <option value="standalone">Standalone Rules</option>
                                    </select>
                                </div>
                            </div>

                            {/* Threat Intel Switch */}
                            <div className="flex items-center justify-between bg-[var(--bg-page)]/60 p-3 rounded-lg border border-[var(--border-strong)]/40">
                                <div>
                                    <span className="block text-xs font-semibold text-[var(--text-primary)]">Enforce TI Pipeline</span>
                                    <span className="block text-[10px] text-[var(--text-muted)]">Process raw findings into TI findings</span>
                                </div>
                                <button
                                    onClick={() => setIncludeTi(!includeTi)}
                                    className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                        includeTi ? "bg-cyan-500" : "bg-[var(--bg-elevated)]"
                                    }`}
                                >
                                    <span
                                        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                                            includeTi ? "translate-x-4" : "translate-x-0"
                                        }`}
                                    />
                                </button>
                            </div>

                            {/* Action Button */}
                            <button
                                onClick={generateTIReport}
                                disabled={isLaunching || !selectedHistoryId || scanHistory.length === 0}
                                className="w-full bg-cyan-600 hover:bg-cyan-500 text-[var(--text-primary)] font-semibold text-xs py-3 rounded-lg shadow-lg hover:shadow-cyan-900/20 transition-all cursor-pointer disabled:opacity-40"
                            >
                                {isLaunching ? "Processing TI Layer..." : "Generate TI Report"}
                            </button>
                        </div>
                    )}
                </section>

                {/* Right Area: Results & Tracking */}
                <section className="lg:col-span-8 space-y-6">
                    {/* Live Tracker (Shows when flow starts) */}
                    {(investigationId || pollingError) && (
                        <div className="bg-[var(--bg-card)]/50 border border-[var(--border-strong)]/80 rounded-xl p-5 shadow-2xl backdrop-blur-sm space-y-5">
                            <div className="flex items-center justify-between">
                                <h2 className="text-sm font-semibold text-cyan-400 uppercase tracking-wider">
                                    🔄 Real-Time Pipeline Tracker
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
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 bg-[var(--bg-page)]/60 p-4 rounded-xl border border-[var(--border-strong)]/40 text-xs">
                                <div>
                                    <span className="block text-[var(--text-muted)]">Investigation ID</span>
                                    <span className="font-mono text-[var(--text-primary)] truncate block">{investigationId || "-"}</span>
                                </div>
                                <div>
                                    <span className="block text-[var(--text-muted)]">Scan Ingestion Ref</span>
                                    <span className="font-mono text-[var(--text-primary)] block">{investigationId || "-"}</span>
                                </div>
                                <div>
                                    <span className="block text-[var(--text-muted)]">Total Findings (TI)</span>
                                    <span className="font-semibold text-[var(--text-primary)] block">
                                        {statusInfo?.ti_findings?.length || 0}
                                    </span>
                                </div>
                                <div>
                                    <span className="block text-[var(--text-muted)]">TI Risk Score</span>
                                    <span className="font-semibold text-[var(--text-primary)] block">
                                        {statusInfo?.risk_score?.toFixed(1) || "-"}
                                    </span>
                                </div>
                            </div>

                            {/* Progress info hidden as it doesn't map directly to the strict TI schema anymore */}

                            {pollingError && (
                                <div className="text-xs bg-red-950/40 border border-red-900/30 text-red-300 p-3 rounded-lg">
                                    ⚠️ Connection Error: {pollingError}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Results Explorer (Shows when results exist) */}
                    {fullResults ? (
                        <div className="bg-[var(--bg-card)]/50 border border-[var(--border-strong)]/80 rounded-xl p-5 shadow-2xl backdrop-blur-sm space-y-5">
                            {/* Tabs Header */}
                            <div className="flex border-b border-[var(--border-strong)] gap-1 overflow-x-auto">
                                {[
                                    { key: "findings", label: `TI Findings (${fullResults.ti_findings?.length || 0})` },
                                    { key: "reports", label: "Threat Summary" },
                                    { key: "raw", label: "Strict TI Schema Payload" }
                                ].map((tab) => (
                                    <button
                                        key={tab.key}
                                        onClick={() => setActiveTab(tab.key as typeof activeTab)}
                                        className={`px-4 py-2 text-xs font-semibold border-b-2 whitespace-nowrap transition-colors cursor-pointer ${
                                            activeTab === tab.key
                                                ? "border-cyan-500 text-cyan-400"
                                                : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-primary)]"
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
                                        {fullResults.ti_findings && fullResults.ti_findings.length > 0 ? (
                                            fullResults.ti_findings.map((f, i) => {
                                                const uniqueId = f.finding_id + i;
                                                const isExpanded = expandedFinding === uniqueId;
                                                return (
                                                    <div
                                                        key={uniqueId}
                                                        className="bg-[var(--bg-page)]/60 rounded-xl border border-[var(--border-strong)]/60 overflow-hidden shadow-md"
                                                    >
                                                        {/* Accordion header */}
                                                        <div
                                                            onClick={() => setExpandedFinding(isExpanded ? null : uniqueId)}
                                                            className="p-4 flex items-center justify-between gap-3 cursor-pointer hover:bg-[var(--bg-page)]/90 transition-colors"
                                                        >
                                                            <div className="space-y-1">
                                                                <div className="flex items-center gap-2 flex-wrap">
                                                                    <span className={`text-[9px] uppercase font-bold px-2 py-0.5 border rounded-md ${getSeverityColor(f.severity)}`}>
                                                                        {f.severity}
                                                                    </span>
                                                                    <span className="text-[10px] font-semibold text-[var(--text-muted)] bg-[var(--bg-card)] border border-[var(--border-strong)] px-2 py-0.5 rounded-md">
                                                                        {f.category}
                                                                    </span>
                                                                    {f.verification_status && (
                                                                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-md border ${
                                                                            f.verification_status === "confirmed" || f.verification_status === "verified"
                                                                                ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                                                                                : "bg-amber-950 text-amber-400 border-amber-800"
                                                                        }`}>
                                                                            {f.verification_status}
                                                                        </span>
                                                                    )}
                                                                </div>
                                                                <h3 className="text-xs font-bold text-[var(--text-primary)] mt-1">{f.title}</h3>
                                                            </div>
                                                            <div className="flex items-center gap-4">
                                                                <div className="text-right">
                                                                    <span className="block text-[10px] text-[var(--text-muted)]">Confidence</span>
                                                                    <span className="text-xs font-bold text-cyan-400">{(f.confidence * 100).toFixed(0)}%</span>
                                                                </div>
                                                                <span className="text-[var(--text-muted)] text-xs">{isExpanded ? "▲" : "▼"}</span>
                                                            </div>
                                                        </div>

                                                        {/* Accordion body */}
                                                        {isExpanded && (
                                                            <div className="p-4 border-t border-[var(--border-strong)] bg-[var(--bg-page)]/40 space-y-3 text-xs">
                                                                <div className="grid grid-cols-2 gap-4">
                                                                    <div>
                                                                        <span className="block text-[10px] text-[var(--text-muted)] font-semibold mb-1">Affected Endpoint</span>
                                                                        <span className="font-mono text-[var(--text-secondary)] break-all">{f.affected_asset}</span>
                                                                    </div>
                                                                    <div>
                                                                        <span className="block text-[10px] text-[var(--text-muted)] font-semibold mb-1">Exploitability</span>
                                                                        <span className="font-mono text-[var(--text-secondary)] capitalize">{f.exploitability}</span>
                                                                    </div>
                                                                </div>
                                                                
                                                                <div className="grid grid-cols-2 gap-4">
                                                                    <div>
                                                                        <span className="block text-[10px] text-[var(--text-muted)] font-semibold mb-1">FP Probability</span>
                                                                        <span className="font-mono text-[var(--text-secondary)]">{(f.false_positive_probability * 100).toFixed(0)}%</span>
                                                                    </div>
                                                                    <div>
                                                                        <span className="block text-[10px] text-[var(--text-muted)] font-semibold mb-1">Risk Multiplier</span>
                                                                        <span className="font-mono text-[var(--text-secondary)]">{f.risk_multiplier}x</span>
                                                                    </div>
                                                                </div>

                                                                {f.tags && f.tags.length > 0 && (
                                                                    <div>
                                                                        <span className="block text-[10px] text-[var(--text-muted)] font-semibold mb-1">Tags</span>
                                                                        <div className="flex flex-wrap gap-1">
                                                                            {f.tags.map((t, idx) => (
                                                                                <span key={idx} className="text-[10px] text-[var(--text-muted)] bg-[var(--bg-card)] border border-[var(--border-strong)] px-2 py-0.5 rounded">
                                                                                    {t}
                                                                                </span>
                                                                            ))}
                                                                        </div>
                                                                    </div>
                                                                )}
                                                                <div>
                                                                    <span className="block text-[10px] text-[var(--text-muted)] font-semibold mb-1">Vulnerability Evidence Trace</span>
                                                                    <pre className="w-full bg-[var(--bg-page)] border border-[var(--border-strong)] rounded-lg p-3 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-[150px] whitespace-pre-wrap">
                                                                        {f.evidence || "No evidence details captured."}
                                                                    </pre>
                                                                </div>
                                                            </div>
                                                        )}
                                                    </div>
                                                );
                                            })
                                        ) : (
                                            <div className="text-center py-12 text-[var(--text-muted)] text-xs">
                                                Zero vulnerability findings discovered for this target website.
                                            </div>
                                        )}
                                    </div>
                                )}



                                {/* ─── REPORTS COMPLIANCE TAB ─── */}
                                {activeTab === "reports" && (
                                    <div className="space-y-6">
                                        <div className="bg-[var(--bg-page)]/60 border border-[var(--border-strong)]/60 p-5 rounded-xl space-y-3">
                                            <div className="flex items-center justify-between border-b border-[var(--border-strong)] pb-2">
                                                <h3 className="text-xs font-bold text-[var(--text-primary)]">🔍 Threat Summary</h3>
                                                <span className="text-xs font-semibold text-cyan-400">
                                                    Risk Index: {fullResults.risk_score?.toFixed(1) || 0}
                                                </span>
                                            </div>
                                            <div className="text-xs space-y-1">
                                                <pre className="text-[var(--text-secondary)] leading-relaxed bg-[var(--bg-page)] p-3 rounded-lg border border-[var(--border-strong)] whitespace-pre-wrap font-sans">
                                                    {JSON.stringify(fullResults.summary, null, 2)}
                                                </pre>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* ─── RAW JSON TAB ─── */}
                                {activeTab === "raw" && (
                                    <div className="space-y-2">
                                        <span className="text-[10px] text-[var(--text-muted)] block font-mono">Raw Investigation Schema Payload</span>
                                        <pre className="w-full bg-[var(--bg-page)] border border-[var(--border-strong)] rounded-xl p-4 text-[11px] font-mono text-cyan-400 overflow-x-auto max-h-[360px] whitespace-pre">
                                            {JSON.stringify(fullResults, null, 2)}
                                        </pre>
                                    </div>
                                )}
                            </div>
                        </div>
                    ) : (
                        /* Default state when not scanning */
                        !investigationId && (
                            <div className="bg-[var(--bg-card)]/30 border border-[var(--border-strong)]/60 rounded-xl py-20 text-center text-[var(--text-muted)] flex flex-col items-center justify-center space-y-4">
                                <span className="text-4xl">🚀</span>
                                <div>
                                    <h3 className="text-sm font-bold text-[var(--text-primary)]">TI Pipeline Sandbox Ready</h3>
                                    <p className="text-xs text-[var(--text-muted)] mt-1 max-w-sm mx-auto leading-relaxed">
                                        Select a past Pentest Investigation on the left panel to dynamically route its raw findings through the TI Normalization and Risk Inference engines, displaying ONLY the refined findings here.
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
