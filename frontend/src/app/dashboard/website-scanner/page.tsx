"use client";

import { useState, useRef } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";

// ─── Types ───────────────────────────────────────────────────

interface Finding {
    id: string;
    title: string;
    severity: "high" | "medium" | "low";
    classification?: "vulnerability" | "best_practice";
    confidence_label?: string;
    severity_justification?: string;
    url: string;
    description: string;
    evidence?: string;
    false_positive_check?: string;
    remediation?: string;
    auto_fix?: string;
}

interface ScanResult {
    scan_id: string;
    target: string;
    started_at: string;
    duration: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    endpoints_found: number;
    findings: Finding[];
    headers: Record<string, string>;
    endpoints: Array<{
        type: string;
        url: string;
        text?: string;
        method?: string;
        status?: number;
        inputs?: Array<{ name: string; type: string }>;
    }>;
    false_positives_filtered?: string[];
    error?: string;
}

// ─── Test options ────────────────────────────────────────────

const TEST_OPTIONS = [
    { key: "security_headers", label: "Security Headers", icon: "🔒" },
    { key: "xss", label: "XSS Testing", icon: "💉" },
    { key: "sqli", label: "SQL Injection", icon: "🗃️" },
    { key: "endpoint_crawling", label: "Endpoint Crawling", icon: "📂" },
    { key: "cookie_analysis", label: "Cookie Analysis", icon: "🍪" },
    { key: "misconfiguration", label: "Misconfiguration", icon: "⚙️" },
    { key: "directory_discovery", label: "Directory Discovery", icon: "🔍" },
    { key: "brute_force", label: "Brute Force", icon: "🔓" },
];

// ─── Severity colors ─────────────────────────────────────────

const SEVERITY_STYLES: Record<string, { bg: string; border: string; text: string; badge: string }> = {
    high: {
        bg: "bg-red-500/10",
        border: "border-red-500/30",
        text: "text-red-400",
        badge: "bg-red-500 text-white",
    },
    medium: {
        bg: "bg-orange-500/10",
        border: "border-orange-500/30",
        text: "text-orange-400",
        badge: "bg-orange-500 text-white",
    },
    low: {
        bg: "bg-yellow-500/10",
        border: "border-yellow-500/30",
        text: "text-yellow-400",
        badge: "bg-yellow-600 text-white",
    },
};

// ─── Main Page ───────────────────────────────────────────────

export default function WebsiteScannerPage() {
    const { token } = useAuth();
    const [url, setUrl] = useState("");
    const [selectedTests, setSelectedTests] = useState<string[]>(
        TEST_OPTIONS.map((t) => t.key)
    );
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState("");
    const [activeTab, setActiveTab] = useState<"findings" | "headers" | "endpoints">("findings");
    const [severityFilter, setSeverityFilter] = useState<"all" | "high" | "medium" | "low">("all");
    const reportRef = useRef<HTMLDivElement>(null);

    const toggleTest = (key: string) => {
        setSelectedTests((prev) =>
            prev.includes(key) ? prev.filter((t) => t !== key) : [...prev, key]
        );
    };

    const handleScan = async () => {
        if (!url.trim()) return;
        if (selectedTests.length === 0) {
            setError("Please select at least one test.");
            return;
        }

        setScanning(true);
        setError("");
        setResult(null);

        try {
            const data = await api.post<ScanResult>(
                "/api/v1/website-scanner/scan",
                { target: url.trim(), tests: selectedTests },
                token || undefined
            );
            setResult(data);
            // Scroll to report
            setTimeout(() => {
                reportRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
            }, 100);
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : "Scan failed";
            setError(message);
        } finally {
            setScanning(false);
        }
    };

    const exportJSON = () => {
        if (!result) return;
        const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${result.scan_id}.json`;
        a.click();
        URL.revokeObjectURL(url);
    };

    const filteredFindings = result?.findings.filter(
        (f) => severityFilter === "all" || f.severity === severityFilter
    ) || [];

    return (
        <div className="space-y-6 max-w-5xl mx-auto">
            {/* ── Scanner Input ─────────────────────────────────── */}
            <div className="rounded-2xl border border-white/[0.08] bg-[#0f172a]/80 p-6">
                {/* URL Input */}
                <div className="flex gap-3">
                    <div className="flex-1 relative">
                        <div className="absolute left-4 top-1/2 -translate-y-1/2">
                            <svg className="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
                            </svg>
                        </div>
                        <input
                            id="scanner-url-input"
                            type="text"
                            placeholder="https://example.com/"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            onKeyDown={(e) => e.key === "Enter" && handleScan()}
                            className="w-full bg-[#1e293b] border border-white/[0.08] rounded-xl py-3.5 pl-12 pr-4 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/25 transition-all"
                        />
                    </div>
                    <button
                        id="scan-now-button"
                        onClick={handleScan}
                        disabled={scanning || !url.trim()}
                        className="px-6 py-3.5 rounded-xl bg-gradient-to-r from-purple-600 to-purple-500 text-white text-sm font-semibold hover:from-purple-500 hover:to-purple-400 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 shadow-lg shadow-purple-500/20"
                    >
                        {scanning ? (
                            <>
                                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                </svg>
                                Scanning...
                            </>
                        ) : (
                            <>
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <circle cx="11" cy="11" r="8" /><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35" />
                                </svg>
                                Scan Now
                            </>
                        )}
                    </button>
                </div>

                {/* Test Checkboxes */}
                <div className="flex flex-wrap gap-3 mt-4">
                    {TEST_OPTIONS.map((test) => (
                        <label
                            key={test.key}
                            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs cursor-pointer transition-all border ${
                                selectedTests.includes(test.key)
                                    ? "bg-purple-500/15 border-purple-500/30 text-purple-300"
                                    : "bg-white/[0.03] border-white/[0.08] text-slate-400 hover:bg-white/[0.06]"
                            }`}
                        >
                            <input
                                type="checkbox"
                                checked={selectedTests.includes(test.key)}
                                onChange={() => toggleTest(test.key)}
                                className="w-3 h-3 rounded accent-purple-500"
                            />
                            <span>{test.icon}</span>
                            <span>{test.label}</span>
                        </label>
                    ))}
                </div>

                {/* Legal Notice */}
                <div className="flex items-start gap-2 mt-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3">
                    <svg className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <p className="text-xs text-yellow-400/80">
                        <strong className="text-yellow-400">Legal Notice:</strong> Only scan websites you own or have explicit written permission to test. Unauthorized scanning may be illegal. You are responsible for your actions.
                    </p>
                </div>
            </div>

            {/* ── Error ─────────────────────────────────────────── */}
            {error && (
                <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-400">
                    {error}
                </div>
            )}

            {/* ── Scanning Animation ────────────────────────────── */}
            {scanning && (
                <div className="rounded-2xl border border-purple-500/20 bg-[#0f172a]/80 p-8 text-center space-y-4">
                    <div className="relative mx-auto w-16 h-16">
                        <div className="absolute inset-0 rounded-full border-2 border-purple-500/20" />
                        <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-purple-500 animate-spin" />
                        <div className="absolute inset-2 rounded-full border-2 border-transparent border-t-purple-400 animate-spin" style={{ animationDirection: "reverse", animationDuration: "1.5s" }} />
                        <svg className="absolute inset-0 w-full h-full p-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <circle cx="11" cy="11" r="8" /><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35" />
                        </svg>
                    </div>
                    <div>
                        <p className="text-sm font-semibold text-slate-200">Scanning target...</p>
                        <p className="text-xs text-slate-500 mt-1">{url}</p>
                    </div>
                </div>
            )}

            {/* ── Scan Report ───────────────────────────────────── */}
            {result && !result.error && (
                <div ref={reportRef} className="space-y-5">
                    {/* Report Header */}
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-purple-500/15 flex items-center justify-center">
                                <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                </svg>
                            </div>
                            <div>
                                <h2 className="text-lg font-bold text-slate-100">Scan Report</h2>
                                <p className="text-xs text-slate-500">{result.target}</p>
                            </div>
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={exportJSON}
                                className="px-3 py-1.5 rounded-lg border border-white/[0.08] bg-white/[0.04] text-xs text-slate-300 hover:bg-white/[0.08] transition-colors flex items-center gap-1.5"
                            >
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                </svg>
                                JSON
                            </button>
                            <button
                                onClick={() => { setResult(null); setUrl(""); }}
                                className="px-3 py-1.5 rounded-lg border border-purple-500/20 bg-purple-500/10 text-xs text-purple-300 hover:bg-purple-500/20 transition-colors flex items-center gap-1.5"
                            >
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                                </svg>
                                New Scan
                            </button>
                        </div>
                    </div>

                    {/* Severity Cards */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {[
                            { label: "HIGH RISK", count: result.high, color: "text-red-400", border: "border-red-500/30", bg: "bg-red-500/10" },
                            { label: "MEDIUM RISK", count: result.medium, color: "text-orange-400", border: "border-orange-500/30", bg: "bg-orange-500/10" },
                            { label: "LOW RISK", count: result.low, color: "text-yellow-400", border: "border-yellow-500/30", bg: "bg-yellow-500/10" },
                            { label: "TOTAL", count: result.total, color: "text-purple-400", border: "border-purple-500/30", bg: "bg-purple-500/10" },
                        ].map((card) => (
                            <div key={card.label} className={`rounded-xl border-2 ${card.border} ${card.bg} p-4 text-center`}>
                                <p className={`text-3xl font-black ${card.color}`}>{card.count}</p>
                                <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mt-1">{card.label}</p>
                            </div>
                        ))}
                    </div>

                    {/* Scan Metadata */}
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
                        {[
                            { label: "SCAN ID", value: result.scan_id },
                            { label: "TARGET", value: result.target },
                            { label: "DURATION", value: `${result.duration}s` },
                            { label: "ENDPOINTS FOUND", value: String(result.endpoints_found) },
                            { label: "STARTED", value: result.started_at },
                        ].map((item) => (
                            <div key={item.label} className="rounded-lg border border-white/[0.06] bg-white/[0.03] p-3">
                                <p className="text-[10px] text-slate-600 uppercase tracking-widest font-semibold">{item.label}</p>
                                <p className="text-slate-300 font-medium mt-1 truncate" title={item.value}>{item.value}</p>
                            </div>
                        ))}
                    </div>

                    {/* Tabs */}
                    <div className="flex items-center gap-1 border-b border-white/[0.06] pb-0">
                        {([
                            { key: "findings", label: "Findings", icon: "🔴" },
                            { key: "headers", label: "Headers", icon: "🟢" },
                            { key: "endpoints", label: "Endpoints", icon: "🔵" },
                        ] as const).map((tab) => (
                            <button
                                key={tab.key}
                                onClick={() => setActiveTab(tab.key)}
                                className={`px-4 py-2.5 text-xs font-medium transition-colors border-b-2 -mb-px flex items-center gap-1.5 ${
                                    activeTab === tab.key
                                        ? "border-purple-500 text-purple-300"
                                        : "border-transparent text-slate-500 hover:text-slate-300"
                                }`}
                            >
                                <span>{tab.icon}</span>
                                {tab.label}
                            </button>
                        ))}
                    </div>

                    {/* ── Findings Tab ──────────────────────────── */}
                    {activeTab === "findings" && (
                        <div className="space-y-4">
                            {/* Severity Filter */}
                            <div className="flex items-center justify-between">
                                <p className="text-xs text-slate-500">{filteredFindings.length} Findings</p>
                                <div className="flex gap-1">
                                    {(["all", "high", "medium", "low"] as const).map((sev) => (
                                        <button
                                            key={sev}
                                            onClick={() => setSeverityFilter(sev)}
                                            className={`px-3 py-1 rounded-md text-xs transition-colors ${
                                                severityFilter === sev
                                                    ? sev === "all"
                                                        ? "bg-slate-600 text-white"
                                                        : sev === "high"
                                                        ? "bg-red-500 text-white"
                                                        : sev === "medium"
                                                        ? "bg-orange-500 text-white"
                                                        : "bg-yellow-600 text-white"
                                                    : "bg-white/[0.04] text-slate-400 hover:bg-white/[0.08]"
                                            }`}
                                        >
                                            {sev === "all" ? "All" : `● ${sev.charAt(0).toUpperCase() + sev.slice(1)}`}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Finding Cards */}
                            {filteredFindings.length === 0 ? (
                                <div className="rounded-xl border border-green-500/20 bg-green-500/10 p-6 text-center">
                                    <svg className="w-8 h-8 text-green-400 mx-auto mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    <p className="text-sm text-green-400 font-semibold">No vulnerabilities found!</p>
                                    <p className="text-xs text-green-400/60 mt-1">The target appears to be well secured.</p>
                                </div>
                            ) : (
                                filteredFindings.map((finding) => {
                                    const style = SEVERITY_STYLES[finding.severity] || SEVERITY_STYLES.low;
                                    return (
                                        <div
                                            key={finding.id}
                                            className={`rounded-xl border ${style.border} ${style.bg} p-5 space-y-3`}
                                        >
                                            {/* Header row */}
                                            <div className="flex items-start justify-between gap-3">
                                                <div>
                                                    <p className="text-[10px] text-slate-600 font-mono">{finding.id}</p>
                                                    <h3 className="text-sm font-bold text-slate-100 mt-0.5">{finding.title}</h3>
                                                    <p className="text-xs text-purple-400 mt-1 flex items-center gap-1">
                                                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                            <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                                                        </svg>
                                                        {finding.url}
                                                    </p>
                                                </div>
                                                <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase ${style.badge}`}>
                                                    {finding.severity}
                                                </span>
                                                {finding.confidence_label && (
                                                    <span className={`px-2.5 py-1 rounded-md text-[10px] font-semibold ${
                                                        finding.confidence_label.includes('Confirmed') ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                                                        finding.confidence_label.includes('False Positive') ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                                                        'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                                                    }`}>
                                                        {finding.confidence_label}
                                                    </span>
                                                )}
                                            </div>

                                            {/* Classification Banner */}
                                            {finding.classification === "best_practice" ? (
                                                <div className="flex items-center gap-2 bg-amber-500/10 rounded-lg px-3 py-2 border border-amber-500/20">
                                                    <span className="text-amber-400 text-sm">❗</span>
                                                    <p className="text-[11px] text-amber-400 font-medium">This is NOT an exploitable vulnerability, but a missing security best practice.</p>
                                                </div>
                                            ) : finding.classification === "vulnerability" ? (
                                                <div className="flex items-center gap-2 bg-red-500/10 rounded-lg px-3 py-2 border border-red-500/20">
                                                    <span className="text-red-400 text-sm">🔴</span>
                                                    <p className="text-[11px] text-red-400 font-medium">Exploitable vulnerability — confirmed through active testing.</p>
                                                </div>
                                            ) : null}

                                            {/* Severity Justification */}
                                            {finding.severity_justification && (
                                                <div className="bg-white/[0.03] rounded-lg p-3 border border-white/[0.06]">
                                                    <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">⚖️ Severity Justification</p>
                                                    <p className="text-xs text-slate-400 leading-relaxed">{finding.severity_justification}</p>
                                                </div>
                                            )}

                                            {/* Description */}
                                            <p className="text-xs text-slate-400 leading-relaxed">{finding.description}</p>

                                            {/* Evidence */}
                                            {finding.evidence && (
                                                <div className="bg-black/30 rounded-lg p-3 border border-white/[0.06]">
                                                    <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">🏷️ Evidence</p>
                                                    <p className="text-xs font-mono text-purple-300 whitespace-pre-wrap break-all">
                                                        {finding.evidence}
                                                    </p>
                                                </div>
                                            )}

                                            {/* False Positive Check */}
                                            {finding.false_positive_check && (
                                                <div className="bg-blue-500/10 rounded-lg p-3 border border-blue-500/20">
                                                    <p className="text-[10px] font-semibold text-blue-400 uppercase tracking-wider mb-1">🔍 False Positive Analysis</p>
                                                    <p className="text-xs text-blue-300/80 leading-relaxed">{finding.false_positive_check}</p>
                                                </div>
                                            )}

                                            {/* Remediation */}
                                            {finding.remediation && (
                                                <div className="bg-green-500/10 rounded-lg p-3 border border-green-500/20">
                                                    <p className="text-[10px] font-semibold text-green-400 uppercase tracking-wider mb-1">🟩 Remediation</p>
                                                    <p className="text-xs text-green-400/80 mt-1 whitespace-pre-wrap">{finding.remediation}</p>
                                                </div>
                                            )}

                                            {/* Auto-Fix */}
                                            {finding.auto_fix && (
                                                <div className="bg-cyan-500/10 rounded-lg border border-cyan-500/20 overflow-hidden">
                                                    <div className="flex items-center justify-between px-3 py-2 bg-cyan-500/5 border-b border-cyan-500/10">
                                                        <p className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">⚡ Auto-Fix Suggestion</p>
                                                        <button
                                                            onClick={() => navigator.clipboard.writeText(finding.auto_fix || "")}
                                                            className="text-[10px] text-cyan-400/60 hover:text-cyan-300 transition-colors flex items-center gap-1"
                                                        >
                                                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                                                                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                                                            </svg>
                                                            Copy
                                                        </button>
                                                    </div>
                                                    <pre className="px-3 py-2.5 text-[11px] font-mono text-cyan-300/80 whitespace-pre-wrap break-all overflow-x-auto">{finding.auto_fix}</pre>
                                                </div>
                                            )}
                                        </div>
                                    );
                                })
                            )}
                        </div>
                    )}

                    {/* ── Headers Tab ───────────────────────────── */}
                    {activeTab === "headers" && (
                        <div className="rounded-xl border border-white/[0.06] overflow-hidden">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="bg-white/[0.04]">
                                        <th className="text-left px-4 py-2.5 text-slate-500 font-semibold uppercase tracking-wider">Header</th>
                                        <th className="text-left px-4 py-2.5 text-slate-500 font-semibold uppercase tracking-wider">Value</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {Object.entries(result.headers).map(([key, value]) => (
                                        <tr key={key} className="border-t border-white/[0.04]">
                                            <td className="px-4 py-2.5 text-purple-300 font-mono font-medium">{key}</td>
                                            <td className="px-4 py-2.5 text-slate-400 font-mono break-all">{value}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {/* ── Endpoints Tab ─────────────────────────── */}
                    {activeTab === "endpoints" && (
                        <div className="space-y-2">
                            {result.endpoints.length === 0 ? (
                                <div className="rounded-xl border border-white/[0.06] bg-white/[0.03] p-6 text-center">
                                    <p className="text-xs text-slate-500">No endpoints discovered. Enable &quot;Directory Discovery&quot; to find paths.</p>
                                </div>
                            ) : (
                                result.endpoints.map((ep, i) => (
                                    <div key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.03] p-3 flex items-center gap-3">
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                            ep.type === "form"
                                                ? "bg-orange-500/15 text-orange-400 border border-orange-500/20"
                                                : "bg-blue-500/15 text-blue-400 border border-blue-500/20"
                                        }`}>
                                            {ep.type === "form" ? (ep.method || "GET") : "LINK"}
                                        </span>
                                        <div className="flex-1 min-w-0">
                                            <p className="text-xs text-slate-300 font-mono truncate">{ep.url}</p>
                                            {ep.text && <p className="text-[10px] text-slate-500 mt-0.5 truncate">{ep.text}</p>}
                                            {ep.inputs && ep.inputs.length > 0 && (
                                                <div className="flex flex-wrap gap-1 mt-1">
                                                    {ep.inputs.map((inp, j) => (
                                                        <span key={j} className="text-[10px] bg-purple-500/10 text-purple-300 px-1.5 py-0.5 rounded border border-purple-500/20">
                                                            {inp.name} ({inp.type})
                                                        </span>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* ── Error result ──────────────────────────────────── */}
            {result && result.error && (
                <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-5 space-y-2">
                    <h3 className="text-sm font-bold text-red-400">Scan Failed</h3>
                    <p className="text-xs text-red-400/80">{result.error}</p>
                </div>
            )}
        </div>
    );
}
