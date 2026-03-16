"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card } from "@/components/ui";

interface Scan {
    id: string;
    scan_type: string;
    target: string;
    status: string;
    threat_level: string | null;
    created_at: string;
    completed_at: string | null;
}

interface ScanReport {
    id: string;
    scan_id: string;
    summary: string;
    details: Record<string, unknown>;
    indicators: Array<{
        type: string;
        value: string;
        threat_level: string;
    }>;
    created_at: string;
}

// ─── Download helpers ────────────────────────────────────────

function downloadBlob(content: string, filename: string, mime: string) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function buildTextReport(scan: Scan, report: ScanReport): string {
    const divider = "═".repeat(60);
    const thinDiv = "─".repeat(60);
    const lines: string[] = [];

    lines.push(divider);
    lines.push("  TIBSA — Threat Intelligence Security Report");
    lines.push(divider);
    lines.push("");
    lines.push(`  Report ID    : ${report.id}`);
    lines.push(`  Scan ID      : ${scan.id}`);
    lines.push(`  Scan Type    : ${scan.scan_type.toUpperCase()}`);
    lines.push(`  Target       : ${scan.target}`);
    lines.push(`  Threat Level : ${(scan.threat_level || "unknown").toUpperCase()}`);
    lines.push(`  Scanned At   : ${new Date(scan.created_at).toLocaleString()}`);
    if (scan.completed_at) {
        lines.push(`  Completed At : ${new Date(scan.completed_at).toLocaleString()}`);
    }
    lines.push("");
    lines.push(thinDiv);
    lines.push("  SUMMARY");
    lines.push(thinDiv);
    lines.push("");
    lines.push(`  ${report.summary}`);
    lines.push("");

    // ── VT section ──
    const details = report.details as Record<string, unknown>;
    const vt = details?.virustotal as Record<string, unknown> | undefined;
    if (vt && !vt.error) {
        lines.push(thinDiv);
        lines.push("  VIRUSTOTAL ANALYSIS");
        lines.push(thinDiv);
        lines.push("");
        const malicious = (vt.malicious as number) || 0;
        const suspicious = (vt.suspicious as number) || 0;
        const stats = (vt.stats as Record<string, number>) || {};
        const clean = (stats.harmless || 0) + (stats.undetected || 0);
        const total = malicious + suspicious + clean;
        lines.push(`  Detection Ratio : ${malicious} / ${total} engines`);
        lines.push(`  Malicious       : ${malicious}`);
        lines.push(`  Suspicious      : ${suspicious}`);
        lines.push(`  Clean           : ${clean}`);
        if (vt.file_name) lines.push(`  File Name       : ${vt.file_name}`);
        if (vt.file_type) lines.push(`  File Type       : ${vt.file_type}`);
        lines.push("");
    }

    // ── AI section ──
    const ai = details?.ai_classifier as Record<string, unknown> | undefined;
    if (ai && ai.model !== "model_not_loaded") {
        lines.push(thinDiv);
        lines.push("  AI PHISHING CLASSIFIER");
        lines.push(thinDiv);
        lines.push("");
        const isPhishing = ai.is_phishing as boolean;
        const confidence = ((ai.confidence as number) || 0) * 100;
        lines.push(`  Verdict    : ${isPhishing ? "PHISHING" : "LEGITIMATE"}`);
        lines.push(`  Confidence : ${confidence.toFixed(1)}%`);
        lines.push(`  Model      : ${ai.model}`);
        lines.push("");
    }

    // ── Combined Threat Score section ──
    const threatScore = details?.threat_score as number | undefined;
    const verdict = details?.verdict as string | undefined;
    if (typeof threatScore === "number" && verdict) {
        lines.push(thinDiv);
        lines.push("  COMBINED THREAT SCORE");
        lines.push(thinDiv);
        lines.push("");
        lines.push(`  Score      : ${(threatScore * 100).toFixed(1)} / 100`);
        lines.push(`  Verdict    : ${verdict.toUpperCase()}`);
        lines.push(`  Formula    : (0.6 × AI Score) + (0.4 × VT Score)`);
        lines.push("");
    }

    // ── Malice section ──
    const malice = details?.malice as Record<string, unknown> | undefined;
    if (malice && !malice.error) {
        lines.push(thinDiv);
        lines.push("  LOCAL AV ENGINE RESULTS");
        lines.push(thinDiv);
        lines.push("");
        lines.push(`  Detected By : ${malice.detected_by || 0} / ${malice.total_engines || 0} engines`);
        if (malice.top_result) lines.push(`  Top Threat  : ${malice.top_result}`);
        const engines = (malice.engines as Array<Record<string, unknown>>) || [];
        if (engines.length > 0) {
            lines.push("");
            lines.push(`  ${"Engine".padEnd(20)} ${"Status".padEnd(12)} Result`);
            lines.push(`  ${"─".repeat(20)} ${"─".repeat(12)} ${"─".repeat(24)}`);
            for (const eng of engines) {
                const name = String(eng.label || eng.engine).padEnd(20);
                const isMal = eng.malware as boolean;
                const stat = (isMal ? "DETECTED" : eng.error ? "ERROR" : "Clean").padEnd(12);
                const res = isMal ? String(eng.result || "Malware") : (eng.error ? String(eng.error) : "—");
                lines.push(`  ${name} ${stat} ${res}`);
            }
        }
        lines.push("");
    }

    // ── Indicators ──
    if (report.indicators?.length > 0) {
        lines.push(thinDiv);
        lines.push("  INDICATORS OF COMPROMISE");
        lines.push(thinDiv);
        lines.push("");
        for (const ind of report.indicators) {
            lines.push(`  [${ind.threat_level.toUpperCase()}] ${ind.type}: ${ind.value}`);
        }
        lines.push("");
    }

    lines.push(divider);
    lines.push(`  Generated by TIBSA Platform — ${new Date().toLocaleString()}`);
    lines.push(divider);

    return lines.join("\n");
}

function buildJsonReport(scan: Scan, report: ScanReport): string {
    return JSON.stringify({
        meta: {
            generator: "TIBSA Platform",
            generated_at: new Date().toISOString(),
            report_id: report.id,
        },
        scan: {
            id: scan.id,
            type: scan.scan_type,
            target: scan.target,
            status: scan.status,
            threat_level: scan.threat_level,
            created_at: scan.created_at,
            completed_at: scan.completed_at,
        },
        report: {
            summary: report.summary,
            details: report.details,
            indicators: report.indicators,
        },
    }, null, 2);
}

export default function ReportsPage() {
    const { token } = useAuth();
    const [scans, setScans] = useState<Scan[]>([]);
    const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
    const [selectedReport, setSelectedReport] = useState<ScanReport | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [reportLoading, setReportLoading] = useState(false);
    const [downloadMenuOpen, setDownloadMenuOpen] = useState(false);

    const fetchScans = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<Scan[]>("/api/v1/scans/", token);
            setScans(data.filter((s) => s.status === "completed"));
        } catch (err) {
            console.error("Failed to fetch scans:", err);
        } finally {
            setIsLoading(false);
        }
    }, [token]);

    useEffect(() => {
        fetchScans();
    }, [fetchScans]);

    const viewReport = async (scanId: string) => {
        if (!token) return;
        setReportLoading(true);
        setDownloadMenuOpen(false);
        const scan = scans.find((s) => s.id === scanId) || null;
        setSelectedScan(scan);
        try {
            const data = await api.get<ScanReport>(`/api/v1/scans/${scanId}`, token);
            setSelectedReport(data);
        } catch {
            setSelectedReport(null);
        } finally {
            setReportLoading(false);
        }
    };

    const handleDownload = (format: "txt" | "json") => {
        if (!selectedReport || !selectedScan) return;
        const safeName = selectedScan.target.replace(/[^a-zA-Z0-9.-]/g, "_").slice(0, 40);
        const date = new Date(selectedScan.created_at).toISOString().slice(0, 10);
        if (format === "txt") {
            const text = buildTextReport(selectedScan, selectedReport);
            downloadBlob(text, `TIBSA_Report_${safeName}_${date}.txt`, "text/plain;charset=utf-8");
        } else {
            const json = buildJsonReport(selectedScan, selectedReport);
            downloadBlob(json, `TIBSA_Report_${safeName}_${date}.json`, "application/json");
        }
        setDownloadMenuOpen(false);
    };

    const threatColor = (level: string | null) => {
        const colors: Record<string, string> = {
            safe: "text-green-400",
            low: "text-yellow-400",
            medium: "text-orange-400",
            high: "text-red-400",
            critical: "text-red-500",
        };
        return colors[level || "safe"] || "text-slate-500";
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-white">Scan Reports</h1>
                <p className="text-slate-400 mt-1">View detailed reports for completed scans</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Scan List */}
                <div className="lg:col-span-1">
                    <Card title="Completed Scans">
                        {isLoading ? (
                            <div className="text-center py-8 text-slate-500 text-sm">Loading...</div>
                        ) : scans.length === 0 ? (
                            <div className="text-center py-8 text-slate-500 text-sm">
                                No completed scans yet.
                            </div>
                        ) : (
                            <div className="space-y-2">
                                {scans.map((scan) => (
                                    <button
                                        key={scan.id}
                                        onClick={() => viewReport(scan.id)}
                                        className="w-full text-left p-3 rounded-lg bg-white/[0.04] hover:bg-blue-500/10 transition-colors text-sm border border-white/[0.06]"
                                    >
                                        <div className="flex items-center justify-between">
                                            <span className="font-medium text-slate-200">
                                                {scan.scan_type === "url" ? "🔗" : "📄"}{" "}
                                                {scan.scan_type.toUpperCase()}
                                            </span>
                                            <span className={`text-xs font-medium capitalize ${threatColor(scan.threat_level)}`}>
                                                {scan.threat_level || "—"}
                                            </span>
                                        </div>
                                        <p className="text-xs text-slate-500 truncate mt-1 font-mono">
                                            {scan.target}
                                        </p>
                                        <p className="text-xs text-slate-500 mt-1">
                                            {new Date(scan.created_at).toLocaleDateString()}
                                        </p>
                                    </button>
                                ))}
                            </div>
                        )}
                    </Card>
                </div>

                {/* Report Detail */}
                <div className="lg:col-span-2">
                    <Card title="Report Details">
                        {reportLoading ? (
                            <div className="text-center py-12 text-slate-500">Loading report...</div>
                        ) : !selectedReport ? (
                            <div className="text-center py-12 text-slate-500">
                                <p className="text-lg">📄</p>
                                <p className="mt-2">Select a scan to view its report</p>
                            </div>
                        ) : (
                            <div className="space-y-4">
                                {/* Download button */}
                                <div className="flex justify-end relative">
                                    <button
                                        onClick={() => setDownloadMenuOpen((v) => !v)}
                                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-500/15 text-blue-400 hover:bg-blue-500/25 border border-blue-500/20 transition-colors text-sm font-medium"
                                    >
                                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                        </svg>
                                        Download Report
                                        <svg className={`w-3 h-3 transition-transform ${downloadMenuOpen ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                                        </svg>
                                    </button>
                                    {downloadMenuOpen && (
                                        <div className="absolute right-0 top-full mt-1 w-52 rounded-lg bg-[#1a2744] border border-white/[0.08] shadow-2xl shadow-black/40 overflow-hidden z-10">
                                            <button
                                                onClick={() => handleDownload("txt")}
                                                className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-white/[0.06] transition-colors"
                                            >
                                                <div className="w-8 h-8 rounded-lg bg-emerald-500/15 flex items-center justify-center flex-shrink-0">
                                                    <svg className="w-4 h-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                                    </svg>
                                                </div>
                                                <div>
                                                    <p className="text-sm font-medium text-slate-200">Text Report</p>
                                                    <p className="text-[10px] text-slate-500">.txt — human-readable</p>
                                                </div>
                                            </button>
                                            <button
                                                onClick={() => handleDownload("json")}
                                                className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-white/[0.06] transition-colors border-t border-white/[0.04]"
                                            >
                                                <div className="w-8 h-8 rounded-lg bg-purple-500/15 flex items-center justify-center flex-shrink-0">
                                                    <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                                                    </svg>
                                                </div>
                                                <div>
                                                    <p className="text-sm font-medium text-slate-200">JSON Report</p>
                                                    <p className="text-[10px] text-slate-500">.json — machine-readable</p>
                                                </div>
                                            </button>
                                        </div>
                                    )}
                                </div>

                                <div>
                                    <h3 className="font-medium text-white">Summary</h3>
                                    <p className="text-sm text-slate-400 mt-1">{selectedReport.summary}</p>
                                </div>

                                {selectedReport.indicators?.length > 0 && (
                                    <div>
                                        <h3 className="font-medium text-white mb-2">Indicators Found</h3>
                                        <div className="space-y-2">
                                            {selectedReport.indicators.map((ind, i) => (
                                                <div key={i} className="flex items-center justify-between bg-white/[0.04] p-3 rounded-lg text-sm border border-white/[0.06]">
                                                    <div>
                                                        <span className="text-slate-500 text-xs uppercase">{ind.type}</span>
                                                        <p className="font-mono text-slate-200">{ind.value}</p>
                                                    </div>
                                                    <span className={`font-medium capitalize ${threatColor(ind.threat_level)}`}>
                                                        {ind.threat_level}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {selectedReport.details && Object.keys(selectedReport.details).length > 0 && (
                                    <div>
                                        <h3 className="font-medium text-white mb-2">Details</h3>
                                        <pre className="bg-[#0f172a] p-3 rounded-lg text-xs text-slate-400 overflow-x-auto border border-white/[0.06]">
                                            {JSON.stringify(selectedReport.details, null, 2)}
                                        </pre>
                                    </div>
                                )}
                            </div>
                        )}
                    </Card>
                </div>
            </div>
        </div>
    );
}
