"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";

// ─── URL validation helper ────────────────────────────────────
function isValidUrl(value: string): boolean {
    if (!value.trim()) return false;
    try {
        const u = new URL(value.trim());
        return u.protocol === "http:" || u.protocol === "https:";
    } catch {
        return false;
    }
}

// ─── Compact MD5 (RFC 1321) — pure TypeScript ─────────────────
function md5(input: ArrayBuffer): string {
    const bytes = new Uint8Array(input);
    const len = bytes.length;
    // pre-process: add bit '1', zeros, then 64-bit length
    const extra = ((55 - len) % 64 + 64) % 64;
    const msg = new Uint8Array(len + extra + 9);
    msg.set(bytes);
    msg[len] = 0x80;
    const bitLen = len * 8;
    msg[msg.length - 8] = bitLen & 0xff;
    msg[msg.length - 7] = (bitLen >>> 8) & 0xff;
    msg[msg.length - 6] = (bitLen >>> 16) & 0xff;
    msg[msg.length - 5] = (bitLen >>> 24) & 0xff;

    const T = new Uint32Array(64);
    for (let i = 0; i < 64; i++)
        T[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;

    const s = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    const view = new DataView(msg.buffer);
    for (let off = 0; off < msg.length; off += 64) {
        const M = Array.from({ length: 16 }, (_, i) => view.getUint32(off + i * 4, true));
        let A = a0, B = b0, C = c0, D = d0;
        for (let i = 0; i < 64; i++) {
            let F: number, g: number;
            if (i < 16) { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
            else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
            else { F = C ^ (B | ~D); g = (7 * i) % 16; }
            F = (F + A + T[i] + M[g]) >>> 0;
            A = D; D = C; C = B;
            B = (B + ((F << s[i]) | (F >>> (32 - s[i])))) >>> 0;
        }
        a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0;
        c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }

    const toLE = (n: number) => {
        const b = new Uint8Array(4);
        new DataView(b.buffer).setUint32(0, n, true);
        return b;
    };
    return [...toLE(a0), ...toLE(b0), ...toLE(c0), ...toLE(d0)]
        .map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ─── Browser SHA helper ────────────────────────────────────────
async function browserHash(algo: "SHA-1" | "SHA-256", buf: ArrayBuffer): Promise<string> {
    const hashBuf = await crypto.subtle.digest(algo, buf);
    return Array.from(new Uint8Array(hashBuf))
        .map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ─── FileInfo type ────────────────────────────────────────────
interface FileInfo {
    name: string;
    size: number;
    extension: string;
    mimeType: string;
    md5: string;
    sha1: string;
    sha256: string;
}

// ─── FileInfoPanel component ──────────────────────────────────
function FileInfoPanel({ info, loading }: { info: FileInfo | null; loading: boolean }) {
    if (loading) {
        return (
            <div className="mt-3 rounded-xl border border-purple-200 bg-purple-50 p-4 space-y-2 animate-pulse">
                {Array.from({ length: 6 }).map((_, i) => (
                    <div key={i} className="flex justify-between">
                        <div className="h-3 w-20 bg-purple-200 rounded" />
                        <div className="h-3 w-48 bg-purple-200 rounded" />
                    </div>
                ))}
            </div>
        );
    }
    if (!info) return null;

    const formatSize = (bytes: number) => {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
        return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
    };

    const rows: [string, string][] = [
        ["File Name", info.name],
        ["Size", formatSize(info.size)],
        ["Extension", info.extension || "(none)"],
        ["File Type", info.mimeType || "Unknown"],
        ["MD5", info.md5],
        ["SHA-1", info.sha1],
        ["SHA-256", info.sha256],
    ];

    return (
        <div className="mt-3 rounded-xl border border-purple-200 bg-purple-50 p-4">
            <p className="text-xs font-semibold text-purple-700 mb-2 flex items-center gap-1.5">
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                File Analysis
            </p>
            <div className="space-y-1.5">
                {rows.map(([label, value]) => (
                    <div key={label} className="flex items-start justify-between gap-2 text-xs">
                        <span className="text-gray-500 font-medium flex-shrink-0 w-20">{label}</span>
                        <span
                            className={`font-mono text-gray-800 break-all text-right ${["MD5", "SHA-1", "SHA-256"].includes(label)
                                    ? "text-[10px] text-purple-800"
                                    : ""
                                }`}
                        >
                            {value}
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
}

// ─── Types ───────────────────────────────────────────────────

interface Scan {
    id: string;
    scan_type: "url" | "file" | "file_upload";
    target: string;
    status: "pending" | "running" | "in_progress" | "completed" | "failed" | "cancelled";
    threat_level: string | null;
    created_at: string;
    completed_at: string | null;
}

interface ScanReport {
    id: string;
    scan_id: string;
    summary: string;
    details: Record<string, unknown>;
    indicators: Array<Record<string, unknown>>;
    created_at: string;
}

// ─── VirusTotal Types ─────────────────────────────────────────────

interface VTDetails {
    found?: boolean | null;
    status?: string;
    threat_level?: string;
    stats?: Record<string, number>;
    total_engines?: number;
    malicious?: number;
    suspicious?: number;
    analysis_id?: string;
    file_name?: string;
    file_type?: string;
}

// ─── VirusTotal Stats Display ──────────────────────────────────────

function VTStatsDisplay({ details }: { details: VTDetails }) {
    const stats = details.stats || {};
    const malicious  = details.malicious  || 0;
    const suspicious = details.suspicious || 0;
    const harmless   = stats.harmless   || 0;
    const undetected = stats.undetected || 0;

    // For files: harmless is always 0; undetected = engines that found nothing = CLEAN
    // Combine both into one "Clean / Safe" green segment
    const clean = harmless + undetected;

    // Only count decisive results for the ratio denominator
    const effectiveTotal = malicious + suspicious + clean;

    // Non-decisive engines (informational only)
    const nonDecisive =
        (stats["timeout"]          || 0) +
        (stats["confirmed-timeout"]|| 0) +
        (stats["failure"]          || 0) +
        (stats["type-unsupported"] || 0);

    if (details.found === false) {
        return (
            <div className="rounded-xl border border-yellow-200 bg-yellow-50 p-5 space-y-3">
                <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-full bg-yellow-200 flex items-center justify-center flex-shrink-0">
                        <svg className="w-5 h-5 text-yellow-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z"/></svg>
                    </div>
                    <div>
                        <p className="font-semibold text-yellow-800">File not in threat database</p>
                        <p className="text-sm text-yellow-700 mt-1">
                            This file hash has never been submitted before — no analysis data is available.
                        </p>
                    </div>
                </div>
                <div className="bg-yellow-100 rounded-lg p-3 border border-yellow-200">
                    <p className="text-xs font-semibold text-yellow-800 mb-1 flex items-center gap-1"><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg> What to do?</p>
                    <p className="text-xs text-yellow-700">
                        Use <strong>Upload File</strong> mode instead of <strong>Enter Hash</strong>.
                        Uploading the actual file will submit it for analysis and give you real results.
                    </p>
                </div>
            </div>
        );
    }

    if (details.found === null) {
        return (
            <div className="rounded-xl border border-orange-200 bg-orange-50 p-5 space-y-3">
                <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-full bg-orange-200 flex items-center justify-center flex-shrink-0">
                        <svg className="w-5 h-5 text-orange-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                    </div>
                    <div>
                        <p className="font-semibold text-orange-800">Analysis timed out</p>
                        <p className="text-sm text-orange-700 mt-1">
                            The scan engines took too long to respond. Your file was submitted successfully.
                        </p>
                    </div>
                </div>
                <div className="bg-orange-100 rounded-lg p-3 border border-orange-200">
                    <p className="text-xs font-semibold text-orange-800 mb-1 flex items-center gap-1"><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg> What to do?</p>
                    <p className="text-xs text-orange-700">
                        Try scanning the same file again — it has been submitted and results will be available faster next time.
                    </p>
                </div>
            </div>
        );
    }

    const segments = [
        { key: "malicious",  label: "Malicious",    count: malicious,  barColor: "bg-red-500",   textColor: "text-red-700",   bgColor: "bg-red-50",   borderColor: "border-red-200" },
        { key: "suspicious", label: "Suspicious",   count: suspicious, barColor: "bg-orange-400",textColor: "text-orange-700",bgColor: "bg-orange-50",borderColor: "border-orange-200" },
        { key: "clean",      label: "Clean / Safe", count: clean,      barColor: "bg-green-500", textColor: "text-green-700", bgColor: "bg-green-50", borderColor: "border-green-200" },
    ];

    return (
        <div className="space-y-4">
            {/* Detection Score */}
            <div className={`flex items-center justify-between rounded-xl p-5 border-2 ${
                malicious >= 5 ? "bg-red-50 border-red-200" :
                malicious > 0 ? "bg-orange-50 border-orange-200" :
                suspicious > 0 ? "bg-yellow-50 border-yellow-200" :
                "bg-green-50 border-green-200"
            }`}>
                <div>
                    <p className="text-xs text-gray-500 font-semibold uppercase tracking-widest">Detection Ratio</p>
                    <p className="text-5xl font-black mt-1 tabular-nums">
                        <span className={malicious > 0 ? "text-red-600" : "text-green-600"}>{malicious}</span>
                        <span className="text-gray-300 text-3xl font-light"> / {effectiveTotal}</span>
                    </p>
                    <p className="text-xs text-gray-400 mt-1.5">
                        {malicious === 0
                            ? `File is clean — ${clean} engine${clean !== 1 ? "s" : ""} found no threats`
                            : `${malicious} engine${malicious > 1 ? "s" : ""} flagged this as malicious`}
                    </p>
                    {nonDecisive > 0 && (
                        <p className="text-[10px] text-gray-300 mt-1">
                            +{nonDecisive} engine{nonDecisive > 1 ? "s" : ""} skipped (timeout / unsupported)
                        </p>
                    )}
                </div>
                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shadow-md ${
                    malicious >= 5 ? "bg-red-100" : malicious > 0 ? "bg-orange-100" : suspicious > 0 ? "bg-yellow-100" : "bg-green-100"
                }`}>
                    {malicious >= 5 ? (
                        <svg className="w-7 h-7 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    ) : malicious > 0 ? (
                        <svg className="w-7 h-7 text-orange-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    ) : suspicious > 0 ? (
                        <svg className="w-7 h-7 text-yellow-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    ) : (
                        <svg className="w-7 h-7 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    )}
                </div>
            </div>

            {/* Stacked progress bar */}
            {effectiveTotal > 0 && (
                <div className="h-3 flex rounded-full overflow-hidden gap-px bg-gray-100">
                    {segments.filter((s) => s.count > 0).map((s) => (
                        <div
                            key={s.key}
                            className={`${s.barColor} transition-all`}
                            style={{ width: `${(s.count / effectiveTotal) * 100}%` }}
                            title={`${s.label}: ${s.count}`}
                        />
                    ))}
                </div>
            )}

            {/* Stat grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {segments.map((s) => (
                    <div key={s.key} className={`rounded-xl border p-3 text-center ${s.bgColor} ${s.borderColor}`}>
                        <p className={`text-2xl font-bold ${s.textColor}`}>{s.count}</p>
                        <p className="text-xs text-gray-500 mt-0.5">{s.label}</p>
                    </div>
                ))}
            </div>

            {/* File metadata */}
            {(details.file_name || details.file_type) && (
                <div className="flex flex-wrap gap-4 text-xs bg-blue-50 rounded-lg p-3 border border-blue-200">
                    {details.file_name && (
                        <span><span className="text-blue-600 font-semibold">File:</span> {details.file_name}</span>
                    )}
                    {details.file_type && (
                        <span><span className="text-blue-600 font-semibold">Type:</span> {details.file_type}</span>
                    )}
                </div>
            )}
        </div>
    );
}

// ─── Scan Detail Modal ────────────────────────────────────────────

function ScanDetailModal({
    scan,
    token,
    onClose,
}: {
    scan: Scan;
    token?: string;
    onClose: () => void;
}) {
    const [report, setReport] = useState<ScanReport | null>(null);
    const [reportLoading, setReportLoading] = useState(false);

    useEffect(() => {
        if (scan.status !== "completed" || !token) return;
        setReportLoading(true);
        api.get<ScanReport>(`/api/v1/scans/${scan.id}`, token)
            .then(setReport)
            .catch(() => setReport(null))
            .finally(() => setReportLoading(false));
    }, [scan.id, scan.status, token]);

    const threatColors: Record<string, string> = {
        safe:     "text-green-600 bg-green-50 border-green-200",
        clean:    "text-green-600 bg-green-50 border-green-200",
        low:      "text-yellow-600 bg-yellow-50 border-yellow-200",
        medium:   "text-orange-600 bg-orange-50 border-orange-200",
        high:     "text-red-600 bg-red-50 border-red-200",
        critical: "text-red-700 bg-red-100 border-red-300",
        unknown:  "text-gray-500 bg-gray-50 border-gray-200",
    };
    const tClass = threatColors[scan.threat_level || ""] || "text-gray-500 bg-gray-50 border-gray-200";
    const vtDetails = report?.details as VTDetails | null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
            <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 bg-gray-50">
                    <div>
                        <div className="flex items-center gap-2">
                            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                                {scan.scan_type === "url"
                                    ? <svg className="w-4 h-4 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                                    : <svg className="w-4 h-4 text-purple-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                                }
                                Scan Report
                            </h2>
                            {["pending", "in_progress", "running"].includes(scan.status) && (
                                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 text-xs font-medium border border-blue-200">
                                    <span className="relative flex h-1.5 w-1.5">
                                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-500 opacity-75" />
                                        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-blue-500" />
                                    </span>
                                    Live
                                </span>
                            )}
                        </div>
                        <p className="text-xs text-gray-400 mt-0.5 font-mono">ID: {scan.id}</p>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-200 transition-colors"
                    >
                        <svg className="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                        </svg>
                    </button>
                </div>

                <div className="overflow-y-auto flex-1 p-6 space-y-5">
                    {/* Meta */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="bg-gray-50 rounded-xl p-3">
                            <p className="text-xs text-gray-500">Type</p>
                            <p className="font-semibold text-gray-800 mt-0.5 capitalize">{scan.scan_type.replace("_", " ")}</p>
                        </div>
                        <div className="bg-gray-50 rounded-xl p-3">
                            <p className="text-xs text-gray-500">Status</p>
                            <p className="font-semibold text-gray-800 mt-0.5 capitalize">{scan.status.replace("_", " ")}</p>
                        </div>
                        <div className="bg-gray-50 rounded-xl p-3">
                            <p className="text-xs text-gray-500">Threat Level</p>
                            {scan.threat_level ? (
                                <span className={`inline-block mt-0.5 px-2 py-0.5 rounded-full text-xs font-semibold border ${tClass}`}>
                                    {scan.threat_level}
                                </span>
                            ) : (
                                <p className="font-semibold text-gray-400 mt-0.5">—</p>
                            )}
                        </div>
                        <div className="bg-gray-50 rounded-xl p-3">
                            <p className="text-xs text-gray-500">Scanned</p>
                            <p className="font-semibold text-gray-800 mt-0.5 text-xs">{new Date(scan.created_at).toLocaleString()}</p>
                        </div>
                    </div>

                    {/* Target */}
                    <div>
                        <p className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-1.5">
                            {scan.scan_type === "url" ? "URL" : "File Hash / Name"}
                        </p>
                        <div className="bg-gray-900 rounded-lg px-4 py-3 font-mono text-sm text-green-400 break-all">
                            {scan.target}
                        </div>
                    </div>

                    {/* Results section */}
                    {scan.status === "completed" ? (
                        reportLoading ? (
                            <div className="flex flex-col items-center justify-center py-10 gap-3">
                                <svg className="animate-spin h-8 w-8 text-blue-500" viewBox="0 0 24 24" fill="none">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                                </svg>
                                <p className="text-sm text-gray-400">Loading scan results…</p>
                            </div>
                        ) : vtDetails ? (
                            <div className="space-y-4">
                                <h3 className="text-sm font-semibold text-gray-800 flex items-center gap-2">
                                    <span className="w-6 h-6 rounded-md bg-blue-100 flex items-center justify-center text-blue-600">
                                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"/></svg>
                                    </span>
                                    Threat Analysis Results
                                </h3>
                                <VTStatsDisplay details={vtDetails} />
                                {report?.summary && (
                                    <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
                                        <p className="text-xs font-medium text-gray-500 mb-1">Summary</p>
                                        <p className="text-sm text-gray-700">{report.summary}</p>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <div className="text-center py-8 text-gray-400">
                                <div className="flex justify-center mb-2">
                                    <svg className="w-10 h-10 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                                </div>
                                <p className="text-sm">Report details not available.</p>
                            </div>
                        )
                    ) : scan.status === "cancelled" ? (
                        <div className="text-center py-12">
                            <div className="flex justify-center mb-4">
                                <div className="w-16 h-16 rounded-full bg-gray-100 flex items-center justify-center">
                                    <svg className="w-8 h-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                                </div>
                            </div>
                            <p className="font-semibold text-gray-700 text-base">Scan was cancelled</p>
                            <p className="text-sm text-gray-400 mt-1">This scan was stopped before it completed.</p>
                        </div>
                    ) : scan.status === "failed" ? (
                        <div className="text-center py-12">
                            <div className="flex justify-center mb-4">
                                <div className="w-16 h-16 rounded-full bg-red-100 flex items-center justify-center">
                                    <svg className="w-8 h-8 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                </div>
                            </div>
                            <p className="font-semibold text-red-600 text-base">Scan failed</p>
                            <p className="text-sm text-gray-400 mt-1">Something went wrong. Please try again.</p>
                        </div>
                    ) : (
                        <div className="text-center py-12">
                            <div className="flex justify-center mb-5">
                                <span className="relative flex h-16 w-16">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-30" />
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-20" style={{ animationDelay: "0.5s" }} />
                                    <span className="relative inline-flex items-center justify-center rounded-full h-16 w-16 bg-gradient-to-br from-blue-500 to-blue-600 text-white shadow-lg shadow-blue-200">
                                        <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                                    </span>
                                </span>
                            </div>
                            <p className="font-semibold text-gray-800 text-base">Scanning in progress…</p>
                            <p className="text-sm text-gray-400 mt-2">Analyzing your target across multiple security engines.</p>
                            <p className="text-xs text-gray-300 mt-1">Results will update automatically when ready.</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
// ─── Aggregate Chart (Scan History Overview) ──────────────────

function HistoryBarChart({ scans }: { scans: Scan[] }) {
    const completed = scans.filter(s => s.status === "completed");
    const active    = scans.filter(s => ["pending","in_progress","running"].includes(s.status));
    const failed    = scans.filter(s => ["failed","cancelled"].includes(s.status));

    const threats = {
        high:   completed.filter(s => ["high","critical"].includes(s.threat_level || "")).length,
        medium: completed.filter(s => s.threat_level === "medium").length,
        low:    completed.filter(s => s.threat_level === "low").length,
        clean:  completed.filter(s => ["clean","safe"].includes(s.threat_level || "")).length,
        unknown:completed.filter(s => !s.threat_level || s.threat_level === "unknown").length,
    };

    const urlScans  = scans.filter(s => s.scan_type === "url").length;
    const fileScans = scans.filter(s => s.scan_type !== "url").length;
    const total     = scans.length || 1;

    return (
        <div className="space-y-6">
            {/* ── Top stat cards ── */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {([
                    { label: "Completed",   value: completed.length, color: "text-green-700",  bg: "bg-green-50",  border: "border-green-200", iconColor: "text-green-600",
                      icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> },
                    { label: "In Progress", value: active.length,    color: "text-blue-700",   bg: "bg-blue-50",   border: "border-blue-200",  iconColor: "text-blue-600",
                      icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> },
                    { label: "URL Scans",   value: urlScans,         color: "text-indigo-700", bg: "bg-indigo-50", border: "border-indigo-200", iconColor: "text-indigo-600",
                      icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg> },
                    { label: "File Scans",  value: fileScans,        color: "text-purple-700", bg: "bg-purple-50", border: "border-purple-200", iconColor: "text-purple-600",
                      icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg> },
                ] as Array<{label:string;value:number;color:string;bg:string;border:string;iconColor:string;icon:React.ReactNode}>).map(c => (
                    <div key={c.label} className={`rounded-xl border ${c.border} ${c.bg} px-4 py-3 flex items-center gap-3`}>
                        <span className={c.iconColor}>{c.icon}</span>
                        <div>
                            <p className={`text-xl font-black ${c.color}`}>{c.value}</p>
                            <p className="text-xs text-gray-500 font-medium">{c.label}</p>
                        </div>
                    </div>
                ))}
            </div>

            {/* ── Threat breakdown ── */}
            {completed.length > 0 && (() => {
                const chartBars = [
                    { label: "High / Critical", value: threats.high,   barColor: "#ef4444", trackColor: "#fef2f2", textColor: "#dc2626" },
                    { label: "Medium",           value: threats.medium, barColor: "#f97316", trackColor: "#fff7ed", textColor: "#ea580c" },
                    { label: "Low",              value: threats.low,    barColor: "#eab308", trackColor: "#fefce8", textColor: "#ca8a04" },
                    { label: "Clean / Safe",     value: threats.clean,  barColor: "#22c55e", trackColor: "#f0fdf4", textColor: "#16a34a" },
                    ...(threats.unknown > 0
                        ? [{ label: "Unknown", value: threats.unknown, barColor: "#9ca3af", trackColor: "#f9fafb", textColor: "#6b7280" }]
                        : []),
                ];
                const maxVal = Math.max(...chartBars.map(b => b.value), 1);

                return (
                    <div>
                        <div className="flex items-center justify-between mb-4">
                            <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest">Threat Breakdown</p>
                            <p className="text-xs text-gray-400">{completed.length} completed scan{completed.length !== 1 ? "s" : ""}</p>
                        </div>

                        <div className="space-y-3">
                            {chartBars.map(b => {
                                const widthPct = maxVal > 0 ? (b.value / maxVal) * 100 : 0;
                                const pct = Math.round((b.value / completed.length) * 100);
                                return (
                                    <div key={b.label} className="flex items-center gap-3">
                                        {/* Label */}
                                        <div className="flex items-center gap-2 w-28 flex-shrink-0">
                                            <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: b.barColor }} />
                                            <span className="text-xs text-gray-600 font-medium truncate">{b.label}</span>
                                        </div>

                                        {/* Bar */}
                                        <div className="flex-1 h-5 rounded-md overflow-hidden" style={{ background: b.trackColor }}>
                                            <div
                                                className="h-full rounded-md transition-all duration-700 ease-out flex items-center justify-end pr-2"
                                                style={{
                                                    width: b.value > 0 ? `${Math.max(widthPct, 8)}%` : "0%",
                                                    background: b.value > 0 ? `linear-gradient(to right, ${b.barColor}cc, ${b.barColor})` : "transparent",
                                                }}
                                            >
                                                {b.value > 0 && widthPct > 15 && (
                                                    <span className="text-[10px] font-bold text-white">{pct}%</span>
                                                )}
                                            </div>
                                        </div>

                                        {/* Count + % */}
                                        <div className="flex items-center gap-1.5 w-14 flex-shrink-0 justify-end">
                                            <span className="text-sm font-bold tabular-nums" style={{ color: b.value > 0 ? b.textColor : "#d1d5db" }}>
                                                {b.value}
                                            </span>
                                            <span className="text-[10px] text-gray-300 tabular-nums">
                                                {b.value > 0 ? `${pct}%` : "—"}
                                            </span>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                );
            })()}

            {/* ── URL vs File donut-style split ── */}
            <div className="flex items-center gap-4">
                <div className="flex-1 h-2.5 rounded-full overflow-hidden bg-gray-100 flex">
                    <div className="bg-indigo-500 h-full rounded-l-full transition-all duration-700" style={{ width: `${(urlScans / total) * 100}%` }} />
                    <div className="bg-purple-400 h-full rounded-r-full transition-all duration-700" style={{ width: `${(fileScans / total) * 100}%` }} />
                </div>
                <div className="flex items-center gap-3 text-xs text-gray-500 flex-shrink-0">
                    <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-indigo-500 inline-block" />URLs</span>
                    <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" />Files</span>
                </div>
            </div>
        </div>
    );
}

// ─── Main Page ────────────────────────────────────────────────

export default function ScansPage() {
    const { token } = useAuth();
    const [scans, setScans] = useState<Scan[]>([]);
    const [isLoading, setIsLoading] = useState(true);

    // URL Scan state
    const [urlTarget, setUrlTarget] = useState("");
    const [urlValidationError, setUrlValidationError] = useState("");
    const [isUrlSubmitting, setIsUrlSubmitting] = useState(false);
    const [urlError, setUrlError] = useState("");
    const [urlSuccess, setUrlSuccess] = useState("");

    // File Scan state
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [fileInfo, setFileInfo] = useState<FileInfo | null>(null);
    const [isHashingFile, setIsHashingFile] = useState(false);
    const [fileHash, setFileHash] = useState("");
    const [fileMode, setFileMode] = useState<"upload" | "hash">("upload");
    const [isFileSubmitting, setIsFileSubmitting] = useState(false);
    const [fileError, setFileError] = useState("");
    const [fileSuccess, setFileSuccess] = useState("");
    const fileInputRef = useRef<HTMLInputElement>(null);

    // History state
    const [activeTab, setActiveTab] = useState<"all" | "url" | "file">("all");
    const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
    const selectedScan = selectedScanId ? (scans.find(s => s.id === selectedScanId) ?? null) : null;
    const [cancellingId, setCancellingId] = useState<string | null>(null);
    const [deletingId, setDeletingId] = useState<string | null>(null);

    // ─── Fetch scans ──────────────────────────────────────────

    const fetchScans = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<Scan[]>("/api/v1/scans/", token);
            setScans(data);
        } catch (err) {
            console.error("Failed to fetch scans:", err);
        } finally {
            setIsLoading(false);
        }
    }, [token]);

    useEffect(() => {
        fetchScans();
    }, [fetchScans]);

    // ─── Auto-refresh every 5 s when scans are active ─────────

    useEffect(() => {
        const hasActive = scans.some(s =>
            ["pending", "in_progress", "running"].includes(s.status)
        );
        if (!hasActive) return;
        const timer = setInterval(fetchScans, 5000);
        return () => clearInterval(timer);
    }, [scans, fetchScans]);

    // ─── URL Scan submit ──────────────────────────────────────

    const handleUrlSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!token || !urlTarget.trim()) return;

        setIsUrlSubmitting(true);
        setUrlError("");
        setUrlSuccess("");

        try {
            await api.post(
                "/api/v1/scans/url",
                { target: urlTarget, scan_type: "url" },
                token
            );
            setUrlSuccess("URL scan submitted! Results will appear in history below.");
            setUrlTarget("");
            fetchScans();
        } catch (err) {
            setUrlError(err instanceof Error ? err.message : "URL scan submission failed");
        } finally {
            setIsUrlSubmitting(false);
        }
    };

    // ─── File Scan submit ─────────────────────────────────────

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0] || null;
        setSelectedFile(file);
        setFileInfo(null);
        setFileError("");
        setFileSuccess("");
        if (!file) return;

        setIsHashingFile(true);
        const reader = new FileReader();
        reader.onload = async (ev) => {
            const buf = ev.target?.result as ArrayBuffer;
            const [sha1, sha256] = await Promise.all([
                browserHash("SHA-1", buf),
                browserHash("SHA-256", buf),
            ]);
            const md5Hash = md5(buf);
            const ext = file.name.includes(".")
                ? "." + file.name.split(".").pop()!.toLowerCase()
                : "";
            setFileInfo({
                name: file.name,
                size: file.size,
                extension: ext,
                mimeType: file.type || "application/octet-stream",
                md5: md5Hash,
                sha1,
                sha256,
            });
            setIsHashingFile(false);
        };
        reader.readAsArrayBuffer(file);
    };

    const handleFileSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!token) return;

        // In upload mode, validate file selection; in hash mode, validate hash text
        if (fileMode === "upload" && !selectedFile) {
            setFileError("Please select a file to scan.");
            return;
        }
        if (fileMode === "hash" && !fileHash.trim()) {
            setFileError("Please enter a file hash (SHA-256).");
            return;
        }

        setIsFileSubmitting(true);
        setFileError("");
        setFileSuccess("");

        try {
            if (fileMode === "upload" && selectedFile) {
                // Upload the actual file bytes to VirusTotal via the backend
                await api.uploadFile("/api/v1/scans/file/upload", selectedFile, token);
            } else {
                // Hash-only lookup (MD5 / SHA-1 / SHA-256)
                const target = fileHash.trim();
                await api.post(
                    "/api/v1/scans/file",
                    { target, scan_type: "file" },
                    token
                );
            }
            setFileSuccess(
                "File scan submitted! Results will appear in history below."
            );
            setSelectedFile(null);
            setFileInfo(null);
            setFileHash("");
            if (fileInputRef.current) fileInputRef.current.value = "";
            fetchScans();
        } catch (err) {
            setFileError(
                err instanceof Error ? err.message : "File scan submission failed"
            );
        } finally {
            setIsFileSubmitting(false);
        }
    };

    // ─── Cancel scan ──────────────────────────────────────────

    const handleCancelScan = async (scanId: string) => {
        if (!token) return;
        if (!confirm("Cancel this scan? This cannot be undone.")) return;
        setCancellingId(scanId);
        try {
            await api.post(`/api/v1/scans/${scanId}/cancel`, {}, token);
            fetchScans();
        } catch (err) {
            console.error("Cancel scan failed:", err);
            alert("Failed to cancel scan. It may have already completed.");
        } finally {
            setCancellingId(null);
        }
    };

    // ─── Delete scan ──────────────────────────────────────────

    const handleDeleteScan = async (scanId: string) => {
        if (!token) return;
        if (!confirm("Delete this scan permanently? This cannot be undone.")) return;
        setDeletingId(scanId);
        // Close modal if deleting the currently opened scan
        if (selectedScanId === scanId) setSelectedScanId(null);
        try {
            await api.delete(`/api/v1/scans/${scanId}`, token);
            setScans(prev => prev.filter(s => s.id !== scanId));
        } catch (err) {
            console.error("Delete scan failed:", err);
            alert("Failed to delete scan.");
            fetchScans();
        } finally {
            setDeletingId(null);
        }
    };

    // ─── Helpers ──────────────────────────────────────────────

    const statusBadge = (status: string) => {
        const styles: Record<string, string> = {
            pending: "bg-yellow-100 text-yellow-700 border border-yellow-200",
            running: "bg-blue-100 text-blue-700 border border-blue-200",
            in_progress: "bg-blue-100 text-blue-700 border border-blue-200",
            completed: "bg-green-100 text-green-700 border border-green-200",
            failed: "bg-red-100 text-red-700 border border-red-200",
            cancelled: "bg-gray-100 text-gray-500 border border-gray-200",
        };
        return styles[status] || "bg-gray-100 text-gray-600 border border-gray-200";
    };

    const threatBadge = (level: string | null) => {
        const styles: Record<string, string> = {
            safe:      "bg-green-50 text-green-700 border border-green-200",
            clean:     "bg-green-50 text-green-700 border border-green-200",
            low:       "bg-yellow-50 text-yellow-700 border border-yellow-200",
            medium:    "bg-orange-50 text-orange-700 border border-orange-200",
            high:      "bg-red-50 text-red-700 border border-red-200",
            critical:  "bg-red-100 text-red-800 border border-red-300 font-bold",
            not_found: "bg-gray-50 text-gray-500 border border-gray-200",
            timeout:   "bg-yellow-50 text-yellow-600 border border-yellow-200",
            unknown:   "bg-gray-50 text-gray-500 border border-gray-200",
        };
        return styles[level || ""] || "bg-gray-50 text-gray-400 border border-gray-200";
    };

    const filteredScans = scans.filter((s) =>
        activeTab === "all" ? true : s.scan_type === activeTab
    );

    // ─── Aggregate stats for chart ────────────────────────────

    const urlScans = scans.filter((s) => s.scan_type === "url");
    const fileScans = scans.filter((s) => s.scan_type === "file" || s.scan_type === "file_upload");

    // ─── Render ───────────────────────────────────────────────

    return (
        <div className="space-y-6">
            {/* Page header */}
            <div>
                <h1 className="text-2xl font-bold text-gray-900">Security Scans</h1>
                <p className="text-gray-500 mt-1">
                    Scan URLs and files for threats using multiple antivirus engines
                </p>
            </div>

            {/* ── Stats Summary Row ── */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                    { label: "Total Scans", value: scans.length, color: "text-gray-900", bg: "bg-gray-50" },
                    { label: "URL Scans", value: urlScans.length, color: "text-blue-700", bg: "bg-blue-50" },
                    { label: "File Scans", value: fileScans.length, color: "text-purple-700", bg: "bg-purple-50" },
                    {
                        label: "Threats Found",
                        value: scans.filter((s) =>
                            ["high", "critical", "medium"].includes(s.threat_level || "")
                        ).length,
                        color: "text-red-700",
                        bg: "bg-red-50",
                    },
                ].map((stat) => (
                    <div
                        key={stat.label}
                        className={`${stat.bg} rounded-xl p-4 border border-white/80`}
                    >
                        <p className="text-xs text-gray-500 font-medium">{stat.label}</p>
                        <p className={`text-3xl font-bold ${stat.color} mt-1`}>
                            {isLoading ? "…" : stat.value}
                        </p>
                    </div>
                ))}
            </div>

            {/* ── Scan Input Forms — Side by Side ── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* URL Scan Card */}
                <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-100 bg-gradient-to-r from-blue-50 to-white">
                        <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center text-white flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                        </div>
                        <div>
                            <h3 className="text-base font-semibold text-gray-900">URL Scan</h3>
                            <p className="text-xs text-gray-500">
                                Check a URL against multiple antivirus engines
                            </p>
                        </div>
                    </div>
                    <form onSubmit={handleUrlSubmit} className="px-6 py-5 space-y-4">
                        <div>
                            <label className="block text-xs font-medium text-gray-700 mb-1.5">
                                URL to Scan
                            </label>
                            <div className="relative">
                                <input
                                    type="text"
                                    id="url-scan-input"
                                    placeholder="https://example.com"
                                    value={urlTarget}
                                    onChange={(e) => {
                                        const v = e.target.value;
                                        setUrlTarget(v);
                                        if (!v.trim()) {
                                            setUrlValidationError("");
                                        } else if (!isValidUrl(v)) {
                                            setUrlValidationError(
                                                "Please enter a valid URL starting with http:// or https://"
                                            );
                                        } else {
                                            setUrlValidationError("");
                                        }
                                    }}
                                    className={`w-full px-3.5 py-2.5 pr-10 text-sm border rounded-lg focus:outline-none focus:ring-2 focus:border-transparent transition-all placeholder-gray-400 ${urlValidationError
                                            ? "border-red-400 focus:ring-red-400 bg-red-50"
                                            : urlTarget && !urlValidationError
                                                ? "border-green-400 focus:ring-green-400 bg-green-50/30"
                                                : "border-gray-300 focus:ring-blue-500"
                                        }`}
                                />
                                {/* validation icon */}
                                {urlTarget && (
                                    <span className="absolute right-3 top-1/2 -translate-y-1/2">
                                        {urlValidationError
                                            ? <svg className="w-4 h-4 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                                            : <svg className="w-4 h-4 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/></svg>
                                        }
                                    </span>
                                )}
                            </div>
                            {urlValidationError ? (
                                <p className="text-xs text-red-600 mt-1 flex items-center gap-1">
                                    <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg> {urlValidationError}
                                </p>
                            ) : (
                                <p className="text-xs text-gray-400 mt-1">
                                    Enter the full URL including <code>https://</code>
                                </p>
                            )}
                        </div>

                        {urlError && (
                            <div className="flex items-start gap-2 text-sm text-red-700 bg-red-50 border border-red-200 px-3 py-2.5 rounded-lg">
                                <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                <span>{urlError}</span>
                            </div>
                        )}
                        {urlSuccess && (
                            <div className="flex items-center gap-2 text-sm text-green-700 bg-green-50 border border-green-200 px-3 py-2.5 rounded-lg">
                                <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                <span>{urlSuccess}</span>
                            </div>
                        )}

                        <button
                            type="submit"
                            id="url-scan-submit"
                            disabled={isUrlSubmitting || !urlTarget.trim() || !!urlValidationError}
                            className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                        >
                            {isUrlSubmitting ? (
                                <>
                                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                                    </svg>
                                    Scanning…
                                </>
                            ) : (
                                <>
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                                    Scan URL
                                </>
                            )}
                        </button>
                    </form>
                </div>

                {/* File Scan Card */}
                <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-100 bg-gradient-to-r from-purple-50 to-white">
                        <div className="w-9 h-9 rounded-xl bg-purple-600 flex items-center justify-center text-white flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                        </div>
                        <div>
                            <h3 className="text-base font-semibold text-gray-900">File Scan</h3>
                            <p className="text-xs text-gray-500">
                                Upload a file or enter its SHA-256 hash to scan
                            </p>
                        </div>
                    </div>

                    <form onSubmit={handleFileSubmit} className="px-6 py-5 space-y-4">
                        {/* Mode Toggle */}
                        <div className="flex bg-gray-100 rounded-lg p-1 gap-1">
                            <button
                                type="button"
                                id="file-upload-mode"
                                onClick={() => setFileMode("upload")}
                                className={`flex-1 py-1.5 px-3 text-xs font-medium rounded-md transition-all ${fileMode === "upload"
                                        ? "bg-white text-gray-900 shadow-sm"
                                        : "text-gray-500 hover:text-gray-700"
                                    }`}
                            >
                                Upload File
                            </button>
                            <button
                                type="button"
                                id="file-hash-mode"
                                onClick={() => setFileMode("hash")}
                                className={`flex-1 py-1.5 px-3 text-xs font-medium rounded-md transition-all ${fileMode === "hash"
                                        ? "bg-white text-gray-900 shadow-sm"
                                        : "text-gray-500 hover:text-gray-700"
                                    }`}
                            >
                                Enter Hash
                            </button>
                        </div>

                        {fileMode === "upload" ? (
                            <div>
                                <label className="block text-xs font-medium text-gray-700 mb-1.5">
                                    Select File
                                </label>
                                <label
                                    htmlFor="file-upload"
                                    className={`flex flex-col items-center justify-center w-full h-28 border-2 border-dashed rounded-xl cursor-pointer transition-all ${selectedFile
                                            ? "border-purple-400 bg-purple-50"
                                            : "border-gray-300 bg-gray-50 hover:border-purple-400 hover:bg-purple-50"
                                        }`}
                                >
                                    {selectedFile ? (
                                        <div className="text-center px-4">
                                            <div className="flex justify-center"><svg className="w-8 h-8 text-purple-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg></div>
                                            <p className="text-sm font-medium text-purple-700 mt-1 truncate max-w-[220px]">
                                                {selectedFile.name}
                                            </p>
                                            <p className="text-xs text-gray-400">
                                                {selectedFile.size < 1024 * 1024
                                                    ? `${(selectedFile.size / 1024).toFixed(1)} KB`
                                                    : `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB`}
                                                {" · "}
                                                {selectedFile.type || "Unknown type"}
                                            </p>
                                        </div>
                                    ) : (
                                        <div className="text-center">
                                            <div className="flex justify-center"><svg className="w-8 h-8 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/></svg></div>
                                            <p className="text-sm text-gray-500 mt-1">
                                                Click to upload or drag & drop
                                            </p>
                                            <p className="text-xs text-gray-400">
                                                Any file type supported
                                            </p>
                                        </div>
                                    )}
                                    <input
                                        id="file-upload"
                                        ref={fileInputRef}
                                        type="file"
                                        className="hidden"
                                        onChange={handleFileChange}
                                    />
                                </label>
                                {/* File info panel (hashes + metadata) */}
                                <FileInfoPanel info={fileInfo} loading={isHashingFile} />
                            </div>
                        ) : (
                            <div>
                                <label className="block text-xs font-medium text-gray-700 mb-1.5">
                                    File Hash (SHA-256)
                                </label>
                                <input
                                    type="text"
                                    id="file-hash-input"
                                    placeholder="e.g. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                                    value={fileHash}
                                    onChange={(e) => setFileHash(e.target.value)}
                                    className="w-full px-3.5 py-2.5 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all placeholder-gray-400 font-mono"
                                />
                                <p className="text-xs text-gray-400 mt-1">
                                    SHA-256, MD5, or SHA-1 hash accepted
                                </p>
                            </div>
                        )}

                        {fileError && (
                            <div className="flex items-start gap-2 text-sm text-red-700 bg-red-50 border border-red-200 px-3 py-2.5 rounded-lg">
                                <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                <span>{fileError}</span>
                            </div>
                        )}
                        {fileSuccess && (
                            <div className="flex items-center gap-2 text-sm text-green-700 bg-green-50 border border-green-200 px-3 py-2.5 rounded-lg">
                                <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                <span>{fileSuccess}</span>
                            </div>
                        )}

                        <button
                            type="submit"
                            id="file-scan-submit"
                            disabled={
                                isFileSubmitting ||
                                (fileMode === "upload" ? !selectedFile : !fileHash.trim())
                            }
                            className="w-full py-2.5 px-4 bg-purple-600 hover:bg-purple-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                        >
                            {isFileSubmitting ? (
                                <>
                                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                                    </svg>
                                    Scanning…
                                </>
                            ) : (
                                <>
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                                    Scan File
                                </>
                            )}
                        </button>
                    </form>
                </div>
            </div>

            {/* ── Overview Bar Chart ── */}
            {scans.length > 0 && (
                <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
                    <div className="px-6 py-4 border-b border-gray-100">
                        <h3 className="text-base font-semibold text-gray-900 flex items-center gap-2">
                            <svg className="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                            Scan Results Overview
                        </h3>
                        <p className="text-xs text-gray-500 mt-0.5">
                            Comparison of clean vs infected results across URL and File scans
                        </p>
                    </div>
                    <div className="px-6 py-5">
                        <HistoryBarChart scans={scans} />
                    </div>
                </div>
            )}

            {/* ── Scan History ── */}
            <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 px-6 py-4 border-b border-gray-100">
                    <div>
                        <h3 className="text-base font-semibold text-gray-900 flex items-center gap-2">
                            <svg className="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
                            Scan History
                        </h3>
                        <p className="text-xs text-gray-500 mt-0.5">
                            Click any row to view detailed antivirus results & graphs
                        </p>
                    </div>
                    {/* Filter tabs */}
                    <div className="flex bg-gray-100 rounded-lg p-1 gap-1 text-xs font-medium self-start sm:self-auto">
                        {(["all", "url", "file"] as const).map((tab) => (
                            <button
                                key={tab}
                                onClick={() => setActiveTab(tab)}
                                className={`px-3 py-1.5 rounded-md transition-all capitalize ${activeTab === tab
                                        ? "bg-white text-gray-900 shadow-sm"
                                        : "text-gray-500 hover:text-gray-700"
                                    }`}
                            >
                                {tab === "all" ? "All" : tab === "url" ? "URLs" : "Files"}
                            </button>
                        ))}
                    </div>
                </div>

                {isLoading ? (
                    <div className="text-center py-16">
                        <div className="inline-flex items-center gap-2 text-gray-400">
                            <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24" fill="none">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                            </svg>
                            Loading scan history…
                        </div>
                    </div>
                ) : filteredScans.length === 0 ? (
                    <div className="text-center py-16">
                        <div className="flex justify-center mb-3">
                            <svg className="w-12 h-12 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                        </div>
                        <p className="font-medium text-gray-700">No scans yet</p>
                        <p className="text-sm text-gray-400 mt-1">
                            {activeTab === "all"
                                ? "Submit a URL or file scan above to get started."
                                : `No ${activeTab} scans found. Switch to "All" or start a new scan.`}
                        </p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="bg-gray-50 border-b border-gray-200">
                                    <th className="text-left px-6 py-3 font-medium text-gray-500 text-xs uppercase tracking-wider">
                                        Type
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-gray-500 text-xs uppercase tracking-wider">
                                        Target
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-gray-500 text-xs uppercase tracking-wider">
                                        Status
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-gray-500 text-xs uppercase tracking-wider">
                                        Threat Level
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-gray-500 text-xs uppercase tracking-wider">
                                        Date
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-gray-500 text-xs uppercase tracking-wider">
                                        Actions
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100">
                                {filteredScans.map((scan) => {
                                    const isActive = ["pending", "in_progress", "running"].includes(scan.status);
                                    return (
                                        <tr
                                            key={scan.id}
                                            onClick={() => setSelectedScanId(scan.id)}
                                            className="hover:bg-blue-50/40 transition-colors cursor-pointer group"
                                        >
                                            <td className="px-6 py-4">
                                                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                                                    scan.scan_type === "url"
                                                        ? "bg-blue-50 text-blue-700 border border-blue-200"
                                                        : "bg-purple-50 text-purple-700 border border-purple-200"
                                                }`}>
                                                    {scan.scan_type === "url"
                                                        ? <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                                                        : <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                                                    }
                                                    {scan.scan_type === "url" ? "URL" : "FILE"}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 max-w-[220px]">
                                                <span
                                                    className="font-mono text-xs text-gray-600 truncate block group-hover:text-blue-700 transition-colors"
                                                    title={scan.target}
                                                >
                                                    {scan.target}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${statusBadge(scan.status)}`}>
                                                    {isActive && (
                                                        <span className="relative flex h-2 w-2">
                                                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-75" />
                                                            <span className="relative inline-flex rounded-full h-2 w-2 bg-current" />
                                                        </span>
                                                    )}
                                                    {scan.status.replace(/_/g, " ")}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                                {scan.threat_level ? (
                                                    <span className={`px-2.5 py-1 rounded-full text-xs font-semibold capitalize ${threatBadge(scan.threat_level)}`}>
                                                        {scan.threat_level}
                                                    </span>
                                                ) : (
                                                    <span className="text-gray-300 text-xs">—</span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 text-gray-400 text-xs whitespace-nowrap">
                                                {new Date(scan.created_at).toLocaleString()}
                                            </td>
                                            <td className="px-6 py-4" onClick={e => e.stopPropagation()}>
                                                <div className="flex items-center gap-2">
                                                    <button
                                                        onClick={() => setSelectedScanId(scan.id)}
                                                        className="px-3 py-1.5 rounded-lg bg-blue-50 border border-blue-200 text-blue-600 hover:bg-blue-600 hover:text-white text-xs font-medium transition-all flex items-center gap-1.5 flex-shrink-0"
                                                    >
                                                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                                                        </svg>
                                                        Details
                                                    </button>
                                                    {isActive && (
                                                        <button
                                                            onClick={() => handleCancelScan(scan.id)}
                                                            disabled={cancellingId === scan.id}
                                                            title="Cancel this scan"
                                                            className="w-8 h-8 rounded-lg bg-orange-50 border border-orange-200 text-orange-500 hover:bg-orange-500 hover:text-white flex items-center justify-center transition-all disabled:opacity-40 disabled:cursor-not-allowed flex-shrink-0"
                                                        >
                                                            {cancellingId === scan.id ? (
                                                                <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none">
                                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                                                                </svg>
                                                            ) : (
                                                                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                                                                    <rect x="6" y="6" width="12" height="12" rx="2" />
                                                                </svg>
                                                            )}
                                                        </button>
                                                    )}
                                                    <button
                                                        onClick={() => handleDeleteScan(scan.id)}
                                                        disabled={deletingId === scan.id}
                                                        title="Delete scan permanently"
                                                        className="w-8 h-8 rounded-lg bg-red-50 border border-red-200 text-red-400 hover:bg-red-500 hover:text-white hover:border-red-500 flex items-center justify-center transition-all disabled:opacity-40 disabled:cursor-not-allowed flex-shrink-0"
                                                    >
                                                        {deletingId === scan.id ? (
                                                            <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none">
                                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                                                            </svg>
                                                        ) : (
                                                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                                <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                                            </svg>
                                                        )}
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* ── Scan Detail Modal ── */}
            {selectedScan && (
                <ScanDetailModal
                    scan={selectedScan}
                    token={token ?? undefined}
                    onClose={() => setSelectedScanId(null)}
                />
            )}
        </div>
    );
}
