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
            <div className="mt-3 rounded-xl border border-purple-500/20 bg-purple-500/10 p-4 space-y-2 animate-pulse">
                {Array.from({ length: 6 }).map((_, i) => (
                    <div key={i} className="flex justify-between">
                        <div className="h-3 w-20 bg-purple-500/20 rounded" />
                        <div className="h-3 w-48 bg-purple-500/20 rounded" />
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
        <div className="mt-3 rounded-xl border border-purple-500/20 bg-purple-500/10 p-4">
            <p className="text-xs font-semibold text-purple-400 mb-2 flex items-center gap-1.5">
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                File Analysis
            </p>
            <div className="space-y-1.5">
                {rows.map(([label, value]) => (
                    <div key={label} className="flex items-start justify-between gap-2 text-xs">
                        <span className="text-slate-500 font-medium flex-shrink-0 w-20">{label}</span>
                        <span
                            className={`font-mono text-slate-300 break-all text-right ${["MD5", "SHA-1", "SHA-256"].includes(label)
                                    ? "text-[10px] text-purple-400"
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

// ─── Malice AV Types ──────────────────────────────────────────────

interface MaliceEngineResult {
    engine: string;
    label: string;
    malware: boolean;
    result: string | null;
    updated: string | null;
    error: string | null;
}

interface MaliceDetails {
    engines: MaliceEngineResult[];
    detected_by: number;
    total_engines: number;
    threat_level: string;
    top_result: string | null;
    error?: string;
}

// ─── AI Classifier Types ──────────────────────────────────────────

interface AIClassifierDetails {
    url: string;
    is_phishing: boolean;
    confidence: number;
    model: string;
}

// ─── Combined report details (new format) ─────────────────────────

interface CombinedDetails {
    virustotal?: VTDetails;
    malice?: MaliceDetails;
    ai_classifier?: AIClassifierDetails;
    threat_level?: string;
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
            <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/10 p-5 space-y-3">
                <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-full bg-yellow-500/20 flex items-center justify-center flex-shrink-0">
                        <svg className="w-5 h-5 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z"/></svg>
                    </div>
                    <div>
                        <p className="font-semibold text-yellow-400">File not in threat database</p>
                        <p className="text-sm text-yellow-400/70 mt-1">
                            This file hash has never been submitted before — no analysis data is available.
                        </p>
                    </div>
                </div>
                <div className="bg-yellow-500/10 rounded-lg p-3 border border-yellow-500/20">
                    <p className="text-xs font-semibold text-yellow-400 mb-1 flex items-center gap-1"><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg> What to do?</p>
                    <p className="text-xs text-yellow-400/70">
                        Use <strong>Upload File</strong> mode instead of <strong>Enter Hash</strong>.
                        Uploading the actual file will submit it for analysis and give you real results.
                    </p>
                </div>
            </div>
        );
    }

    if (details.found === null) {
        return (
            <div className="rounded-xl border border-orange-500/20 bg-orange-500/10 p-5 space-y-3">
                <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-full bg-orange-500/20 flex items-center justify-center flex-shrink-0">
                        <svg className="w-5 h-5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                    </div>
                    <div>
                        <p className="font-semibold text-orange-400">Analysis timed out</p>
                        <p className="text-sm text-orange-400/70 mt-1">
                            The scan engines took too long to respond. Your file was submitted successfully.
                        </p>
                    </div>
                </div>
                <div className="bg-orange-500/10 rounded-lg p-3 border border-orange-500/20">
                    <p className="text-xs font-semibold text-orange-400 mb-1 flex items-center gap-1"><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"/></svg> What to do?</p>
                    <p className="text-xs text-orange-400/70">
                        Try scanning the same file again — it has been submitted and results will be available faster next time.
                    </p>
                </div>
            </div>
        );
    }

    const segments = [
        { key: "malicious",  label: "Malicious",    count: malicious,  barColor: "bg-red-500",   textColor: "text-red-400",   bgColor: "bg-red-500/10",   borderColor: "border-red-500/20" },
        { key: "suspicious", label: "Suspicious",   count: suspicious, barColor: "bg-orange-400",textColor: "text-orange-400",bgColor: "bg-orange-500/10",borderColor: "border-orange-500/20" },
        { key: "clean",      label: "Clean / Safe", count: clean,      barColor: "bg-green-500", textColor: "text-green-400", bgColor: "bg-green-500/10", borderColor: "border-green-500/20" },
    ];

    return (
        <div className="space-y-4">
            {/* Detection Score */}
            <div className={`flex items-center justify-between rounded-xl p-5 border-2 ${
                malicious >= 5 ? "bg-red-500/10 border-red-500/20" :
                malicious > 0 ? "bg-orange-500/10 border-orange-500/20" :
                suspicious > 0 ? "bg-yellow-500/10 border-yellow-500/20" :
                "bg-green-500/10 border-green-500/20"
            }`}>
                <div>
                    <p className="text-xs text-slate-500 font-semibold uppercase tracking-widest">Detection Ratio</p>
                    <p className="text-5xl font-black mt-1 tabular-nums">
                        <span className={malicious > 0 ? "text-red-400" : "text-green-400"}>{malicious}</span>
                        <span className="text-slate-600 text-3xl font-light"> / {effectiveTotal}</span>
                    </p>
                    <p className="text-xs text-slate-500 mt-1.5">
                        {malicious === 0
                            ? `File is clean — ${clean} engine${clean !== 1 ? "s" : ""} found no threats`
                            : `${malicious} engine${malicious > 1 ? "s" : ""} flagged this as malicious`}
                    </p>
                    {nonDecisive > 0 && (
                        <p className="text-[10px] text-slate-600 mt-1">
                            +{nonDecisive} engine{nonDecisive > 1 ? "s" : ""} skipped (timeout / unsupported)
                        </p>
                    )}
                </div>
                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shadow-md ${
                    malicious >= 5 ? "bg-red-500/15" : malicious > 0 ? "bg-orange-500/15" : suspicious > 0 ? "bg-yellow-500/15" : "bg-green-500/15"
                }`}>
                    {malicious >= 5 ? (
                        <svg className="w-7 h-7 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    ) : malicious > 0 ? (
                        <svg className="w-7 h-7 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    ) : suspicious > 0 ? (
                        <svg className="w-7 h-7 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    ) : (
                        <svg className="w-7 h-7 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    )}
                </div>
            </div>

            {/* Stacked progress bar */}
            {effectiveTotal > 0 && (
                <div className="h-3 flex rounded-full overflow-hidden gap-px bg-white/[0.06]">
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
                        <p className="text-xs text-slate-500 mt-0.5">{s.label}</p>
                    </div>
                ))}
            </div>

            {/* File metadata */}
            {(details.file_name || details.file_type) && (
                <div className="flex flex-wrap gap-4 text-xs bg-blue-500/10 rounded-lg p-3 border border-blue-500/20">
                    {details.file_name && (
                        <span><span className="text-blue-400 font-semibold">File:</span> {details.file_name}</span>
                    )}
                    {details.file_type && (
                        <span><span className="text-blue-400 font-semibold">Type:</span> {details.file_type}</span>
                    )}
                </div>
            )}
        </div>
    );
}

// ─── Malice AV Results Display ───────────────────────────────────

function MaliceResultsDisplay({ data }: { data: MaliceDetails }) {
    if (data.error) {
        return (
            <div className="rounded-xl border border-white/[0.08] bg-white/[0.04] p-4 text-sm text-slate-500">
                Local AV scan unavailable: {data.error}
            </div>
        );
    }

    const engines = data.engines || [];
    const detected = data.detected_by ?? 0;
    const total    = engines.length;
    const clean    = engines.filter(e => !e.malware && !e.error).length;
    const errors   = engines.filter(e => !!e.error).length;

    return (
        <div className="space-y-4">
            {/* Summary bar */}
            <div className={`flex items-center justify-between rounded-xl p-4 border-2 ${
                detected >= 3 ? "bg-red-500/10 border-red-500/20" :
                detected >= 1 ? "bg-orange-500/10 border-orange-500/20" :
                "bg-green-500/10 border-green-500/20"
            }`}>
                <div>
                    <p className="text-xs text-slate-500 font-semibold uppercase tracking-widest">Local AV Detection</p>
                    <p className="text-4xl font-black mt-1 tabular-nums">
                        <span className={detected > 0 ? "text-red-400" : "text-green-400"}>{detected}</span>
                        <span className="text-slate-600 text-2xl font-light"> / {total}</span>
                    </p>
                    <p className="text-xs text-slate-500 mt-1">
                        {detected === 0
                            ? `All ${clean} engine${clean !== 1 ? "s" : ""} found no threats`
                            : `${detected} engine${detected > 1 ? "s" : ""} flagged this file`
                        }
                        {errors > 0 && ` · ${errors} unavailable`}
                    </p>
                    {data.top_result && (
                        <p className="text-xs font-mono text-red-400 mt-1 bg-red-500/15 rounded px-2 py-0.5 inline-block">
                            {data.top_result}
                        </p>
                    )}
                </div>
                <div className={`w-12 h-12 rounded-2xl flex items-center justify-center shadow ${
                    detected >= 3 ? "bg-red-500/15" : detected >= 1 ? "bg-orange-500/15" : "bg-green-500/15"
                }`}>
                    {detected >= 3 ? (
                        <svg className="w-6 h-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    ) : detected >= 1 ? (
                        <svg className="w-6 h-6 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    ) : (
                        <svg className="w-6 h-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    )}
                </div>
            </div>

            {/* Per-engine grid */}
            {engines.length > 0 && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {engines.map((eng) => {
                        const isError   = !!eng.error;
                        const isMalware = eng.malware;
                        const borderCls = isError   ? "border-white/[0.06] bg-white/[0.03]"
                                        : isMalware ? "border-red-500/20 bg-red-500/10"
                                        :             "border-green-500/15 bg-green-500/10";
                        const iconCls   = isError   ? "text-slate-500"
                                        : isMalware ? "text-red-400"
                                        :             "text-green-400";
                        const statusText = isError ? "Error"
                                         : isMalware ? (eng.result || "Detected")
                                         : "Clean";
                        const statusColor = isError   ? "text-slate-500"
                                          : isMalware ? "text-red-400 font-mono"
                                          :             "text-green-400";
                        return (
                            <div key={eng.engine} className={`rounded-lg border px-3 py-2 flex items-start gap-2 ${borderCls}`}>
                                <div className="mt-0.5 flex-shrink-0">
                                    {isError ? (
                                        <svg className={`w-4 h-4 ${iconCls}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                                    ) : isMalware ? (
                                        <svg className={`w-4 h-4 ${iconCls}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                    ) : (
                                        <svg className={`w-4 h-4 ${iconCls}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                    )}
                                </div>
                                <div className="min-w-0 flex-1">
                                    <p className="text-xs font-semibold text-slate-200 leading-tight">{eng.label}</p>
                                    <p className={`text-[11px] truncate mt-0.5 ${statusColor}`}>
                                        {isError ? eng.error : statusText}
                                    </p>
                                    {eng.updated && !isError && (
                                        <p className="text-[10px] text-slate-600 mt-0.5">DB: {eng.updated}</p>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}

// ─── Unified Scan Results ──────────────────────────────────────────

// ─── AI Classifier Display ────────────────────────────────────────

function AIClassifierDisplay({ data }: { data: AIClassifierDetails }) {
    const isPhishing = data.is_phishing;
    const confidence = Math.round(data.confidence * 100 * 10) / 10;

    const borderColor = isPhishing ? "border-red-500/20" : "border-green-500/20";
    const bgColor     = isPhishing ? "bg-red-500/10" : "bg-green-500/10";
    const accentColor = isPhishing ? "text-red-400" : "text-green-400";
    const barColor    = isPhishing ? "bg-red-500" : "bg-green-500";
    const barTrack    = isPhishing ? "bg-red-500/15" : "bg-green-500/15";

    return (
        <div className="space-y-4">
            {/* Header badge */}
            <div className="flex items-center gap-2 mb-1">
                <div className="w-7 h-7 rounded-lg bg-purple-500/15 flex items-center justify-center">
                    <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                    </svg>
                </div>
                <div>
                    <p className="text-sm font-semibold text-slate-200">AI Phishing Classifier</p>
                    <p className="text-[10px] text-slate-500 font-mono">{data.model}</p>
                </div>
            </div>

            {/* Verdict card */}
            <div className={`flex items-center justify-between rounded-xl p-5 border-2 ${bgColor} ${borderColor}`}>
                <div>
                    <p className="text-xs text-slate-500 font-semibold uppercase tracking-widest">AI Verdict</p>
                    <p className={`text-3xl font-black mt-1 ${accentColor}`}>
                        {isPhishing ? "Phishing" : "Legitimate"}
                    </p>
                    <p className="text-xs text-slate-500 mt-1.5">
                        {isPhishing
                            ? "AI model flagged this URL as a phishing attempt"
                            : "AI model considers this URL safe"}
                    </p>
                </div>
                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shadow-md ${isPhishing ? "bg-red-500/15" : "bg-green-500/15"}`}>
                    {isPhishing ? (
                        <svg className="w-7 h-7 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                    ) : (
                        <svg className="w-7 h-7 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    )}
                </div>
            </div>

            {/* Confidence bar */}
            <div>
                <div className="flex items-center justify-between mb-2">
                    <p className="text-xs text-slate-500 font-medium">Confidence</p>
                    <p className={`text-sm font-bold tabular-nums ${accentColor}`}>{confidence}%</p>
                </div>
                <div className={`h-3 rounded-full overflow-hidden ${barTrack}`}>
                    <div
                        className={`h-full rounded-full transition-all duration-700 ease-out ${barColor}`}
                        style={{ width: `${confidence}%` }}
                    />
                </div>
                <p className="text-[10px] text-slate-600 mt-1.5">
                    {confidence >= 80 ? "High confidence" : confidence >= 60 ? "Moderate confidence" : "Low confidence"}
                    {" — "}
                    {isPhishing
                        ? "exercise caution with this URL"
                        : "URL appears safe based on structural analysis"}
                </p>
            </div>
        </div>
    );
}

function UnifiedScanResults({ vt, malice }: { vt: VTDetails | null; malice: MaliceDetails | null }) {
    // ── VT numbers ──
    const vtMalicious  = vt?.malicious || 0;
    const vtSuspicious = vt?.suspicious || 0;
    const vtHarmless   = vt?.stats?.harmless || 0;
    const vtUndetected = vt?.stats?.undetected || 0;
    const vtClean      = vtHarmless + vtUndetected;
    const vtEffective  = vtMalicious + vtSuspicious + vtClean;
    const vtNonDecisive =
        (vt?.stats?.["timeout"] || 0) +
        (vt?.stats?.["confirmed-timeout"] || 0) +
        (vt?.stats?.["failure"] || 0) +
        (vt?.stats?.["type-unsupported"] || 0);

    // ── Local AV numbers ──
    const localEngines  = malice?.engines || [];
    const localDetected = malice?.detected_by || 0;
    const localClean    = localEngines.filter(e => !e.malware && !e.error).length;
    const localErrors   = localEngines.filter(e => !!e.error).length;
    const localTotal    = localEngines.length;

    // ── Combined ──
    const totalMalicious  = vtMalicious + localDetected;
    const totalSuspicious = vtSuspicious;
    const totalClean      = vtClean + localClean;
    const totalEngines    = vtEffective + localTotal;
    const totalNonDecisive = vtNonDecisive + localErrors;

    const vtNotFound = vt && vt.found === false;
    const vtTimeout  = vt && vt.found === null;

    // ── VT-only special states (no local data) ──
    if (vtNotFound && !malice) {
        return (
            <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/10 p-5 space-y-3">
                <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-full bg-yellow-500/20 flex items-center justify-center flex-shrink-0">
                        <svg className="w-5 h-5 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z"/></svg>
                    </div>
                    <div>
                        <p className="font-semibold text-yellow-400">File not in threat database</p>
                        <p className="text-sm text-yellow-400/70 mt-1">This file hash has never been submitted — no analysis data is available.</p>
                    </div>
                </div>
                <div className="bg-yellow-500/10 rounded-lg p-3 border border-yellow-500/20">
                    <p className="text-xs font-semibold text-yellow-400 mb-1">What to do?</p>
                    <p className="text-xs text-yellow-400/70">Use <strong>Upload File</strong> mode instead of <strong>Enter Hash</strong>.</p>
                </div>
            </div>
        );
    }
    if (vtTimeout && !malice) {
        return (
            <div className="rounded-xl border border-orange-500/20 bg-orange-500/10 p-5 space-y-3">
                <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-full bg-orange-500/20 flex items-center justify-center flex-shrink-0">
                        <svg className="w-5 h-5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                    </div>
                    <div>
                        <p className="font-semibold text-orange-400">Analysis timed out</p>
                        <p className="text-sm text-orange-400/70 mt-1">The scan engines took too long to respond. Try scanning again.</p>
                    </div>
                </div>
            </div>
        );
    }

    const segments = [
        { key: "malicious",  label: "Malicious",    count: totalMalicious,  barColor: "bg-red-500",    textColor: "text-red-400",    bgColor: "bg-red-500/10",    borderColor: "border-red-500/20" },
        { key: "suspicious", label: "Suspicious",   count: totalSuspicious, barColor: "bg-orange-400", textColor: "text-orange-400", bgColor: "bg-orange-500/10", borderColor: "border-orange-500/20" },
        { key: "clean",      label: "Clean / Safe", count: totalClean,      barColor: "bg-green-500",  textColor: "text-green-400",  bgColor: "bg-green-500/10",  borderColor: "border-green-500/20" },
    ];

    return (
        <div className="space-y-4">
            {/* VT special state banners (when local data IS available) */}
            {vtNotFound && (
                <div className="flex items-center gap-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20 px-3 py-2 text-xs text-yellow-400">
                    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    Hash not found in cloud database — showing local engine results only
                </div>
            )}
            {vtTimeout && (
                <div className="flex items-center gap-2 rounded-lg bg-orange-500/10 border border-orange-500/20 px-3 py-2 text-xs text-orange-400">
                    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                    Cloud analysis timed out — showing local engine results only
                </div>
            )}

            {/* Combined Detection Summary */}
            <div className={`flex items-center justify-between rounded-xl p-5 border-2 ${
                totalMalicious >= 5 ? "bg-red-500/10 border-red-500/20" :
                totalMalicious > 0  ? "bg-orange-500/10 border-orange-500/20" :
                totalSuspicious > 0 ? "bg-yellow-500/10 border-yellow-500/20" :
                "bg-green-500/10 border-green-500/20"
            }`}>
                <div>
                    <p className="text-xs text-slate-500 font-semibold uppercase tracking-widest">Detection Ratio</p>
                    <p className="text-5xl font-black mt-1 tabular-nums">
                        <span className={totalMalicious > 0 ? "text-red-400" : "text-green-400"}>{totalMalicious}</span>
                        <span className="text-slate-600 text-3xl font-light"> / {totalEngines}</span>
                    </p>
                    <p className="text-xs text-slate-500 mt-1.5">
                        {totalMalicious === 0
                            ? `File is clean — ${totalClean} engine${totalClean !== 1 ? "s" : ""} found no threats`
                            : `${totalMalicious} engine${totalMalicious > 1 ? "s" : ""} flagged this as malicious`}
                    </p>
                    {totalNonDecisive > 0 && (
                        <p className="text-[10px] text-slate-600 mt-1">
                            +{totalNonDecisive} engine{totalNonDecisive > 1 ? "s" : ""} skipped (timeout / unsupported)
                        </p>
                    )}
                </div>
                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shadow-md ${
                    totalMalicious >= 5 ? "bg-red-500/15" : totalMalicious > 0 ? "bg-orange-500/15" : totalSuspicious > 0 ? "bg-yellow-500/15" : "bg-green-500/15"
                }`}>
                    {totalMalicious >= 5 ? (
                        <svg className="w-7 h-7 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    ) : totalMalicious > 0 ? (
                        <svg className="w-7 h-7 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                    ) : totalSuspicious > 0 ? (
                        <svg className="w-7 h-7 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    ) : (
                        <svg className="w-7 h-7 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                    )}
                </div>
            </div>

            {/* Stacked progress bar */}
            {totalEngines > 0 && (
                <div className="h-3 flex rounded-full overflow-hidden gap-px bg-white/[0.06]">
                    {segments.filter(s => s.count > 0).map(s => (
                        <div
                            key={s.key}
                            className={`${s.barColor} transition-all`}
                            style={{ width: `${(s.count / totalEngines) * 100}%` }}
                            title={`${s.label}: ${s.count}`}
                        />
                    ))}
                </div>
            )}

            {/* Stat grid */}
            <div className="grid grid-cols-3 gap-2">
                {segments.map(s => (
                    <div key={s.key} className={`rounded-xl border p-3 text-center ${s.bgColor} ${s.borderColor}`}>
                        <p className={`text-2xl font-bold ${s.textColor}`}>{s.count}</p>
                        <p className="text-xs text-slate-500 mt-0.5">{s.label}</p>
                    </div>
                ))}
            </div>

            {/* File metadata */}
            {vt && (vt.file_name || vt.file_type) && (
                <div className="flex flex-wrap gap-4 text-xs bg-blue-500/10 rounded-lg p-3 border border-blue-500/20">
                    {vt.file_name && <span><span className="text-blue-400 font-semibold">File:</span> {vt.file_name}</span>}
                    {vt.file_type && <span><span className="text-blue-400 font-semibold">Type:</span> {vt.file_type}</span>}
                </div>
            )}

            {/* Top threat result */}
            {malice?.top_result && (
                <p className="text-xs font-mono text-red-400 bg-red-500/15 rounded px-2 py-1 inline-block border border-red-500/20">
                    {malice.top_result}
                </p>
            )}

            {/* Malice error banner */}
            {malice?.error && (
                <div className="rounded-xl border border-white/[0.08] bg-white/[0.04] p-4 text-sm text-slate-500">
                    Local scan unavailable: {malice.error}
                </div>
            )}

            {/* Per-engine results grid */}
            {localEngines.length > 0 && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {localEngines.map(eng => {
                        const isError   = !!eng.error;
                        const isMalware = eng.malware;
                        const borderCls = isError   ? "border-white/[0.06] bg-white/[0.03]"
                                        : isMalware ? "border-red-500/20 bg-red-500/10"
                                        :             "border-green-500/15 bg-green-500/10";
                        const iconCls   = isError ? "text-slate-500" : isMalware ? "text-red-400" : "text-green-400";
                        const statusText = isError ? "Error" : isMalware ? (eng.result || "Detected") : "Clean";
                        const statusColor = isError ? "text-slate-500" : isMalware ? "text-red-400 font-mono" : "text-green-400";
                        return (
                            <div key={eng.engine} className={`rounded-lg border px-3 py-2 flex items-start gap-2 ${borderCls}`}>
                                <div className="mt-0.5 flex-shrink-0">
                                    {isError ? (
                                        <svg className={`w-4 h-4 ${iconCls}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                                    ) : isMalware ? (
                                        <svg className={`w-4 h-4 ${iconCls}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                    ) : (
                                        <svg className={`w-4 h-4 ${iconCls}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                    )}
                                </div>
                                <div className="min-w-0 flex-1">
                                    <p className="text-xs font-semibold text-slate-200 leading-tight">{eng.label}</p>
                                    <p className={`text-[11px] truncate mt-0.5 ${statusColor}`}>
                                        {isError ? eng.error : statusText}
                                    </p>
                                    {eng.updated && !isError && (
                                        <p className="text-[10px] text-slate-600 mt-0.5">DB: {eng.updated}</p>
                                    )}
                                </div>
                            </div>
                        );
                    })}
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
        safe:     "text-green-400 bg-green-500/10 border-green-500/20",
        clean:    "text-green-400 bg-green-500/10 border-green-500/20",
        low:      "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
        medium:   "text-orange-400 bg-orange-500/10 border-orange-500/20",
        high:     "text-red-400 bg-red-500/10 border-red-500/20",
        critical: "text-red-400 bg-red-500/20 border-red-500/30",
        unknown:  "text-slate-400 bg-white/[0.06] border-white/[0.08]",
    };
    const tClass = threatColors[scan.threat_level || ""] || "text-slate-400 bg-white/[0.06] border-white/[0.08]";

    // Support both new combined format { virustotal, malice } and legacy flat VT format
    const rawDetails = report?.details as (CombinedDetails & VTDetails) | null;
    const isCombined = rawDetails && ("virustotal" in rawDetails || "malice" in rawDetails || "ai_classifier" in rawDetails);
    const vtDetails: VTDetails | null = isCombined
        ? (rawDetails?.virustotal ?? null)
        : (rawDetails as VTDetails | null);
    const maliceDetails: MaliceDetails | null = isCombined
        ? (rawDetails?.malice ?? null)
        : null;
    const aiDetails: AIClassifierDetails | null = isCombined
        ? ((rawDetails as CombinedDetails)?.ai_classifier ?? null)
        : null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-[#1a2744] rounded-2xl shadow-2xl shadow-black/40 w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col border border-white/[0.08]">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.08] bg-[#263554]">
                    <div>
                        <div className="flex items-center gap-2">
                            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                                {scan.scan_type === "url" ? (
                                    <svg className="w-4 h-4 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                                ) : scan.scan_type === "file" ? (
                                    <svg className="w-4 h-4 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14"/></svg>
                                ) : (
                                    <svg className="w-4 h-4 text-purple-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                                )}
                                Scan Report
                            </h2>
                            {["pending", "in_progress", "running"].includes(scan.status) && (
                                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-400 text-xs font-medium border border-blue-500/20">
                                    <span className="relative flex h-1.5 w-1.5">
                                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-500 opacity-75" />
                                        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-blue-500" />
                                    </span>
                                    Live
                                </span>
                            )}
                        </div>
                        <p className="text-xs text-slate-500 mt-0.5 font-mono">ID: {scan.id}</p>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 rounded-lg text-slate-500 hover:text-white hover:bg-white/[0.08] transition-colors"
                    >
                        <svg className="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                        </svg>
                    </button>
                </div>

                <div className="overflow-y-auto flex-1 p-6 space-y-5">
                    {/* Meta */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="bg-white/[0.04] rounded-xl p-3 border border-white/[0.06]">
                            <p className="text-xs text-slate-500">Type</p>
                            <p className="font-semibold text-slate-200 mt-0.5 capitalize">{scan.scan_type === "file" ? "Hash" : scan.scan_type.replace("_", " ")}</p>
                        </div>
                        <div className="bg-white/[0.04] rounded-xl p-3 border border-white/[0.06]">
                            <p className="text-xs text-slate-500">Status</p>
                            <p className="font-semibold text-slate-200 mt-0.5 capitalize">{scan.status.replace("_", " ")}</p>
                        </div>
                        <div className="bg-white/[0.04] rounded-xl p-3 border border-white/[0.06]">
                            <p className="text-xs text-slate-500">Threat Level</p>
                            {scan.threat_level ? (
                                <span className={`inline-block mt-0.5 px-2 py-0.5 rounded-full text-xs font-semibold border ${tClass}`}>
                                    {scan.threat_level}
                                </span>
                            ) : (
                                <p className="font-semibold text-slate-500 mt-0.5">—</p>
                            )}
                        </div>
                        <div className="bg-white/[0.04] rounded-xl p-3 border border-white/[0.06]">
                            <p className="text-xs text-slate-500">Scanned</p>
                            <p className="font-semibold text-slate-200 mt-0.5 text-xs">{new Date(scan.created_at).toLocaleString()}</p>
                        </div>
                    </div>

                    {/* Target */}
                    <div>
                        <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1.5">
                            {scan.scan_type === "url" ? "URL" : scan.scan_type === "file" ? "Hash" : "File Name"}
                        </p>
                        <div className="bg-[#0f172a] rounded-lg px-4 py-3 font-mono text-sm text-green-400 break-all border border-white/[0.06]">
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
                                <p className="text-sm text-slate-500">Loading scan results…</p>
                            </div>
                        ) : (vtDetails || maliceDetails || aiDetails) ? (
                            <div className="space-y-6">
                                {/* VirusTotal + Local AV (file scans or URL-with-VT) */}
                                {(vtDetails || maliceDetails) && (
                                    <div>
                                        <div className="flex items-center gap-2 mb-3">
                                            <div className="w-7 h-7 rounded-lg bg-blue-500/15 flex items-center justify-center">
                                                <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                    <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                                </svg>
                                            </div>
                                            <p className="text-sm font-semibold text-slate-200">VirusTotal Analysis</p>
                                        </div>
                                        <UnifiedScanResults vt={vtDetails} malice={maliceDetails} />
                                    </div>
                                )}

                                {/* AI Classifier (URL scans) */}
                                {aiDetails && (
                                    <div className="border-t border-white/[0.06] pt-6">
                                        <AIClassifierDisplay data={aiDetails} />
                                    </div>
                                )}

                                {/* Summary */}
                                {report?.summary && (
                                    <div className="bg-white/[0.04] border border-white/[0.06] rounded-xl p-4">
                                        <p className="text-xs font-medium text-slate-500 mb-1">Summary</p>
                                        <p className="text-sm text-slate-300">{report.summary}</p>
                                    </div>
                                )}
                            </div>
                        ) : (
                            <div className="text-center py-8 text-slate-500">
                                <div className="flex justify-center mb-2">
                                    <svg className="w-10 h-10 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                                </div>
                                <p className="text-sm">Report details not available.</p>
                            </div>
                        )
                    ) : scan.status === "cancelled" ? (
                        <div className="text-center py-12">
                            <div className="flex justify-center mb-4">
                                <div className="w-16 h-16 rounded-full bg-white/[0.04] flex items-center justify-center">
                                    <svg className="w-8 h-8 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                                </div>
                            </div>
                            <p className="font-semibold text-slate-300 text-base">Scan was cancelled</p>
                            <p className="text-sm text-slate-500 mt-1">This scan was stopped before it completed.</p>
                        </div>
                    ) : scan.status === "failed" ? (
                        <div className="text-center py-12">
                            <div className="flex justify-center mb-4">
                                <div className="w-16 h-16 rounded-full bg-red-500/15 flex items-center justify-center">
                                    <svg className="w-8 h-8 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                </div>
                            </div>
                            <p className="font-semibold text-red-400 text-base">Scan failed</p>
                            <p className="text-sm text-slate-500 mt-1">Something went wrong. Please try again.</p>
                        </div>
                    ) : (
                        <div className="text-center py-12">
                            <div className="flex justify-center mb-5">
                                <span className="relative flex h-16 w-16">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-30" />
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-20" style={{ animationDelay: "0.5s" }} />
                                    <span className="relative inline-flex items-center justify-center rounded-full h-16 w-16 bg-gradient-to-br from-blue-500 to-blue-600 text-white shadow-lg shadow-blue-500/30">
                                        <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                                    </span>
                                </span>
                            </div>
                            <p className="font-semibold text-slate-200 text-base">Scanning in progress…</p>
                            <p className="text-sm text-slate-500 mt-2">Analyzing your target across multiple security engines.</p>
                            <p className="text-xs text-slate-600 mt-1">Results will update automatically when ready.</p>
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
                    { label: "Completed",   value: completed.length, color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/20", iconColor: "text-green-400",
                      icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> },
                    { label: "In Progress", value: active.length,    color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/20",  iconColor: "text-blue-400",
                      icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> },
                    { label: "URL Scans",   value: urlScans,         color: "text-indigo-400", bg: "bg-indigo-500/10", border: "border-indigo-500/20", iconColor: "text-indigo-400",
                      icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg> },
                    { label: "File Scans",  value: fileScans,        color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20", iconColor: "text-purple-400",
                      icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg> },
                ] as Array<{label:string;value:number;color:string;bg:string;border:string;iconColor:string;icon:React.ReactNode}>).map(c => (
                    <div key={c.label} className={`rounded-xl border ${c.border} ${c.bg} px-4 py-3 flex items-center gap-3`}>
                        <span className={c.iconColor}>{c.icon}</span>
                        <div>
                            <p className={`text-xl font-black ${c.color}`}>{c.value}</p>
                            <p className="text-xs text-slate-500 font-medium">{c.label}</p>
                        </div>
                    </div>
                ))}
            </div>

            {/* ── Threat breakdown ── */}
            {completed.length > 0 && (() => {
                const chartBars = [
                    { label: "High / Critical", value: threats.high,   barColor: "#ef4444", trackColor: "rgba(239,68,68,0.1)", textColor: "#f87171" },
                    { label: "Medium",           value: threats.medium, barColor: "#f97316", trackColor: "rgba(249,115,22,0.1)", textColor: "#fb923c" },
                    { label: "Low",              value: threats.low,    barColor: "#eab308", trackColor: "rgba(234,179,8,0.1)", textColor: "#facc15" },
                    { label: "Clean / Safe",     value: threats.clean,  barColor: "#22c55e", trackColor: "rgba(34,197,94,0.1)", textColor: "#4ade80" },
                    ...(threats.unknown > 0
                        ? [{ label: "Unknown", value: threats.unknown, barColor: "#9ca3af", trackColor: "rgba(156,163,175,0.1)", textColor: "#9ca3af" }]
                        : []),
                ];
                const maxVal = Math.max(...chartBars.map(b => b.value), 1);

                return (
                    <div>
                        <div className="flex items-center justify-between mb-4">
                            <p className="text-xs font-semibold text-slate-500 uppercase tracking-widest">Threat Breakdown</p>
                            <p className="text-xs text-slate-600">{completed.length} completed scan{completed.length !== 1 ? "s" : ""}</p>
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
                                            <span className="text-xs text-slate-400 font-medium truncate">{b.label}</span>
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
                                            <span className="text-sm font-bold tabular-nums" style={{ color: b.value > 0 ? b.textColor : "#475569" }}>
                                                {b.value}
                                            </span>
                                            <span className="text-[10px] text-slate-600 tabular-nums">
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
                <div className="flex-1 h-2.5 rounded-full overflow-hidden bg-white/[0.06] flex">
                    <div className="bg-indigo-500 h-full rounded-l-full transition-all duration-700" style={{ width: `${(urlScans / total) * 100}%` }} />
                    <div className="bg-purple-400 h-full rounded-r-full transition-all duration-700" style={{ width: `${(fileScans / total) * 100}%` }} />
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-500 flex-shrink-0">
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
            pending: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/20",
            running: "bg-blue-500/15 text-blue-400 border border-blue-500/20",
            in_progress: "bg-blue-500/15 text-blue-400 border border-blue-500/20",
            completed: "bg-green-500/15 text-green-400 border border-green-500/20",
            failed: "bg-red-500/15 text-red-400 border border-red-500/20",
            cancelled: "bg-white/[0.06] text-slate-400 border border-white/[0.08]",
        };
        return styles[status] || "bg-white/[0.06] text-slate-500 border border-white/[0.08]";
    };

    const threatBadge = (level: string | null) => {
        const styles: Record<string, string> = {
            safe:      "bg-green-500/15 text-green-400 border border-green-500/20",
            clean:     "bg-green-500/15 text-green-400 border border-green-500/20",
            low:       "bg-yellow-500/15 text-yellow-400 border border-yellow-500/20",
            medium:    "bg-orange-500/15 text-orange-400 border border-orange-500/20",
            high:      "bg-red-500/15 text-red-400 border border-red-500/20",
            critical:  "bg-red-500/20 text-red-400 border border-red-500/30 font-bold",
            not_found: "bg-white/[0.06] text-slate-500 border border-white/[0.08]",
            timeout:   "bg-yellow-500/15 text-yellow-400 border border-yellow-500/20",
            unknown:   "bg-white/[0.06] text-slate-500 border border-white/[0.08]",
        };
        return styles[level || ""] || "bg-white/[0.06] text-slate-500 border border-white/[0.08]";
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
                <h1 className="text-2xl font-bold text-white">Security Scans</h1>
                <p className="text-slate-400 mt-1">
                    Scan URLs and files for threats using multiple antivirus engines
                </p>
            </div>

            {/* ── Stats Summary Row ── */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                    { label: "Total Scans", value: scans.length, color: "text-white", bg: "bg-white/[0.04]" },
                    { label: "URL Scans", value: urlScans.length, color: "text-blue-400", bg: "bg-blue-500/10" },
                    { label: "File Scans", value: fileScans.length, color: "text-purple-400", bg: "bg-purple-500/10" },
                    {
                        label: "Threats Found",
                        value: scans.filter((s) =>
                            ["high", "critical", "medium"].includes(s.threat_level || "")
                        ).length,
                        color: "text-red-400",
                        bg: "bg-red-500/10",
                    },
                ].map((stat) => (
                    <div
                        key={stat.label}
                        className={`${stat.bg} rounded-xl p-4 border border-white/[0.08]`}
                    >
                        <p className="text-xs text-slate-500 font-medium">{stat.label}</p>
                        <p className={`text-3xl font-bold ${stat.color} mt-1`}>
                            {isLoading ? "…" : stat.value}
                        </p>
                    </div>
                ))}
            </div>

            {/* ── Scan Input Forms — Side by Side ── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* URL Scan Card */}
                <div className="bg-[#263554] rounded-2xl border border-white/[0.08] shadow-lg shadow-black/25 overflow-hidden">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-white/[0.06] bg-gradient-to-r from-blue-500/10 to-transparent">
                        <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center text-white flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                        </div>
                        <div>
                            <h3 className="text-base font-semibold text-white">URL Scan</h3>
                            <p className="text-xs text-slate-400">
                                Check a URL against multiple antivirus engines
                            </p>
                        </div>
                    </div>
                    <form onSubmit={handleUrlSubmit} className="px-6 py-5 space-y-4">
                        <div>
                            <label className="block text-xs font-medium text-slate-300 mb-1.5">
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
                                    className={`w-full px-3.5 py-2.5 pr-10 text-sm border rounded-lg focus:outline-none focus:ring-2 focus:border-transparent transition-all placeholder-slate-500 bg-[#1a2744] text-slate-100 ${urlValidationError
                                            ? "border-red-500/50 focus:ring-red-500/40 bg-red-500/5"
                                            : urlTarget && !urlValidationError
                                                ? "border-green-500/50 focus:ring-green-500/40 bg-green-500/5"
                                                : "border-white/[0.08] focus:ring-blue-500/60"
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
                                <p className="text-xs text-slate-500 mt-1">
                                    Enter the full URL including <code>https://</code>
                                </p>
                            )}
                        </div>

                        {urlError && (
                            <div className="flex items-start gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/20 px-3 py-2.5 rounded-lg">
                                <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                <span>{urlError}</span>
                            </div>
                        )}
                        {urlSuccess && (
                            <div className="flex items-center gap-2 text-sm text-green-400 bg-green-500/10 border border-green-500/20 px-3 py-2.5 rounded-lg">
                                <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                <span>{urlSuccess}</span>
                            </div>
                        )}

                        <button
                            type="submit"
                            id="url-scan-submit"
                            disabled={isUrlSubmitting || !urlTarget.trim() || !!urlValidationError}
                            className="w-full py-2.5 px-4 bg-[#3b82f6] hover:bg-[#60a5fa] text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-blue-600/25"
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
                <div className="bg-[#263554] rounded-2xl border border-white/[0.08] shadow-lg shadow-black/25 overflow-hidden">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-white/[0.06] bg-gradient-to-r from-purple-500/10 to-transparent">
                        <div className="w-9 h-9 rounded-xl bg-purple-600 flex items-center justify-center text-white flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                        </div>
                        <div>
                            <h3 className="text-base font-semibold text-white">File Scan</h3>
                            <p className="text-xs text-slate-400">
                                Upload a file or enter its SHA-256 hash to scan
                            </p>
                        </div>
                    </div>

                    <form onSubmit={handleFileSubmit} className="px-6 py-5 space-y-4">
                        {/* Mode Toggle */}
                        <div className="flex bg-white/[0.04] rounded-lg p-1 gap-1">
                            <button
                                type="button"
                                id="file-upload-mode"
                                onClick={() => setFileMode("upload")}
                                className={`flex-1 py-1.5 px-3 text-xs font-medium rounded-md transition-all ${fileMode === "upload"
                                        ? "bg-[#263554] text-white shadow-sm border border-white/[0.08]"
                                        : "text-slate-400 hover:text-slate-200"
                                    }`}
                            >
                                Upload File
                            </button>
                            <button
                                type="button"
                                id="file-hash-mode"
                                onClick={() => setFileMode("hash")}
                                className={`flex-1 py-1.5 px-3 text-xs font-medium rounded-md transition-all ${fileMode === "hash"
                                        ? "bg-[#263554] text-white shadow-sm border border-white/[0.08]"
                                        : "text-slate-400 hover:text-slate-200"
                                    }`}
                            >
                                Enter Hash
                            </button>
                        </div>

                        {fileMode === "upload" ? (
                            <div>
                                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                                    Select File
                                </label>
                                <label
                                    htmlFor="file-upload"
                                    className={`flex flex-col items-center justify-center w-full h-28 border-2 border-dashed rounded-xl cursor-pointer transition-all ${selectedFile
                                            ? "border-purple-500/50 bg-purple-500/10"
                                            : "border-white/[0.12] bg-white/[0.03] hover:border-purple-500/50 hover:bg-purple-500/10"
                                        }`}
                                >
                                    {selectedFile ? (
                                        <div className="text-center px-4">
                                            <div className="flex justify-center"><svg className="w-8 h-8 text-purple-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg></div>
                                            <p className="text-sm font-medium text-purple-400 mt-1 truncate max-w-[220px]">
                                                {selectedFile.name}
                                            </p>
                                            <p className="text-xs text-slate-500">
                                                {selectedFile.size < 1024 * 1024
                                                    ? `${(selectedFile.size / 1024).toFixed(1)} KB`
                                                    : `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB`}
                                                {" · "}
                                                {selectedFile.type || "Unknown type"}
                                            </p>
                                        </div>
                                    ) : (
                                        <div className="text-center">
                                            <div className="flex justify-center"><svg className="w-8 h-8 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"/></svg></div>
                                            <p className="text-sm text-slate-400 mt-1">
                                                Click to upload or drag & drop
                                            </p>
                                            <p className="text-xs text-slate-500">
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
                                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                                    File Hash (SHA-256)
                                </label>
                                <input
                                    type="text"
                                    id="file-hash-input"
                                    placeholder="e.g. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                                    value={fileHash}
                                    onChange={(e) => setFileHash(e.target.value)}
                                    className="w-full px-3.5 py-2.5 text-sm border border-white/[0.08] rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500/60 focus:border-transparent transition-all placeholder-slate-500 font-mono bg-[#1a2744] text-slate-100"
                                />
                                <p className="text-xs text-slate-500 mt-1">
                                    SHA-256, MD5, or SHA-1 hash accepted
                                </p>
                            </div>
                        )}

                        {fileError && (
                            <div className="flex items-start gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/20 px-3 py-2.5 rounded-lg">
                                <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                <span>{fileError}</span>
                            </div>
                        )}
                        {fileSuccess && (
                            <div className="flex items-center gap-2 text-sm text-green-400 bg-green-500/10 border border-green-500/20 px-3 py-2.5 rounded-lg">
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
                <div className="bg-[#263554] rounded-2xl border border-white/[0.08] shadow-lg shadow-black/25 overflow-hidden">
                    <div className="px-6 py-4 border-b border-white/[0.06]">
                        <h3 className="text-base font-semibold text-white flex items-center gap-2">
                            <svg className="w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                            Scan Results Overview
                        </h3>
                        <p className="text-xs text-slate-500 mt-0.5">
                            Comparison of clean vs infected results across URL and File scans
                        </p>
                    </div>
                    <div className="px-6 py-5">
                        <HistoryBarChart scans={scans} />
                    </div>
                </div>
            )}

            {/* ── Scan History ── */}
            <div className="bg-[#263554] rounded-2xl border border-white/[0.08] shadow-lg shadow-black/25 overflow-hidden">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 px-6 py-4 border-b border-white/[0.06]">
                    <div>
                        <h3 className="text-base font-semibold text-white flex items-center gap-2">
                            <svg className="w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>
                            Scan History
                        </h3>
                        <p className="text-xs text-slate-500 mt-0.5">
                            Click any row to view detailed antivirus results & graphs
                        </p>
                    </div>
                    {/* Filter tabs */}
                    <div className="flex bg-white/[0.04] rounded-lg p-1 gap-1 text-xs font-medium self-start sm:self-auto">
                        {(["all", "url", "file"] as const).map((tab) => (
                            <button
                                key={tab}
                                onClick={() => setActiveTab(tab)}
                                className={`px-3 py-1.5 rounded-md transition-all capitalize ${activeTab === tab
                                        ? "bg-[#263554] text-white shadow-sm border border-white/[0.08]"
                                        : "text-slate-400 hover:text-slate-200"
                                    }`}
                            >
                                {tab === "all" ? "All" : tab === "url" ? "URLs" : "Files"}
                            </button>
                        ))}
                    </div>
                </div>

                {isLoading ? (
                    <div className="text-center py-16">
                        <div className="inline-flex items-center gap-2 text-slate-500">
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
                            <svg className="w-12 h-12 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                        </div>
                        <p className="font-medium text-slate-300">No scans yet</p>
                        <p className="text-sm text-slate-500 mt-1">
                            {activeTab === "all"
                                ? "Submit a URL or file scan above to get started."
                                : `No ${activeTab} scans found. Switch to "All" or start a new scan.`}
                        </p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="bg-white/[0.03] border-b border-white/[0.08]">
                                    <th className="text-left px-6 py-3 font-medium text-slate-400 text-xs uppercase tracking-wider">
                                        Type
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-slate-400 text-xs uppercase tracking-wider">
                                        Target
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-slate-400 text-xs uppercase tracking-wider">
                                        Status
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-slate-400 text-xs uppercase tracking-wider">
                                        Threat Level
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-slate-400 text-xs uppercase tracking-wider">
                                        Date
                                    </th>
                                    <th className="text-left px-6 py-3 font-medium text-slate-400 text-xs uppercase tracking-wider">
                                        Actions
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/[0.06]">
                                {filteredScans.map((scan) => {
                                    const isActive = ["pending", "in_progress", "running"].includes(scan.status);
                                    return (
                                        <tr
                                            key={scan.id}
                                            onClick={() => setSelectedScanId(scan.id)}
                                            className="hover:bg-white/[0.03] transition-colors cursor-pointer group"
                                        >
                                            <td className="px-6 py-4">
                                                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${
                                                    scan.scan_type === "url"
                                                        ? "bg-blue-500/15 text-blue-400 border border-blue-500/20"
                                                        : scan.scan_type === "file"
                                                        ? "bg-indigo-500/15 text-indigo-400 border border-indigo-500/20"
                                                        : "bg-purple-500/15 text-purple-400 border border-purple-500/20"
                                                }`}>
                                                    {scan.scan_type === "url" ? (
                                                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>
                                                    ) : scan.scan_type === "file" ? (
                                                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14"/></svg>
                                                    ) : (
                                                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                                                    )}
                                                    {scan.scan_type === "url" ? "URL" : scan.scan_type === "file" ? "HASH" : "FILE"}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 max-w-[220px]">
                                                <span
                                                    className="font-mono text-xs text-slate-400 truncate block group-hover:text-blue-400 transition-colors"
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
                                                    <span className="text-slate-600 text-xs">—</span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4 text-slate-500 text-xs whitespace-nowrap">
                                                {new Date(scan.created_at).toLocaleString()}
                                            </td>
                                            <td className="px-6 py-4" onClick={e => e.stopPropagation()}>
                                                <div className="flex items-center gap-2">
                                                    <button
                                                        onClick={() => setSelectedScanId(scan.id)}
                                                        className="px-3 py-1.5 rounded-lg bg-blue-500/15 border border-blue-500/20 text-blue-400 hover:bg-blue-500 hover:text-white text-xs font-medium transition-all flex items-center gap-1.5 flex-shrink-0"
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
                                                            className="w-8 h-8 rounded-lg bg-orange-500/15 border border-orange-500/20 text-orange-400 hover:bg-orange-500 hover:text-white flex items-center justify-center transition-all disabled:opacity-40 disabled:cursor-not-allowed flex-shrink-0"
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
                                                        className="w-8 h-8 rounded-lg bg-red-500/15 border border-red-500/20 text-red-400 hover:bg-red-500 hover:text-white hover:border-red-500 flex items-center justify-center transition-all disabled:opacity-40 disabled:cursor-not-allowed flex-shrink-0"
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
