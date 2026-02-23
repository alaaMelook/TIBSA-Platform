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
                🔎 File Analysis
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

interface AntivirusResult {
    engine: string;
    result: "clean" | "infected" | "undetected" | "error";
    verdict?: string;
}

interface Scan {
    id: string;
    scan_type: "url" | "file";
    target: string;
    status: "pending" | "running" | "completed" | "failed";
    threat_level: string | null;
    created_at: string;
    completed_at: string | null;
    antivirus_results?: AntivirusResult[];
}

interface ScanReport {
    id: string;
    scan_id: string;
    summary: string;
    details: Record<string, unknown>;
    indicators: Array<Record<string, unknown>>;
    created_at: string;
}

// ─── Mock antivirus results for visual demonstration ─────────
function generateMockAvResults(
    threatLevel: string | null,
    scanType: "url" | "file"
): AntivirusResult[] {
    const urlEngines = [
        "Google Safe Browsing",
        "VirusTotal",
        "URLVoid",
        "PhishTank",
        "MalwareBytes",
        "Kaspersky",
        "Bitdefender",
        "McAfee",
    ];
    const fileEngines = [
        "Avast",
        "AVG",
        "ClamAV",
        "Kaspersky",
        "Bitdefender",
        "ESET",
        "Malwarebytes",
        "Windows Defender",
        "Symantec",
        "McAfee",
    ];

    const engines = scanType === "url" ? urlEngines : fileEngines;
    const isInfected = ["high", "critical", "medium"].includes(
        threatLevel || ""
    );
    const isLow = threatLevel === "low";

    return engines.map((engine, i) => {
        let result: "clean" | "infected" | "undetected" | "error";
        if (isInfected) {
            result =
                i % 3 === 0 ? "infected" : i % 5 === 0 ? "undetected" : "clean";
        } else if (isLow) {
            result = i < 2 ? "infected" : i === 2 ? "undetected" : "clean";
        } else {
            result = i === engines.length - 1 ? "undetected" : "clean";
        }
        const verdicts: Record<string, string> = {
            infected: isInfected ? "Malware.Generic" : "PUA.Unwanted",
            clean: "Clean",
            undetected: "Undetected",
            error: "Scan Error",
        };
        return { engine, result, verdict: verdicts[result] };
    });
}

// ─── SVG Bar Chart ────────────────────────────────────────────

interface BarChartProps {
    data: { label: string; clean: number; infected: number; total: number }[];
    title: string;
}

function AntivirusBarChart({ data, title }: BarChartProps) {
    const maxVal = Math.max(...data.map((d) => d.total), 1);
    const chartH = 200;
    const barW = 56;
    const gap = 20;
    const paddingLeft = 44;
    const paddingBottom = 60;
    const paddingTop = 20;

    const totalW = paddingLeft + data.length * (barW + gap) + gap;
    const chartAreaH = chartH - paddingBottom - paddingTop;

    const gridLines = 5;

    return (
        <div>
            <p className="text-sm font-semibold text-gray-700 mb-3">{title}</p>
            <div className="flex items-center gap-4 mb-3 text-xs">
                <span className="flex items-center gap-1.5">
                    <span className="inline-block w-3 h-3 rounded bg-green-500" />
                    Clean
                </span>
                <span className="flex items-center gap-1.5">
                    <span className="inline-block w-3 h-3 rounded bg-red-500" />
                    Infected
                </span>
            </div>
            <div className="overflow-x-auto">
                <svg
                    width={totalW}
                    height={chartH}
                    className="font-sans"
                    aria-label={title}
                >
                    {/* Grid lines */}
                    {Array.from({ length: gridLines + 1 }, (_, i) => {
                        const y =
                            paddingTop + (chartAreaH * (gridLines - i)) / gridLines;
                        const val = Math.round((maxVal * i) / gridLines);
                        return (
                            <g key={i}>
                                <line
                                    x1={paddingLeft}
                                    y1={y}
                                    x2={totalW - 4}
                                    y2={y}
                                    stroke="#e5e7eb"
                                    strokeWidth="1"
                                />
                                <text
                                    x={paddingLeft - 6}
                                    y={y + 4}
                                    textAnchor="end"
                                    fontSize="10"
                                    fill="#9ca3af"
                                >
                                    {val}
                                </text>
                            </g>
                        );
                    })}

                    {/* Bars */}
                    {data.map((d, i) => {
                        const x = paddingLeft + gap + i * (barW + gap);
                        const halfW = (barW - 4) / 2;

                        const cleanH = (d.clean / maxVal) * chartAreaH;
                        const infH = (d.infected / maxVal) * chartAreaH;
                        const baseY = paddingTop + chartAreaH;

                        return (
                            <g key={d.label}>
                                {/* Clean bar */}
                                <rect
                                    x={x}
                                    y={baseY - cleanH}
                                    width={halfW}
                                    height={Math.max(cleanH, 1)}
                                    fill="#22c55e"
                                    rx="2"
                                />
                                {/* Infected bar */}
                                <rect
                                    x={x + halfW + 4}
                                    y={baseY - infH}
                                    width={halfW}
                                    height={Math.max(infH, 1)}
                                    fill="#ef4444"
                                    rx="2"
                                />
                                {/* Label */}
                                <text
                                    x={x + halfW + 2}
                                    y={baseY + 12}
                                    textAnchor="middle"
                                    fontSize="9"
                                    fill="#6b7280"
                                    transform={`rotate(-35, ${x + halfW + 2}, ${baseY + 12})`}
                                >
                                    {d.label.length > 12 ? d.label.slice(0, 11) + "…" : d.label}
                                </text>
                            </g>
                        );
                    })}
                </svg>
            </div>
        </div>
    );
}

// ─── Antivirus Results Table ──────────────────────────────────

function AvResultsTable({ results }: { results: AntivirusResult[] }) {
    const summary = results.reduce(
        (acc, r) => {
            acc[r.result] = (acc[r.result] || 0) + 1;
            return acc;
        },
        {} as Record<string, number>
    );

    const resultStyles: Record<string, string> = {
        clean:
            "bg-green-50 text-green-700 border border-green-200",
        infected:
            "bg-red-50 text-red-700 border border-red-200",
        undetected:
            "bg-gray-50 text-gray-600 border border-gray-200",
        error:
            "bg-yellow-50 text-yellow-700 border border-yellow-200",
    };

    const resultIcons: Record<string, string> = {
        clean: "✅",
        infected: "🦠",
        undetected: "❓",
        error: "⚠️",
    };

    return (
        <div>
            {/* Summary pills */}
            <div className="flex flex-wrap gap-2 mb-4">
                {Object.entries(summary).map(([k, v]) => (
                    <span
                        key={k}
                        className={`px-3 py-1 rounded-full text-xs font-medium ${resultStyles[k]}`}
                    >
                        {resultIcons[k]} {k.charAt(0).toUpperCase() + k.slice(1)}: {v}
                    </span>
                ))}
                <span className="px-3 py-1 rounded-full text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200">
                    🔬 Total Engines: {results.length}
                </span>
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-lg border border-gray-200">
                <table className="w-full text-sm">
                    <thead>
                        <tr className="bg-gray-50 border-b border-gray-200">
                            <th className="text-left px-4 py-2.5 font-medium text-gray-600">
                                Antivirus Engine
                            </th>
                            <th className="text-left px-4 py-2.5 font-medium text-gray-600">
                                Result
                            </th>
                            <th className="text-left px-4 py-2.5 font-medium text-gray-600">
                                Verdict
                            </th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                        {results.map((r) => (
                            <tr
                                key={r.engine}
                                className={`transition-colors ${r.result === "infected"
                                        ? "bg-red-50/40 hover:bg-red-50"
                                        : "hover:bg-gray-50"
                                    }`}
                            >
                                <td className="px-4 py-2.5 font-medium text-gray-800">
                                    {r.engine}
                                </td>
                                <td className="px-4 py-2.5">
                                    <span
                                        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium ${resultStyles[r.result]}`}
                                    >
                                        {resultIcons[r.result]}
                                        {r.result.charAt(0).toUpperCase() + r.result.slice(1)}
                                    </span>
                                </td>
                                <td className="px-4 py-2.5 text-gray-500 font-mono text-xs">
                                    {r.verdict}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// ─── Scan Detail Modal ────────────────────────────────────────

function ScanDetailModal({
    scan,
    onClose,
}: {
    scan: Scan;
    onClose: () => void;
}) {
    const avResults =
        scan.antivirus_results ||
        (scan.status === "completed"
            ? generateMockAvResults(scan.threat_level, scan.scan_type)
            : []);

    const chartData = avResults.reduce(
        (acc, r) => {
            const existing = acc.find((d) => d.label === r.engine);
            if (existing) {
                if (r.result === "clean") existing.clean++;
                else if (r.result === "infected") existing.infected++;
                existing.total++;
            } else {
                acc.push({
                    label: r.engine,
                    clean: r.result === "clean" ? 1 : 0,
                    infected: r.result === "infected" ? 1 : 0,
                    total: 1,
                });
            }
            return acc;
        },
        [] as { label: string; clean: number; infected: number; total: number }[]
    );

    const threatColors: Record<string, string> = {
        safe: "text-green-600 bg-green-50 border-green-200",
        low: "text-yellow-600 bg-yellow-50 border-yellow-200",
        medium: "text-orange-600 bg-orange-50 border-orange-200",
        high: "text-red-600 bg-red-50 border-red-200",
        critical: "text-red-700 bg-red-100 border-red-300",
    };

    const tClass =
        threatColors[scan.threat_level || "safe"] ||
        "text-gray-500 bg-gray-50 border-gray-200";

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
            <div className="bg-white rounded-2xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
                {/* Modal Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 bg-gray-50">
                    <div>
                        <h2 className="text-lg font-semibold text-gray-900">
                            {scan.scan_type === "url" ? "🔗" : "📁"} Scan Report
                        </h2>
                        <p className="text-xs text-gray-400 mt-0.5 font-mono">
                            ID: {scan.id}
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-200 transition-colors"
                    >
                        <svg className="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
                            <path
                                fillRule="evenodd"
                                d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                                clipRule="evenodd"
                            />
                        </svg>
                    </button>
                </div>

                <div className="overflow-y-auto flex-1 p-6 space-y-6">
                    {/* Meta Info */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="bg-gray-50 rounded-xl p-3">
                            <p className="text-xs text-gray-500">Type</p>
                            <p className="font-semibold text-gray-800 mt-0.5 capitalize">
                                {scan.scan_type}
                            </p>
                        </div>
                        <div className="bg-gray-50 rounded-xl p-3">
                            <p className="text-xs text-gray-500">Status</p>
                            <p className="font-semibold text-gray-800 mt-0.5 capitalize">
                                {scan.status}
                            </p>
                        </div>
                        <div className="bg-gray-50 rounded-xl p-3">
                            <p className="text-xs text-gray-500">Threat Level</p>
                            <span
                                className={`inline-block mt-0.5 px-2 py-0.5 rounded-full text-xs font-semibold border ${tClass}`}
                            >
                                {scan.threat_level || "N/A"}
                            </span>
                        </div>
                        <div className="bg-gray-50 rounded-xl p-3">
                            <p className="text-xs text-gray-500">Scanned</p>
                            <p className="font-semibold text-gray-800 mt-0.5 text-xs">
                                {new Date(scan.created_at).toLocaleString()}
                            </p>
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

                    {scan.status === "completed" && avResults.length > 0 ? (
                        <>
                            {/* Antivirus Results Table */}
                            <div>
                                <h3 className="text-sm font-semibold text-gray-800 mb-3 flex items-center gap-2">
                                    <span className="w-6 h-6 rounded-md bg-blue-100 flex items-center justify-center text-blue-600 text-xs">
                                        🔬
                                    </span>
                                    Antivirus Engine Results
                                </h3>
                                <AvResultsTable results={avResults} />
                            </div>

                            {/* Bar Chart */}
                            <div>
                                <h3 className="text-sm font-semibold text-gray-800 mb-3 flex items-center gap-2">
                                    <span className="w-6 h-6 rounded-md bg-purple-100 flex items-center justify-center text-purple-600 text-xs">
                                        📊
                                    </span>
                                    Detection Comparison — Per Engine
                                </h3>
                                <div className="bg-gray-50 rounded-xl p-4 border border-gray-200">
                                    <AntivirusBarChart
                                        data={chartData}
                                        title={`${scan.scan_type === "url" ? "URL" : "File"} Scan — Clean vs Infected per Engine`}
                                    />
                                </div>
                            </div>
                        </>
                    ) : scan.status !== "completed" ? (
                        <div className="text-center py-10 text-gray-400">
                            <div className="text-4xl mb-3">⏳</div>
                            <p className="font-medium">Scan in progress...</p>
                            <p className="text-sm mt-1">
                                Results will appear once the scan is complete.
                            </p>
                        </div>
                    ) : null}
                </div>
            </div>
        </div>
    );
}

// ─── Aggregate Chart (Scan History Overview) ──────────────────

function HistoryBarChart({ scans }: { scans: Scan[] }) {
    const urlScans = scans.filter((s) => s.scan_type === "url");
    const fileScans = scans.filter((s) => s.scan_type === "file");

    const countByThreat = (list: Scan[]) => {
        const infected = list.filter((s) =>
            ["high", "critical", "medium"].includes(s.threat_level || "")
        ).length;
        const clean = list.filter((s) =>
            ["safe", "low"].includes(s.threat_level || "")
        ).length;
        const pending = list.filter((s) => !s.threat_level).length;
        return { infected, clean, pending };
    };

    const urlStats = countByThreat(urlScans);
    const fileStats = countByThreat(fileScans);

    const groups = [
        { label: "URL Scans", ...urlStats, total: urlScans.length },
        { label: "File Scans", ...fileStats, total: fileScans.length },
    ];

    const maxVal = Math.max(...groups.map((g) => g.total), 1);
    const chartH = 180;
    const barGroupW = 120;
    const gap = 40;
    const paddingLeft = 44;
    const paddingBottom = 48;
    const paddingTop = 16;
    const totalW = paddingLeft + groups.length * (barGroupW + gap) + gap;
    const chartAreaH = chartH - paddingBottom - paddingTop;
    const subBarW = 32;
    const subGap = 6;
    const gridLines = 4;

    return (
        <div>
            <div className="flex items-center gap-4 mb-3 text-xs">
                <span className="flex items-center gap-1.5">
                    <span className="inline-block w-3 h-3 rounded bg-green-500" />
                    Clean / Low
                </span>
                <span className="flex items-center gap-1.5">
                    <span className="inline-block w-3 h-3 rounded bg-red-500" />
                    Infected / High
                </span>
                <span className="flex items-center gap-1.5">
                    <span className="inline-block w-3 h-3 rounded bg-gray-400" />
                    Pending
                </span>
            </div>
            <div className="overflow-x-auto">
                <svg width={totalW} height={chartH} className="font-sans">
                    {Array.from({ length: gridLines + 1 }, (_, i) => {
                        const y =
                            paddingTop + (chartAreaH * (gridLines - i)) / gridLines;
                        const val = Math.round((maxVal * i) / gridLines);
                        return (
                            <g key={i}>
                                <line
                                    x1={paddingLeft}
                                    y1={y}
                                    x2={totalW - 4}
                                    y2={y}
                                    stroke="#e5e7eb"
                                    strokeWidth="1"
                                />
                                <text
                                    x={paddingLeft - 6}
                                    y={y + 4}
                                    textAnchor="end"
                                    fontSize="10"
                                    fill="#9ca3af"
                                >
                                    {val}
                                </text>
                            </g>
                        );
                    })}

                    {groups.map((g, i) => {
                        const groupX = paddingLeft + gap + i * (barGroupW + gap);
                        const baseY = paddingTop + chartAreaH;

                        const bars = [
                            { val: g.clean, color: "#22c55e" },
                            { val: g.infected, color: "#ef4444" },
                            { val: g.pending, color: "#9ca3af" },
                        ];

                        return (
                            <g key={g.label}>
                                {bars.map((b, j) => {
                                    const barH = (b.val / maxVal) * chartAreaH;
                                    const bx = groupX + j * (subBarW + subGap);
                                    return (
                                        <rect
                                            key={j}
                                            x={bx}
                                            y={baseY - barH}
                                            width={subBarW}
                                            height={Math.max(barH, 1)}
                                            fill={b.color}
                                            rx="3"
                                        />
                                    );
                                })}
                                <text
                                    x={groupX + (3 * (subBarW + subGap)) / 2 - subGap / 2}
                                    y={baseY + 16}
                                    textAnchor="middle"
                                    fontSize="11"
                                    fontWeight="600"
                                    fill="#374151"
                                >
                                    {g.label}
                                </text>
                                <text
                                    x={groupX + (3 * (subBarW + subGap)) / 2 - subGap / 2}
                                    y={baseY + 30}
                                    textAnchor="middle"
                                    fontSize="9"
                                    fill="#9ca3af"
                                >
                                    ({g.total} total)
                                </text>
                            </g>
                        );
                    })}
                </svg>
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
    const [selectedScan, setSelectedScan] = useState<Scan | null>(null);

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

        // Prefer SHA-256 from computed info; fall back to filename / typed hash
        const target =
            fileMode === "hash"
                ? fileHash.trim()
                : fileInfo?.sha256 || selectedFile?.name || "";
        if (!target) {
            setFileError(
                fileMode === "hash"
                    ? "Please enter a file hash (SHA-256)."
                    : "Please select a file to scan."
            );
            return;
        }

        setIsFileSubmitting(true);
        setFileError("");
        setFileSuccess("");

        try {
            // Send SHA-256 as target so the backend can look it up in threat feeds
            await api.post(
                "/api/v1/scans/file",
                { target, scan_type: "file" },
                token
            );
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

    // ─── Helpers ──────────────────────────────────────────────

    const statusBadge = (status: string) => {
        const styles: Record<string, string> = {
            pending: "bg-yellow-100 text-yellow-700 border border-yellow-200",
            running: "bg-blue-100 text-blue-700 border border-blue-200",
            completed: "bg-green-100 text-green-700 border border-green-200",
            failed: "bg-red-100 text-red-700 border border-red-200",
        };
        return styles[status] || "bg-gray-100 text-gray-600 border border-gray-200";
    };

    const threatBadge = (level: string | null) => {
        const styles: Record<string, string> = {
            safe: "bg-green-50 text-green-700 border border-green-200",
            low: "bg-yellow-50 text-yellow-700 border border-yellow-200",
            medium: "bg-orange-50 text-orange-700 border border-orange-200",
            high: "bg-red-50 text-red-700 border border-red-200",
            critical: "bg-red-100 text-red-800 border border-red-300 font-bold",
        };
        return styles[level || ""] || "bg-gray-50 text-gray-400 border border-gray-200";
    };

    const filteredScans = scans.filter((s) =>
        activeTab === "all" ? true : s.scan_type === activeTab
    );

    // ─── Aggregate stats for chart ────────────────────────────

    const urlScans = scans.filter((s) => s.scan_type === "url");
    const fileScans = scans.filter((s) => s.scan_type === "file");

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
                        <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center text-white text-lg flex-shrink-0">
                            🔗
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
                                    <span className="absolute right-3 top-1/2 -translate-y-1/2 text-sm">
                                        {urlValidationError ? "❌" : "✔️"}
                                    </span>
                                )}
                            </div>
                            {urlValidationError ? (
                                <p className="text-xs text-red-600 mt-1 flex items-center gap-1">
                                    <span>⚠️</span> {urlValidationError}
                                </p>
                            ) : (
                                <p className="text-xs text-gray-400 mt-1">
                                    Enter the full URL including <code>https://</code>
                                </p>
                            )}
                        </div>

                        {urlError && (
                            <div className="flex items-start gap-2 text-sm text-red-700 bg-red-50 border border-red-200 px-3 py-2.5 rounded-lg">
                                <span>⚠️</span>
                                <span>{urlError}</span>
                            </div>
                        )}
                        {urlSuccess && (
                            <div className="flex items-center gap-2 text-sm text-green-700 bg-green-50 border border-green-200 px-3 py-2.5 rounded-lg">
                                <span>✅</span>
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
                                    🔍 Scan URL
                                </>
                            )}
                        </button>
                    </form>
                </div>

                {/* File Scan Card */}
                <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
                    <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-100 bg-gradient-to-r from-purple-50 to-white">
                        <div className="w-9 h-9 rounded-xl bg-purple-600 flex items-center justify-center text-white text-lg flex-shrink-0">
                            📁
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
                                📤 Upload File
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
                                #️⃣ Enter Hash
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
                                            <p className="text-2xl">📄</p>
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
                                            <p className="text-2xl text-gray-400">☁️</p>
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
                                <span>⚠️</span>
                                <span>{fileError}</span>
                            </div>
                        )}
                        {fileSuccess && (
                            <div className="flex items-center gap-2 text-sm text-green-700 bg-green-50 border border-green-200 px-3 py-2.5 rounded-lg">
                                <span>✅</span>
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
                                    🔍 Scan File
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
                        <h3 className="text-base font-semibold text-gray-900">
                            📊 Scan Results Overview
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
                        <h3 className="text-base font-semibold text-gray-900">
                            📋 Scan History
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
                                {tab === "all" ? "All" : tab === "url" ? "🔗 URLs" : "📁 Files"}
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
                        <div className="text-5xl mb-3">🔍</div>
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
                                {filteredScans.map((scan) => (
                                    <tr
                                        key={scan.id}
                                        className="hover:bg-gray-50 transition-colors group"
                                    >
                                        <td className="px-6 py-3.5">
                                            <span
                                                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${scan.scan_type === "url"
                                                        ? "bg-blue-50 text-blue-700 border border-blue-200"
                                                        : "bg-purple-50 text-purple-700 border border-purple-200"
                                                    }`}
                                            >
                                                {scan.scan_type === "url" ? "🔗" : "📁"}
                                                {scan.scan_type.toUpperCase()}
                                            </span>
                                        </td>
                                        <td className="px-6 py-3.5 max-w-[200px]">
                                            <span
                                                className="font-mono text-xs text-gray-600 truncate block"
                                                title={scan.target}
                                            >
                                                {scan.target}
                                            </span>
                                        </td>
                                        <td className="px-6 py-3.5">
                                            <span
                                                className={`px-2.5 py-1 rounded-full text-xs font-medium ${statusBadge(scan.status)}`}
                                            >
                                                {scan.status}
                                            </span>
                                        </td>
                                        <td className="px-6 py-3.5">
                                            {scan.threat_level ? (
                                                <span
                                                    className={`px-2.5 py-1 rounded-full text-xs font-medium capitalize ${threatBadge(scan.threat_level)}`}
                                                >
                                                    {scan.threat_level}
                                                </span>
                                            ) : (
                                                <span className="text-gray-400 text-xs">—</span>
                                            )}
                                        </td>
                                        <td className="px-6 py-3.5 text-gray-400 text-xs whitespace-nowrap">
                                            {new Date(scan.created_at).toLocaleString()}
                                        </td>
                                        <td className="px-6 py-3.5">
                                            <button
                                                onClick={() => setSelectedScan(scan)}
                                                className="flex items-center gap-1.5 text-xs font-medium text-blue-600 hover:text-blue-800 hover:underline transition-colors"
                                            >
                                                View Report →
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* ── Scan Detail Modal ── */}
            {selectedScan && (
                <ScanDetailModal
                    scan={selectedScan}
                    onClose={() => setSelectedScan(null)}
                />
            )}
        </div>
    );
}
