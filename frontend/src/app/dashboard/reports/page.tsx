"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card } from "@/components/ui";

<<<<<<< HEAD
=======
// ─── Types ───────────────────────────────────────────────────

>>>>>>> b4a826d (edit threat modeling)
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
<<<<<<< HEAD
    indicators: Array<{
        type: string;
        value: string;
        threat_level: string;
    }>;
    created_at: string;
}

=======
    indicators: Array<{ type: string; value: string; threat_level: string }>;
    created_at: string;
}

interface ThreatModelItem {
    id: string;
    project_name: string;
    app_type: string;
    risk_score: number;
    risk_label: string;
    threat_count: number;
    created_at: string;
}

interface ThreatModelDetail {
    id: string;
    project_name: string;
    app_type: string;
    uses_auth: boolean;
    uses_database: boolean;
    has_admin_panel: boolean;
    uses_external_apis: boolean;
    stores_sensitive_data: boolean;
    frameworks: string[];
    languages: string[];
    deploy_envs: string[];
    deploy_types: string[];
    databases: string[];
    protocols: string[];
    risk_score: number;
    risk_label: string;
    threats: Array<{ id: string; title: string; risk: string; category: string; description: string; mitigation: string }>;
    created_at: string;
}

type ActiveTab = "scans" | "threat-models";

>>>>>>> b4a826d (edit threat modeling)
// ─── Download helpers ────────────────────────────────────────

function downloadBlob(content: string, filename: string, mime: string) {
    const blob = new Blob([content], { type: mime });
<<<<<<< HEAD
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
=======
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
>>>>>>> b4a826d (edit threat modeling)
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
<<<<<<< HEAD
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
=======
    if (scan.completed_at) lines.push(`  Completed At : ${new Date(scan.completed_at).toLocaleString()}`);
    lines.push(""); lines.push(thinDiv); lines.push("  SUMMARY"); lines.push(thinDiv); lines.push("");
    lines.push(`  ${report.summary}`); lines.push("");

    const details = report.details as Record<string, unknown>;
    const vt = details?.virustotal as Record<string, unknown> | undefined;
    if (vt && !vt.error) {
        lines.push(thinDiv); lines.push("  VIRUSTOTAL ANALYSIS"); lines.push(thinDiv); lines.push("");
>>>>>>> b4a826d (edit threat modeling)
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

<<<<<<< HEAD
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
=======
    const ai = details?.ai_classifier as Record<string, unknown> | undefined;
    if (ai && ai.model !== "model_not_loaded") {
        lines.push(thinDiv); lines.push("  AI PHISHING CLASSIFIER"); lines.push(thinDiv); lines.push("");
        const confidence = ((ai.confidence as number) || 0) * 100;
        lines.push(`  Verdict    : ${ai.is_phishing ? "PHISHING" : "LEGITIMATE"}`);
>>>>>>> b4a826d (edit threat modeling)
        lines.push(`  Confidence : ${confidence.toFixed(1)}%`);
        lines.push(`  Model      : ${ai.model}`);
        lines.push("");
    }

<<<<<<< HEAD
    // ── Combined Threat Score section ──
    const threatScore = details?.threat_score as number | undefined;
    const verdict = details?.verdict as string | undefined;
    if (typeof threatScore === "number" && verdict) {
        lines.push(thinDiv);
        lines.push("  COMBINED THREAT SCORE");
        lines.push(thinDiv);
        lines.push("");
=======
    const threatScore = details?.threat_score as number | undefined;
    const verdict     = details?.verdict as string | undefined;
    if (typeof threatScore === "number" && verdict) {
        lines.push(thinDiv); lines.push("  COMBINED THREAT SCORE"); lines.push(thinDiv); lines.push("");
>>>>>>> b4a826d (edit threat modeling)
        lines.push(`  Score      : ${(threatScore * 100).toFixed(1)} / 100`);
        lines.push(`  Verdict    : ${verdict.toUpperCase()}`);
        lines.push(`  Formula    : (0.6 × AI Score) + (0.4 × VT Score)`);
        lines.push("");
    }

<<<<<<< HEAD
    // ── Malice section ──
    const malice = details?.malice as Record<string, unknown> | undefined;
    if (malice && !malice.error) {
        lines.push(thinDiv);
        lines.push("  LOCAL AV ENGINE RESULTS");
        lines.push(thinDiv);
        lines.push("");
=======
    const malice = details?.malice as Record<string, unknown> | undefined;
    if (malice && !malice.error) {
        lines.push(thinDiv); lines.push("  LOCAL AV ENGINE RESULTS"); lines.push(thinDiv); lines.push("");
>>>>>>> b4a826d (edit threat modeling)
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
<<<<<<< HEAD
                const stat = (isMal ? "DETECTED" : eng.error ? "ERROR" : "Clean").padEnd(12);
                const res = isMal ? String(eng.result || "Malware") : (eng.error ? String(eng.error) : "—");
=======
                const stat  = (isMal ? "DETECTED" : eng.error ? "ERROR" : "Clean").padEnd(12);
                const res   = isMal ? String(eng.result || "Malware") : (eng.error ? String(eng.error) : "—");
>>>>>>> b4a826d (edit threat modeling)
                lines.push(`  ${name} ${stat} ${res}`);
            }
        }
        lines.push("");
    }

<<<<<<< HEAD
    // ── Indicators ──
    if (report.indicators?.length > 0) {
        lines.push(thinDiv);
        lines.push("  INDICATORS OF COMPROMISE");
        lines.push(thinDiv);
        lines.push("");
        for (const ind of report.indicators) {
            lines.push(`  [${ind.threat_level.toUpperCase()}] ${ind.type}: ${ind.value}`);
        }
=======
    if (report.indicators?.length > 0) {
        lines.push(thinDiv); lines.push("  INDICATORS OF COMPROMISE"); lines.push(thinDiv); lines.push("");
        for (const ind of report.indicators)
            lines.push(`  [${ind.threat_level.toUpperCase()}] ${ind.type}: ${ind.value}`);
>>>>>>> b4a826d (edit threat modeling)
        lines.push("");
    }

    lines.push(divider);
    lines.push(`  Generated by TIBSA Platform — ${new Date().toLocaleString()}`);
    lines.push(divider);
<<<<<<< HEAD

=======
>>>>>>> b4a826d (edit threat modeling)
    return lines.join("\n");
}

function buildJsonReport(scan: Scan, report: ScanReport): string {
    return JSON.stringify({
<<<<<<< HEAD
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

=======
        meta: { generator: "TIBSA Platform", generated_at: new Date().toISOString(), report_id: report.id },
        scan: { id: scan.id, type: scan.scan_type, target: scan.target, status: scan.status, threat_level: scan.threat_level, created_at: scan.created_at, completed_at: scan.completed_at },
        report: { summary: report.summary, details: report.details, indicators: report.indicators },
    }, null, 2);
}

// ─── PDF builder for Threat Model reports ───────────────────

function buildThreatModelPDF(detail: ThreatModelDetail): void {
    const riskColor: Record<string, string> = {
        High: "#ef4444", Medium: "#f97316", Low: "#eab308", Critical: "#dc2626",
    };
    const label = detail.risk_label;
    const now   = new Date().toLocaleString();

    const stackTags = [
        ...detail.frameworks, ...detail.languages,
        ...detail.deploy_envs, ...detail.deploy_types,
        ...detail.databases, ...detail.protocols,
    ];

    const tagsHtml = stackTags.length > 0
        ? stackTags.map(t => `<span style="display:inline-block;padding:3px 10px;margin:3px;background:#eff6ff;color:#1d4ed8;border-radius:999px;font-size:12px;border:1px solid #bfdbfe">${t}</span>`).join("")
        : "<span style='color:#94a3b8;font-size:13px'>None selected</span>";

    const highCount   = detail.threats.filter(t => t.risk === "High").length;
    const medCount    = detail.threats.filter(t => t.risk === "Medium").length;
    const lowCount    = detail.threats.filter(t => t.risk === "Low").length;

    const threatsHtml = detail.threats.map(t => `
        <div style="margin-bottom:16px;padding:14px;border:1px solid #e2e8f0;border-radius:8px;border-left:4px solid ${riskColor[t.risk] || "#94a3b8"}">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                <span style="font-weight:700;font-size:15px;color:#1e293b">${t.title}</span>
                <span style="font-size:12px;font-weight:600;color:${riskColor[t.risk]};background:${riskColor[t.risk]}22;padding:2px 10px;border-radius:999px;border:1px solid ${riskColor[t.risk]}44">${t.risk}</span>
            </div>
            <div style="font-size:11px;color:#64748b;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em">${t.category}</div>
            <p style="font-size:13px;color:#475569;margin:0 0 8px 0;line-height:1.6"><strong>Risk:</strong> ${t.description}</p>
            <p style="font-size:13px;color:#0f766e;margin:0;line-height:1.6;background:#f0fdf4;padding:8px;border-radius:6px"><strong>✅ Mitigation:</strong> ${t.mitigation}</p>
        </div>`).join("");

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8">
    <title>Threat Report — ${detail.project_name}</title>
    <style>
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:32px;color:#1e293b;background:#fff}
        @media print{body{padding:0}} h2{font-size:17px;margin:24px 0 12px;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:6px}
        .badge{display:inline-block;padding:4px 14px;border-radius:999px;font-weight:700;font-size:13px}
        table{width:100%;border-collapse:collapse;font-size:13px} td{padding:6px 10px;border-bottom:1px solid #f1f5f9} td:first-child{color:#64748b;width:160px}
    </style></head><body>
    <div style="background:linear-gradient(135deg,#1d4ed8,#1e40af);color:white;padding:28px 32px;border-radius:12px;margin-bottom:28px">
        <div style="font-size:12px;text-transform:uppercase;letter-spacing:0.1em;opacity:0.7;margin-bottom:6px">TIBSA · Security Analysis · TMaaS</div>
        <h1 style="margin:0;font-size:26px">Threat Report — ${detail.project_name}</h1>
        <div style="opacity:0.8;margin-top:6px;font-size:14px">${detail.app_type} Application · Generated ${now}</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px;margin-bottom:24px">
        <div style="padding:16px;background:#fef2f2;border-radius:10px;text-align:center;border:1px solid #fecaca">
            <div style="font-size:28px;font-weight:800;color:#ef4444">${highCount}</div>
            <div style="font-size:12px;color:#b91c1c;font-weight:600">HIGH</div>
        </div>
        <div style="padding:16px;background:#fff7ed;border-radius:10px;text-align:center;border:1px solid #fed7aa">
            <div style="font-size:28px;font-weight:800;color:#f97316">${medCount}</div>
            <div style="font-size:12px;color:#c2410c;font-weight:600">MEDIUM</div>
        </div>
        <div style="padding:16px;background:#fefce8;border-radius:10px;text-align:center;border:1px solid #fde68a">
            <div style="font-size:28px;font-weight:800;color:#eab308">${lowCount}</div>
            <div style="font-size:12px;color:#a16207;font-weight:600">LOW</div>
        </div>
        <div style="padding:16px;background:#f0f9ff;border-radius:10px;text-align:center;border:1px solid #bae6fd">
            <div style="font-size:28px;font-weight:800;color:${riskColor[label] || "#0ea5e9"}">${detail.risk_score}</div>
            <div style="font-size:12px;color:#0369a1;font-weight:600">RISK SCORE</div>
        </div>
    </div>
    <h2>Project Information</h2>
    <table>
        <tr><td>Project Name</td><td><strong>${detail.project_name}</strong></td></tr>
        <tr><td>App Type</td><td>${detail.app_type}</td></tr>
        <tr><td>Risk Label</td><td><span class="badge" style="background:${riskColor[label]}22;color:${riskColor[label]};border:1px solid ${riskColor[label]}44">${label}</span></td></tr>
        <tr><td>Uses Auth</td><td>${detail.uses_auth ? "✅ Yes" : "❌ No"}</td></tr>
        <tr><td>Uses Database</td><td>${detail.uses_database ? "✅ Yes" : "❌ No"}</td></tr>
        <tr><td>Admin Panel</td><td>${detail.has_admin_panel ? "✅ Yes" : "❌ No"}</td></tr>
        <tr><td>External APIs</td><td>${detail.uses_external_apis ? "✅ Yes" : "❌ No"}</td></tr>
        <tr><td>Sensitive Data</td><td>${detail.stores_sensitive_data ? "✅ Yes" : "❌ No"}</td></tr>
        <tr><td>Saved At</td><td>${new Date(detail.created_at).toLocaleString()}</td></tr>
    </table>
    <h2>Technology Stack</h2>
    <div style="margin-bottom:8px">${tagsHtml}</div>
    <h2>Identified Threats (${detail.threats.length})</h2>
    ${threatsHtml}
    <div style="margin-top:32px;padding:14px;background:#f8fafc;border-radius:8px;font-size:12px;color:#94a3b8;text-align:center;border:1px solid #e2e8f0">
        Generated by TIBSA Platform · Threat Modeling as a Service · ${now}
    </div>
    </body></html>`;

    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url  = URL.createObjectURL(blob);
    const win  = window.open(url, "_blank");
    if (win) {
        win.addEventListener("load", () => {
            setTimeout(() => { win.print(); URL.revokeObjectURL(url); }, 400);
        });
    }
}

// ─── Colour helpers ──────────────────────────────────────────

function threatColor(level: string | null) {
    const colors: Record<string, string> = {
        safe: "text-green-400", low: "text-yellow-400",
        medium: "text-orange-400", high: "text-red-400", critical: "text-red-500",
    };
    return colors[level || "safe"] || "text-slate-500";
}

function riskBadge(label: string) {
    const map: Record<string, string> = {
        Critical: "bg-red-500/15 text-red-400 border-red-500/30",
        High:     "bg-red-500/10 text-red-400 border-red-500/20",
        Medium:   "bg-orange-500/10 text-orange-400 border-orange-500/20",
        Low:      "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    };
    return map[label] || "bg-slate-500/10 text-slate-400 border-slate-500/20";
}

// ─── Main component ──────────────────────────────────────────

export default function ReportsPage() {
    const { token } = useAuth();

    // Scans state
    const [scans, setScans]                   = useState<Scan[]>([]);
    const [selectedScan, setSelectedScan]     = useState<Scan | null>(null);
    const [selectedReport, setSelectedReport] = useState<ScanReport | null>(null);
    const [scansLoading, setScansLoading]     = useState(true);
    const [reportLoading, setReportLoading]   = useState(false);
    const [downloadMenuOpen, setDownloadMenuOpen] = useState(false);

    // Threat model state
    const [tmList, setTmList]               = useState<ThreatModelItem[]>([]);
    const [selectedTm, setSelectedTm]       = useState<ThreatModelDetail | null>(null);
    const [tmLoading, setTmLoading]         = useState(true);
    const [tmDetailLoading, setTmDetailLoading] = useState(false);

    // Tab
    const [activeTab, setActiveTab] = useState<ActiveTab>("scans");

    // ── Fetch scans ─────────────────────────────────────────
>>>>>>> b4a826d (edit threat modeling)
    const fetchScans = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<Scan[]>("/api/v1/scans/", token);
<<<<<<< HEAD
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

=======
            setScans(data.filter(s => s.status === "completed"));
        } catch (err) {
            console.error("Failed to fetch scans:", err);
        } finally {
            setScansLoading(false);
        }
    }, [token]);

    // ── Fetch threat model list ──────────────────────────────
    const fetchTmList = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<ThreatModelItem[]>("/api/v1/threat-modeling/analyses", token);
            setTmList(data);
        } catch (err) {
            console.error("Failed to fetch threat models:", err);
        } finally {
            setTmLoading(false);
        }
    }, [token]);

    useEffect(() => { fetchScans(); fetchTmList(); }, [fetchScans, fetchTmList]);

    // ── Select scan ──────────────────────────────────────────
>>>>>>> b4a826d (edit threat modeling)
    const viewReport = async (scanId: string) => {
        if (!token) return;
        setReportLoading(true);
        setDownloadMenuOpen(false);
<<<<<<< HEAD
        const scan = scans.find((s) => s.id === scanId) || null;
        setSelectedScan(scan);
=======
        setSelectedScan(scans.find(s => s.id === scanId) || null);
>>>>>>> b4a826d (edit threat modeling)
        try {
            const data = await api.get<ScanReport>(`/api/v1/scans/${scanId}`, token);
            setSelectedReport(data);
        } catch {
            setSelectedReport(null);
        } finally {
            setReportLoading(false);
        }
    };

<<<<<<< HEAD
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
=======
    // ── Select threat model ──────────────────────────────────
    const viewTmDetail = async (id: string) => {
        if (!token) return;
        setTmDetailLoading(true);
        setSelectedTm(null);
        try {
            const data = await api.get<ThreatModelDetail>(`/api/v1/threat-modeling/analyses/${id}`, token);
            setSelectedTm(data);
        } catch (err) {
            console.error("Failed to fetch threat model detail:", err);
        } finally {
            setTmDetailLoading(false);
        }
    };

    // ── Scan download ────────────────────────────────────────
    const handleDownload = (format: "txt" | "json") => {
        if (!selectedReport || !selectedScan) return;
        const safeName = selectedScan.target.replace(/[^a-zA-Z0-9.-]/g, "_").slice(0, 40);
        const date     = new Date(selectedScan.created_at).toISOString().slice(0, 10);
        if (format === "txt") {
            downloadBlob(buildTextReport(selectedScan, selectedReport), `TIBSA_Report_${safeName}_${date}.txt`, "text/plain;charset=utf-8");
        } else {
            downloadBlob(buildJsonReport(selectedScan, selectedReport), `TIBSA_Report_${safeName}_${date}.json`, "application/json");
>>>>>>> b4a826d (edit threat modeling)
        }
        setDownloadMenuOpen(false);
    };

<<<<<<< HEAD
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
=======
    // ── Threat model delete ──────────────────────────────────
    const handleDeleteTm = async (id: string) => {
        if (!token || !confirm("Delete this threat model report?")) return;
        try {
            await api.delete(`/api/v1/threat-modeling/analyses/${id}`, token);
            setTmList(prev => prev.filter(t => t.id !== id));
            if (selectedTm?.id === id) setSelectedTm(null);
        } catch (err) {
            console.error("Delete failed:", err);
        }
    };

    // ── Render ───────────────────────────────────────────────
    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-white">Reports</h1>
                <p className="text-slate-400 mt-1">View and download your security analysis reports</p>
            </div>

            {/* Tab switcher */}
            <div className="flex gap-1 bg-white/[0.04] p-1 rounded-xl w-fit border border-white/[0.06]">
                {(["scans", "threat-models"] as ActiveTab[]).map(tab => (
                    <button
                        key={tab}
                        onClick={() => setActiveTab(tab)}
                        className={`px-5 py-2 rounded-lg text-sm font-medium transition-all ${
                            activeTab === tab
                                ? "bg-blue-600 text-white shadow"
                                : "text-slate-400 hover:text-slate-200"
                        }`}
                    >
                        {tab === "scans" ? "🔍 Scan Reports" : "🛡 Threat Models"}
                        {tab === "threat-models" && tmList.length > 0 && (
                            <span className="ml-2 bg-blue-500/30 text-blue-300 text-xs px-1.5 py-0.5 rounded-full">{tmList.length}</span>
                        )}
                    </button>
                ))}
            </div>

            {/* ══ SCAN REPORTS TAB ══════════════════════════════════ */}
            {activeTab === "scans" && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Scan List */}
                    <div className="lg:col-span-1">
                        <Card title="Completed Scans">
                            {scansLoading ? (
                                <div className="text-center py-8 text-slate-500 text-sm">Loading…</div>
                            ) : scans.length === 0 ? (
                                <div className="text-center py-8 text-slate-500 text-sm">No completed scans yet.</div>
                            ) : (
                                <div className="space-y-2">
                                    {scans.map(scan => (
                                        <button
                                            key={scan.id}
                                            onClick={() => viewReport(scan.id)}
                                            className={`w-full text-left p-3 rounded-lg transition-colors text-sm border ${
                                                selectedScan?.id === scan.id
                                                    ? "bg-blue-500/15 border-blue-500/30"
                                                    : "bg-white/[0.04] hover:bg-blue-500/10 border-white/[0.06]"
                                            }`}
                                        >
                                            <div className="flex items-center justify-between">
                                                <span className="font-medium text-slate-200">
                                                    {scan.scan_type === "url" ? "🔗" : "📄"} {scan.scan_type.toUpperCase()}
                                                </span>
                                                <span className={`text-xs font-medium capitalize ${threatColor(scan.threat_level)}`}>
                                                    {scan.threat_level || "—"}
                                                </span>
                                            </div>
                                            <p className="text-xs text-slate-500 truncate mt-1 font-mono">{scan.target}</p>
                                            <p className="text-xs text-slate-500 mt-1">{new Date(scan.created_at).toLocaleDateString()}</p>
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
                                <div className="text-center py-12 text-slate-500">Loading report…</div>
                            ) : !selectedReport ? (
                                <div className="text-center py-12 text-slate-500">
                                    <p className="text-lg">📄</p>
                                    <p className="mt-2">Select a scan to view its report</p>
                                </div>
                            ) : (
                                <div className="space-y-4">
                                    <div className="flex justify-end relative">
                                        <button
                                            onClick={() => setDownloadMenuOpen(v => !v)}
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
                                                <button onClick={() => handleDownload("txt")} className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-white/[0.06] transition-colors">
                                                    <div className="w-8 h-8 rounded-lg bg-emerald-500/15 flex items-center justify-center flex-shrink-0">
                                                        <svg className="w-4 h-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                                                    </div>
                                                    <div><p className="text-sm font-medium text-slate-200">Text Report</p><p className="text-[10px] text-slate-500">.txt — human-readable</p></div>
                                                </button>
                                                <button onClick={() => handleDownload("json")} className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-white/[0.06] transition-colors border-t border-white/[0.04]">
                                                    <div className="w-8 h-8 rounded-lg bg-purple-500/15 flex items-center justify-center flex-shrink-0">
                                                        <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
                                                    </div>
                                                    <div><p className="text-sm font-medium text-slate-200">JSON Report</p><p className="text-[10px] text-slate-500">.json — machine-readable</p></div>
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
                                                        <span className={`font-medium capitalize ${threatColor(ind.threat_level)}`}>{ind.threat_level}</span>
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
            )}

            {/* ══ THREAT MODELS TAB ═════════════════════════════════ */}
            {activeTab === "threat-models" && (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* TM List */}
                    <div className="lg:col-span-1">
                        <Card title="Saved Analyses">
                            {tmLoading ? (
                                <div className="text-center py-8 text-slate-500 text-sm">Loading…</div>
                            ) : tmList.length === 0 ? (
                                <div className="text-center py-8 text-slate-500 text-sm">
                                    <p className="text-2xl mb-2">🛡</p>
                                    <p>No saved analyses yet.</p>
                                    <p className="text-xs mt-1 text-slate-600">Go to Threat Modeling and click Save Report.</p>
                                </div>
                            ) : (
                                <div className="space-y-2">
                                    {tmList.map(tm => (
                                        <button
                                            key={tm.id}
                                            onClick={() => viewTmDetail(tm.id)}
                                            className={`w-full text-left p-3 rounded-lg transition-colors text-sm border ${
                                                selectedTm?.id === tm.id
                                                    ? "bg-blue-500/15 border-blue-500/30"
                                                    : "bg-white/[0.04] hover:bg-blue-500/10 border-white/[0.06]"
                                            }`}
                                        >
                                            <div className="flex items-center justify-between">
                                                <span className="font-semibold text-slate-200 truncate mr-2">🛡 {tm.project_name}</span>
                                                <span className={`text-xs font-medium px-2 py-0.5 rounded-full border flex-shrink-0 ${riskBadge(tm.risk_label)}`}>
                                                    {tm.risk_label}
                                                </span>
                                            </div>
                                            <div className="flex items-center justify-between mt-1">
                                                <span className="text-xs text-slate-500">{tm.app_type} · {tm.threat_count} threats</span>
                                                <span className="text-xs text-slate-600 font-mono">Score: {tm.risk_score}</span>
                                            </div>
                                            <p className="text-xs text-slate-600 mt-1">{new Date(tm.created_at).toLocaleDateString()}</p>
                                        </button>
                                    ))}
                                </div>
                            )}
                        </Card>
                    </div>

                    {/* TM Detail */}
                    <div className="lg:col-span-2">
                        <Card title="Analysis Details">
                            {tmDetailLoading ? (
                                <div className="text-center py-12 text-slate-500">Loading…</div>
                            ) : !selectedTm ? (
                                <div className="text-center py-12 text-slate-500">
                                    <p className="text-2xl">🛡</p>
                                    <p className="mt-2">Select an analysis to view details</p>
                                </div>
                            ) : (
                                <div className="space-y-5">
                                    {/* Header + actions */}
                                    <div className="flex items-start justify-between gap-3 flex-wrap">
                                        <div>
                                            <h2 className="text-lg font-bold text-white">{selectedTm.project_name}</h2>
                                            <p className="text-sm text-slate-400 mt-0.5">
                                                {selectedTm.app_type} · {selectedTm.threats.length} threats · Saved {new Date(selectedTm.created_at).toLocaleDateString()}
                                            </p>
                                        </div>
                                        <div className="flex gap-2 flex-shrink-0">
                                            <button
                                                onClick={() => buildThreatModelPDF(selectedTm)}
                                                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-blue-500/15 text-blue-400 hover:bg-blue-500/25 border border-blue-500/20 text-sm font-medium transition-colors"
                                            >
                                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                                </svg>
                                                Download PDF
                                            </button>
                                            <button
                                                onClick={() => handleDeleteTm(selectedTm.id)}
                                                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 text-sm font-medium transition-colors"
                                            >
                                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                                </svg>
                                                Delete
                                            </button>
                                        </div>
                                    </div>

                                    {/* Risk Score bar */}
                                    <div className="bg-white/[0.04] rounded-xl p-4 border border-white/[0.06]">
                                        <div className="flex justify-between items-center mb-2">
                                            <span className="text-sm font-medium text-slate-300">Risk Score</span>
                                            <span className={`text-sm font-bold px-2 py-0.5 rounded-full border ${riskBadge(selectedTm.risk_label)}`}>
                                                {selectedTm.risk_label} — {selectedTm.risk_score}/100
                                            </span>
                                        </div>
                                        <div className="w-full bg-white/[0.06] rounded-full h-2.5">
                                            <div
                                                className={`h-2.5 rounded-full transition-all ${
                                                    selectedTm.risk_label === "Critical" ? "bg-red-600" :
                                                    selectedTm.risk_label === "High"     ? "bg-red-500" :
                                                    selectedTm.risk_label === "Medium"   ? "bg-orange-400" : "bg-green-500"
                                                }`}
                                                style={{ width: `${selectedTm.risk_score}%` }}
                                            />
                                        </div>
                                    </div>

                                    {/* Threat list */}
                                    <div>
                                        <h3 className="text-sm font-semibold text-slate-300 mb-3">Identified Threats</h3>
                                        <div className="space-y-3">
                                            {selectedTm.threats.map(t => (
                                                <div key={t.id} className={`p-3 rounded-lg border border-white/[0.06] bg-white/[0.03] border-l-2 ${
                                                    t.risk === "High" ? "border-l-red-500" : t.risk === "Medium" ? "border-l-orange-400" : "border-l-yellow-400"
                                                }`}>
                                                    <div className="flex items-center justify-between mb-1">
                                                        <span className="text-sm font-semibold text-white">{t.title}</span>
                                                        <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${
                                                            t.risk === "High" ? "bg-red-500/15 text-red-400 border-red-500/30" :
                                                            t.risk === "Medium" ? "bg-orange-500/15 text-orange-400 border-orange-500/30" :
                                                            "bg-yellow-500/15 text-yellow-400 border-yellow-500/30"
                                                        }`}>{t.risk}</span>
                                                    </div>
                                                    <p className="text-xs text-slate-500 mb-2 uppercase tracking-wide font-medium">{t.category}</p>
                                                    <p className="text-xs text-slate-400 leading-relaxed mb-2">{t.description}</p>
                                                    <div className="bg-green-500/5 border border-green-500/15 rounded-lg p-2">
                                                        <p className="text-xs text-green-400 leading-relaxed">
                                                            <span className="font-semibold">✅ Mitigation: </span>{t.mitigation}
                                                        </p>
                                                    </div>
>>>>>>> b4a826d (edit threat modeling)
                                                </div>
                                            ))}
                                        </div>
                                    </div>
<<<<<<< HEAD
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
=======
                                </div>
                            )}
                        </Card>
                    </div>
                </div>
            )}
>>>>>>> b4a826d (edit threat modeling)
        </div>
    );
}
