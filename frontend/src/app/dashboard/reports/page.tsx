"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card } from "@/components/ui";
import {
  Shield,
  Search,
  ArrowRight,
  Play,
  Database,
  ServerCrash,
  Clock,
  Sparkles,
  Code,
  Globe,
  Cookie,
  Sliders,
  FolderOpen,
  Lock,
  Terminal,
  Activity,
  FileText,
  FileJson,
  ArrowUpRight,
  ShieldAlert,
  Cpu,
  ExternalLink,
  RefreshCw,
  Download
} from "lucide-react";

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

interface ThreatModelItem {
  id: string;
  project_name: string;
  app_type: string;
  risk_score: number;
  risk_label: string;
  threat_count: number;
  mitigation_count?: number;
  created_at: string;
}

interface InvestigationItem {
  id: string;
  scan_id: string;
  target: string;
  status: string;
  risk_score: number;
  current_stage: string;
  started_at: string;
  completed_at: string | null;
}

interface PentestHistoryItem {
  id: string;
  target: string;
  summary?: {
    detected_technologies?: any[];
    detected_assets?: any[];
    findings?: any[];
  };
  created_at: string;
}

// ─── Download helpers ──────────────────────────────────────────────────────────

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
  const divider = "=".repeat(60);
  const thinDiv = "-".repeat(60);
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
      lines.push(`  ${"-".repeat(20)} ${"-".repeat(12)} ${"-".repeat(24)}`);
      for (const eng of engines) {
        const name = String(eng.label || eng.engine).padEnd(20);
        const isMal = eng.malware as boolean;
        const stat = (isMal ? "DETECTED" : eng.error ? "ERROR" : "Clean").padEnd(12);
        const res = isMal ? String(eng.result || "Malware") : (eng.error ? String(eng.error) : "-");
        lines.push(`  ${name} ${stat} ${res}`);
      }
    }
    lines.push("");
  }

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
  return JSON.stringify(
    {
      meta: {
        generator: "TIBSA Platform",
        generated_at: new Date().toISOString(),
        report_id: report.id
      },
      scan: {
        id: scan.id,
        type: scan.scan_type,
        target: scan.target,
        status: scan.status,
        threat_level: scan.threat_level,
        created_at: scan.created_at,
        completed_at: scan.completed_at
      },
      report: {
        summary: report.summary,
        details: report.details,
        indicators: report.indicators
      }
    },
    null,
    2
  );
}

export default function ReportsHistoryPage() {
  const router = useRouter();
  const { token } = useAuth();

  // Multi-service action lists
  const [investigations, setInvestigations] = useState<InvestigationItem[]>([]);
  const [pentestScans, setPentestScans] = useState<PentestHistoryItem[]>([]);
  const [threatScans, setThreatScans] = useState<Scan[]>([]);
  const [threatModels, setThreatModels] = useState<ThreatModelItem[]>([]);

  // Selection states
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [selectedReport, setSelectedReport] = useState<ScanReport | null>(null);
  const [selectedThreatModel, setSelectedThreatModel] = useState<ThreatModelItem | null>(null);

  // Status indicators
  const [isLoading, setIsLoading] = useState(true);
  const [reportLoading, setReportLoading] = useState(false);
  const [downloadMenuOpen, setDownloadMenuOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"investigations" | "pentest" | "threat-scans" | "threat-models">("investigations");

  const fetchReports = useCallback(async () => {
    if (!token) {
      setIsLoading(false);
      return;
    }
    try {
      setIsLoading(true);

      // 1. Fetch Ingestion Investigations
      let invList: InvestigationItem[] = [];
      try {
        const response = await api.get<{ success: boolean; data: InvestigationItem[] }>("/api/v1/investigations/", token);
        if (response && response.success && response.data) {
          invList = response.data;
        }
      } catch (err) {
        console.warn("Failed to load Ingestion Investigations history:", err);
      }

      // 2. Fetch Penetration Testing (Website scanner)
      let penList: PentestHistoryItem[] = [];
      try {
        const data = await api.get<PentestHistoryItem[]>("/api/v1/website-scanner/history", token);
        penList = data || [];
      } catch (err) {
        console.warn("Failed to load Penetration Testing history:", err);
      }

      // 3. Fetch Threat Intelligence scans
      let scansList: Scan[] = [];
      try {
        const data = await api.get<Scan[]>("/api/v1/scans/", token);
        scansList = (data || []).filter((s) => s.status === "completed");
      } catch (err) {
        console.warn("Failed to load Threat scans:", err);
      }

      // 4. Fetch Threat Modeling
      let modelList: ThreatModelItem[] = [];
      try {
        const data = await api.get<ThreatModelItem[]>("/api/v1/threat-modeling/analyses", token);
        modelList = data || [];
      } catch (err) {
        console.warn("Failed to load Threat Models:", err);
      }

      setInvestigations(invList);
      setPentestScans(penList);
      setThreatScans(scansList);
      setThreatModels(modelList);
    } catch (err) {
      console.error("Unified Reports retrieval error:", err);
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  // Load and route to Penetration Testing review dashboard
  const handleViewPentestReview = async (scanId: string) => {
    if (!token) return;
    try {
      setReportLoading(true);
      const data = await api.get<any>(`/api/v1/website-scanner/history/${scanId}`, token);
      
      // Cache payload in localStorage so client review page loads it instantly
      localStorage.setItem(
        "tibsa_scanner_json",
        JSON.stringify({
          scan_id: data.id || scanId,
          target: { url: data.target },
          detected_technologies: data.detected_technologies || [],
          detected_assets: data.detected_assets || [],
          findings: data.findings || data.scanner_json?.findings || [],
          ...data
        })
      );
      router.push("/dashboard/website-scanner/review");
    } catch (err) {
      console.error("Failed loading pentest review details:", err);
      alert("Failed loading details for website penetration test.");
    } finally {
      setReportLoading(false);
    }
  };

  const viewThreatReport = async (scanId: string) => {
    if (!token) return;
    setReportLoading(true);
    setDownloadMenuOpen(false);
    const scan = threatScans.find((s) => s.id === scanId) || null;
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

  const handleDownloadThreatReport = (format: "txt" | "json") => {
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

  // Heuristic color helpers
  const threatColor = (level: string | null) => {
    const colors: Record<string, string> = {
      safe: "text-green-400 border-green-500/20 bg-green-500/10",
      low: "text-yellow-400 border-yellow-500/20 bg-yellow-500/10",
      medium: "text-orange-400 border-orange-500/20 bg-orange-500/10",
      high: "text-red-400 border-red-500/20 bg-red-500/10",
      critical: "text-red-500 border-red-600/20 bg-red-600/10"
    };
    return colors[level || "safe"] || "text-[var(--text-muted)] border-[var(--border-strong)] bg-[var(--bg-elevated)]";
  };

  const getStatusBadge = (status: string) => {
    const common = "px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border tracking-wider";
    switch (status) {
      case "completed":
        return <span className={`${common} border-emerald-500/20 bg-emerald-500/10 text-emerald-400`}>Completed</span>;
      case "failed":
        return <span className={`${common} border-red-500/20 bg-red-500/10 text-red-400`}>Failed</span>;
      case "pending":
      case "created":
        return <span className={`${common} border-[var(--border-strong)] bg-[var(--bg-elevated)] text-[var(--text-muted)]`}>Pending</span>;
      default:
        return <span className={`${common} border-[var(--primary)] bg-[var(--primary)]/10 text-[var(--primary)] animate-pulse`}>{status || "Running"}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Service Selector Header */}
      <div 
        style={{
          background: "linear-gradient(90deg, rgba(230,226,220,0.95) 0%, rgba(156,158,160,0.75) 55%, #0f172a 100%)"
        }}
        className="border border-[var(--border-soft)] p-[32px] rounded-[20px] shadow-xl relative overflow-hidden animate-[cardFadeIn_300ms_ease-out_forwards] motion-reduce:animate-none"
      >
        <div className="flex items-center gap-2 mb-2">
          <Clock className="w-4 h-4 text-[#0f9d76]" />
          <span className="text-[10px] font-bold text-[#0f9d76] uppercase tracking-widest">
            Platform History Logs
          </span>
        </div>
        <h1 className="text-2xl font-black text-[#1d1d1d] tracking-tight">Reports History</h1>
        <p className="text-[#4f4a45] mt-1 max-w-xl text-sm leading-relaxed font-medium">
          Review generated security reports, scan summaries, risk scores, investigation history, and previous analysis results in one organized place.
        </p>

        {/* Tab Controls */}
        <div className="flex border-b border-[var(--border-soft)] overflow-x-auto whitespace-nowrap scrollbar-none gap-2 mt-6">
          {[
            { key: "investigations", label: "Security Investigations", count: investigations.length, icon: Shield },
            { key: "pentest", label: "Penetration Testing", count: pentestScans.length, icon: Globe },
            { key: "threat-scans", label: "Threat Scans", count: threatScans.length, icon: ShieldAlert },
            { key: "threat-models", label: "Threat Models", count: threatModels.length, icon: Sliders }
          ].map((tab) => {
            const active = activeTab === tab.key;
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                onClick={() => {
                  setActiveTab(tab.key as any);
                  setSelectedScan(null);
                  setSelectedReport(null);
                  setSelectedThreatModel(null);
                }}
                className={`py-3 px-4 text-xs font-bold uppercase tracking-wider border-b-2 transition-all duration-180 cursor-pointer flex items-center gap-2 hover:-translate-y-[1px] active:scale-[0.97] focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 motion-reduce:transition-colors motion-reduce:hover:transform-none ${
                  active
                    ? "border-[#0f9d76] text-[#0f9d76]"
                    : "border-transparent text-[#4f4a45] hover:text-[#0f9d76] hover:bg-[#edf8f3] rounded-t-lg"
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {tab.label}
                <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                  active ? "bg-[#0f9d76]/15 text-[#0f9d76] font-black" : "bg-[#fffaf4] text-[#4f4a45] border border-[#e7ddd1]"
                }`}>
                  {tab.count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {isLoading ? (
        <div className="py-24 text-center text-[var(--text-muted)] font-medium">
          <span className="inline-block animate-spin mr-2 h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full" />
          Loading reports history...
        </div>
      ) : (
        <div className="space-y-4">
          {/* TAB 1: Investigations */}
          {activeTab === "investigations" && (
            <Card title="Security Investigations Logs" description="Audit log of Ingestion scans running across endpoints">
              {investigations.length === 0 ? (
                <div className="py-12 text-center text-[var(--text-muted)] text-sm">
                  No pipeline investigations found in history.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b border-[var(--border-strong)] text-[var(--text-muted)] font-semibold bg-[var(--bg-card)]/10">
                        <th className="py-3 px-4">Scan ID / Ingestion</th>
                        <th className="py-3 px-4">Target</th>
                        <th className="py-3 px-4">Risk Score</th>
                        <th className="py-3 px-4">Active Stage</th>
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Date Started</th>
                        <th className="py-3 px-4"></th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/[0.04]">
                      {investigations.map((inv) => (
                        <tr
                          key={inv.id}
                          onClick={() => router.push(`/dashboard/investigations/${inv.id}`)}
                          className="bg-[#ffffff] hover:bg-[#edf8f3] cursor-pointer transition-all duration-180 group focus-within:ring-2 focus-within:ring-[#0f9d76]/35 outline-none"
                          tabIndex={0}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              router.push(`/dashboard/investigations/${inv.id}`);
                            }
                          }}
                        >
                          <td className="py-4 px-4 font-mono text-xs font-semibold text-[var(--text-secondary)]">
                            <div>{inv.scan_id || "SCAN-INF"}</div>
                            <div className="text-[10px] text-[var(--text-muted)] uppercase mt-0.5 font-sans">
                              ID: {inv.id.substring(0, 8)}
                            </div>
                          </td>
                          <td className="py-4 px-4 text-[var(--text-primary)] font-medium truncate max-w-[200px]">
                            {inv.target}
                          </td>
                          <td className="py-4 px-4">
                            <span className={`font-bold font-mono text-xs ${
                              inv.status === "failed" ? "text-[var(--text-muted)]" :
                              inv.risk_score > 60 ? "text-red-400" :
                              inv.risk_score > 30 ? "text-orange-400" : "text-emerald-400"
                            }`}>
                              {inv.status === "failed" ? "—" : Math.round(inv.risk_score)}
                            </span>
                          </td>
                          <td className="py-4 px-4 text-xs text-[var(--text-muted)] font-medium">
                            {inv.current_stage || "Queued"}
                          </td>
                          <td className="py-4 px-4">{getStatusBadge(inv.status)}</td>
                          <td className="py-4 px-4 text-xs text-[var(--text-muted)]">
                            {new Date(inv.started_at).toLocaleDateString()}
                          </td>
                          <td className="py-4 px-4 text-right">
                            <ArrowRight className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--primary)] group-hover:translate-x-1 transition-all" />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          )}

          {/* TAB 2: Penetration Testing */}
          {activeTab === "pentest" && (
            <Card title="Penetration Testing Logs" description="Logs of technological fingerprints, vulnerability scans, and endpoint maps">
              {pentestScans.length === 0 ? (
                <div className="py-12 text-center text-[var(--text-muted)] text-sm">
                  No penetration testing runs found in history.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b border-[var(--border-strong)] text-[var(--text-muted)] font-semibold bg-[var(--bg-card)]/10">
                        <th className="py-3 px-4">Scan Target</th>
                        <th className="py-3 px-4">Technologies</th>
                        <th className="py-3 px-4">Assets Logged</th>
                        <th className="py-3 px-4">Vulnerability Findings</th>
                        <th className="py-3 px-4">Scan Date</th>
                        <th className="py-3 px-4"></th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/[0.04]">
                      {pentestScans.map((pt) => {
                        const techsCount = pt.summary?.detected_technologies?.length || 0;
                        const assetsCount = pt.summary?.detected_assets?.length || 0;
                        const findingsCount = pt.summary?.findings?.length || 0;

                        return (
                          <tr
                            key={pt.id}
                            onClick={() => handleViewPentestReview(pt.id)}
                            className="bg-[#ffffff] hover:bg-[#edf8f3] cursor-pointer transition-all duration-180 group focus-within:ring-2 focus-within:ring-[#0f9d76]/35 outline-none"
                            tabIndex={0}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                handleViewPentestReview(pt.id);
                              }
                            }}
                          >
                            <td className="py-4 px-4 text-[var(--text-primary)] font-semibold">
                              <div className="flex items-center gap-1.5">
                                <Globe className="w-3.5 h-3.5 text-[var(--primary)]/70" />
                                {pt.target}
                              </div>
                              <div className="text-[10px] text-[var(--text-muted)] mt-0.5 font-mono select-all">
                                ID: {pt.id}
                              </div>
                            </td>
                            <td className="py-4 px-4 text-[var(--text-secondary)] text-xs">
                              {techsCount} service{techsCount !== 1 ? "s" : ""}
                            </td>
                            <td className="py-4 px-4 text-[var(--text-secondary)] text-xs">
                              {assetsCount} asset{assetsCount !== 1 ? "s" : ""}
                            </td>
                            <td className="py-4 px-4">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                findingsCount > 0 ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              }`}>
                                {findingsCount} finding{findingsCount !== 1 ? "s" : ""}
                              </span>
                            </td>
                            <td className="py-4 px-4 text-xs text-[var(--text-muted)]">
                              {new Date(pt.created_at).toLocaleString()}
                            </td>
                            <td className="py-4 px-4 text-right">
                              <div className="flex items-center justify-end gap-1.5 text-[var(--text-muted)] group-hover:text-[var(--primary)] transition-colors">
                                <span className="text-[10px] uppercase font-bold tracking-wider">Review</span>
                                <ArrowUpRight className="w-3.5 h-3.5" />
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          )}

          {/* TAB 3: Threat Intelligence Scans */}
          {activeTab === "threat-scans" && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Scan List */}
              <div className="lg:col-span-1">
                <Card title="Completed Threat Scans">
                  {threatScans.length === 0 ? (
                    <div className="text-center py-8 text-[var(--text-muted)] text-sm">
                      No completed threat scans yet.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {threatScans.map((scan) => (
                        <button
                          key={scan.id}
                          onClick={() => viewThreatReport(scan.id)}
                          className={`w-full text-left p-3 rounded-xl border transition-all duration-180 text-sm select-none focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 motion-reduce:transition-colors motion-reduce:hover:transform-none hover:-translate-y-[1px] active:scale-[0.97] hover:shadow-sm ${
                            selectedScan?.id === scan.id
                              ? "bg-[#edf8f3] border-[#0f9d76] text-[#1d1d1d]"
                              : "bg-[#ffffff] border-[#e7ddd1] hover:bg-[#edf8f3] hover:border-[#0f9d76]"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-[#1d1d1d] flex items-center gap-1.5">
                              {scan.scan_type === "url" ? <Globe className="w-3.5 h-3.5 text-[#4f4a45]" /> : <FileText className="w-3.5 h-3.5 text-[#4f4a45]" />}
                              {scan.scan_type.toUpperCase()}
                            </span>
                            <span className={`text-[10px] px-2 py-0.5 rounded border uppercase font-bold tracking-wider ${threatColor(scan.threat_level)}`}>
                              {scan.threat_level || "Clean"}
                            </span>
                          </div>
                          <p className="text-xs text-[#4f4a45] truncate mt-2 font-mono">
                            {scan.target}
                          </p>
                          <p className="text-[10px] text-[#4f4a45] mt-1 font-medium">
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
                <Card title="Analysis Details">
                  {reportLoading ? (
                    <div className="text-center py-12 text-[var(--text-muted)] flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[var(--primary)]" />
                      Loading report data...
                    </div>
                  ) : !selectedReport ? (
                    <div className="text-center py-16 text-[var(--text-muted)]">
                      <FileText className="w-10 h-10 mx-auto mb-3 opacity-20" />
                      <p className="font-semibold">Select a scan to inspect its findings</p>
                      <p className="text-xs text-[var(--text-muted)] mt-1">Review detections, reputations, and compromise indicators</p>
                    </div>
                  ) : (
                    <div className="space-y-6">
                      {/* Download button */}
                      <div className="flex justify-between items-center relative border-b border-[var(--border-strong)] pb-4">
                        <div className="flex flex-col items-start">
                          <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">Report Identifier</span>
                          <span className="font-mono text-xs text-[var(--text-secondary)] mt-0.5 select-all">{selectedReport.id}</span>
                        </div>
                        <div className="relative">
                          <button
                            onClick={() => setDownloadMenuOpen((v) => !v)}
                            className="btn-animated btn-primary-emerald inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg shadow-sm transition-all duration-180 text-xs font-bold focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 hover:-translate-y-[1px] active:scale-[0.97] motion-reduce:transition-colors motion-reduce:hover:transform-none"
                          >
                            <Download className="w-3.5 h-3.5" />
                            Download Report
                            <ArrowRight className={`w-3 h-3 transition-transform ${downloadMenuOpen ? "rotate-90" : ""}`} />
                          </button>
                          {downloadMenuOpen && (
                            <div className="absolute right-0 top-full mt-2 w-52 rounded-xl bg-[#ffffff] border border-[#e7ddd1] shadow-xl overflow-hidden z-10">
                              <button
                                onClick={() => handleDownloadThreatReport("txt")}
                                className="w-full text-left px-4 py-3 flex items-center gap-3 bg-[#ffffff] hover:bg-[#edf8f3] transition-all duration-180 focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 active:scale-[0.99]"
                              >
                                <div className="w-8 h-8 rounded-lg bg-emerald-500/15 flex items-center justify-center flex-shrink-0">
                                  <FileText className="w-4 h-4 text-emerald-400" />
                                </div>
                                <div>
                                  <p className="text-xs font-bold text-[#1d1d1d]">Text Report</p>
                                  <p className="text-[9px] text-[#4f4a45]">.txt — Human readable</p>
                                </div>
                              </button>
                              <button
                                onClick={() => handleDownloadThreatReport("json")}
                                className="w-full text-left px-4 py-3 flex items-center gap-3 bg-[#ffffff] hover:bg-[#edf8f3] transition-all duration-180 border-t border-[#e7ddd1] focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 active:scale-[0.99]"
                              >
                                <div className="w-8 h-8 rounded-lg bg-[var(--primary-soft)] flex items-center justify-center flex-shrink-0">
                                  <FileJson className="w-4 h-4 text-[var(--primary)]" />
                                </div>
                                <div>
                                  <p className="text-xs font-bold text-[#1d1d1d]">JSON Report</p>
                                  <p className="text-[9px] text-[#4f4a45]">.json — Machine parsed</p>
                                </div>
                              </button>
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <h3 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-widest">Executive Summary</h3>
                        <p className="text-sm text-[var(--text-secondary)] leading-relaxed bg-[var(--bg-page)]/25 p-3 rounded-xl border border-[var(--border-soft)]">
                          {selectedReport.summary}
                        </p>
                      </div>

                      {selectedReport.indicators?.length > 0 && (
                        <div className="space-y-2">
                          <h3 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-widest">Indicators Found</h3>
                          <div className="space-y-2 max-h-[160px] overflow-y-auto pr-1">
                            {selectedReport.indicators.map((ind, i) => (
                              <div key={i} className="flex items-center justify-between bg-[var(--bg-page)]/20 p-2.5 rounded-lg text-xs border border-[var(--border-soft)]">
                                <div>
                                  <span className="text-[9px] text-[var(--text-muted)] uppercase font-bold tracking-wider">{ind.type}</span>
                                  <p className="font-mono text-[var(--text-primary)] mt-0.5">{ind.value}</p>
                                </div>
                                <span className={`text-[9px] px-2 py-0.5 rounded border uppercase font-bold tracking-wider ${threatColor(ind.threat_level)}`}>
                                  {ind.threat_level}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {selectedReport.details && Object.keys(selectedReport.details).length > 0 && (
                        <div className="space-y-2">
                          <h3 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-widest">Metadata Payload</h3>
                          <pre className="bg-[#0b0f19] p-3 rounded-xl text-[10px] text-[var(--text-muted)] overflow-x-auto border border-[var(--border-soft)] max-h-48 font-mono">
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

          {/* TAB 4: Threat Models */}
          {activeTab === "threat-models" && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Threat Model List */}
              <div className="lg:col-span-1">
                <Card title="Saved Threat Models">
                  {threatModels.length === 0 ? (
                    <div className="text-center py-8 text-[var(--text-muted)] text-sm">
                      No threat models saved yet.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {threatModels.map((model) => (
                        <button
                          key={model.id}
                          onClick={() => setSelectedThreatModel(model)}
                          className={`w-full text-left p-3 rounded-xl border transition-all duration-180 text-sm select-none focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 motion-reduce:transition-colors motion-reduce:hover:transform-none hover:-translate-y-[1px] active:scale-[0.97] hover:shadow-sm ${
                            selectedThreatModel?.id === model.id
                              ? "bg-[#edf8f3] border-[#0f9d76] text-[#1d1d1d]"
                              : "bg-[#ffffff] border-[#e7ddd1] hover:bg-[#edf8f3] hover:border-[#0f9d76]"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-[#1d1d1d]">
                              {model.project_name}
                            </span>
                            <span className={`text-[9px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider ${
                              model.risk_label === "Critical" ? "bg-red-50 text-red-600 border border-red-200" :
                              model.risk_label === "High" ? "bg-red-50 text-red-600 border border-red-200" :
                              model.risk_label === "Medium" ? "bg-orange-50 text-orange-600 border border-orange-200" :
                              "bg-green-50 text-green-600 border border-green-200"
                            }`}>
                              {model.risk_label}
                            </span>
                          </div>
                          <p className="text-xs text-[#4f4a45] mt-2 font-medium">
                            {model.app_type} • {model.threat_count} threat{model.threat_count !== 1 ? "s" : ""}
                          </p>
                          <p className="text-[10px] text-[#4f4a45] mt-1 font-medium">
                            {new Date(model.created_at).toLocaleDateString()}
                          </p>
                        </button>
                      ))}
                    </div>
                  )}
                </Card>
              </div>

              {/* Threat Model Detail */}
              <div className="lg:col-span-2">
                <Card title="Analysis Details">
                  {!selectedThreatModel ? (
                    <div className="text-center py-16 text-[var(--text-muted)]">
                      <Sliders className="w-10 h-10 mx-auto mb-3 opacity-20" />
                      <p className="font-semibold">Select a threat model to inspect its parameters</p>
                      <p className="text-xs text-[var(--text-muted)] mt-1">Review vulnerability counts, criticality ratings, and properties</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div>
                        <h3 className="text-base font-black text-[var(--text-primary)]">{selectedThreatModel.project_name}</h3>
                        <p className="text-xs text-[var(--text-muted)] mt-1">Application Paradigm: {selectedThreatModel.app_type}</p>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-3 mt-4">
                        <div className="rounded-xl bg-[var(--bg-page)]/20 border border-[var(--border-soft)] p-3.5">
                          <p className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">Aggregate Risk Score</p>
                          <p className="text-2xl font-black text-[var(--text-primary)] mt-1.5">{selectedThreatModel.risk_score}</p>
                        </div>
                        <div className="rounded-xl bg-[var(--bg-page)]/20 border border-[var(--border-soft)] p-3.5">
                          <p className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">Normalized Risk Level</p>
                          <p className={`text-base font-extrabold mt-2 uppercase tracking-wide ${
                            selectedThreatModel.risk_label === "Critical" || selectedThreatModel.risk_label === "High" ? "text-red-400" :
                            selectedThreatModel.risk_label === "Medium" ? "text-orange-400" : "text-yellow-400"
                          }`}>{selectedThreatModel.risk_label}</p>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div className="rounded-xl bg-[var(--bg-page)]/20 border border-[var(--border-soft)] p-3.5">
                          <p className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">Threats Identified</p>
                          <p className="text-2xl font-black text-[var(--text-primary)] mt-1.5">{selectedThreatModel.threat_count}</p>
                        </div>
                        <div className="rounded-xl bg-[var(--bg-page)]/20 border border-[var(--border-soft)] p-3.5">
                          <p className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">Date Compiled</p>
                          <p className="text-xs text-[var(--text-secondary)] font-medium mt-3.5">
                            {new Date(selectedThreatModel.created_at).toLocaleString()}
                          </p>
                        </div>
                      </div>

                      <div className="border-t border-[var(--border-strong)] pt-4 flex justify-end">
                        <button
                          onClick={() => router.push(`/dashboard/threat-modeling`)}
                          className="btn-animated flex items-center gap-1.5 text-xs font-bold transition-all duration-180 cursor-pointer bg-[#ffffff] border border-[#e7ddd1] text-[#0f9d76] hover:bg-[#edf8f3] hover:border-[#0f9d76] px-4 py-2 rounded-xl shadow-sm hover:-translate-y-[1px] active:scale-[0.97] focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 motion-reduce:transition-colors motion-reduce:hover:transform-none"
                        >
                          Launch Threat Modeler <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  )}
                </Card>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
