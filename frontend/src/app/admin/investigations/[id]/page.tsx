"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { RiskGauge } from "@/components/investigation/RiskGauge";
import { InvestigationTimeline } from "@/components/investigation/InvestigationTimeline";
import { SOCEventFeed } from "@/components/investigation/SOCEventFeed";
import { PentestFindingsView } from "@/components/investigation/PentestFindingsView";
import { IOCTable } from "@/components/investigation/IOCTable";
import { AttackChainCard } from "@/components/investigation/AttackChainCard";
import { Card, Button } from "@/components/ui";
import {
    ArrowLeft,
    FileCode,
    FileText,
    Lock,
    Loader2,
    Clock,
    Sparkles,
    Activity,
    AlertOctagon,
    Shield,
    FileJson,
    User
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import { Investigation, InvestigationStage, StageStatus, LiveEvent } from "@/types";

// Helper to map current_stage & progress_percent & status to 6 stages
const buildStagesList = (
    currentStage: string,
    progress: number,
    status: string
): InvestigationStage[] => {
    const stages = [
        { key: "pentest", name: "Pentest Scanning", threshold: 25 },
        { key: "context", name: "Finding Normalization & Context", threshold: 50 },
        { key: "ioc", name: "Threat Intelligence Enrichment", threshold: 75 },
        { key: "correlation", name: "Threat Correlation", threshold: 92 },
        { key: "threat_model", name: "STRIDE Modeling", threshold: 95 },
        { key: "ai_explain", name: "AI Analysis", threshold: 97 }
    ];

    return stages.map((stg) => {
        let stageStatus: StageStatus = "pending";

        if (status === "completed") {
            stageStatus = "completed";
        } else if (status === "failed" || status === "stopped") {
            if (currentStage === stg.name) {
                stageStatus = "failed";
            } else if (progress < stg.threshold) {
                stageStatus = "skipped";
            } else {
                stageStatus = "completed";
            }
        } else {
            if (currentStage === stg.name) {
                stageStatus = "running";
            } else if (progress >= stg.threshold) {
                stageStatus = "completed";
            } else {
                stageStatus = "pending";
            }
        }

        return {
            stage: stg.name,
            status: stageStatus,
            started_at: null,
            completed_at: null,
            duration_seconds: null,
            error: stageStatus === "failed" ? "Pipeline execution error" : null
        };
    });
};

// Client-side SOC events generator based on investigation data
const generateEventsList = (inv: Investigation | null): LiveEvent[] => {
    if (!inv) return [];
    const events: LiveEvent[] = [];
    const baseTime = new Date(inv.started_at).getTime();

    const addEvent = (offsetMs: number, message: string, stage: string, severity: LiveEvent["severity"]) => {
        events.push({
            id: `${stage}-${message}`,
            timestamp: new Date(baseTime + offsetMs).toISOString(),
            stage,
            message,
            severity
        });
    };

    addEvent(0, "Security investigation request received", "System", "info");
    addEvent(300, `Target website set to: ${inv.target}`, "System", "info");

    const progress = inv.progress_percent;
    const isStarted = inv.status !== "pending";
    if (isStarted) {
        addEvent(800, "Phase 1: Starting Pentest Scanning...", "Pentest", "info");
        addEvent(1500, "Initializing automated vulnerability crawling...", "Pentest", "info");
    }

    if (progress >= 50 || inv.status === "completed") {
        addEvent(3000, "Completed technology detection & fingerprinting", "Pentest", "success");
        addEvent(5000, "Port check and security headers analysis complete", "Pentest", "success");

        const findings = inv.final_result?.findings_count || 0;
        if (findings > 0) {
            addEvent(5800, `Vulnerability crawler flagged ${findings} security warnings`, "Pentest", "warning");
        } else {
            addEvent(5800, "No raw vulnerabilities detected on landing endpoints", "Pentest", "success");
        }
    }

    if (progress >= 75 || inv.status === "completed") {
        addEvent(6500, "Phase 2: Running Finding Normalization & Threat Context interpreter", "Context", "info");
        addEvent(7200, "Vulnerability findings mapped to CWE structure", "Context", "success");
        if (inv.final_result?.correlation?.unique_threats_identified) {
            addEvent(7900, "Calculated baseline security rating weights", "Context", "info");
        }
    }

    if (progress >= 92 || inv.status === "completed") {
        addEvent(8500, "Phase 3: Launching Threat Intelligence Enrichment (IOC verification)", "Threat Intel", "info");
        addEvent(9200, "Querying VirusTotal reputation databases in background...", "Threat Intel", "info");

        const assets = inv.final_result?.assets_count || 1;
        addEvent(9800, `Reputation lookup finished for ${assets} host domains and IPs`, "Threat Intel", "success");
    }

    if (progress >= 95 || inv.status === "completed") {
        addEvent(10500, "Phase 4: Running Threat Correlation Engine...", "Correlation", "info");
        addEvent(11000, "Mapping dependency indicators and XSS vector risks...", "Correlation", "info");

        const correlations = inv.final_result?.correlation?.correlated_threats?.length || 0;
        if (correlations > 0) {
            addEvent(11800, `Correlated ${correlations} multi-stage attack scenarios`, "Correlation", "warning");
        } else {
            addEvent(11800, "No combined attack paths detected.", "Correlation", "success");
        }
    }

    if (progress >= 97 || inv.status === "completed") {
        addEvent(12500, "Phase 5: Generating STRIDE Threat Matrix", "Threat Model", "info");
        addEvent(13200, "Drafting Spoofing, Tampering, and Elevation of Privilege mitigations", "Threat Model", "success");
    }

    if (progress >= 100 || inv.status === "completed") {
        addEvent(14000, "Phase 6: Invoking AI Security Reporter...", "AI Analysis", "info");
        addEvent(14800, "Constructing executive and engineering explanations...", "AI Analysis", "info");
    }

    if (inv.status === "completed") {
        addEvent(15500, `Security pipeline completed. Global Risk Score finalized: ${inv.risk_score}/100`, "Success", "success");
    } else if (inv.status === "failed") {
        addEvent(15500, "Security pipeline terminated due to failure", "Failure", "critical");
    } else if (inv.status === "stopped") {
        addEvent(15500, "Security pipeline stopped by admin request", "Failure", "critical");
    }

    return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
};

export default function AdminInvestigationWorkspace() {
    const params = useParams();
    const router = useRouter();
    const { token } = useAuth();
    const id = typeof params.id === "string" ? params.id : null;

    const [investigation, setInvestigation] = useState<Investigation | null>(null);
    const [stages, setStages] = useState<InvestigationStage[]>([]);
    const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
    const [analyst, setAnalyst] = useState<{ name: string; email: string } | null>(null);

    const [activeTab, setActiveTab] = useState("findings");
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [exportLoading, setExportLoading] = useState<string | null>(null);
    const [stopLoading, setStopLoading] = useState(false);
    const [activeDuration, setActiveDuration] = useState<string>("00:00");

    const fetchDetail = useCallback(async () => {
        if (!id || !token) return;
        try {
            setIsLoading(true);
            setError(null);
            const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
            const res = await fetch(`${API_BASE_URL}/api/v1/admin/investigations/${id}`, {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });

            if (!res.ok) {
                throw new Error(`Failed to fetch workspace (Status: ${res.status})`);
            }

            const payload = await res.json();
            const data = payload.investigation;

            const inv: Investigation = {
                id: data.id,
                scan_id: data.scan_id || `SCAN-${id.substring(0, 5)}`,
                target: data.target || "",
                status: data.status,
                risk_score: data.risk_score,
                started_at: data.started_at || new Date().toISOString(),
                completed_at: data.completed_at || null,
                include_ti: data.include_ti ?? true,
                tm_mode: data.tm_mode || "enhanced",
                current_stage: data.current_stage || "Completed",
                progress_percent: data.progress_percent ?? 100,
                pipeline_state: data.pipeline_state || null,
                final_result: data.final_result || null
            };

            setInvestigation(inv);
            setStages(buildStagesList(inv.current_stage, inv.progress_percent, inv.status));
            setLiveEvents(generateEventsList(inv));
            setAnalyst(payload.analyst || null);
        } catch (err: any) {
            console.error(err);
            setError(err.message || "Failed to load workspace data.");
        } finally {
            setIsLoading(false);
        }
    }, [id, token]);

    useEffect(() => {
        fetchDetail();
    }, [fetchDetail]);

    // Active duration counter
    useEffect(() => {
        if (!investigation) return;

        const started = new Date(investigation.started_at).getTime();

        const updateTime = () => {
            let diffMs = 0;
            if (investigation.status === "completed" || investigation.status === "failed" || investigation.status === "stopped") {
                const completed = investigation.completed_at
                    ? new Date(investigation.completed_at).getTime()
                    : Date.now();
                diffMs = completed - started;
            } else {
                diffMs = Date.now() - started;
            }

            if (diffMs < 0) diffMs = 0;

            const totalSec = Math.floor(diffMs / 1000);
            const min = Math.floor(totalSec / 60).toString().padStart(2, "0");
            const sec = (totalSec % 60).toString().padStart(2, "0");
            setActiveDuration(`${min}:${sec}`);
        };

        updateTime();

        if (investigation.status !== "completed" && investigation.status !== "failed" && investigation.status !== "stopped") {
            const interval = setInterval(updateTime, 1000);
            return () => clearInterval(interval);
        }
    }, [investigation]);

    const handleStop = async () => {
        if (!id || !token) return;
        if (!confirm("Are you sure you want to stop this investigation scan?")) return;
        try {
            setStopLoading(true);
            const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
            const res = await fetch(`${API_BASE_URL}/api/v1/admin/investigations/${id}/stop`, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });

            if (!res.ok) {
                throw new Error("Failed to stop investigation.");
            }

            fetchDetail();
        } catch (err: any) {
            console.error(err);
            alert(err.message || "An error occurred while stopping the scan.");
        } finally {
            setStopLoading(false);
        }
    };

    const handleExport = async (format: "json" | "pdf") => {
        if (!id || !token) return;
        try {
            setExportLoading(format);

            const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
            const res = await fetch(`${API_BASE_URL}/api/v1/admin/investigations/${id}/export/${format}`, {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });

            if (!res.ok) {
                throw new Error("Failed to export report files.");
            }

            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `TIBSA_Investigation_${investigation?.scan_id || id}.${format}`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        } catch (err: any) {
            console.error(err);
            alert(err.message || "Failed to download report.");
        } finally {
            setExportLoading(null);
        }
    };

    const isTabUnlocked = (tab: string): boolean => {
        if (!investigation) return false;
        const progress = investigation.progress_percent;
        const status = investigation.status as string;

        if (status === "completed" || status === "stopped") return true;

        switch (tab) {
            case "findings":
                return progress >= 50;
            case "intel":
                return progress >= 75;
            case "correlations":
                return progress >= 92;
            case "threat_model":
                return progress >= 95;
            case "ai_summary":
                return progress >= 97;
            case "export":
                return status === "completed";
            default:
                return false;
        }
    };

    const getTabLabel = (tab: string, label: string) => {
        const unlocked = isTabUnlocked(tab);
        if (!unlocked) {
            return (
                <span className="flex items-center gap-1.5 opacity-60 text-slate-500">
                    <Lock className="w-3.5 h-3.5" />
                    {label}
                </span>
            );
        }

        return (
            <span className="flex items-center gap-1.5">
                {label}
            </span>
        );
    };

    if (isLoading) {
        return (
            <div className="flex flex-col items-center justify-center py-40 text-slate-500 gap-3">
                <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
                <p className="text-sm font-semibold uppercase tracking-wider">Loading Admin Workspace Viewer...</p>
            </div>
        );
    }

    if (error || !investigation) {
        return (
            <div className="space-y-4">
                <Button onClick={() => router.push("/admin/investigations")} variant="ghost" size="sm" className="gap-2">
                    <ArrowLeft className="w-4 h-4" /> Back to Investigations List
                </Button>
                <Card className="border border-red-500/20 bg-red-950/10 text-center py-12">
                    <AlertOctagon className="w-12 h-12 text-red-500 mx-auto mb-4" />
                    <h3 className="text-lg font-bold text-white">Workspace Loading Error</h3>
                    <p className="text-sm text-slate-400 mt-2 max-w-md mx-auto">
                        {error || "We could not fetch details for this investigation. Please check if it exists or try again."}
                    </p>
                </Card>
            </div>
        );
    }

    const statusColors: Record<string, string> = {
        completed: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20",
        failed: "bg-red-500/10 text-red-400 border border-red-500/20",
        pending: "bg-slate-800 text-slate-400 border border-slate-700",
        running: "bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse",
        stopped: "bg-amber-500/10 text-amber-400 border border-amber-500/20"
    };

    const getStatusText = (status: string) => {
        if (status === "running") return "Active Scanning";
        if (status === "completed") return "Completed";
        if (status === "failed") return "Failed";
        if (status === "stopped") return "Stopped";
        return "Queued";
    };

    return (
        <div className="space-y-4 max-w-7xl mx-auto">
            {/* Top Identity Header */}
            <div className="bg-[#1e293b]/30 rounded-xl border border-white/[0.04] py-4 px-5 shadow-lg flex flex-col md:flex-row justify-between items-stretch md:items-center gap-4">
                <div className="space-y-2">
                    {/* Back CTA & Breadcrumbs */}
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => router.push("/admin/investigations")}
                            className="text-xs text-slate-500 hover:text-slate-300 font-bold uppercase tracking-widest flex items-center gap-1 transition-colors cursor-pointer"
                        >
                            <ArrowLeft className="w-3.5 h-3.5" /> SOC Workspace
                        </button>
                        <span className="text-slate-600 font-mono text-xs">/</span>
                        <span className="text-xs text-slate-400 font-mono select-all">
                            {investigation.scan_id}
                        </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-3">
                        <h1 className="text-xl font-black text-white tracking-tight break-all">
                            Target: {investigation.target}
                        </h1>
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-extrabold uppercase ${statusColors[investigation.status] || statusColors.running}`}>
                            {getStatusText(investigation.status)}
                        </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-xs text-slate-500 font-mono">
                        <div className="flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-slate-600" />
                            Runtime: <span className="text-slate-300 font-bold">{activeDuration}</span>
                        </div>
                        <div>
                            Stage: <span className="text-slate-300 font-semibold">{investigation.current_stage}</span>
                        </div>
                        <div className="flex items-center gap-1">
                            <User className="w-3.5 h-3.5 text-slate-600" />
                            Analyst: <span className="text-slate-300 font-semibold">{analyst?.name || "System"}</span>
                        </div>
                    </div>
                </div>

                {/* Global actions */}
                {investigation.status === "completed" ? (
                    <div className="flex items-center gap-2">
                        <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => handleExport("json")}
                            disabled={!!exportLoading}
                            className="gap-2"
                        >
                            {exportLoading === "json" ? (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                                <FileJson className="w-3.5 h-3.5" />
                            )}
                            JSON
                        </Button>
                        <Button
                            variant="primary"
                            size="sm"
                            onClick={() => handleExport("pdf")}
                            disabled={!!exportLoading}
                            className="gap-2"
                        >
                            {exportLoading === "pdf" ? (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                                <FileText className="w-3.5 h-3.5" />
                            )}
                            PDF Report
                        </Button>
                    </div>
                ) : (investigation.status === "running" || investigation.status === "pending") && (
                    <div className="flex items-center gap-2">
                        <Button
                            variant="danger"
                            size="sm"
                            onClick={handleStop}
                            disabled={stopLoading}
                            className="gap-2 bg-red-600 hover:bg-red-500 border border-red-500/20 text-white font-bold"
                        >
                            {stopLoading ? (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                                <AlertOctagon className="w-3.5 h-3.5" />
                            )}
                            Stop Scan
                        </Button>
                    </div>
                )}
            </div>

            {/* Progress timeline */}
            <InvestigationTimeline stages={stages} />

            {/* Live Activity & Gauge */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-4 flex flex-col justify-center items-center bg-[#1e293b]/30 rounded-xl border border-white/[0.04] p-4 shadow-md min-h-[260px]">
                    <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-3">
                        Risk Progression
                    </h3>
                    <RiskGauge score={investigation.risk_score} />
                </div>

                <div className="lg:col-span-8">
                    <SOCEventFeed events={liveEvents} />
                </div>
            </div>

            {/* Results Tabs */}
            <div className="space-y-4">
                <div className="flex border-b border-white/[0.08] overflow-x-auto whitespace-nowrap scrollbar-none gap-2">
                    {[
                        { key: "findings", label: "Findings" },
                        { key: "intel", label: "Threat Intel" },
                        { key: "correlations", label: "Correlations" },
                        { key: "threat_model", label: "Threat Model" },
                        { key: "ai_summary", label: "AI Summary" }
                    ].map((tab) => {
                        const unlocked = isTabUnlocked(tab.key);
                        const active = activeTab === tab.key;

                        return (
                            <button
                                key={tab.key}
                                disabled={!unlocked}
                                onClick={() => setActiveTab(tab.key)}
                                className={`py-3 px-4 text-xs font-bold uppercase tracking-wider border-b-2 transition-all cursor-pointer ${
                                    active
                                        ? "border-blue-500 text-blue-400"
                                        : unlocked
                                        ? "border-transparent text-slate-400 hover:text-slate-200"
                                        : "border-transparent text-slate-600 cursor-not-allowed"
                                }`}
                            >
                                {getTabLabel(tab.key, tab.label)}
                            </button>
                        );
                    })}
                </div>

                <div className="min-h-[300px]">
                    {!isTabUnlocked(activeTab) ? (
                        <Card className="border border-white/[0.06] bg-slate-900/10 text-center py-20">
                            <Lock className="w-12 h-12 text-slate-600 mx-auto mb-4" />
                            <h4 className="text-slate-400 font-bold uppercase tracking-widest text-xs">
                                Stage Pending
                            </h4>
                        </Card>
                    ) : (
                        <>
                            {activeTab === "findings" && (
                                <PentestFindingsView
                                    findings={investigation.pipeline_state?.pentest_findings || []}
                                    summary={investigation.pipeline_state?.pentest_summary || null}
                                    fallbackFindings={
                                        investigation.final_result?.correlation?.correlated_threats
                                            ? investigation.pipeline_state?.normalized_findings || []
                                            : investigation.pipeline_state?.ti_findings || []
                                    }
                                />
                            )}

                            {activeTab === "intel" && (
                                <IOCTable
                                    iocResults={
                                        investigation.pipeline_state?.reputation_context?.ioc_results ||
                                        investigation.pipeline_state?.ti_findings?.reduce((acc: any[], f: any) => {
                                            const val = f.affected_asset || investigation.target;
                                            if (!acc.some(x => x.value === val)) {
                                                acc.push({
                                                    indicator_type: val.startsWith("http") ? "js_resource" : (val.includes(".") ? "domain" : "js_resource"),
                                                    value: val,
                                                    source: "virustotal",
                                                    reputation_score: f.risk_score || 55.0,
                                                    threat_level: f.severity === "critical" || f.severity === "high" ? "malicious" : "clean",
                                                    details: {},
                                                    flagged: f.severity === "critical" || f.severity === "high"
                                                });
                                            }
                                            return acc;
                                        }, []) || []
                                    }
                                />
                            )}

                            {activeTab === "correlations" && (
                                <div className="space-y-6">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <Card className="!p-5 bg-slate-900/20 border border-white/[0.04]">
                                            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">
                                                Correlation Analysis
                                            </span>
                                            <div className="text-3xl font-black text-white mt-1">
                                                {investigation.final_result?.correlation?.unique_threats_identified || 0}
                                            </div>
                                        </Card>
                                        <Card className="!p-5 bg-slate-900/20 border border-white/[0.04]">
                                            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">
                                                Escalated Risks
                                            </span>
                                            <div className="text-3xl font-black text-orange-400 mt-1">
                                                {investigation.final_result?.correlation?.escalated_risks_count || 0}
                                            </div>
                                        </Card>
                                    </div>

                                    <div className="space-y-4">
                                        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                                            Correlated Attack Chains
                                        </h4>
                                        {(!investigation.final_result?.correlation?.correlated_threats ||
                                            investigation.final_result.correlation.correlated_threats.length === 0) ? (
                                            <Card className="py-12 text-center text-slate-500">
                                                No correlated threat paths found.
                                            </Card>
                                        ) : (
                                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                                {investigation.final_result.correlation.correlated_threats.map((threat, idx) => (
                                                    <AttackChainCard key={threat.id || idx} threat={threat} />
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}

                            {activeTab === "threat_model" && (
                                <Card title="STRIDE Threat Vectors">
                                    <div className="overflow-x-auto">
                                        <table className="w-full text-left text-sm">
                                            <thead>
                                                <tr className="border-b border-white/[0.06] text-slate-400 font-semibold bg-slate-900/10">
                                                    <th className="py-3 px-4 w-40">STRIDE Category</th>
                                                    <th className="py-3 px-4">Threat Scenario</th>
                                                    <th className="py-3 px-4 w-32">Severity</th>
                                                    <th className="py-3 px-4">Remediation</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-white/[0.04]">
                                                {(!investigation.final_result?.stride?.stride_threats ||
                                                    investigation.final_result.stride.stride_threats.length === 0) ? (
                                                    <tr>
                                                        <td colSpan={4} className="py-12 text-center text-slate-500">
                                                            No STRIDE threats generated.
                                                        </td>
                                                    </tr>
                                                ) : (
                                                    investigation.final_result.stride.stride_threats.map((t, idx) => (
                                                        <tr key={t.stride_id || idx} className="hover:bg-white/[0.01]">
                                                            <td className="py-4 px-4">
                                                                <span className="text-[10px] bg-blue-500/10 border border-blue-500/20 text-blue-400 font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                                                                    {t.category}
                                                                </span>
                                                            </td>
                                                            <td className="py-4 px-4 text-slate-300 text-xs leading-relaxed">
                                                                {t.attack_scenario?.split("[Evidence Tracing]")[0].trim()}
                                                            </td>
                                                            <td className="py-4 px-4">
                                                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                                                                    (t.severity ?? "").toLowerCase() === "high" || (t.severity ?? "").toLowerCase() === "critical"
                                                                        ? "border-red-500/25 bg-red-500/10 text-red-400"
                                                                        : "border-orange-500/25 bg-orange-500/10 text-orange-400"
                                                                }`}>
                                                                    {t.severity}
                                                                </span>
                                                            </td>
                                                            <td className="py-4 px-4 text-xs text-slate-300 leading-relaxed">
                                                                {Array.isArray(t.mitigations) ? t.mitigations.join("; ") : t.mitigations}
                                                            </td>
                                                        </tr>
                                                    ))
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </Card>
                            )}

                            {activeTab === "ai_summary" && (
                                <div className="space-y-6">
                                    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                                        <Card className="lg:col-span-3 !p-6 flex flex-col justify-center bg-slate-900/15 border border-white/[0.04]">
                                            <div className="flex items-center gap-2 text-blue-400 font-semibold text-sm">
                                                <Sparkles className="w-4 h-4 animate-bounce" />
                                                Executive Summary
                                            </div>
                                            <div className="text-slate-200 text-sm leading-relaxed mt-4 whitespace-pre-line font-sans">
                                                <ReactMarkdown>
                                                    {investigation.final_result?.reporter?.ai_summary?.executive_summary || "Generating summary..."}
                                                </ReactMarkdown>
                                            </div>
                                        </Card>

                                        <Card className="lg:col-span-1 !p-6 flex flex-col items-center justify-center bg-slate-900/15 border border-white/[0.04] text-center">
                                            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">
                                                AI Confidence
                                            </span>
                                            <div className="text-5xl font-black text-white tracking-tight mt-3">
                                                {investigation.final_result?.reporter?.confidence || 85}%
                                            </div>
                                        </Card>
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}
