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
import { motion } from "framer-motion";
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
            <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] flex flex-col items-center justify-center text-[#7C6F64] gap-3">
                <Loader2 className="w-8 h-8 animate-spin text-[#10B981]" />
                <p className="text-sm font-semibold uppercase tracking-wider">Loading Admin Workspace Viewer...</p>
            </div>
        );
    }

    if (error || !investigation) {
        return (
            <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] space-y-4">
                <Button onClick={() => router.push("/admin/investigations")} variant="ghost" size="sm" className="gap-2 text-[#7C6F64] hover:text-[#10B981] hover:bg-[#10B981]/10">
                    <ArrowLeft className="w-4 h-4" /> Back to Investigations List
                </Button>
                <div className="border border-[#EF4444]/20 bg-[#EF4444]/5 text-center py-12 rounded-[20px] shadow-sm max-w-3xl mx-auto mt-10">
                    <AlertOctagon className="w-12 h-12 text-[#EF4444] mx-auto mb-4" />
                    <h3 className="text-lg font-bold text-[#EF4444]">Workspace Loading Error</h3>
                    <p className="text-sm text-[#EF4444] mt-2 max-w-md mx-auto">
                        {error || "We could not fetch details for this investigation. Please check if it exists or try again."}
                    </p>
                </div>
            </div>
        );
    }

    const statusColors: Record<string, string> = {
        completed: "bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/20",
        failed: "bg-[#EF4444]/10 text-[#EF4444] border border-[#EF4444]/20",
        pending: "bg-orange-500/10 text-orange-600 border border-orange-500/20",
        running: "bg-[#2F80ED]/10 text-[#2F80ED] border border-[#2F80ED]/20 animate-pulse",
        stopped: "bg-orange-500/10 text-orange-600 border border-orange-500/20"
    };

    const getStatusText = (status: string) => {
        if (status === "running") return "Active Scanning";
        if (status === "completed") return "Completed";
        if (status === "failed") return "Failed";
        if (status === "stopped") return "Stopped";
        return "Queued";
    };

    return (
        <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] text-[#1F2933]">
        <div className="space-y-6 max-w-[1600px] mx-auto">
            {/* Top Identity Header */}
            <motion.div 
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}
                style={{ background: "linear-gradient(90deg, #FFFCF7 0%, #F4EFE7 45%, #E9EDF3 100%)" }}
                className="rounded-[24px] border border-[#E6DDD2] py-6 px-8 shadow-sm flex flex-col md:flex-row justify-between items-stretch md:items-center gap-4"
            >
                <div className="space-y-2">
                    {/* Back CTA & Breadcrumbs */}
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => router.push("/admin/investigations")}
                            className="text-xs text-[#7C6F64] hover:text-[#10B981] font-bold uppercase tracking-widest flex items-center gap-1 transition-colors cursor-pointer"
                        >
                            <ArrowLeft className="w-3.5 h-3.5" /> SOC Workspace
                        </button>
                        <span className="text-[#E6DDD2] font-mono text-xs">/</span>
                        <span className="text-xs text-[#7C6F64] font-mono select-all">
                            {investigation.scan_id}
                        </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-3">
                        <h1 className="text-2xl font-black text-[#1d1d1d] tracking-tight break-all">
                            Target: {investigation.target}
                        </h1>
                        <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase ${statusColors[investigation.status] || statusColors.running}`}>
                            {getStatusText(investigation.status)}
                        </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-xs text-[#7C6F64] font-mono mt-2">
                        <div className="flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-[#7C6F64]" />
                            Runtime: <span className="text-[#1F2933] font-bold">{activeDuration}</span>
                        </div>
                        <div>
                            Stage: <span className="text-[#1F2933] font-semibold">{investigation.current_stage}</span>
                        </div>
                        <div className="flex items-center gap-1">
                            <User className="w-3.5 h-3.5 text-[#7C6F64]" />
                            Analyst: <span className="text-[#1F2933] font-semibold">{analyst?.name || "System"}</span>
                        </div>
                    </div>
                </div>

                {/* Global actions */}
                {investigation.status === "completed" ? (
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => handleExport("json")}
                            disabled={!!exportLoading}
                            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-white text-[#1F2933] hover:border-[#10B981] hover:text-[#10B981] border border-[#E6DDD2] transition-colors text-sm font-semibold shadow-sm disabled:opacity-50 cursor-pointer"
                        >
                            {exportLoading === "json" ? (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                                <FileJson className="w-3.5 h-3.5" />
                            )}
                            JSON
                        </button>
                        <button
                            onClick={() => handleExport("pdf")}
                            disabled={!!exportLoading}
                            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-[#10B981] to-teal-400 text-white hover:shadow-md hover:-translate-y-0.5 border border-transparent transition-all text-sm font-semibold shadow-sm disabled:opacity-50 cursor-pointer"
                        >
                            {exportLoading === "pdf" ? (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                                <FileText className="w-3.5 h-3.5" />
                            )}
                            PDF Report
                        </button>
                    </div>
                ) : (investigation.status === "running" || investigation.status === "pending") && (
                    <div className="flex items-center gap-2">
                        <button
                            onClick={handleStop}
                            disabled={stopLoading}
                            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-white border border-[#EF4444]/50 hover:bg-[#EF4444]/10 text-[#EF4444] transition-colors text-sm font-semibold shadow-sm disabled:opacity-50 cursor-pointer"
                        >
                            {stopLoading ? (
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                                <AlertOctagon className="w-3.5 h-3.5" />
                            )}
                            Stop Scan
                        </button>
                    </div>
                )}
            </motion.div>

            {/* Progress timeline */}
            <InvestigationTimeline stages={stages} />

            {/* Live Activity & Gauge */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.2 }} className="lg:col-span-4 flex flex-col justify-center items-center bg-white rounded-[20px] border border-[#E6DDD2] p-4 shadow-sm min-h-[260px]">
                    <h3 className="text-xs font-bold text-[#7C6F64] uppercase tracking-widest mb-3">
                        Risk Progression
                    </h3>
                    <RiskGauge score={investigation.risk_score} />
                </motion.div>

                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.3 }} className="lg:col-span-8">
                    <SOCEventFeed events={liveEvents} />
                </motion.div>
            </div>

            {/* Results Tabs */}
            <div className="space-y-4">
                <div className="flex border-b border-[#E6DDD2] overflow-x-auto whitespace-nowrap scrollbar-none gap-2">
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
                                        ? "border-[#10B981] text-[#10B981]"
                                        : unlocked
                                        ? "border-transparent text-[#7C6F64] hover:text-[#10B981]"
                                        : "border-transparent text-gray-400 cursor-not-allowed"
                                }`}
                            >
                                {getTabLabel(tab.key, tab.label)}
                            </button>
                        );
                    })}
                </div>

                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }} className="min-h-[300px]">
                    {!isTabUnlocked(activeTab) ? (
                        <div className="border border-[#E6DDD2] bg-white text-center py-20 rounded-[20px] shadow-sm">
                            <Lock className="w-12 h-12 text-[#7C6F64] mx-auto mb-4 opacity-50" />
                            <h4 className="text-[#7C6F64] font-bold uppercase tracking-widest text-xs">
                                Stage Pending
                            </h4>
                        </div>
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
                                        <div className="p-5 bg-white rounded-[20px] border border-[#E6DDD2] shadow-sm">
                                            <span className="text-[10px] text-[#7C6F64] font-bold uppercase tracking-wider block">
                                                Correlation Analysis
                                            </span>
                                            <div className="text-3xl font-black text-[#10B981] mt-1">
                                                {investigation.final_result?.correlation?.unique_threats_identified || 0}
                                            </div>
                                        </div>
                                        <div className="p-5 bg-white rounded-[20px] border border-[#E6DDD2] shadow-sm">
                                            <span className="text-[10px] text-[#7C6F64] font-bold uppercase tracking-wider block">
                                                Escalated Risks
                                            </span>
                                            <div className="text-3xl font-black text-[#F97316] mt-1">
                                                {investigation.final_result?.correlation?.escalated_risks_count || 0}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="space-y-4">
                                        <h4 className="text-xs font-bold text-[#7C6F64] uppercase tracking-widest">
                                            Correlated Attack Chains
                                        </h4>
                                        {(!investigation.final_result?.correlation?.correlated_threats ||
                                            investigation.final_result.correlation.correlated_threats.length === 0) ? (
                                            <div className="py-12 text-center text-[#7C6F64] bg-white rounded-[20px] border border-[#E6DDD2] shadow-sm">
                                                No correlated threat paths found.
                                            </div>
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

                            {activeTab === "threat_model" && (() => {
                                const allThreats = investigation.final_result?.stride?.stride_threats || [];

                                const isConfirmed = (t: any) => {
                                    const status = (t.status || "").toLowerCase();
                                    const evidenceType = (t.evidence_type || "").toLowerCase();
                                    const classification = (t.classification || "").toLowerCase();
                                    const confidence = (t.confidence || "").toLowerCase();

                                    return (
                                        status === "confirmed" ||
                                        evidenceType === "vulnerability" ||
                                        classification === "vulnerability" ||
                                        confidence === "verified" ||
                                        confidence === "high"
                                    );
                                };

                                const confirmedThreats = allThreats.filter(isConfirmed);
                                const potentialScenarios = allThreats.filter((t: any) => !isConfirmed(t));

                                const parseScenario = (scenarioStr: string) => {
                                    const parts = (scenarioStr || "").split("[Evidence Tracing]");
                                    const mainDesc = parts[0].trim();
                                    const evidence = parts.slice(1).join("[Evidence Tracing]").trim();
                                    return { mainDesc, evidence };
                                };

                                const groupThreats = (threatsList: any[]) => {
                                    const map = new Map<string, any>();
                                    threatsList.forEach((t) => {
                                        const { mainDesc } = parseScenario(t.attack_scenario);
                                        const key = `${mainDesc}::${t.affected_asset || ""}`;
                                        if (!map.has(key)) {
                                            map.set(key, {
                                                ...t,
                                                categories: [t.category],
                                                originalThreats: [t],
                                            });
                                        } else {
                                            const existing = map.get(key);
                                            existing.originalThreats.push(t);
                                            if (!existing.categories.includes(t.category)) {
                                                existing.categories.push(t.category);
                                            }
                                            const severityOrder: Record<string, number> = {
                                                info: 0, low: 1, medium: 2, high: 3, critical: 4
                                            };
                                            const tSev = (t.severity || "info").toLowerCase();
                                            const eSev = (existing.severity || "info").toLowerCase();
                                            if ((severityOrder[tSev] ?? 0) > (severityOrder[eSev] ?? 0)) {
                                                existing.severity = t.severity;
                                            }
                                            const existingMitigations = Array.isArray(existing.mitigations) 
                                                ? existing.mitigations 
                                                : [existing.mitigations];
                                            const newMitigations = Array.isArray(t.mitigations) 
                                                ? t.mitigations 
                                                : [t.mitigations];
                                            newMitigations.forEach((m: string) => {
                                                if (m && !existingMitigations.includes(m)) {
                                                    existingMitigations.push(m);
                                                }
                                            });
                                            existing.mitigations = existingMitigations;
                                        }
                                    });
                                    return Array.from(map.values());
                                };

                                const groupedConfirmed = groupThreats(confirmedThreats);
                                const groupedPotential = groupThreats(potentialScenarios);

                                // ── Summary Metrics ──
                                const uniqueCategories = new Set(allThreats.map((t: any) => t.category)).size;
                                const getHighestRisk = () => {
                                    const severities = allThreats.map((t: any) => (t.severity || "").toLowerCase());
                                    if (severities.includes("critical")) return "Critical";
                                    if (severities.includes("high")) return "High";
                                    if (severities.includes("medium")) return "Medium";
                                    if (severities.includes("low")) return "Low";
                                    return "Info";
                                };

                                const getShortWhyGenerated = (t: any) => {
                                    const whyStr = t.why_generated || "";
                                    const notConfStr = t.why_not_confirmed || "";
                                    const text = (whyStr || notConfStr).trim();
                                    
                                    if (!text) {
                                        return "Generated from correlated security hardening findings.";
                                    }
                                    
                                    if (text.toLowerCase().includes("csp") || text.toLowerCase().includes("content-security-policy")) {
                                        return "Generated from hardening evidence related to Content-Security-Policy.";
                                    }
                                    
                                    if (text.toLowerCase().includes("cors") || text.toLowerCase().includes("cross-origin")) {
                                        return "Generated from hardening evidence related to CORS policy.";
                                    }

                                    if (text.toLowerCase().includes("security header") || text.toLowerCase().includes("x-frame-options") || text.toLowerCase().includes("x-content-type-options")) {
                                        return "Generated from correlated security header hardening recommendations.";
                                    }

                                    if (text.toLowerCase().includes("auth") || text.toLowerCase().includes("jwt") || text.toLowerCase().includes("session")) {
                                        return "Generated from authorization boundary indicators.";
                                    }

                                    const sentence = text.split(/[.!?]/)[0].trim();
                                    if (sentence && sentence.length > 5 && !sentence.includes("{") && !sentence.includes("[")) {
                                        const cleanText = sentence + ".";
                                        return cleanText.length > 85 ? cleanText.slice(0, 82) + "..." : cleanText;
                                    }

                                    return "Generated from correlated security hardening findings.";
                                };

                                return (
                                    <div className="space-y-6">
                                        {/* Header Summary Row */}
                                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                                            {/* Confirmed Threats Card */}
                                            <div className="p-5 bg-white border border-[#E6DDD2] rounded-[20px] shadow-sm hover:shadow-md transition-all duration-200 flex flex-col justify-between">
                                                <div>
                                                    <span className="text-[10px] text-[#7C6F64] font-bold uppercase tracking-wider block">
                                                        Confirmed Threats
                                                    </span>
                                                    <div className="text-3xl font-black text-[#EF4444] mt-1">
                                                        {confirmedThreats.length}
                                                    </div>
                                                </div>
                                                <p className="text-[11px] text-[#7C6F64] mt-2">
                                                    Active vulnerabilities verified by scan evidence.
                                                </p>
                                            </div>

                                            {/* Potential Scenarios Card */}
                                            <div className="p-5 bg-white border border-[#E6DDD2] rounded-[20px] shadow-sm hover:shadow-md transition-all duration-200 flex flex-col justify-between">
                                                <div>
                                                    <span className="text-[10px] text-[#7C6F64] font-bold uppercase tracking-wider block">
                                                        Potential Scenarios
                                                    </span>
                                                    <div className="text-3xl font-black text-[#F59E0B] mt-1">
                                                        {potentialScenarios.length}
                                                    </div>
                                                </div>
                                                <p className="text-[11px] text-[#7C6F64] mt-2">
                                                    Architectural hardening and security advisories.
                                                </p>
                                            </div>

                                            {/* Highest Risk Card */}
                                            <div className="p-5 bg-white border border-[#E6DDD2] rounded-[20px] shadow-sm hover:shadow-md transition-all duration-200 flex flex-col justify-between">
                                                <div>
                                                    <span className="text-[10px] text-[#7C6F64] font-bold uppercase tracking-wider block">
                                                        Highest Threat Risk
                                                    </span>
                                                    <div className={`text-3xl font-black mt-1 ${
                                                        getHighestRisk() === "Critical" || getHighestRisk() === "High" ? "text-[#EF4444]" : "text-[#10B981]"
                                                    }`}>
                                                        {getHighestRisk()}
                                                    </div>
                                                </div>
                                                <p className="text-[11px] text-[#7C6F64] mt-2">
                                                    Maximum threat level detected on target.
                                                </p>
                                            </div>

                                            {/* STRIDE Categories Card */}
                                            <div className="p-5 bg-white border border-[#E6DDD2] rounded-[20px] shadow-sm hover:shadow-md transition-all duration-200 flex flex-col justify-between">
                                                <div>
                                                    <span className="text-[10px] text-[#7C6F64] font-bold uppercase tracking-wider block">
                                                        STRIDE Mappings
                                                    </span>
                                                    <div className="text-3xl font-black text-[#10B981] mt-1">
                                                        {uniqueCategories} / 6
                                                    </div>
                                                </div>
                                                <p className="text-[11px] text-[#7C6F64] mt-2">
                                                    Standard security threat model categories.
                                                </p>
                                            </div>
                                        </div>

                                        {/* Section 1: Confirmed Threats */}
                                        <div className="bg-white rounded-[20px] border border-[#E6DDD2] shadow-sm overflow-hidden">
                                            <div className="px-6 py-4 border-b border-[#E6DDD2] bg-[#FAF7F1]">
                                                <h3 className="font-semibold text-[#1F2933]">Confirmed Threats</h3>
                                                <p className="text-xs text-[#7C6F64] mt-0.5">Security vulnerabilities requiring immediate remediation action</p>
                                            </div>
                                            <div className="overflow-x-auto">
                                                <table className="w-full text-left text-sm">
                                                    <thead>
                                                        <tr className="border-b border-[#E6DDD2] text-[#7C6F64] font-semibold bg-[#FAF7F1]">
                                                            <th className="py-3 px-4 w-40">STRIDE Category</th>
                                                            <th className="py-3 px-4">Threat Description</th>
                                                            <th className="py-3 px-4 w-32">Risk Level</th>
                                                            <th className="py-3 px-4 w-60">Evidence</th>
                                                            <th className="py-3 px-4">Recommended Mitigation</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody className="divide-y divide-[#E6DDD2]/40">
                                                        {groupedConfirmed.length === 0 ? (
                                                            <tr>
                                                                <td colSpan={5} className="py-12 text-center text-[#7C6F64] font-medium">
                                                                    No confirmed threats found. Potential hardening scenarios are listed below.
                                                                </td>
                                                            </tr>
                                                        ) : (
                                                            groupedConfirmed.map((t: any, idx: number) => {
                                                                const { mainDesc, evidence } = parseScenario(t.attack_scenario);
                                                                return (
                                                                    <tr key={t.stride_id || idx} className="hover:bg-[#FAF7F1] transition-colors duration-150">
                                                                        <td className="py-4 px-4 vertical-top">
                                                                            <div className="space-y-2">
                                                                                <div className="flex flex-wrap gap-1.5">
                                                                                    {t.categories.map((cat: string, cIdx: number) => (
                                                                                        <span key={cIdx} className="inline-block text-[10px] bg-[#EF4444]/10 border border-[#EF4444]/20 text-[#EF4444] font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                                                                                            {cat}
                                                                                        </span>
                                                                                    ))}
                                                                                </div>
                                                                            </div>
                                                                        </td>
                                                                        <td className="py-4 px-4 font-semibold text-[#1F2933] text-xs leading-relaxed max-w-sm vertical-top">
                                                                            <p className="font-normal text-[#7C6F64]">{mainDesc}</p>
                                                                        </td>
                                                                        <td className="py-4 px-4 vertical-top">
                                                                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                                                                                (t.severity ?? "").toLowerCase() === "high" || (t.severity ?? "").toLowerCase() === "critical"
                                                                                    ? "border-[#EF4444]/25 bg-[#EF4444]/10 text-[#EF4444]"
                                                                                    : (t.severity ?? "").toLowerCase() === "medium"
                                                                                        ? "border-orange-500/25 bg-orange-500/10 text-orange-600"
                                                                                        : "border-[#10B981]/25 bg-[#10B981]/10 text-[#10B981]"
                                                                            }`}>
                                                                                {t.severity}
                                                                            </span>
                                                                        </td>
                                                                        <td className="py-4 px-4 text-xs text-[#7C6F64] vertical-top">
                                                                            {evidence ? (
                                                                                <details className="group">
                                                                                    <summary className="text-[11px] text-[#10B981] hover:text-[#10B981]/80 cursor-pointer select-none font-semibold outline-none flex items-center gap-1">
                                                                                        <span className="inline-block transition-transform duration-200 group-open:rotate-90">▶</span>
                                                                                        View Technical Evidence
                                                                                    </summary>
                                                                                    <pre className="mt-1.5 p-2.5 rounded bg-[#FAF7F1]/80 border border-[#E6DDD2] text-[10px] text-[#7C6F64] font-mono overflow-x-auto max-w-md whitespace-pre-wrap leading-relaxed">
                                                                                        {evidence.startsWith("-") || evidence.startsWith(":") ? evidence.replace(/^[:\s\-]+/, "") : evidence}
                                                                                    </pre>
                                                                                </details>
                                                                            ) : (
                                                                                <span className="text-[#7C6F64] italic">No trace log available</span>
                                                                            )}
                                                                        </td>
                                                                        <td className="py-4 px-4 text-xs text-[#7C6F64] leading-relaxed font-sans max-w-xs vertical-top">
                                                                            {Array.isArray(t.mitigations) ? t.mitigations.join("; ") : t.mitigations || "N/A"}
                                                                        </td>
                                                                    </tr>
                                                                );
                                                            })
                                                        )}
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>

                                        {/* Section 2: Potential Scenarios */}
                                        <div className="bg-white rounded-[20px] border border-[#E6DDD2] shadow-sm overflow-hidden">
                                            <div className="px-6 py-4 border-b border-[#E6DDD2] bg-[#FAF7F1]">
                                                <h3 className="font-semibold text-[#1F2933]">Potential Scenarios</h3>
                                                <p className="text-xs text-[#7C6F64] mt-0.5">Architectural hardening opportunities and defensive recommendations</p>
                                            </div>
                                            <div className="overflow-x-auto">
                                                <table className="w-full text-left text-sm">
                                                    <thead>
                                                        <tr className="border-b border-[#E6DDD2] text-[#7C6F64] font-semibold bg-[#FAF7F1]">
                                                            <th className="py-3 px-4 w-40">STRIDE Category</th>
                                                            <th className="py-3 px-4">Scenario Description</th>
                                                            <th className="py-3 px-4 w-32">Advisory Risk</th>
                                                            <th className="py-3 px-4 w-60">Why Generated</th>
                                                            <th className="py-3 px-4">Recommended Hardening</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody className="divide-y divide-[#E6DDD2]/40">
                                                        {groupedPotential.length === 0 ? (
                                                            <tr>
                                                                <td colSpan={5} className="py-12 text-center text-[#7C6F64] font-medium">
                                                                    No potential hardening scenarios generated.
                                                                </td>
                                                            </tr>
                                                        ) : (
                                                            groupedPotential.map((t: any, idx: number) => {
                                                                const { mainDesc, evidence } = parseScenario(t.attack_scenario);
                                                                return (
                                                                    <tr key={t.stride_id || idx} className="hover:bg-[#FAF7F1] transition-colors duration-150">
                                                                        <td className="py-4 px-4 vertical-top">
                                                                            <div className="space-y-2">
                                                                                <div className="flex flex-wrap gap-1.5">
                                                                                    {t.categories.map((cat: string, cIdx: number) => (
                                                                                        <span key={cIdx} className="inline-block text-[10px] bg-[#F59E0B]/10 border border-[#F59E0B]/20 text-[#F59E0B] font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                                                                                            {cat}
                                                                                        </span>
                                                                                    ))}
                                                                                </div>
                                                                            </div>
                                                                        </td>
                                                                        <td className="py-4 px-4 font-semibold text-[#1F2933] text-xs leading-relaxed max-w-sm vertical-top">
                                                                            <p className="font-normal text-[#7C6F64]">{mainDesc}</p>
                                                                        </td>
                                                                        <td className="py-4 px-4 vertical-top">
                                                                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                                                                                (t.severity ?? "").toLowerCase() === "high" || (t.severity ?? "").toLowerCase() === "critical"
                                                                                    ? "border-[#F59E0B]/25 bg-[#F59E0B]/10 text-[#F59E0B]"
                                                                                    : (t.severity ?? "").toLowerCase() === "medium"
                                                                                        ? "border-[#3B82F6]/25 bg-[#3B82F6]/10 text-[#3B82F6]"
                                                                                        : "border-[#10B981]/25 bg-[#10B981]/10 text-[#10B981]"
                                                                            }`}>
                                                                                {t.severity || "Low"}
                                                                            </span>
                                                                        </td>
                                                                        <td className="py-4 px-4 text-xs text-[#7C6F64] max-w-xs leading-relaxed vertical-top">
                                                                            <div className="line-clamp-2" title={getShortWhyGenerated(t)}>
                                                                                {getShortWhyGenerated(t)}
                                                                            </div>
                                                                            <div className="mt-2">
                                                                                <details className="group">
                                                                                    <summary className="text-[11px] text-[#10B981] hover:text-[#10B981]/80 cursor-pointer select-none font-semibold outline-none flex items-center gap-1">
                                                                                        <span className="inline-block transition-transform duration-200 group-open:rotate-90">▶</span>
                                                                                        View Technical Evidence
                                                                                    </summary>
                                                                                    <div className="mt-2 p-3 rounded bg-[#FAF7F1]/80 border border-[#E6DDD2] text-[10px] text-[#7C6F64] font-mono overflow-x-auto max-w-md whitespace-pre-wrap leading-relaxed space-y-1">
                                                                                        <div>
                                                                                            <span className="text-[#1F2933] font-semibold">Finding ID:</span> {t.related_findings?.join(", ") || t.stride_id || "N/A"}
                                                                                        </div>
                                                                                        <div>
                                                                                            <span className="text-[#1F2933] font-semibold">Source Module:</span> {t.source_module || "pentest_engine_module"}
                                                                                        </div>
                                                                                        {t.related_findings && t.related_findings.length > 0 && (
                                                                                            <div>
                                                                                                <span className="text-[#1F2933] font-semibold">Related Findings:</span> {t.related_findings.join(", ")}
                                                                                            </div>
                                                                                        )}
                                                                                        <div>
                                                                                            <span className="text-[#1F2933] font-semibold">Confidence:</span> {t.confidence || "advisory"}
                                                                                        </div>
                                                                                        {t.why_generated && (
                                                                                            <div>
                                                                                                <span className="text-[#1F2933] font-semibold">Why Generated:</span> {t.why_generated}
                                                                                            </div>
                                                                                        )}
                                                                                        {t.why_not_confirmed && (
                                                                                            <div>
                                                                                                <span className="text-[#1F2933] font-semibold">Why Not Confirmed:</span> {t.why_not_confirmed}
                                                                                            </div>
                                                                                        )}
                                                                                        {evidence && (
                                                                                            <div className="mt-2 pt-2 border-t border-[#E6DDD2]">
                                                                                                <span className="text-[#1F2933] font-semibold block mb-1">Raw Evidence:</span>
                                                                                                <pre className="whitespace-pre-wrap font-mono leading-relaxed">{evidence.startsWith("-") || evidence.startsWith(":") ? evidence.replace(/^[:\s\-]+/, "") : evidence}</pre>
                                                                                            </div>
                                                                                        )}
                                                                                    </div>
                                                                                </details>
                                                                            </div>
                                                                        </td>
                                                                        <td className="py-4 px-4 text-xs text-[#7C6F64] leading-relaxed font-sans max-w-xs vertical-top">
                                                                            {Array.isArray(t.mitigations) ? t.mitigations.join("; ") : t.mitigations || "N/A"}
                                                                        </td>
                                                                    </tr>
                                                                );
                                                            })
                                                        )}
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
                                    </div>
                                );
                            })()}

                            {activeTab === "ai_summary" && (
                                <div className="space-y-6">
                                    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                                        <div className="lg:col-span-3 p-6 flex flex-col justify-center bg-white rounded-[20px] border border-[#E6DDD2] shadow-sm">
                                            <div className="flex items-center gap-2 text-[#10B981] font-semibold text-sm">
                                                <Sparkles className="w-4 h-4 animate-bounce" />
                                                Executive Summary
                                            </div>
                                            <div className="text-[#1F2933] text-sm leading-relaxed mt-4 whitespace-pre-line font-sans">
                                                <ReactMarkdown>
                                                    {investigation.final_result?.reporter?.ai_summary?.executive_summary || "Generating summary..."}
                                                </ReactMarkdown>
                                            </div>
                                        </div>

                                        <div className="lg:col-span-1 p-6 flex flex-col items-center justify-center bg-white rounded-[20px] border border-[#E6DDD2] text-center shadow-sm">
                                            <span className="text-[10px] text-[#7C6F64] font-bold uppercase tracking-wider block">
                                                AI Confidence
                                            </span>
                                            <div className="text-5xl font-black text-[#10B981] tracking-tight mt-3">
                                                {investigation.final_result?.reporter?.confidence || 85}%
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                </motion.div>
            </div>
        </div>
        </div>
    );
}
