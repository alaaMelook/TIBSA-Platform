"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card } from "@/components/ui";

interface ScanHistoryItem {
    id: string;
    analysis_id: string;
    project_name: string;
    app_type: string;
    risk_score: number;
    risk_label: string;
    threat_count: number;
    mitigation_count: number;
    status: string;
    error_message?: string;
    analysis_type: string;
    created_at: string;
    completed_at?: string;
}

interface ScanHistoryResponse {
    total_scans: number;
    scans: ScanHistoryItem[];
    average_risk_score: number | null;
    high_risk_count: number;
    medium_risk_count: number;
    low_risk_count: number;
}

const RISK_COLORS: Record<string, string> = {
    "Critical": "bg-red-600 text-white",
    "High": "bg-red-500 text-white",
    "Medium": "bg-orange-400 text-white",
    "Low": "bg-green-500 text-white",
};

const RISK_TEXT_COLORS: Record<string, string> = {
    "Critical": "text-red-400",
    "High": "text-red-300",
    "Medium": "text-orange-300",
    "Low": "text-green-300",
};

export function ScanHistory() {
    const { token } = useAuth();
    const [history, setHistory] = useState<ScanHistoryResponse | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchHistory = async () => {
            if (!token) {
                setIsLoading(false);
                return;
            }

            try {
                const response = await api.get<ScanHistoryResponse>(
                    "/api/v1/threat-modeling/scan-history",
                    token
                );
                setHistory(response);
                setError(null);
            } catch (err) {
                setError(
                    err instanceof Error
                        ? err.message
                        : "Failed to load scan history"
                );
            } finally {
                setIsLoading(false);
            }
        };

        fetchHistory();
    }, [token]);

    if (!token) {
        return (
            <Card className="p-6 text-center">
                <p className="text-slate-400">Sign in to view scan history</p>
            </Card>
        );
    }

    if (isLoading) {
        return (
            <Card className="p-6">
                <div className="animate-pulse space-y-4">
                    <div className="h-4 bg-white/10 rounded w-1/4"></div>
                    <div className="h-8 bg-white/10 rounded w-full"></div>
                </div>
            </Card>
        );
    }

    if (error) {
        return (
            <Card className="p-6 border-red-500/20 bg-red-500/5">
                <p className="text-red-400">❌ {error}</p>
            </Card>
        );
    }

    if (!history || history.total_scans === 0) {
        return (
            <Card className="p-6 text-center">
                <p className="text-slate-400">No scan history yet. Create your first threat model analysis above!</p>
            </Card>
        );
    }

    return (
        <div className="space-y-6 animate-[fadeIn_0.5s_ease-out]">
            {/* Statistics Summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-[#0f1523]/80 backdrop-blur-md rounded-xl p-5 border border-white/[0.05] border-t-4 border-t-blue-500 shadow-lg shadow-black/20 hover:bg-[#151c2e] transition-colors">
                    <p className="text-[11px] font-bold text-slate-500 mb-2 uppercase tracking-widest">Total Scans</p>
                    <p className="text-3xl font-extrabold text-white animate-[pulse_2s_ease-in-out_1]">{history.total_scans}</p>
                </div>
                <div className={`bg-[#0f1523]/80 backdrop-blur-md rounded-xl p-5 border border-white/[0.05] border-t-4 shadow-lg shadow-black/20 hover:bg-[#151c2e] transition-colors ${
                    history.average_risk_score && history.average_risk_score >= 80 ? 'border-t-red-600' :
                    history.average_risk_score && history.average_risk_score >= 60 ? 'border-t-red-500' :
                    history.average_risk_score && history.average_risk_score >= 35 ? 'border-t-orange-400' : 'border-t-green-500'
                }`}>
                    <p className="text-[11px] font-bold text-slate-500 mb-2 uppercase tracking-widest">Average Risk</p>
                    <p className={`text-3xl font-extrabold animate-[pulse_2s_ease-in-out_1] ${RISK_TEXT_COLORS[getRiskLabel(history.average_risk_score || 0)]}`}>
                        {history.average_risk_score ? history.average_risk_score.toFixed(1) : "—"}
                    </p>
                </div>
                <div className="bg-[#0f1523]/80 backdrop-blur-md rounded-xl p-5 border border-white/[0.05] border-t-4 border-t-red-500 shadow-lg shadow-black/20 hover:bg-[#151c2e] transition-colors">
                    <p className="text-[11px] font-bold text-slate-500 mb-2 uppercase tracking-widest">High Risk Scans</p>
                    <p className="text-3xl font-extrabold text-red-400 animate-[pulse_2s_ease-in-out_1]">{history.high_risk_count}</p>
                </div>
                <div className="bg-[#0f1523]/80 backdrop-blur-md rounded-xl p-5 border border-white/[0.05] border-t-4 border-t-orange-400 shadow-lg shadow-black/20 hover:bg-[#151c2e] transition-colors">
                    <p className="text-[11px] font-bold text-slate-500 mb-2 uppercase tracking-widest">Medium Risk Scans</p>
                    <p className="text-3xl font-extrabold text-orange-400 animate-[pulse_2s_ease-in-out_1]">{history.medium_risk_count}</p>
                </div>
            </div>

            {/* Scan History Table */}
            <div className="bg-[#0f1523]/80 backdrop-blur-md border border-white/[0.05] rounded-2xl shadow-[0_8px_30px_rgba(0,0,0,0.5)] overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full border-collapse">
                        <thead>
                            <tr className="bg-[#151c2e] border-b border-white/[0.08]">
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-slate-400 uppercase tracking-widest whitespace-nowrap">Project</th>
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-slate-400 uppercase tracking-widest whitespace-nowrap">App Type</th>
                                <th className="px-6 py-4 text-center text-[11px] font-bold text-slate-400 uppercase tracking-widest whitespace-nowrap">Risk Score</th>
                                <th className="px-6 py-4 text-center text-[11px] font-bold text-slate-400 uppercase tracking-widest whitespace-nowrap">Threats</th>
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-slate-400 uppercase tracking-widest whitespace-nowrap">Scanned On</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/[0.04]">
                            {history.scans.map((scan, idx) => {
                                const isCritical = scan.risk_score >= 80;
                                const isHigh = scan.risk_score >= 60 && scan.risk_score < 80;
                                const isMed = scan.risk_score >= 35 && scan.risk_score < 60;
                                
                                let badgeClass = "bg-green-500/10 text-green-400 border-green-500/20 shadow-[0_0_10px_rgba(34,197,94,0.2)]";
                                if (isCritical) badgeClass = "bg-red-600/20 text-red-400 border-red-500/30 shadow-[0_0_15px_rgba(220,38,38,0.4)]";
                                else if (isHigh) badgeClass = "bg-red-500/15 text-red-400 border-red-500/20 shadow-[0_0_10px_rgba(239,68,68,0.2)]";
                                else if (isMed) badgeClass = "bg-orange-500/15 text-orange-400 border-orange-500/20 shadow-[0_0_10px_rgba(249,115,22,0.2)]";

                                return (
                                    <tr
                                        key={`${scan.id}-${idx}`}
                                        className="group hover:bg-blue-500/[0.04] transition-colors duration-200"
                                        style={{ animation: `fadeIn 0.3s ease-out ${(idx * 0.05).toFixed(2)}s both` }}
                                    >
                                        <td className="px-6 py-4">
                                            <div className="font-semibold text-white group-hover:text-blue-400 transition-colors">
                                                {scan.project_name}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-slate-800 text-slate-300 border border-white/[0.05]">
                                                {scan.app_type}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-center">
                                            <span
                                                className={`inline-flex items-center justify-center min-w-[3rem] px-2 py-1 rounded-lg text-xs font-bold border transition-all ${badgeClass}`}
                                            >
                                                {scan.risk_score}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-center">
                                            <div className="text-sm font-semibold text-slate-300">
                                                {scan.threat_count}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="text-xs font-medium text-slate-500">
                                                {formatDate(scan.created_at)}
                                            </div>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

function getRiskLabel(score: number): string {
    if (score >= 80) return "Critical";
    if (score >= 60) return "High";
    if (score >= 35) return "Medium";
    return "Low";
}

function formatDate(dateString: string): string {
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString() + " " + date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } catch {
        return dateString;
    }
}
