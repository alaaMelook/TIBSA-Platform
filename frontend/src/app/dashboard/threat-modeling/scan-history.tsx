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
    "Critical": "bg-[#EF4444] text-[#1F2933]",
    "High": "bg-[#EF4444] text-[#1F2933]",
    "Medium": "bg-[#F97316] text-[#1F2933]",
    "Low": "bg-[#10B981] text-[#1F2933]",
};

const RISK_TEXT_COLORS: Record<string, string> = {
    "Critical": "text-[#EF4444]",
    "High": "text-[#EF4444]",
    "Medium": "text-[#F97316]",
    "Low": "text-[#10B981]",
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
                <p className="text-[#7C6F64]">Sign in to view scan history</p>
            </Card>
        );
    }

    if (isLoading) {
        return (
            <Card className="p-6">
                <div className="animate-pulse space-y-4">
                    <div className="h-4 bg-[#F4EFE7] rounded w-1/4"></div>
                    <div className="h-8 bg-[#F4EFE7] rounded w-full"></div>
                </div>
            </Card>
        );
    }

    if (error) {
        return (
            <Card className="p-6 border-[#EF4444]/20 bg-[#EF4444]/10">
                <p className="text-[#EF4444]">❌ {error}</p>
            </Card>
        );
    }

    if (!history || history.total_scans === 0) {
        return (
            <Card className="p-6 text-center">
                <p className="text-[#7C6F64]">No scan history yet. Create your first threat model analysis above!</p>
            </Card>
        );
    }

    return (
        <div className="space-y-6 animate-[fadeIn_0.5s_ease-out]">
            {/* Statistics Summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="bg-[#FFFFFF] backdrop-blur-md rounded-xl p-5 border border-[#E6DDD2] border-t-4 border-t-[#10B981] shadow-lg shadow-black/5 hover:bg-[#F4EFE7] transition-colors">
                    <p className="text-[11px] font-bold text-[#7C6F64] mb-2 uppercase tracking-widest">Total Scans</p>
                    <p className="text-3xl font-extrabold text-[#1F2933] animate-[pulse_2s_ease-in-out_1]">{history.total_scans}</p>
                </div>
                <div className={`bg-[#FFFFFF] backdrop-blur-md rounded-xl p-5 border border-[#E6DDD2] border-t-4 shadow-lg shadow-black/5 hover:bg-[#F4EFE7] transition-colors ${
                    history.average_risk_score && history.average_risk_score >= 80 ? 'border-t-[#EF4444]' :
                    history.average_risk_score && history.average_risk_score >= 60 ? 'border-t-[#EF4444]' :
                    history.average_risk_score && history.average_risk_score >= 35 ? 'border-t-[#F97316]' : 'border-t-[#10B981]'
                }`}>
                    <p className="text-[11px] font-bold text-[#7C6F64] mb-2 uppercase tracking-widest">Average Risk</p>
                    <p className={`text-3xl font-extrabold animate-[pulse_2s_ease-in-out_1] ${RISK_TEXT_COLORS[getRiskLabel(history.average_risk_score || 0)]}`}>
                        {history.average_risk_score ? history.average_risk_score.toFixed(1) : "—"}
                    </p>
                </div>
                <div className="bg-[#FFFFFF] backdrop-blur-md rounded-xl p-5 border border-[#E6DDD2] border-t-4 border-t-[#EF4444] shadow-lg shadow-black/5 hover:bg-[#F4EFE7] transition-colors">
                    <p className="text-[11px] font-bold text-[#7C6F64] mb-2 uppercase tracking-widest">High Risk Scans</p>
                    <p className="text-3xl font-extrabold text-[#EF4444] animate-[pulse_2s_ease-in-out_1]">{history.high_risk_count}</p>
                </div>
                <div className="bg-[#FFFFFF] backdrop-blur-md rounded-xl p-5 border border-[#E6DDD2] border-t-4 border-t-[#F97316] shadow-lg shadow-black/5 hover:bg-[#F4EFE7] transition-colors">
                    <p className="text-[11px] font-bold text-[#7C6F64] mb-2 uppercase tracking-widest">Medium Risk Scans</p>
                    <p className="text-3xl font-extrabold text-[#F97316] animate-[pulse_2s_ease-in-out_1]">{history.medium_risk_count}</p>
                </div>
            </div>

            {/* Scan History Table */}
            <div className="bg-[#FFFFFF] backdrop-blur-md border border-[#E6DDD2] rounded-2xl shadow-sm overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full border-collapse">
                        <thead>
                            <tr className="bg-[#F4EFE7] border-b border-[#E6DDD2]">
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-[#7C6F64] uppercase tracking-widest whitespace-nowrap">Project</th>
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-[#7C6F64] uppercase tracking-widest whitespace-nowrap">App Type</th>
                                <th className="px-6 py-4 text-center text-[11px] font-bold text-[#7C6F64] uppercase tracking-widest whitespace-nowrap">Risk Score</th>
                                <th className="px-6 py-4 text-center text-[11px] font-bold text-[#7C6F64] uppercase tracking-widest whitespace-nowrap">Threats</th>
                                <th className="px-6 py-4 text-left text-[11px] font-bold text-[#7C6F64] uppercase tracking-widest whitespace-nowrap">Scanned On</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-[#E6DDD2]">
                            {history.scans.map((scan, idx) => {
                                const isCritical = scan.risk_score >= 80;
                                const isHigh = scan.risk_score >= 60 && scan.risk_score < 80;
                                const isMed = scan.risk_score >= 35 && scan.risk_score < 60;
                                
                                let badgeClass = "bg-[#10B981]/10 text-[#10B981] border-[#10B981]/20 shadow-sm";
                                if (isCritical) badgeClass = "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/20 shadow-sm";
                                else if (isHigh) badgeClass = "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/20 shadow-sm";
                                else if (isMed) badgeClass = "bg-[#F97316]/10 text-[#F97316] border-[#F97316]/20 shadow-sm";

                                return (
                                    <tr
                                        key={`${scan.id}-${idx}`}
                                        className="group hover:bg-[#10B981]/[0.04] transition-colors duration-200"
                                        style={{ animation: `fadeIn 0.3s ease-out ${(idx * 0.05).toFixed(2)}s both` }}
                                    >
                                        <td className="px-6 py-4">
                                            <div className="font-semibold text-[#1F2933] group-hover:text-[#10B981] transition-colors">
                                                {scan.project_name}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-[#F4EFE7] text-[#7C6F64] border border-[#E6DDD2]">
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
                                            <div className="text-sm font-semibold text-[#7C6F64]">
                                                {scan.threat_count}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="text-xs font-medium text-[#7C6F64]">
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
