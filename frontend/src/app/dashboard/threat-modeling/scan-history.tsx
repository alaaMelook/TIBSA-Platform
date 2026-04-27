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
        <div className="space-y-6">
            {/* Statistics Summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="p-4">
                    <p className="text-sm text-slate-400 mb-1">Total Scans</p>
                    <p className="text-2xl font-bold text-white">{history.total_scans}</p>
                </Card>
                <Card className="p-4">
                    <p className="text-sm text-slate-400 mb-1">Average Risk</p>
                    <p className={`text-2xl font-bold ${RISK_TEXT_COLORS[getRiskLabel(history.average_risk_score || 0)]}`}>
                        {history.average_risk_score ? history.average_risk_score.toFixed(1) : "—"}
                    </p>
                </Card>
                <Card className="p-4">
                    <p className="text-sm text-slate-400 mb-1">High Risk Scans</p>
                    <p className="text-2xl font-bold text-red-400">{history.high_risk_count}</p>
                </Card>
                <Card className="p-4">
                    <p className="text-sm text-slate-400 mb-1">Medium Risk Scans</p>
                    <p className="text-2xl font-bold text-orange-400">{history.medium_risk_count}</p>
                </Card>
            </div>

            {/* Scan History Table */}
            <Card className="overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full">
                        <thead>
                            <tr className="border-b border-white/10 bg-white/5">
                                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-300">Project</th>
                                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-300">App Type</th>
                                <th className="px-6 py-3 text-center text-xs font-semibold text-slate-300">Risk Score</th>
                                <th className="px-6 py-3 text-center text-xs font-semibold text-slate-300">Threats</th>
                                <th className="px-6 py-3 text-left text-xs font-semibold text-slate-300">Scanned</th>
                            </tr>
                        </thead>
                        <tbody>
                            {history.scans.map((scan, idx) => (
                                <tr
                                    key={`${scan.id}-${idx}`}
                                    className="border-b border-white/5 hover:bg-white/[0.02] transition-colors"
                                >
                                    <td className="px-6 py-4 text-sm text-white font-medium">
                                        {scan.project_name}
                                    </td>
                                    <td className="px-6 py-4 text-sm text-slate-300">
                                        {scan.app_type}
                                    </td>
                                    <td className="px-6 py-4 text-center">
                                        <span
                                            className={`inline-block px-3 py-1 rounded-lg text-sm font-semibold ${
                                                RISK_COLORS[scan.risk_label] || "bg-slate-600 text-white"
                                            }`}
                                        >
                                            {scan.risk_score}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-center text-sm text-slate-300">
                                        {scan.threat_count}
                                    </td>

                                    <td className="px-6 py-4 text-sm text-slate-400">
                                        {formatDate(scan.created_at)}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Card>
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
