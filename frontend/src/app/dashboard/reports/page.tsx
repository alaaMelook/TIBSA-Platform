"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card } from "@/components/ui";

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

export default function ReportsPage() {
    const { token } = useAuth();
    const [scans, setScans] = useState<Scan[]>([]);
    const [selectedReport, setSelectedReport] = useState<ScanReport | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [reportLoading, setReportLoading] = useState(false);

    const fetchScans = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<Scan[]>("/api/v1/scans/", token);
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

    const viewReport = async (scanId: string) => {
        if (!token) return;
        setReportLoading(true);
        try {
            const data = await api.get<ScanReport>(`/api/v1/scans/${scanId}`, token);
            setSelectedReport(data);
        } catch {
            setSelectedReport(null);
        } finally {
            setReportLoading(false);
        }
    };

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
        </div>
    );
}
