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
            safe: "text-green-600",
            low: "text-yellow-500",
            medium: "text-orange-500",
            high: "text-red-500",
            critical: "text-red-700",
        };
        return colors[level || "safe"] || "text-gray-400";
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900">Scan Reports</h1>
                <p className="text-gray-500 mt-1">View detailed reports for completed scans</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Scan List */}
                <div className="lg:col-span-1">
                    <Card title="Completed Scans">
                        {isLoading ? (
                            <div className="text-center py-8 text-gray-400 text-sm">Loading...</div>
                        ) : scans.length === 0 ? (
                            <div className="text-center py-8 text-gray-400 text-sm">
                                No completed scans yet.
                            </div>
                        ) : (
                            <div className="space-y-2">
                                {scans.map((scan) => (
                                    <button
                                        key={scan.id}
                                        onClick={() => viewReport(scan.id)}
                                        className="w-full text-left p-3 rounded-lg bg-gray-50 hover:bg-blue-50 transition-colors text-sm"
                                    >
                                        <div className="flex items-center justify-between">
                                            <span className="font-medium text-gray-800">
                                                {scan.scan_type === "url" ? "🔗" : "📄"}{" "}
                                                {scan.scan_type.toUpperCase()}
                                            </span>
                                            <span className={`text-xs font-medium capitalize ${threatColor(scan.threat_level)}`}>
                                                {scan.threat_level || "—"}
                                            </span>
                                        </div>
                                        <p className="text-xs text-gray-500 truncate mt-1 font-mono">
                                            {scan.target}
                                        </p>
                                        <p className="text-xs text-gray-400 mt-1">
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
                            <div className="text-center py-12 text-gray-400">Loading report...</div>
                        ) : !selectedReport ? (
                            <div className="text-center py-12 text-gray-400">
                                <p className="text-lg">📄</p>
                                <p className="mt-2">Select a scan to view its report</p>
                            </div>
                        ) : (
                            <div className="space-y-4">
                                <div>
                                    <h3 className="font-medium text-gray-900">Summary</h3>
                                    <p className="text-sm text-gray-600 mt-1">{selectedReport.summary}</p>
                                </div>

                                {selectedReport.indicators?.length > 0 && (
                                    <div>
                                        <h3 className="font-medium text-gray-900 mb-2">Indicators Found</h3>
                                        <div className="space-y-2">
                                            {selectedReport.indicators.map((ind, i) => (
                                                <div key={i} className="flex items-center justify-between bg-gray-50 p-3 rounded-lg text-sm">
                                                    <div>
                                                        <span className="text-gray-400 text-xs uppercase">{ind.type}</span>
                                                        <p className="font-mono text-gray-800">{ind.value}</p>
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
                                        <h3 className="font-medium text-gray-900 mb-2">Details</h3>
                                        <pre className="bg-gray-50 p-3 rounded-lg text-xs text-gray-600 overflow-x-auto">
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
