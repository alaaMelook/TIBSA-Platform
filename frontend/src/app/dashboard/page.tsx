"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card } from "@/components/ui";
import Link from "next/link";

interface DashboardStats {
    total_scans: number;
    active_scans: number;
    threats_detected: number;
    completed_scans: number;
    recent_scans: Array<{
        id: string;
        scan_type: string;
        target: string;
        status: string;
        threat_level: string | null;
        created_at: string;
    }>;
}

export default function DashboardPage() {
    const { user, token } = useAuth();
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    const fetchStats = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<DashboardStats>("/api/v1/users/dashboard/stats", token);
            setStats(data);
        } catch (error) {
            console.error("Failed to fetch stats:", error);
        } finally {
            setIsLoading(false);
        }
    }, [token]);

    useEffect(() => {
        fetchStats();
    }, [fetchStats]);

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

    const statusBadge = (status: string) => {
        const styles: Record<string, string> = {
            pending: "bg-yellow-100 text-yellow-700",
            running: "bg-blue-100 text-blue-700",
            completed: "bg-green-100 text-green-700",
            failed: "bg-red-100 text-red-700",
        };
        return styles[status] || "bg-gray-100 text-gray-600";
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
                <p className="text-gray-500 mt-1">Welcome back, {user?.full_name}</p>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card className="!p-4">
                    <div className="text-sm text-gray-500">Total Scans</div>
                    <div className="text-2xl font-bold text-gray-900 mt-1">
                        {isLoading ? "..." : stats?.total_scans ?? 0}
                    </div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-gray-500">Threats Detected</div>
                    <div className="text-2xl font-bold text-red-600 mt-1">
                        {isLoading ? "..." : stats?.threats_detected ?? 0}
                    </div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-gray-500">Active Scans</div>
                    <div className="text-2xl font-bold text-blue-600 mt-1">
                        {isLoading ? "..." : stats?.active_scans ?? 0}
                    </div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-gray-500">Completed</div>
                    <div className="text-2xl font-bold text-green-600 mt-1">
                        {isLoading ? "..." : stats?.completed_scans ?? 0}
                    </div>
                </Card>
            </div>

            {/* Quick Actions */}
            <Card title="Quick Actions">
                <div className="flex flex-wrap gap-3">
                    <Link
                        href="/dashboard/scans"
                        className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 transition-colors"
                    >
                        🔍 New URL Scan
                    </Link>
                    <Link
                        href="/dashboard/scans"
                        className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 transition-colors"
                    >
                        📁 Upload File for Scan
                    </Link>
                    <Link
                        href="/dashboard/threats"
                        className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm hover:bg-gray-200 transition-colors"
                    >
                        🛡️ Threat Lookup
                    </Link>
                    <Link
                        href="/dashboard/reports"
                        className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm hover:bg-gray-200 transition-colors"
                    >
                        📄 View Reports
                    </Link>
                </div>
            </Card>

            {/* Recent Activity */}
            <Card title="Recent Activity" description="Your latest scans and threat detections">
                {isLoading ? (
                    <div className="text-center py-8 text-gray-400">Loading...</div>
                ) : !stats?.recent_scans?.length ? (
                    <div className="text-center py-8 text-gray-400">
                        <p>No recent activity yet.</p>
                        <p className="text-sm mt-1">Start by scanning a URL or uploading a file.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-left border-b border-gray-200">
                                    <th className="pb-3 font-medium text-gray-500">Type</th>
                                    <th className="pb-3 font-medium text-gray-500">Target</th>
                                    <th className="pb-3 font-medium text-gray-500">Status</th>
                                    <th className="pb-3 font-medium text-gray-500">Threat</th>
                                    <th className="pb-3 font-medium text-gray-500">Date</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100">
                                {stats.recent_scans.map((scan) => (
                                    <tr key={scan.id} className="hover:bg-gray-50">
                                        <td className="py-3">
                                            {scan.scan_type === "url" ? "🔗" : "📄"} {scan.scan_type.toUpperCase()}
                                        </td>
                                        <td className="py-3 text-gray-600 max-w-xs truncate">{scan.target}</td>
                                        <td className="py-3">
                                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(scan.status)}`}>
                                                {scan.status}
                                            </span>
                                        </td>
                                        <td className={`py-3 font-medium ${threatColor(scan.threat_level)}`}>
                                            {scan.threat_level || "—"}
                                        </td>
                                        <td className="py-3 text-gray-400 text-xs">
                                            {new Date(scan.created_at).toLocaleDateString()}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </Card>
        </div>
    );
}
