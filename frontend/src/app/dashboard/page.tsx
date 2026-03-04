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
            safe: "text-green-400",
            low: "text-yellow-400",
            medium: "text-orange-400",
            high: "text-red-400",
            critical: "text-red-500",
        };
        return colors[level || "safe"] || "text-slate-500";
    };

    const statusBadge = (status: string) => {
        const styles: Record<string, string> = {
            pending: "bg-yellow-500/15 text-yellow-400",
            running: "bg-blue-500/15 text-blue-400",
            completed: "bg-green-500/15 text-green-400",
            failed: "bg-red-500/15 text-red-400",
        };
        return styles[status] || "bg-white/5 text-slate-400";
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-white">Dashboard</h1>
                <p className="text-slate-400 mt-1">Welcome back, {user?.full_name}</p>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card className="!p-4">
                    <div className="text-sm text-slate-400">Total Scans</div>
                    <div className="text-2xl font-bold text-white mt-1">
                        {isLoading ? "..." : stats?.total_scans ?? 0}
                    </div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-slate-400">Threats Detected</div>
                    <div className="text-2xl font-bold text-red-400 mt-1">
                        {isLoading ? "..." : stats?.threats_detected ?? 0}
                    </div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-slate-400">Active Scans</div>
                    <div className="text-2xl font-bold text-blue-400 mt-1">
                        {isLoading ? "..." : stats?.active_scans ?? 0}
                    </div>
                </Card>
                <Card className="!p-4">
                    <div className="text-sm text-slate-400">Completed</div>
                    <div className="text-2xl font-bold text-green-400 mt-1">
                        {isLoading ? "..." : stats?.completed_scans ?? 0}
                    </div>
                </Card>
            </div>

            {/* Quick Actions */}
            <Card title="Quick Actions">
                <div className="flex flex-wrap gap-3">
                    <Link
                        href="/dashboard/scans"
                        className="px-4 py-2 bg-[#3b82f6] text-white rounded-lg text-sm hover:bg-[#60a5fa] transition-colors shadow-lg shadow-blue-600/25"
                    >
                        🔍 New URL Scan
                    </Link>
                    <Link
                        href="/dashboard/scans"
                        className="px-4 py-2 bg-[#3b82f6] text-white rounded-lg text-sm hover:bg-[#60a5fa] transition-colors shadow-lg shadow-blue-600/25"
                    >
                        📁 Upload File for Scan
                    </Link>
                    <Link
                        href="/dashboard/threats"
                        className="px-4 py-2 bg-[#263554] text-slate-300 rounded-lg text-sm hover:bg-[#2d3f61] transition-colors border border-white/[0.08]"
                    >
                        🛡️ Threat Lookup
                    </Link>
                    <Link
                        href="/dashboard/reports"
                        className="px-4 py-2 bg-[#263554] text-slate-300 rounded-lg text-sm hover:bg-[#2d3f61] transition-colors border border-white/[0.08]"
                    >
                        📄 View Reports
                    </Link>
                </div>
            </Card>

            {/* Recent Activity */}
            <Card title="Recent Activity" description="Your latest scans and threat detections">
                {isLoading ? (
                    <div className="text-center py-8 text-slate-500">Loading...</div>
                ) : !stats?.recent_scans?.length ? (
                    <div className="text-center py-8 text-slate-500">
                        <p>No recent activity yet.</p>
                        <p className="text-sm mt-1">Start by scanning a URL or uploading a file.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-left border-b border-white/[0.08]">
                                    <th className="pb-3 font-medium text-slate-400">Type</th>
                                    <th className="pb-3 font-medium text-slate-400">Target</th>
                                    <th className="pb-3 font-medium text-slate-400">Status</th>
                                    <th className="pb-3 font-medium text-slate-400">Threat</th>
                                    <th className="pb-3 font-medium text-slate-400">Date</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/[0.06]">
                                {stats.recent_scans.map((scan) => (
                                    <tr key={scan.id} className="hover:bg-white/[0.03]">
                                        <td className="py-3">
                                            {scan.scan_type === "url" ? "🔗" : "📄"} {scan.scan_type.toUpperCase()}
                                        </td>
                                        <td className="py-3 text-slate-400 max-w-xs truncate">{scan.target}</td>
                                        <td className="py-3">
                                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(scan.status)}`}>
                                                {scan.status}
                                            </span>
                                        </td>
                                        <td className={`py-3 font-medium ${threatColor(scan.threat_level)}`}>
                                            {scan.threat_level || "—"}
                                        </td>
                                        <td className="py-3 text-slate-500 text-xs">
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
