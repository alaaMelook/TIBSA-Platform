"use client";

import { TibsaRefreshButton } from "@/components/ui";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useAuth } from "@/hooks/useAuth";

import {
    StatCard,
    AdminSectionCard,
    ScanVolumeChart,
    UserGrowthChart,
    ThreatTrendChart,
    ThreatDistributionChart,
} from "../components";

// ─── Icons ──────────────────────────────────────────────────
const IconChart = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
);
const IconTrend = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
    </svg>
);
const IconTarget = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" />
    </svg>
);
const IconClock = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <circle cx="12" cy="12" r="10" /><path strokeLinecap="round" d="M12 6v6l4 2" />
    </svg>
);

function ThreatBadge({ level }: { level: string }) {
    const styles: Record<string, string> = {
        safe: "bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/20",
        low: "bg-[#F97316]/15 text-[#F97316] border border-[#F97316]/20",
        medium: "bg-[#F97316]/15 text-[#F97316] border border-[#F97316]/20",
        high: "bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/20",
        critical: "bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/20",
    };
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${styles[level] || styles.safe}`}>
            {level}
        </span>
    );
}

export default function AnalyticsPage() {
    const { token } = useAuth();
    const [stats, setStats] = useState({ 
        totalScans: 0, 
        scansToday: 0,
        totalUsers: 1, 
        activeUsers: 0,
        threatsDetected: 0,
        detectionRate: 0,
        avgResponseTime: 45,
        systemUptime: 99.9
    });
    const [charts, setCharts] = useState<{
        trends: any[];
        distribution: any[];
        scanVolume: any[];
        topUrls: any[];
        growth: any[];
    }>({ trends: [], distribution: [], scanVolume: [], topUrls: [], growth: [] });
    const [isLoading, setIsLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);

    const fetchData = async () => {
        if (!token) return;
        try {
            const [statsRes, chartsRes, growthRes] = await Promise.all([
                fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/stats`, { headers: { Authorization: `Bearer ${token}` } }),
                fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/charts`, { headers: { Authorization: `Bearer ${token}` } }),
                fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/users/growth`, { headers: { Authorization: `Bearer ${token}` } })
            ]);

            if (statsRes.ok) {
                const s = await statsRes.json();
                setStats({
                    totalScans: s.scans.total,
                    scansToday: s.scans.today,
                    totalUsers: s.users.total || 1,
                    activeUsers: s.users.active,
                    threatsDetected: s.threats.total,
                    detectionRate: s.threats.detectionRate || 0,
                    avgResponseTime: 45,
                    systemUptime: 99.9
                });
            }

            let distribution = [], trends = [], scanVolume = [], topUrls = [], growth = [];
            if (chartsRes.ok) {
                const c = await chartsRes.json();
                distribution = (c.threatDistribution || []).map((item: any, i: number) => ({
                    ...item,
                    color: ["#EF4444", "#F97316", "#10B981", "#EF4444", "#A855F7", "#EC4899", "#7C6F64"][i % 7]
                }));
                trends = c.threatTrends || [];
                scanVolume = c.scanVolume || [];
                topUrls = c.topScannedUrls || [];
            }
            if (growthRes.ok) {
                const g = await growthRes.json();
                growth = g.growth;
            }
            setCharts({ distribution, trends, scanVolume, topUrls, growth });
        } catch (err) {
            console.error("Failed to fetch analytics data:", err);
        }
    };

    useEffect(() => {
        if (!token) return;
        setIsLoading(true);
        fetchData().finally(() => setIsLoading(false));
    }, [token]);

    const handleRefresh = async () => {
        setRefreshing(true);
        await fetchData();
        setRefreshing(false);
    };

    // Derived metrics
    const avgScansPerUser = Math.round((stats.totalScans ?? 0) / (stats.totalUsers || 1));
    const detectionRate = (stats.detectionRate ?? 0).toFixed(1);

    return (
        <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] text-[#1F2933]">
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.4 }}
                className="space-y-6 w-full max-w-[1600px] mx-auto"
            >
                {/* ── Header ─────────────────────────────────── */}
                <div 
                    style={{
                        background: "linear-gradient(90deg, #FFFCF7 0%, #F4EFE7 45%, #E9EDF3 100%)"
                    }}
                    className="border border-[#E6DDD2] p-6 md:p-8 rounded-[24px] shadow-sm relative overflow-hidden flex flex-col md:flex-row justify-between items-start md:items-center gap-6"
                >
                    <div className="flex items-start gap-4">
                        <div className="p-2.5 bg-[#10B981]/10 rounded-xl border border-[#10B981]/20 text-[#10B981] shadow-sm shrink-0 mt-1">
                            <IconChart />
                        </div>
                        <div>
                            <div className="flex items-center gap-2 mb-1.5">
                                <span className="text-[10px] font-bold text-[#10B981] uppercase tracking-widest">
                                    Platform Analytics
                                </span>
                            </div>
                            <h1 className="text-2xl font-black text-[#1F2933] tracking-tight">Platform Analytics</h1>
                            <p className="text-[#7C6F64] mt-1 max-w-xl text-sm leading-relaxed font-medium">
                                Comprehensive platform usage metrics and performance insights.
                            </p>
                        </div>
                    </div>
                    <TibsaRefreshButton
                        onClick={handleRefresh}
                        isRefreshing={refreshing}
                    />
                </div>

                {/* ── Key Metrics ────────────────────────────── */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatCard label="Total Scans" value={stats.totalScans} icon={<IconChart />} color="blue" change={23.1} changeLabel="vs last month" trend="up" delay={0} />
                    <StatCard label="Scans Today" value={stats.scansToday} icon={<IconClock />} color="cyan" change={-3.2} changeLabel="vs yesterday" trend="down" delay={100} />
                    <StatCard label="Avg Scans/User" value={avgScansPerUser} icon={<IconTarget />} color="purple" delay={200} />
                    <StatCard label="Detection Rate" value={`${detectionRate}%`} icon={<IconTrend />} color="amber" delay={300} />
                </div>

                {/* ── Charts: Scan Volume + User Growth ──────── */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <AdminSectionCard
                        title="Scan Volume"
                        description="Daily breakdown by scan type — last 7 days"
                    >
                        <ScanVolumeChart data={charts.scanVolume} />
                    </AdminSectionCard>

                    <AdminSectionCard
                        title="User Growth"
                        description="Total vs active users — last 6 months"
                    >
                        <UserGrowthChart data={charts.growth} />
                    </AdminSectionCard>
                </div>

                {/* ── Charts: Threats ────────────────────────── */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <AdminSectionCard
                        title="Threat Detection Trends"
                        description="14-day severity distribution"
                        className="lg:col-span-2"
                    >
                        <ThreatTrendChart data={charts.trends} />
                    </AdminSectionCard>

                    <AdminSectionCard
                        title="Threat Categories"
                        description="All-time distribution"
                    >
                        <ThreatDistributionChart data={charts.distribution} />
                    </AdminSectionCard>
                </div>

                {/* ── Platform Usage Summary + Top URLs ──────── */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Platform Usage Summary */}
                    <AdminSectionCard
                        title="Platform Usage Summary"
                        description="Key performance indicators"
                    >
                        <div className="space-y-4">
                            {[
                                { label: "Total Users Registered", value: (stats.totalUsers ?? 0).toLocaleString(), bar: 100, color: "bg-[#10B981]" },
                                { label: "Active Users (30d)", value: (stats.activeUsers ?? 0).toLocaleString(), bar: ((stats.activeUsers ?? 0) / (stats.totalUsers || 1)) * 100, color: "bg-[#10B981]" },
                                { label: "Scans Processed", value: (stats.totalScans ?? 0).toLocaleString(), bar: 100, color: "bg-[#2F80ED]" },
                                { label: "Threats Detected", value: (stats.threatsDetected ?? 0).toLocaleString(), bar: ((stats.threatsDetected ?? 0) / (stats.totalScans || 1)) * 100 * 10, color: "bg-[#EF4444]" },
                                { label: "Avg Response Time", value: `${stats.avgResponseTime ?? 0}ms`, bar: Math.min(((stats.avgResponseTime ?? 0) / 500) * 100, 100), color: "bg-[#00A884]" },
                                { label: "System Uptime", value: `${stats.systemUptime ?? 0}%`, bar: stats.systemUptime ?? 0, color: "bg-[#10B981]" },
                            ].map((metric) => (
                                <div key={metric.label} className="space-y-1.5">
                                    <div className="flex items-center justify-between">
                                        <span className="text-xs text-[#7C6F64] font-medium">{metric.label}</span>
                                        <span className="text-sm font-semibold text-[#1F2933] tabular-nums">{metric.value}</span>
                                    </div>
                                    <div className="w-full h-1.5 bg-[#FAF7F1] border border-[#E6DDD2] rounded-full overflow-hidden">
                                        <div
                                            className={`h-full rounded-full ${metric.color} transition-all duration-1000 ease-out`}
                                            style={{ width: `${Math.min(metric.bar, 100)}%` }}
                                        />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </AdminSectionCard>

                    {/* Top Scanned URLs */}
                    <AdminSectionCard
                        title="Most Scanned URLs"
                        description="Top targets by scan frequency"
                    >
                        <div className="space-y-2">
                            {(charts.topUrls || []).map((url, i) => (
                                <div
                                    key={i}
                                    className="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-[#FAF7F1] transition-colors"
                                >
                                    <span className={`flex-shrink-0 w-6 h-6 rounded-md flex items-center justify-center text-[10px] font-bold ${
                                        i < 3 ? "bg-[#10B981]/15 text-[#10B981]" : "bg-[#FAF7F1] text-[#7C6F64] border border-[#E6DDD2]"
                                    }`}>
                                        {i + 1}
                                    </span>
                                    <div className="flex-1 min-w-0">
                                        <p className="text-sm text-[#1F2933] truncate font-mono">{url.url}</p>
                                        <div className="flex items-center gap-2 mt-0.5">
                                            <span className="text-[11px] text-[#7C6F64]">{url.scan_count} scans</span>
                                            <span className="text-[11px] text-[#7C6F64]">•</span>
                                            <span className="text-[11px] text-[#7C6F64]">
                                                {new Date(url.last_scanned || Date.now()).toLocaleDateString()}
                                            </span>
                                        </div>
                                    </div>
                                    <ThreatBadge level={url.threat_level} />
                                </div>
                            ))}
                        </div>
                    </AdminSectionCard>
                </div>
            </motion.div>
        </div>
    );
}
