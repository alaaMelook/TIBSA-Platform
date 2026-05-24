"use client";

import { motion } from "framer-motion";

import {
    StatCard,
    AdminSectionCard,
    ScanVolumeChart,
    UserGrowthChart,
    ThreatTrendChart,
    ThreatDistributionChart,
} from "../components";
import {
    mockAdminStats,
    mockScanVolume,
    mockUserGrowth,
    mockThreatTrends,
    mockThreatDistribution,
    mockTopScannedUrls,
} from "../mock";

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
        safe: "bg-emerald-500/15 text-emerald-400",
        low: "bg-yellow-500/15 text-yellow-400",
        medium: "bg-amber-500/15 text-amber-400",
        high: "bg-orange-500/15 text-orange-400",
        critical: "bg-red-500/15 text-red-400",
    };
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${styles[level] || styles.safe}`}>
            {level}
        </span>
    );
}

export default function AnalyticsPage() {
    const stats = mockAdminStats;

    // Derived metrics
    const avgScansPerUser = Math.round(stats.totalScans / stats.totalUsers);
    const detectionRate = ((stats.threatsDetected / stats.totalScans) * 100).toFixed(1);

    return (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }} className="space-y-6 max-w-[1400px]">
            {/* ── Header ─────────────────────────────────── */}
            <div>
                <div className="flex items-center gap-3 mb-1">
                    <h1 className="text-2xl font-bold text-white">Platform Analytics</h1>
                    <span className="px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-widest bg-gradient-to-r from-purple-500/20 to-blue-500/20 border border-purple-500/20 text-purple-400 rounded-full">
                        Insights
                    </span>
                </div>
                <p className="text-sm text-slate-400">Comprehensive platform usage metrics and performance insights</p>
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
                    <ScanVolumeChart data={mockScanVolume} />
                </AdminSectionCard>

                <AdminSectionCard
                    title="User Growth"
                    description="Total vs active users — last 6 months"
                >
                    <UserGrowthChart data={mockUserGrowth} />
                </AdminSectionCard>
            </div>

            {/* ── Charts: Threats ────────────────────────── */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <AdminSectionCard
                    title="Threat Detection Trends"
                    description="14-day severity distribution"
                    className="lg:col-span-2"
                >
                    <ThreatTrendChart data={mockThreatTrends} />
                </AdminSectionCard>

                <AdminSectionCard
                    title="Threat Categories"
                    description="All-time distribution"
                >
                    <ThreatDistributionChart data={mockThreatDistribution} />
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
                            { label: "Total Users Registered", value: stats.totalUsers.toLocaleString(), bar: 100, color: "bg-blue-500" },
                            { label: "Active Users (30d)", value: stats.activeUsers.toLocaleString(), bar: (stats.activeUsers / stats.totalUsers) * 100, color: "bg-emerald-500" },
                            { label: "Scans Processed", value: stats.totalScans.toLocaleString(), bar: 100, color: "bg-purple-500" },
                            { label: "Threats Detected", value: stats.threatsDetected.toLocaleString(), bar: (stats.threatsDetected / stats.totalScans) * 100 * 10, color: "bg-red-500" },
                            { label: "Avg Response Time", value: `${stats.avgResponseTime}ms`, bar: Math.min((stats.avgResponseTime / 500) * 100, 100), color: "bg-cyan-500" },
                            { label: "System Uptime", value: `${stats.systemUptime}%`, bar: stats.systemUptime, color: "bg-emerald-400" },
                        ].map((metric) => (
                            <div key={metric.label} className="space-y-1.5">
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-slate-400">{metric.label}</span>
                                    <span className="text-sm font-semibold text-white tabular-nums">{metric.value}</span>
                                </div>
                                <div className="w-full h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
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
                        {mockTopScannedUrls.map((url, i) => (
                            <div
                                key={i}
                                className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-white/[0.02] transition-colors"
                            >
                                <span className={`flex-shrink-0 w-6 h-6 rounded-md flex items-center justify-center text-[10px] font-bold ${
                                    i < 3 ? "bg-blue-500/15 text-blue-400" : "bg-white/[0.04] text-slate-500"
                                }`}>
                                    {i + 1}
                                </span>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm text-slate-300 truncate font-mono">{url.url}</p>
                                    <div className="flex items-center gap-2 mt-0.5">
                                        <span className="text-[11px] text-slate-500">{url.scan_count} scans</span>
                                        <span className="text-[11px] text-slate-600">•</span>
                                        <span className="text-[11px] text-slate-500">
                                            {new Date(url.last_scanned).toLocaleDateString()}
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
    );
}
