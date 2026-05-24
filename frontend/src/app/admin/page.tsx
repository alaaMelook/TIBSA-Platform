"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useAuth } from "@/hooks/useAuth";
import {
    StatCard,
    ThreatTrendChart,
    ThreatDistributionChart,
    ScanVolumeChart,
    ActivityFeed,
    AdminSectionCard,
} from "./components";
import {
    mockAdminStats,
    mockThreatTrends,
    mockThreatDistribution,
    mockScanVolume,
    mockRecentActivity,
    mockTopScannedUrls,
    mockServiceHealth,
} from "./mock";
import Link from "next/link";

// ─── Threat Level Badge ─────────────────────────────────────
function ThreatBadge({ level }: { level: string }) {
    const styles: Record<string, string> = {
        safe: "bg-emerald-500/15 text-emerald-400",
        low: "bg-yellow-500/15 text-yellow-400",
        medium: "bg-amber-500/15 text-amber-400",
        high: "bg-orange-500/15 text-orange-400",
        critical: "bg-red-500/15 text-red-400",
    };
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide ${styles[level] || styles.safe}`}>
            {level}
        </span>
    );
}

// ─── Service Status Indicator ───────────────────────────────
function StatusDot({ status }: { status: string }) {
    const colors: Record<string, string> = {
        operational: "bg-emerald-400",
        degraded: "bg-amber-400",
        down: "bg-red-400",
    };
    return (
        <span className="relative flex h-2.5 w-2.5">
            {status === "operational" && (
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${colors[status]} opacity-30`} />
            )}
            <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${colors[status] || colors.operational}`} />
        </span>
    );
}

// ─── Icons ──────────────────────────────────────────────────
const IconUsers = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
);
const IconScans = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <circle cx="11" cy="11" r="8" /><path strokeLinecap="round" d="M21 21l-4.35-4.35" />
    </svg>
);
const IconShield = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
);
const IconUptime = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
);
const IconActive = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
);
const IconClock = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <circle cx="12" cy="12" r="10" /><path strokeLinecap="round" d="M12 6v6l4 2" />
    </svg>
);

export default function AdminPage() {
    const { user } = useAuth();
    const [isLoading, setIsLoading] = useState(true);

    const [isLive, setIsLive] = useState(true);
    const [liveStats, setLiveStats] = useState(mockAdminStats);
    const [liveActivity, setLiveActivity] = useState(mockRecentActivity);

    // TODO: Replace mock data with API calls
    useEffect(() => {
        const timer = setTimeout(() => setIsLoading(false), 600);
        return () => clearTimeout(timer);
    }, []);

    // SOC Live Simulation
    useEffect(() => {
        if (!isLive) return;
        const interval = setInterval(() => {
            setLiveStats(prev => ({
                ...prev,
                totalScans: prev.totalScans + Math.floor(Math.random() * 3),
                scansToday: prev.scansToday + Math.floor(Math.random() * 3),
                threatsDetected: prev.threatsDetected + (Math.random() > 0.8 ? 1 : 0),
                threatsToday: prev.threatsToday + (Math.random() > 0.8 ? 1 : 0),
            }));

            if (Math.random() > 0.6) {
                setLiveActivity(prev => {
                    const severities = ["info", "warning", "critical", "success"] as const;
                    const newActivity = {
                        id: `live-${Date.now()}`,
                        type: "scan" as const,
                        message: "Real-time heuristic scan completed on new payload",
                        timestamp: new Date().toISOString(),
                        severity: severities[Math.floor(Math.random() * severities.length)],
                    };
                    return [newActivity, ...prev.slice(0, 19)];
                });
            }
        }, 3000);
        return () => clearInterval(interval);
    }, [isLive]);

    const healthyServices = mockServiceHealth.filter((s) => s.status === "operational").length;
    const totalServices = mockServiceHealth.length;
    const degradedServices = mockServiceHealth.filter((s) => s.status === "degraded");

    if (isLoading) {
        return (
            <div className="space-y-6 max-w-[1400px] animate-pulse">
                {/* Skeleton header */}
                <div className="flex items-center justify-between">
                    <div>
                        <div className="h-7 w-56 bg-white/[0.04] rounded-lg" />
                        <div className="h-4 w-80 bg-white/[0.03] rounded mt-2" />
                    </div>
                    <div className="h-4 w-40 bg-white/[0.03] rounded hidden md:block" />
                </div>
                {/* Skeleton stat cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
                    {Array.from({ length: 6 }).map((_, i) => (
                        <div key={i} className="h-28 rounded-xl bg-white/[0.03] border border-white/[0.04]" />
                    ))}
                </div>
                {/* Skeleton charts */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div className="lg:col-span-2 h-80 rounded-xl bg-white/[0.03] border border-white/[0.04]" />
                    <div className="h-80 rounded-xl bg-white/[0.03] border border-white/[0.04]" />
                </div>
                {/* Skeleton bottom row */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="h-72 rounded-xl bg-white/[0.03] border border-white/[0.04]" />
                    <div className="h-72 rounded-xl bg-white/[0.03] border border-white/[0.04]" />
                </div>
            </div>
        );
    }

    return (
        <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.4 }}
            className="space-y-6 max-w-[1400px] relative"
        >
            {/* Subtle SOC Scanline / Glow Effect */}
            <div className="absolute top-0 left-0 w-full h-[500px] bg-gradient-to-b from-blue-500/[0.02] to-transparent pointer-events-none -z-10" />

            {/* ── Page Header ──────────────────────────────── */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <div className="flex items-center gap-3 mb-1">
                        <h1 className="text-2xl font-bold text-white tracking-tight">SOC Monitoring Console</h1>
                        {isLive && (
                            <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] font-bold uppercase tracking-widest shadow-[0_0_10px_rgba(239,68,68,0.2)]">
                                <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                                LIVE
                            </span>
                        )}
                    </div>
                    <p className="text-sm text-slate-400">
                        Active threat monitoring and platform oversight for <span className="text-slate-200 font-medium">{user?.full_name}</span>
                    </p>
                </div>
                <div className="flex items-center gap-4 bg-black/40 border border-white/[0.06] rounded-lg p-2 backdrop-blur-md">
                    <div className="flex items-center gap-2 text-xs">
                        <span className="text-slate-400 font-mono">AUTO-REFRESH</span>
                        <button 
                            onClick={() => setIsLive(!isLive)}
                            className={`w-8 h-4 rounded-full transition-colors relative ${isLive ? 'bg-red-500/80 shadow-[0_0_8px_rgba(239,68,68,0.4)]' : 'bg-slate-700'}`}
                        >
                            <span className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform ${isLive ? 'translate-x-4' : 'translate-x-0'}`} />
                        </button>
                    </div>
                    <div className="w-px h-4 bg-white/[0.1]" />
                    <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.4)]" />
                        <span>SYSTEMS_NOMINAL</span>
                    </div>
                </div>
            </div>

            {/* ── Stats Grid ─────────────────────────────── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 relative z-10">
                <StatCard
                    label="Total Users"
                    value={liveStats.totalUsers}
                    change={12.5}
                    changeLabel="vs last month"
                    icon={<IconUsers />}
                    color="blue"
                    trend="up"
                    delay={0}
                />
                <StatCard
                    label="Active Users"
                    value={liveStats.activeUsers}
                    change={8.3}
                    changeLabel="vs last month"
                    icon={<IconActive />}
                    color="green"
                    trend="up"
                    delay={100}
                />
                <StatCard
                    label="Total Scans"
                    value={liveStats.totalScans.toLocaleString()}
                    change={23.1}
                    changeLabel="vs last month"
                    icon={<IconScans />}
                    color="purple"
                    trend="up"
                    delay={200}
                />
                <StatCard
                    label="Scans Today"
                    value={liveStats.scansToday.toLocaleString()}
                    change={-3.2}
                    changeLabel="vs yesterday"
                    icon={<IconClock />}
                    color="cyan"
                    trend="down"
                    delay={300}
                />
                <StatCard
                    label="Threats Detected"
                    value={liveStats.threatsDetected.toLocaleString()}
                    change={15.4}
                    changeLabel="vs last month"
                    icon={<IconShield />}
                    color="red"
                    trend="up"
                    delay={400}
                />
                <StatCard
                    label="System Uptime"
                    value={`${liveStats.systemUptime}%`}
                    change={0.1}
                    changeLabel="vs last month"
                    icon={<IconUptime />}
                    color="green"
                    trend="up"
                    delay={500}
                />
            </div>

            {/* ── Charts Row: Threat Trends + Distribution ── */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <AdminSectionCard
                    title="Threat Trends"
                    description="Last 14 days detection overview"
                    className="lg:col-span-2"
                    action={
                        <Link href="/admin/threats" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                            View all →
                        </Link>
                    }
                >
                    <ThreatTrendChart data={mockThreatTrends} />
                </AdminSectionCard>

                <AdminSectionCard
                    title="Threat Distribution"
                    description="By category"
                >
                    <ThreatDistributionChart data={mockThreatDistribution} />
                </AdminSectionCard>
            </div>

            {/* ── Row: Scan Volume + Activity Feed ──────── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <AdminSectionCard
                    title="Scan Volume"
                    description="Last 7 days"
                    action={
                        <Link href="/admin/analytics" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                            Analytics →
                        </Link>
                    }
                >
                    <ScanVolumeChart data={mockScanVolume} />
                </AdminSectionCard>

                <AdminSectionCard
                    title="Recent Activity"
                    description="Real-time platform events"
                    noPadding
                    action={
                        <Link href="/admin/audit" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                            View audit log →
                        </Link>
                    }
                >
                    <div className="px-2 py-2">
                        <ActivityFeed activities={liveActivity} />
                    </div>
                </AdminSectionCard>
            </div>

            {/* ── Row: Top Scanned URLs + System Health ─── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Top Scanned URLs */}
                <AdminSectionCard
                    title="Top Scanned URLs"
                    description="Most frequently analyzed targets"
                >
                    <div className="space-y-2">
                        {mockTopScannedUrls.slice(0, 6).map((url, i) => (
                            <div
                                key={i}
                                className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/[0.02] transition-colors group"
                            >
                                {/* Rank */}
                                <span className={`flex-shrink-0 w-6 h-6 rounded-md flex items-center justify-center text-[10px] font-bold ${
                                    i < 3 ? "bg-blue-500/15 text-blue-400" : "bg-white/[0.04] text-slate-500"
                                }`}>
                                    {i + 1}
                                </span>
                                {/* URL */}
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm text-slate-300 truncate group-hover:text-white transition-colors">
                                        {url.url}
                                    </p>
                                    <p className="text-[11px] text-slate-500">
                                        {url.scan_count} scans
                                    </p>
                                </div>
                                {/* Threat level */}
                                <ThreatBadge level={url.threat_level} />
                            </div>
                        ))}
                    </div>
                </AdminSectionCard>

                {/* System Health Mini */}
                <AdminSectionCard
                    title="System Health"
                    description={`${healthyServices}/${totalServices} services operational`}
                    action={
                        <Link href="/admin/system" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                            Details →
                        </Link>
                    }
                >
                    <div className="space-y-2">
                        {mockServiceHealth.map((service) => (
                            <div
                                key={service.name}
                                className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/[0.02] transition-colors"
                            >
                                <StatusDot status={service.status} />
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm text-slate-300">{service.name}</p>
                                </div>
                                <span className="text-xs text-slate-500 tabular-nums">{service.responseTime}ms</span>
                                <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
                                    service.status === "operational" ? "bg-emerald-500/10 text-emerald-400" :
                                    service.status === "degraded" ? "bg-amber-500/10 text-amber-400" :
                                    "bg-red-500/10 text-red-400"
                                }`}>
                                    {service.uptime}%
                                </span>
                            </div>
                        ))}
                    </div>
                    {degradedServices.length > 0 && (
                        <div className="mt-3 px-3 py-2 bg-amber-500/5 border border-amber-500/10 rounded-lg">
                            <p className="text-xs text-amber-400">
                                ⚠️ {degradedServices.map(s => s.name).join(", ")} showing degraded performance
                            </p>
                        </div>
                    )}
                </AdminSectionCard>
            </div>

            {/* ── Quick Navigation ──────────────────────── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                    { href: "/admin/users", icon: "👥", title: "User Management", desc: "Manage users, roles & permissions", color: "border-blue-500/20 hover:border-blue-500/40 hover:bg-blue-500/5" },
                    { href: "/admin/threats", icon: "🛡️", title: "Threat Intelligence", desc: "Feeds, indicators & blocklists", color: "border-red-500/20 hover:border-red-500/40 hover:bg-red-500/5" },
                    { href: "/admin/analytics", icon: "📊", title: "Platform Analytics", desc: "Usage metrics & growth data", color: "border-purple-500/20 hover:border-purple-500/40 hover:bg-purple-500/5" },
                    { href: "/admin/audit", icon: "📋", title: "Audit Log", desc: "Security events & admin actions", color: "border-amber-500/20 hover:border-amber-500/40 hover:bg-amber-500/5" },
                ].map((item) => (
                    <Link
                        key={item.href}
                        href={item.href}
                        className={`block p-5 rounded-xl border bg-white/[0.01] transition-all duration-300 group ${item.color}`}
                    >
                        <span className="text-2xl">{item.icon}</span>
                        <h3 className="text-sm font-semibold text-white mt-3 group-hover:text-blue-300 transition-colors">{item.title}</h3>
                        <p className="text-xs text-slate-500 mt-1">{item.desc}</p>
                    </Link>
                ))}
            </div>
        </motion.div>
    );
}
