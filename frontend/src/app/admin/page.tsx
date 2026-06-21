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
import Link from "next/link";
import { AdminStats, RecentActivity, ServiceHealth, ThreatTrend, ThreatDistribution, TopScannedUrl, ScanVolumeData } from "./types";
import { api } from "@/lib/api";

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
    const { user, token } = useAuth();
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const [isLive, setIsLive] = useState(() => {
        if (typeof window !== "undefined") {
            return localStorage.getItem("tibsa_live_dashboard") !== "false";
        }
        return true;
    });

    useEffect(() => {
        if (typeof window !== "undefined") {
            localStorage.setItem("tibsa_live_dashboard", String(isLive));
        }
    }, [isLive]);
    
    // Real Data States
    const [stats, setStats] = useState<AdminStats | null>(null);
    const [presence, setPresence] = useState<{
        active_users: any[];
        offline_users: any[];
        active_count: number;
    } | null>(null);
    const [activity, setActivity] = useState<RecentActivity[]>([]);
    const [health, setHealth] = useState<ServiceHealth[]>([]);
    const [charts, setCharts] = useState<{
        trends: ThreatTrend[];
        distribution: ThreatDistribution[];
        volume: ScanVolumeData[];
        topUrls: TopScannedUrl[];
    } | null>(null);

    const [refreshing, setRefreshing] = useState(false);

    const fetchData = async () => {
        if (!token) return;
        try {
            // 1. Fetch Stats
            const statsRes = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/stats`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (statsRes.ok) {
                const s = await statsRes.json();
                setStats({
                    totalUsers: s.users.total,
                    activeUsers: s.users.active,
                    totalScans: s.scans.total,
                    scansToday: s.scans.today,
                    threatsDetected: s.threats.total,
                    threatsToday: s.threats.today, // Map to actual threats found today from API
                    systemUptime: 99.9,
                    avgResponseTime: 45,
                    infra: s.infra
                });
            }

            // 2. Fetch Charts
            const chartsRes = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/charts`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (chartsRes.ok) {
                const c = await chartsRes.json();
                // Ensure colors exist for distribution
                const coloredDist = c.threatDistribution.map((item: any, i: number) => ({
                    ...item,
                    color: ["#ef4444", "#f97316", "#eab308", "#dc2626", "#a855f7", "#ec4899", "#6b7280"][i % 7]
                }));
                setCharts({
                    trends: c.threatTrends,
                    distribution: coloredDist,
                    volume: c.scanVolume,
                    topUrls: c.topScannedUrls
                });
            }

            // 3. Fetch Activity
            const actRes = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/activity`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (actRes.ok) {
                const a = await actRes.json();
                setActivity(a.recentActivity);
            }

            // 4. Fetch Health
            const healthRes = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/health/system`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (healthRes.ok) {
                const h = await healthRes.json();
                setHealth(h.services);
            }

            // 5. Fetch Presence
            try {
                const presenceRes = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/presence`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                if (presenceRes.ok) {
                    const p = await presenceRes.json();
                    setPresence(p);
                }
            } catch (presErr) {
                console.error("Failed to fetch presence:", presErr);
            }

            setError(null);
        } catch (err) {
            console.error("Failed to fetch admin data:", err);
            setError("Failed to load dashboard data");
        } finally {
            setIsLoading(false);
        }
    };

    const handleRefresh = async () => {
        setRefreshing(true);
        await fetchData();
        setRefreshing(false);
    };

    useEffect(() => {
        fetchData();
    }, [token]);

    // Live polling logic (Real API polling, no fake math)
    useEffect(() => {
        if (!isLive) return;
        const interval = setInterval(fetchData, 3000); // Poll every 3s
        return () => clearInterval(interval);
    }, [isLive, token]);

    const healthyServices = health.filter((s) => s.status === "operational").length;
    const totalServices = health.length;
    const degradedServices = health.filter((s) => s.status === "degraded");

    if (error) {
        return (
            <div className="flex flex-col items-center justify-center h-64 border border-red-500/20 bg-red-500/5 rounded-xl">
                <p className="text-red-400 mb-4">{error}</p>
                <button onClick={fetchData} className="px-4 py-2 bg-red-500/20 text-red-300 rounded hover:bg-red-500/30 transition">
                    Retry Connection
                </button>
            </div>
        );
    }

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
                    <button
                        onClick={handleRefresh}
                        disabled={refreshing}
                        className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium rounded bg-white/[0.04] border border-white/[0.08] text-slate-300 hover:bg-white/[0.08] hover:text-white transition-colors disabled:opacity-50"
                    >
                        <svg className={`w-3 h-3 ${refreshing ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                        {refreshing ? "Refreshing..." : "Refresh"}
                    </button>
                    <div className="w-px h-4 bg-white/[0.1]" />
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
                    value={stats?.totalUsers || 0}
                    change={0}
                    changeLabel="Real-time"
                    icon={<IconUsers />}
                    color="blue"
                    trend="neutral"
                    delay={0}
                />
                <StatCard
                    label="Active Users"
                    value={stats?.activeUsers || 0}
                    change={0}
                    changeLabel="Real-time"
                    icon={<IconActive />}
                    color="green"
                    trend="neutral"
                    delay={100}
                />
                <StatCard
                    label="Total Scans"
                    value={stats?.totalScans.toLocaleString() || "0"}
                    change={0}
                    changeLabel="Real-time"
                    icon={<IconScans />}
                    color="purple"
                    trend="neutral"
                    delay={200}
                />
                <StatCard
                    label="Scans Today"
                    value={stats?.scansToday.toLocaleString() || "0"}
                    change={0}
                    changeLabel="Real-time"
                    icon={<IconClock />}
                    color="cyan"
                    trend="neutral"
                    delay={300}
                />
                <StatCard
                    label="Threats Detected"
                    value={stats?.threatsDetected.toLocaleString() || "0"}
                    change={0}
                    changeLabel="Real-time"
                    icon={<IconShield />}
                    color="red"
                    trend="neutral"
                    delay={400}
                />
                <StatCard
                    label="System Uptime"
                    value={`${stats?.systemUptime || 99.9}%`}
                    change={0}
                    changeLabel="Real-time"
                    icon={<IconUptime />}
                    color="green"
                    trend="neutral"
                    delay={500}
                />
            </div>

            {/* ── Infrastructure Intel Stats Grid ─────────────────── */}
            <div className="border-t border-white/[0.08] pt-6 mt-6">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                        Infrastructure Intelligence Metrics
                    </h2>
                    <Link href="/admin/infra-analytics" className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
                        Detailed Analytics →
                    </Link>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 relative z-10">
                    <StatCard
                        label="Total Infra Inv."
                        value={stats?.infra?.total || 0}
                        change={0}
                        changeLabel="Real-time"
                        icon={<IconScans />}
                        color="cyan"
                        trend="neutral"
                        delay={0}
                    />
                    <StatCard
                        label="Investigations Today"
                        value={stats?.infra?.today || 0}
                        change={0}
                        changeLabel="Real-time"
                        icon={<IconClock />}
                        color="blue"
                        trend="neutral"
                        delay={100}
                    />
                    <StatCard
                        label="Running Inv."
                        value={stats?.infra?.running || 0}
                        change={0}
                        changeLabel="Real-time"
                        icon={<IconActive />}
                        color="green"
                        trend="neutral"
                        delay={200}
                    />
                    <StatCard
                        label="Failed Inv."
                        value={stats?.infra?.failed || 0}
                        change={0}
                        changeLabel="Real-time"
                        icon={<IconShield />}
                        color="red"
                        trend="neutral"
                        delay={300}
                    />
                    <StatCard
                        label="Avg Risk Score"
                        value={stats?.infra?.avgRiskScore || 0}
                        change={0}
                        changeLabel="Real-time"
                        icon={<IconShield />}
                        color="amber"
                        trend="neutral"
                        delay={400}
                    />
                    <StatCard
                        label="High Risk IOCs"
                        value={stats?.infra?.highRiskCount || 0}
                        change={0}
                        changeLabel="Real-time"
                        icon={<IconShield />}
                        color="purple"
                        trend="neutral"
                        delay={500}
                    />
                </div>
            </div>

            {/* ── Charts Row: Threat Trends + Distribution ── */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <AdminSectionCard
                    title="Threat Trends"
                    description="Last 14 days detection overview"
                    className="lg:col-span-2"
                    action={
                        <Link href="/admin/analytics" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                            Analytics →
                        </Link>
                    }
                >
                    <ThreatTrendChart data={charts?.trends || []} />
                </AdminSectionCard>

                <AdminSectionCard
                    title="Threat Distribution"
                    description="By category"
                >
                    <ThreatDistributionChart data={charts?.distribution || []} />
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
                    <ScanVolumeChart data={charts?.volume || []} />
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
                        {activity.length > 0 ? (
                            <ActivityFeed activities={activity} />
                        ) : (
                            <div className="flex flex-col items-center justify-center py-10 text-slate-500">
                                <p className="text-sm">No recent activity found.</p>
                            </div>
                        )}
                    </div>
                </AdminSectionCard>
            </div>

            {/* ── Row: Top Scanned URLs + System Health ─── */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Top Scanned URLs */}
                <AdminSectionCard
                    title="Top Scanned URLs"
                    description="Most frequently analyzed targets"
                >
                    <div className="space-y-2">
                        {charts?.topUrls && charts.topUrls.length > 0 ? (
                            charts.topUrls.map((url, i) => (
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
                                    <ThreatBadge level={url.threat_level || "unknown"} />
                                </div>
                            ))
                        ) : (
                            <div className="py-8 text-center text-slate-500 text-sm">No scan targets found.</div>
                        )}
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
                        {health.map((service) => (
                            <div
                                key={service.name}
                                className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/[0.02] transition-colors"
                            >
                                <StatusDot status={service.status} />
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm text-slate-300">{service.name}</p>
                                    <p className="text-xs text-slate-500 truncate">{service.description}</p>
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

                {/* Active Analysts & Users Presence */}
                <AdminSectionCard
                    title="Active Analysts & Users"
                    description={`${presence?.active_count || 0} active analysts online`}
                    action={
                        <Link href="/admin/users" className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                            Manage Users →
                        </Link>
                    }
                >
                    <div className="space-y-3 max-h-[300px] overflow-y-auto pr-1">
                        {/* Active Users */}
                        {presence?.active_users && presence.active_users.length > 0 ? (
                            presence.active_users.map((user) => (
                                <div key={user.id} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-emerald-500/[0.02] border border-emerald-500/10 hover:bg-emerald-500/[0.04] transition-colors">
                                    {/* Avatar */}
                                    <div className="relative flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center shadow-md">
                                        <span className="text-xs font-bold text-white uppercase">{user.full_name.charAt(0)}</span>
                                        <span className="absolute bottom-0 right-0 w-2 h-2 rounded-full bg-emerald-400 border-2 border-[#0B1528] animate-pulse" />
                                    </div>
                                    {/* Info */}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-1.5">
                                            <p className="text-sm font-medium text-white truncate">{user.full_name}</p>
                                            <span className="px-1.5 py-0.5 rounded text-[8px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/20 uppercase tracking-wide">
                                                Active
                                            </span>
                                        </div>
                                        <p className="text-xs text-slate-500 truncate">{user.email}</p>
                                    </div>
                                    {/* Role Badge */}
                                    <span className={`text-[9px] font-semibold px-2 py-0.5 rounded-md ${
                                        user.role === "admin" ? "bg-purple-500/15 text-purple-400 border border-purple-500/20" : "bg-blue-500/15 text-blue-400 border border-blue-500/20"
                                    }`}>
                                        {user.role === "admin" ? "⚡ ADMIN" : "👤 USER"}
                                    </span>
                                </div>
                            ))
                        ) : null}

                        {/* Offline Users */}
                        {presence?.offline_users && presence.offline_users.length > 0 ? (
                            presence.offline_users.map((user) => {
                                const lastSeenStr = user.seconds_ago === 999999 ? "never" : 
                                    user.seconds_ago < 60 ? `${user.seconds_ago}s ago` :
                                    user.seconds_ago < 3600 ? `${Math.floor(user.seconds_ago / 60)}m ago` :
                                    `${Math.floor(user.seconds_ago / 3600)}h ago`;
                                return (
                                    <div key={user.id} className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-white/[0.01] transition-colors group">
                                        {/* Avatar */}
                                        <div className="relative flex-shrink-0 w-8 h-8 rounded-full bg-slate-800 border border-white/[0.06] flex items-center justify-center">
                                            <span className="text-xs font-bold text-slate-400 uppercase">{user.full_name.charAt(0)}</span>
                                            <span className="absolute bottom-0 right-0 w-2 h-2 rounded-full bg-slate-600 border-2 border-[#0B1528]" />
                                        </div>
                                        {/* Info */}
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm font-medium text-slate-400 group-hover:text-white transition-colors truncate">{user.full_name}</p>
                                            <p className="text-xs text-slate-600 truncate font-mono">last seen {lastSeenStr}</p>
                                        </div>
                                        {/* Role Badge */}
                                        <span className={`text-[9px] font-semibold px-2 py-0.5 rounded-md ${
                                            user.role === "admin" ? "bg-white/[0.04] text-purple-400/60 border border-purple-500/10" : "bg-white/[0.04] text-slate-500 border border-white/[0.06]"
                                        }`}>
                                            {user.role === "admin" ? "ADMIN" : "USER"}
                                        </span>
                                    </div>
                                );
                            })
                        ) : null}

                        {(!presence?.active_users || presence.active_users.length === 0) && 
                         (!presence?.offline_users || presence.offline_users.length === 0) && (
                            <div className="py-8 text-center text-slate-500 text-sm">
                                No registered analysts found.
                            </div>
                        )}
                    </div>
                </AdminSectionCard>
            </div>

            {/* ── Quick Navigation ──────────────────────── */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {[
                    { href: "/admin/users", icon: "👥", title: "User Management", desc: "Manage users, roles & permissions", color: "border-blue-500/20 hover:border-blue-500/40 hover:bg-blue-500/5" },
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
