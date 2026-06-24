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
    LightActionLink,
} from "./components";
import Link from "next/link";
import { AdminStats, RecentActivity, ServiceHealth, ThreatTrend, ThreatDistribution, TopScannedUrl, ScanVolumeData } from "./types";
import { api } from "@/lib/api";
import { TibsaRefreshButton } from "@/components/ui";

// ─── Threat Level Badge ─────────────────────────────────────
function ThreatBadge({ level }: { level: string }) {
    const styles: Record<string, string> = {
        safe: "bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/20",
        low: "bg-[#2F80ED]/10 text-[#2F80ED] border border-[#2F80ED]/20",
        medium: "bg-amber-500/10 text-amber-600 border border-amber-500/20",
        high: "bg-orange-500/10 text-orange-600 border border-orange-500/20",
        critical: "bg-[#EF4444]/10 text-[#EF4444] border border-[#EF4444]/20",
    };
    return (
        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${styles[level] || "bg-[#F4EFE7] text-[#7C6F64] border border-[#E6DDD2]"}`}>
            {level}
        </span>
    );
}

// ─── Service Status Indicator ───────────────────────────────
function StatusDot({ status }: { status: string }) {
    const colors: Record<string, string> = {
        operational: "bg-[#10B981]",
        degraded: "bg-amber-500",
        down: "bg-[#EF4444]",
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
            <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] text-[#1F2933]">
                <div className="flex flex-col items-center justify-center h-64 border border-[#EF4444]/20 bg-[#EF4444]/5 rounded-[20px] shadow-sm">
                    <p className="text-[#EF4444] mb-4 font-semibold text-sm">{error}</p>
                    <button onClick={fetchData} className="px-4 py-2 bg-[#EF4444]/10 text-[#EF4444] rounded-lg hover:bg-[#EF4444]/20 transition-colors font-bold text-xs">
                        Retry Connection
                    </button>
                </div>
            </div>
        );
    }

    if (isLoading) {
        return (
            <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] text-[#1F2933]">
                <div className="space-y-6 max-w-[1400px] animate-pulse">
                    {/* Skeleton header */}
                    <div className="h-[120px] bg-white border border-[#E6DDD2] rounded-[24px] shadow-sm" />
                    {/* Skeleton stat cards */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
                        {Array.from({ length: 6 }).map((_, i) => (
                            <div key={i} className="h-[110px] rounded-[18px] bg-white border border-[#E6DDD2] shadow-sm" />
                        ))}
                    </div>
                    {/* Skeleton charts */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        <div className="lg:col-span-2 h-80 rounded-[20px] bg-white border border-[#E6DDD2] shadow-sm" />
                        <div className="h-80 rounded-[20px] bg-white border border-[#E6DDD2] shadow-sm" />
                    </div>
                    {/* Skeleton bottom row */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <div className="h-72 rounded-[20px] bg-white border border-[#E6DDD2] shadow-sm" />
                        <div className="h-72 rounded-[20px] bg-white border border-[#E6DDD2] shadow-sm" />
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] text-[#1F2933]">
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.4 }}
                className="space-y-6 max-w-[1400px] relative mx-auto"
            >
                {/* ── Page Header ──────────────────────────────── */}
                <motion.div 
                    initial={{ opacity: 0, y: 10, scale: 0.98 }} 
                    animate={{ opacity: 1, y: 0, scale: 1 }} 
                    transition={{ duration: 0.4 }}
                    style={{ background: "linear-gradient(90deg, #FFFCF7 0%, #F4EFE7 45%, #E9EDF3 100%)" }}
                    className="border border-[#E6DDD2] p-[32px] rounded-[24px] shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-6"
                >
                    <div className="flex items-start gap-4">
                        <div className="p-2.5 bg-[#edf8f3] rounded-xl border border-[#0f9d76]/30 shadow-sm shrink-0 mt-1">
                            <IconShield />
                        </div>
                        <div>
                            <div className="flex items-center gap-2 mb-1.5">
                                <span className="text-[10px] font-bold text-[#0f9d76] uppercase tracking-widest">
                                    TIBSA SOC NEXUS
                                </span>
                                {isLive && (
                                    <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-500 text-[10px] font-bold uppercase tracking-widest shadow-sm">
                                        <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                                        LIVE
                                    </span>
                                )}
                            </div>
                            <h1 className="text-2xl font-black text-[#1d1d1d] tracking-tight">Admin Overview</h1>
                            <p className="text-[#7C6F64] mt-1 max-w-xl text-sm leading-relaxed font-medium">
                                Central command view for users, investigations, threats, analytics, and system health.
                            </p>
                        </div>
                    </div>
                    <div className="flex flex-col sm:flex-row items-center gap-3">
                        <button
                            onClick={() => setIsLive(!isLive)}
                            className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-bold transition-colors ${
                                isLive 
                                ? 'bg-red-500/10 border-red-500/20 text-red-500 hover:bg-red-500/15' 
                                : 'bg-white border-[#E6DDD2] text-[#7C6F64] hover:text-[#1F2933]'
                            }`}
                        >
                            <span className={`w-2 h-2 rounded-full ${isLive ? 'bg-red-500 animate-pulse' : 'bg-slate-300'}`} />
                            {isLive ? 'Auto-Refresh ON' : 'Auto-Refresh OFF'}
                        </button>
                        <TibsaRefreshButton
                            onClick={handleRefresh}
                            isRefreshing={refreshing}
                        />
                    </div>
                </motion.div>

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
                <div className="border-t border-[#E6DDD2] pt-6 mt-6">
                    <div className="flex items-center justify-between mb-4">
                        <h2 className="text-sm font-bold text-[#1F2933] uppercase tracking-wider flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-pulse" />
                            Infrastructure Intelligence Metrics
                        </h2>
                        <LightActionLink href="/admin/infra-analytics">Detailed Analytics</LightActionLink>
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
                            <LightActionLink href="/admin/analytics">Analytics</LightActionLink>
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
                            <LightActionLink href="/admin/analytics">Analytics</LightActionLink>
                        }
                    >
                        <ScanVolumeChart data={charts?.volume || []} />
                    </AdminSectionCard>

                    <AdminSectionCard
                        title="Recent Activity"
                        description="Real-time platform events"
                        noPadding
                        action={
                            <LightActionLink href="/admin/audit">View audit log</LightActionLink>
                        }
                    >
                        <div className="px-2 py-2">
                            {activity.length > 0 ? (
                                <ActivityFeed activities={activity} />
                            ) : (
                                <div className="flex flex-col items-center justify-center py-10 text-[#7C6F64]">
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
                                        className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[#F8FDFB] transition-colors group border border-transparent hover:border-[#E6DDD2]"
                                    >
                                        {/* Rank */}
                                        <span className={`flex-shrink-0 w-6 h-6 rounded-md flex items-center justify-center text-[10px] font-bold ${
                                            i < 3 ? "bg-[#2F80ED]/10 text-[#2F80ED]" : "bg-[#F4EFE7] text-[#7C6F64]"
                                        }`}>
                                            {i + 1}
                                        </span>
                                        {/* URL */}
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm font-semibold text-[#1F2933] truncate group-hover:text-[#10B981] transition-colors">
                                                {url.url}
                                            </p>
                                            <p className="text-[11px] text-[#7C6F64] font-medium">
                                                {url.scan_count} scans
                                            </p>
                                        </div>
                                        {/* Threat level */}
                                        <ThreatBadge level={url.threat_level || "unknown"} />
                                    </div>
                                ))
                            ) : (
                                <div className="py-8 text-center text-[#7C6F64] text-sm">No scan targets found.</div>
                            )}
                        </div>
                    </AdminSectionCard>

                    {/* System Health Mini */}
                    <AdminSectionCard
                        title="System Health"
                        description={`${healthyServices}/${totalServices} services operational`}
                        action={
                            <LightActionLink href="/admin/system">Details</LightActionLink>
                        }
                    >
                        <div className="space-y-2">
                            {health.map((service) => (
                                <div
                                    key={service.name}
                                    className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[#F8FDFB] transition-colors group border border-transparent hover:border-[#E6DDD2]"
                                >
                                    <StatusDot status={service.status} />
                                    <div className="flex-1 min-w-0">
                                        <p className="text-sm font-semibold text-[#1F2933] group-hover:text-[#10B981] transition-colors">{service.name}</p>
                                        <p className="text-xs text-[#7C6F64] truncate">{service.description}</p>
                                    </div>
                                    <span className="text-xs text-[#7C6F64] tabular-nums font-mono">{service.responseTime}ms</span>
                                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                                        service.status === "operational" ? "bg-[#10B981]/10 text-[#10B981]" :
                                        service.status === "degraded" ? "bg-amber-500/10 text-amber-600" :
                                        "bg-[#EF4444]/10 text-[#EF4444]"
                                    }`}>
                                        {service.uptime}%
                                    </span>
                                </div>
                            ))}
                        </div>
                        {degradedServices.length > 0 && (
                            <div className="mt-3 px-3 py-2 bg-amber-500/10 border border-amber-500/20 rounded-lg shadow-sm">
                                <p className="text-xs font-bold text-amber-600 flex items-center gap-1.5">
                                    <span className="text-sm">⚠️</span> {degradedServices.map(s => s.name).join(", ")} showing degraded performance
                                </p>
                            </div>
                        )}
                    </AdminSectionCard>

                    {/* Active Analysts & Users Presence */}
                    <AdminSectionCard
                        title="Active Analysts & Users"
                        description={`${presence?.active_count || 0} active analysts online`}
                        action={
                            <LightActionLink href="/admin/users">Manage Users</LightActionLink>
                        }
                    >
                        <div className="space-y-3 max-h-[300px] overflow-y-auto custom-scrollbar pr-1">
                            {/* Active Users */}
                            {presence?.active_users && presence.active_users.length > 0 ? (
                                presence.active_users.map((user) => (
                                    <div key={user.id} className="flex items-center gap-3 px-3 py-2 rounded-lg bg-[#10B981]/5 border border-[#10B981]/20 hover:bg-[#10B981]/10 transition-colors shadow-sm">
                                        {/* Avatar */}
                                        <div className="relative flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-[#10B981] to-[#00A884] flex items-center justify-center shadow-md">
                                            <span className="text-xs font-bold text-white uppercase">{user.full_name.charAt(0)}</span>
                                            <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-[#10B981] border-2 border-white animate-pulse" />
                                        </div>
                                        {/* Info */}
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-1.5">
                                                <p className="text-sm font-bold text-[#1F2933] truncate">{user.full_name}</p>
                                                <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/20 uppercase tracking-wide">
                                                    Active
                                                </span>
                                            </div>
                                            <p className="text-xs text-[#7C6F64] truncate font-medium">{user.email}</p>
                                        </div>
                                        {/* Role Badge */}
                                        <span className={`text-[9px] font-bold px-2 py-0.5 rounded-md border ${
                                            user.role === "admin" ? "bg-[#A855F7]/10 text-[#A855F7] border-[#A855F7]/20" : "bg-[#2F80ED]/10 text-[#2F80ED] border-[#2F80ED]/20"
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
                                        <div key={user.id} className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[#F8FDFB] hover:border-[#E6DDD2] border border-transparent transition-colors group">
                                            {/* Avatar */}
                                            <div className="relative flex-shrink-0 w-8 h-8 rounded-full bg-[#F4EFE7] border border-[#E6DDD2] flex items-center justify-center">
                                                <span className="text-xs font-bold text-[#7C6F64] uppercase">{user.full_name.charAt(0)}</span>
                                                <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-[#E6DDD2] border-2 border-white" />
                                            </div>
                                            {/* Info */}
                                            <div className="flex-1 min-w-0">
                                                <p className="text-sm font-semibold text-[#1F2933] group-hover:text-[#10B981] transition-colors truncate">{user.full_name}</p>
                                                <p className="text-[11px] text-[#7C6F64] truncate font-medium">last seen {lastSeenStr}</p>
                                            </div>
                                            {/* Role Badge */}
                                            <span className={`text-[9px] font-bold px-2 py-0.5 rounded-md border ${
                                                user.role === "admin" ? "bg-white text-[#A855F7] border-[#A855F7]/20" : "bg-white text-[#7C6F64] border-[#E6DDD2]"
                                            }`}>
                                                {user.role === "admin" ? "ADMIN" : "USER"}
                                            </span>
                                        </div>
                                    );
                                })
                            ) : null}

                            {(!presence?.active_users || presence.active_users.length === 0) && 
                             (!presence?.offline_users || presence.offline_users.length === 0) && (
                                <div className="py-8 text-center text-[#7C6F64] text-sm">
                                    No registered analysts found.
                                </div>
                            )}
                        </div>
                    </AdminSectionCard>
                </div>

                {/* ── Quick Navigation ──────────────────────── */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                        { href: "/admin/users", icon: "👥", title: "User Management", desc: "Manage users, roles & permissions", color: "hover:border-[#2F80ED] hover:shadow-[#2F80ED]/10 text-[#2F80ED]" },
                        { href: "/admin/investigations", icon: "🔍", title: "Investigations", desc: "View security operations", color: "hover:border-[#10B981] hover:shadow-[#10B981]/10 text-[#10B981]" },
                        { href: "/admin/analytics", icon: "📊", title: "Platform Analytics", desc: "Usage metrics & growth data", color: "hover:border-[#A855F7] hover:shadow-[#A855F7]/10 text-[#A855F7]" },
                        { href: "/admin/audit", icon: "📋", title: "Audit Log", desc: "Security events & admin actions", color: "hover:border-amber-500 hover:shadow-amber-500/10 text-amber-500" },
                    ].map((item, idx) => (
                        <motion.div
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.3, delay: 0.1 * idx }}
                            key={item.href}
                        >
                            <Link
                                href={item.href}
                                className={`block p-5 rounded-[18px] border border-[#E6DDD2] bg-white shadow-sm transition-all duration-300 group hover:-translate-y-1 hover:shadow-md ${item.color.split(' ')[0]}`}
                            >
                                <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-xl mb-3 bg-[#FAF7F1] border border-[#E6DDD2] group-hover:bg-white transition-colors shadow-sm`}>
                                    {item.icon}
                                </div>
                                <h3 className="text-sm font-bold text-[#1F2933] group-hover:text-[#10B981] transition-colors flex items-center justify-between">
                                    {item.title}
                                    <span className="text-[#7C6F64] group-hover:text-[#10B981] group-hover:translate-x-1 transition-all">→</span>
                                </h3>
                                <p className="text-xs text-[#7C6F64] mt-1.5 font-medium">{item.desc}</p>
                            </Link>
                        </motion.div>
                    ))}
                </div>
            </motion.div>
        </div>
    );
}
