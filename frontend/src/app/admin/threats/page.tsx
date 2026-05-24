"use client";

import { useState, useMemo } from "react";
import { motion } from "framer-motion";
import {
    StatCard,
    AdminSectionCard,
    ThreatTrendChart,
    ThreatDistributionChart,
    DataTable,
    InvestigationDrawer,
} from "../components";
import type { Column } from "../components";
import type { InvestigationContext } from "../components/InvestigationDrawer";
import type { TopThreat, ThreatFeedConfig } from "../types";
import {
    mockAdminStats,
    mockThreatTrends,
    mockThreatDistribution,
    mockTopThreats,
    mockThreatFeeds,
} from "../mock";

// ─── Icons ──────────────────────────────────────────────────
const IconShield = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
);
const IconAlert = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
);
const IconFeed = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 5c7.18 0 13 5.82 13 13M6 11a7 7 0 017 7m-6 0a1 1 0 11-2 0 1 1 0 012 0z" />
    </svg>
);
const IconIndicator = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
    </svg>
);

// ─── Threat Level Badge ─────────────────────────────────────
function ThreatBadge({ level }: { level: string }) {
    const styles: Record<string, string> = {
        critical: "bg-red-500/15 text-red-400 border-red-500/20",
        high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
        medium: "bg-amber-500/15 text-amber-400 border-amber-500/20",
        low: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
    };
    return (
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide border ${styles[level] || styles.medium}`}>
            {level}
        </span>
    );
}

// ─── Type Badge ─────────────────────────────────────────────
function TypeBadge({ type }: { type: string }) {
    const styles: Record<string, string> = {
        ip: "bg-blue-500/15 text-blue-400",
        domain: "bg-purple-500/15 text-purple-400",
        hash: "bg-cyan-500/15 text-cyan-400",
        url: "bg-amber-500/15 text-amber-400",
        email: "bg-emerald-500/15 text-emerald-400",
    };
    return (
        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${styles[type] || "bg-white/5 text-slate-400"}`}>
            {type.toUpperCase()}
        </span>
    );
}

// ─── Category Badge ─────────────────────────────────────────
function CategoryBadge({ category }: { category: string }) {
    const styles: Record<string, string> = {
        malware: "bg-red-500/10 text-red-400",
        phishing: "bg-orange-500/10 text-orange-400",
        c2: "bg-amber-500/10 text-amber-400",
        botnet: "bg-purple-500/10 text-purple-400",
        apt: "bg-pink-500/10 text-pink-400",
        general: "bg-slate-500/10 text-slate-400",
    };
    return (
        <span className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase ${styles[category] || styles.general}`}>
            {category}
        </span>
    );
}

export default function ThreatIntelligencePage() {
    const [activeTab, setActiveTab] = useState<"overview" | "threats" | "feeds">("overview");
    const [drawerContext, setDrawerContext] = useState<InvestigationContext | null>(null);

    const stats = mockAdminStats;
    const activeFeeds = mockThreatFeeds.filter((f) => f.is_active).length;
    const totalIndicators = mockThreatFeeds.reduce((sum, f) => sum + f.indicators_count, 0);

    // SOC Threat Scoring & Aggregation System
    const scoredTopThreats = useMemo(() => {
        return mockTopThreats.map(threat => {
            // 1. Standardize name based on type
            let name = "Unknown Indicator";
            if (threat.type === "ip") name = "Malicious Host / Botnet";
            if (threat.type === "domain") name = "Phishing Campaign";
            if (threat.type === "hash") name = "Malware Payload";
            if (threat.type === "url") name = "Weaponized URL";
            
            // 2. Compute Score: frequency * severity + recency bonus
            const severityWeight = { "critical": 3, "high": 2, "medium": 1, "low": 0.5 }[threat.threat_level] || 1;
            
            // Mock recency: For demo purposes, we'll assign a dynamic recency bonus based on detections mod
            // Since mock dates are static, we fake the recency bonus based on ID for a realistic spread
            const idMod = parseInt(threat.id.replace(/\D/g, "")) || 0;
            const recencyBonus = idMod % 2 === 0 ? 150 : 50; 
            
            const score = Math.floor((threat.detections * severityWeight) + recencyBonus);
            
            // 3. Determine Trend
            const trend = score > 2000 ? "up" : score > 1000 ? "neutral" : "down";
            
            return { ...threat, name, score, trend } as TopThreat;
        }).sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, 5); // Limit Top 5
    }, []);

    const threatColumns: Column<TopThreat>[] = [
        {
            key: "indicator",
            label: "Indicator",
            sortable: true,
            render: (t) => (
                <div 
                    className="flex items-center gap-3 cursor-pointer group hover:bg-white/[0.04] p-1.5 -m-1.5 rounded transition-colors"
                    onClick={() => setDrawerContext({ type: t.type === "ip" ? "ip" : "threat", value: t.indicator, data: t })}
                >
                    <TypeBadge type={t.type} />
                    <div>
                        <p className="text-xs font-semibold text-slate-300">{t.name}</p>
                        <span className="text-[10px] text-slate-500 font-mono truncate max-w-[200px] block group-hover:text-blue-400 transition-colors">
                            {t.indicator}
                        </span>
                    </div>
                </div>
            ),
        },
        {
            key: "threat_level",
            label: "Severity",
            sortable: true,
            render: (t) => <ThreatBadge level={t.threat_level} />,
        },
        {
            key: "score",
            label: "Threat Score",
            sortable: true,
            render: (t) => (
                <div className="flex items-center gap-2">
                    <span className={`text-sm font-bold tabular-nums ${
                        (t.score || 0) > 2000 ? "text-red-400" :
                        (t.score || 0) > 1000 ? "text-amber-400" : "text-blue-400"
                    }`}>
                        {t.score?.toLocaleString()}
                    </span>
                    {t.trend === "up" && <span className="text-red-500 text-xs font-bold">↑</span>}
                    {t.trend === "down" && <span className="text-emerald-500 text-xs font-bold">↓</span>}
                    {t.trend === "neutral" && <span className="text-slate-500 text-xs font-bold">—</span>}
                </div>
            ),
        },
        {
            key: "detections",
            label: "Detections",
            sortable: true,
            render: (t) => <span className="text-sm text-slate-300 tabular-nums">{t.detections.toLocaleString()}</span>,
        },
        {
            key: "source",
            label: "Source",
            render: (t) => <span className="text-xs text-slate-400">{t.source}</span>,
        },
        {
            key: "last_seen",
            label: "Last Seen",
            sortable: true,
            render: (t) => <span className="text-xs text-slate-500">{new Date(t.last_seen).toLocaleString()}</span>,
        },
    ];

    const feedColumns: Column<ThreatFeedConfig>[] = [
        {
            key: "name",
            label: "Feed",
            sortable: true,
            render: (f) => (
                <div>
                    <p className="text-sm font-medium text-white">{f.name}</p>
                    <p className="text-xs text-slate-500">{f.provider}</p>
                </div>
            ),
        },
        {
            key: "category",
            label: "Category",
            render: (f) => <CategoryBadge category={f.category} />,
        },
        {
            key: "is_active",
            label: "Status",
            sortable: true,
            render: (f) => (
                <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${f.is_active ? "bg-emerald-400" : "bg-red-400"}`} />
                    <span className={`text-xs font-medium ${f.is_active ? "text-emerald-400" : "text-red-400"}`}>
                        {f.is_active ? "Active" : "Paused"}
                    </span>
                </div>
            ),
        },
        {
            key: "indicators_count",
            label: "Indicators",
            sortable: true,
            render: (f) => <span className="text-sm text-slate-300 tabular-nums">{f.indicators_count.toLocaleString()}</span>,
        },
        {
            key: "reliability_score",
            label: "Reliability",
            sortable: true,
            render: (f) => (
                <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                        <div
                            className={`h-full rounded-full ${f.reliability_score >= 90 ? "bg-emerald-400" : f.reliability_score >= 80 ? "bg-amber-400" : "bg-red-400"}`}
                            style={{ width: `${f.reliability_score}%` }}
                        />
                    </div>
                    <span className="text-xs text-slate-400 tabular-nums">{f.reliability_score}%</span>
                </div>
            ),
        },
        {
            key: "update_frequency",
            label: "Frequency",
            render: (f) => <span className="text-xs text-slate-400">{f.update_frequency}</span>,
        },
    ];

    const tabs = [
        { key: "overview" as const, label: "Overview" },
        { key: "threats" as const, label: "Top Threats" },
        { key: "feeds" as const, label: "Feed Management" },
    ];

    return (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }} className="space-y-6 max-w-[1400px]">
            {/* ── Header ─────────────────────────────────── */}
            <div className="flex items-center justify-between flex-wrap gap-4">
                <div>
                    <div className="flex items-center gap-3 mb-1">
                        <h1 className="text-2xl font-bold text-white">Threat Intelligence Hub</h1>
                        <span className="px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-widest bg-gradient-to-r from-red-500/20 to-orange-500/20 border border-red-500/20 text-red-400 rounded-full">
                            Intel
                        </span>
                    </div>
                    <p className="text-sm text-slate-400">Monitor threats, manage feeds, and track indicators of compromise</p>
                </div>

                {/* Tab Switcher */}
                <div className="flex items-center bg-white/[0.03] border border-white/[0.06] rounded-lg p-1">
                    {tabs.map((tab) => (
                        <button
                            key={tab.key}
                            onClick={() => setActiveTab(tab.key)}
                            className={`px-4 py-1.5 text-xs font-medium rounded-md transition-all ${
                                activeTab === tab.key
                                    ? "bg-blue-500/20 text-blue-400 border border-blue-500/20"
                                    : "text-slate-400 hover:text-slate-200"
                            }`}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* ── Stats ──────────────────────────────────── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard label="Total Threats" value={stats.threatsDetected} icon={<IconShield />} color="red" change={15.2} changeLabel="vs last month" trend="up" delay={0} />
                <StatCard label="Threats Today" value={stats.threatsToday} icon={<IconAlert />} color="amber" change={18.7} changeLabel="vs yesterday" trend="up" delay={100} />
                <StatCard label="Active Feeds" value={activeFeeds} icon={<IconFeed />} color="green" delay={200} />
                <StatCard label="Total Indicators" value={totalIndicators} icon={<IconIndicator />} color="purple" change={5.4} changeLabel="vs last week" trend="up" delay={300} />
            </div>

            {/* ── Tab Content ────────────────────────────── */}
            {activeTab === "overview" && (
                <div className="space-y-6">
                    {/* Charts */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        <AdminSectionCard
                            title="Threat Trends"
                            description="14-day severity breakdown"
                            className="lg:col-span-2"
                        >
                            <ThreatTrendChart data={mockThreatTrends} />
                        </AdminSectionCard>
                        <AdminSectionCard
                            title="Threat Categories"
                            description="Distribution by type"
                        >
                            <ThreatDistributionChart data={mockThreatDistribution} />
                        </AdminSectionCard>
                    </div>

                    {/* Top Threats Preview */}
                    <AdminSectionCard
                        title="Top Threats"
                        description="Most detected indicators of compromise"
                        action={
                            <button
                                onClick={() => setActiveTab("threats")}
                                className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                            >
                                View all →
                            </button>
                        }
                    >
                        <DataTable
                            columns={threatColumns}
                            data={mockTopThreats}
                            pageSize={5}
                            emptyMessage="No threats detected"
                        />
                    </AdminSectionCard>
                </div>
            )}

            {activeTab === "threats" && (
                <AdminSectionCard
                    title="All Threat Indicators"
                    description="Complete list of detected indicators of compromise"
                >
                    <DataTable
                        columns={threatColumns}
                        data={scoredTopThreats}
                        pageSize={10}
                        searchable
                        searchKeys={["indicator", "source", "name"]}
                        searchPlaceholder="Search top threats..."
                        emptyMessage="No threats found matching your search"
                    />
                </AdminSectionCard>
            )}

            {activeTab === "feeds" && (
                <AdminSectionCard
                    title="Threat Feed Configuration"
                    description="Manage your threat intelligence sources"
                    action={
                        <button className="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-500/20 border border-blue-500/20 text-blue-400 hover:bg-blue-500/30 transition-colors">
                            + Add Feed
                        </button>
                    }
                >
                    <DataTable
                        columns={feedColumns}
                        data={mockThreatFeeds}
                        searchable
                        searchPlaceholder="Search feeds..."
                        searchKeys={["name", "provider", "category"]}
                        pageSize={10}
                        emptyMessage="No feeds configured"
                    />
                </AdminSectionCard>
            )}

            <InvestigationDrawer
                isOpen={!!drawerContext}
                onClose={() => setDrawerContext(null)}
                context={drawerContext}
            />
        </motion.div>
    );
}
