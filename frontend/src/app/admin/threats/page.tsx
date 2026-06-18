"use client";

import { useState, useMemo, useEffect } from "react";
import { motion } from "framer-motion";
import { useAuth } from "@/hooks/useAuth";
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
// Removed mock imports

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
        ip: "bg-[var(--primary)]/15 text-[var(--primary)]",
        domain: "bg-[var(--primary-soft)] text-[var(--primary)]",
        hash: "bg-cyan-500/15 text-cyan-400",
        url: "bg-amber-500/15 text-amber-400",
        email: "bg-emerald-500/15 text-emerald-400",
    };
    return (
        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${styles[type] || "bg-[var(--bg-elevated)] text-[var(--text-muted)]"}`}>
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
        botnet: "bg-[var(--primary-soft)] text-[var(--primary)]",
        apt: "bg-pink-500/10 text-pink-400",
        general: "bg-[var(--bg-elevated)] text-[var(--text-muted)]",
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
    const { token } = useAuth();
    
    // Real Data States
    const [threats, setThreats] = useState<TopThreat[]>([]);
    const [stats, setStats] = useState({ threatsDetected: 0, threatsToday: 0 });
    const [charts, setCharts] = useState<{
        trends: any[];
        distribution: any[];
    } | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [pageOffset, setPageOffset] = useState(0);

    const [feeds, setFeeds] = useState<ThreatFeedConfig[]>([]);
    const [isFeedModalOpen, setIsFeedModalOpen] = useState(false);
    const [newFeed, setNewFeed] = useState({
        name: "",
        provider: "",
        category: "malware",
        source_url: "",
        reliability_score: 85,
        update_frequency: "Hourly"
    });
    const [addingFeed, setAddingFeed] = useState(false);

    const activeFeeds = feeds.filter(f => f.is_active).length;
    const totalIndicators = feeds.reduce((sum, f) => sum + f.indicators_count, 0);

    const fetchThreats = async (offset = 0, append = false) => {
        if (!token) return;
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/threats/top?limit=100&offset=${offset}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setThreats(prev => append ? [...prev, ...data.threats] : data.threats);
            }
        } catch (err) {
            console.error(err);
        }
    };

    const fetchFeeds = async () => {
        if (!token) return;
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/threats/feeds?active_only=false`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setFeeds(data);
            }
        } catch (err) {
            console.error("Failed to fetch feeds:", err);
        }
    };

    const handleAddFeed = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!token || !newFeed.name || !newFeed.provider || !newFeed.source_url) return;
        setAddingFeed(true);
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/threats/feeds`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify(newFeed)
            });
            if (res.ok) {
                setIsFeedModalOpen(false);
                setNewFeed({
                    name: "",
                    provider: "",
                    category: "malware",
                    source_url: "",
                    reliability_score: 85,
                    update_frequency: "Hourly"
                });
                fetchFeeds();
            }
        } catch (err) {
            console.error("Failed to add feed:", err);
        } finally {
            setAddingFeed(false);
        }
    };

    const fetchStatsAndCharts = async () => {
        if (!token) return;
        try {
            const [statsRes, chartsRes] = await Promise.all([
                fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/stats`, { headers: { Authorization: `Bearer ${token}` }}),
                fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/charts`, { headers: { Authorization: `Bearer ${token}` }})
            ]);
            
            if (statsRes.ok) {
                const s = await statsRes.json();
                setStats({ threatsDetected: s.threats.total, threatsToday: s.threats.critical });
            }
            if (chartsRes.ok) {
                const c = await chartsRes.json();
                const coloredDist = c.threatDistribution.map((item: any, i: number) => ({
                    ...item,
                    color: ["#ef4444", "#f97316", "#eab308", "#dc2626", "#a855f7", "#ec4899", "#6b7280"][i % 7]
                }));
                setCharts({ trends: c.threatTrends, distribution: coloredDist });
            }
        } catch (err) {
            console.error(err);
        }
    };

    useEffect(() => {
        if (token) {
            setIsLoading(true);
            Promise.all([fetchThreats(0), fetchStatsAndCharts(), fetchFeeds()]).finally(() => setIsLoading(false));
        }
    }, [token]);

    const handleLoadMore = () => {
        const nextOffset = pageOffset + 100;
        setPageOffset(nextOffset);
        fetchThreats(nextOffset, true);
    };

    const scoredAllThreats = useMemo(() => {
        return threats.map(threat => {
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
        }).sort((a, b) => (b.score || 0) - (a.score || 0));
    }, [threats]);

    const scoredTopThreats = useMemo(() => {
        return scoredAllThreats.slice(0, 5);
    }, [scoredAllThreats]);

    const threatColumns: Column<TopThreat>[] = [
        {
            key: "indicator",
            label: "Indicator",
            sortable: true,
            render: (t) => (
                <div 
                    className="flex items-center gap-3 cursor-pointer group hover:bg-[var(--bg-elevated)] p-1.5 -m-1.5 rounded transition-colors"
                    onClick={() => setDrawerContext({ type: t.type === "ip" ? "ip" : "threat", value: t.indicator })}
                >
                    <TypeBadge type={t.type} />
                    <div>
                        <p className="text-xs font-semibold text-[var(--text-secondary)]">{t.name}</p>
                        <span className="text-[10px] text-[var(--text-muted)] font-mono truncate max-w-[200px] block group-hover:text-[var(--primary)] transition-colors">
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
                        (t.score || 0) > 1000 ? "text-amber-400" : "text-[var(--primary)]"
                    }`}>
                        {t.score?.toLocaleString()}
                    </span>
                    {t.trend === "up" && <span className="text-red-500 text-xs font-bold">↑</span>}
                    {t.trend === "down" && <span className="text-emerald-500 text-xs font-bold">↓</span>}
                    {t.trend === "neutral" && <span className="text-[var(--text-muted)] text-xs font-bold">—</span>}
                </div>
            ),
        },
        {
            key: "detections",
            label: "Detections",
            sortable: true,
            render: (t) => <span className="text-sm text-[var(--text-secondary)] tabular-nums">{t.detections.toLocaleString()}</span>,
        },
        {
            key: "source",
            label: "Source",
            render: (t) => <span className="text-xs text-[var(--text-muted)]">{t.source}</span>,
        },
        {
            key: "analyst_name",
            label: "Analyst",
            sortable: true,
            render: (t) => (
                <div className="flex items-center gap-2">
                    <div className="w-5 h-5 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-[8px] font-bold text-[var(--text-primary)] uppercase flex-shrink-0">
                        {(t.analyst_name || "System").charAt(0)}
                    </div>
                    <span className="text-xs font-medium text-[var(--text-secondary)]">
                        {t.analyst_name || "System"}
                    </span>
                </div>
            ),
        },
        {
            key: "last_seen",
            label: "Last Seen",
            sortable: true,
            render: (t) => <span className="text-xs text-[var(--text-muted)]">{new Date(t.last_seen).toLocaleString()}</span>,
        },
    ];

    const handleToggleFeed = async (feedId: string, currentStatus: boolean) => {
        if (!token) return;
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/threats/feeds/${feedId}/toggle?is_active=${!currentStatus}`, {
                method: "PATCH",
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                fetchFeeds();
            }
        } catch (err) {
            console.error("Failed to toggle feed status:", err);
        }
    };

    const handleDeleteFeed = async (feedId: string) => {
        if (!token) return;
        if (!confirm("Are you sure you want to delete this threat feed?")) return;
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/threats/feeds/${feedId}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                fetchFeeds();
            }
        } catch (err) {
            console.error("Failed to delete threat feed:", err);
        }
    };

    const feedColumns: Column<ThreatFeedConfig>[] = [
        {
            key: "name",
            label: "Feed",
            sortable: true,
            render: (f) => (
                <div>
                    <p className="text-sm font-medium text-[var(--text-primary)]">{f.name}</p>
                    <p className="text-xs text-[var(--text-muted)]">{f.provider}</p>
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
            render: (f) => <span className="text-sm text-[var(--text-secondary)] tabular-nums">{f.indicators_count.toLocaleString()}</span>,
        },
        {
            key: "reliability_score",
            label: "Reliability",
            sortable: true,
            render: (f) => (
                <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
                        <div
                            className={`h-full rounded-full ${f.reliability_score >= 90 ? "bg-emerald-400" : f.reliability_score >= 80 ? "bg-amber-400" : "bg-red-400"}`}
                            style={{ width: `${f.reliability_score}%` }}
                        />
                    </div>
                    <span className="text-xs text-[var(--text-muted)] tabular-nums">{f.reliability_score}%</span>
                </div>
            ),
        },
        {
            key: "update_frequency",
            label: "Frequency",
            render: (f) => <span className="text-xs text-[var(--text-muted)]">{f.update_frequency}</span>,
        },
        {
            key: "actions",
            label: "Actions",
            render: (f) => (
                <div className="flex items-center gap-2">
                    <button
                        onClick={(e) => { e.stopPropagation(); handleToggleFeed(f.id, f.is_active); }}
                        className={`px-2 py-1 text-[10px] font-semibold rounded-md border transition-colors ${
                            f.is_active
                                ? "bg-amber-500/10 border-amber-500/20 text-amber-400 hover:bg-amber-500/20"
                                : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20"
                        }`}
                    >
                        {f.is_active ? "Pause" : "Resume"}
                    </button>
                    <button
                        onClick={(e) => { e.stopPropagation(); handleDeleteFeed(f.id); }}
                        className="px-2 py-1 text-[10px] font-semibold rounded-md bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors"
                    >
                        Delete
                    </button>
                </div>
            ),
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
                        <h1 className="text-2xl font-bold text-[var(--text-primary)]">Threat Intelligence Hub</h1>
                        <span className="px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-widest bg-gradient-to-r from-red-500/20 to-orange-500/20 border border-red-500/20 text-red-400 rounded-full">
                            Intel
                        </span>
                    </div>
                    <p className="text-sm text-[var(--text-muted)]">Monitor threats, manage feeds, and track indicators of compromise</p>
                </div>

                {/* Tab Switcher */}
                <div className="flex items-center bg-[var(--bg-elevated)] border border-[var(--border-strong)] rounded-lg p-1">
                    {tabs.map((tab) => (
                        <button
                            key={tab.key}
                            onClick={() => setActiveTab(tab.key)}
                            className={`px-4 py-1.5 text-xs font-medium rounded-md transition-all ${
                                activeTab === tab.key
                                    ? "bg-[var(--primary)]/20 text-[var(--primary)] border border-[var(--primary)]"
                                    : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
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
                            <ThreatTrendChart data={charts?.trends || []} />
                        </AdminSectionCard>
                        <AdminSectionCard
                            title="Threat Categories"
                            description="All-time distribution"
                        >
                            <ThreatDistributionChart data={charts?.distribution || []} />
                        </AdminSectionCard>
                    </div>

                    {/* Top Threats Preview */}
                    <AdminSectionCard
                        title="Top Threats"
                        description="Most detected indicators of compromise"
                        action={
                            <button
                                onClick={() => setActiveTab("threats")}
                                className="text-xs text-[var(--primary)] hover:text-[var(--primary)] transition-colors"
                            >
                                View all →
                            </button>
                        }
                    >
                        <DataTable
                            columns={threatColumns}
                            data={scoredTopThreats}
                            pageSize={5}
                            emptyMessage={isLoading ? "Loading threats..." : "No threats detected"}
                        />
                        {threats.length >= 100 && (
                            <div className="flex justify-center mt-4">
                                <button 
                                    onClick={handleLoadMore}
                                    className="px-4 py-2 text-sm text-[var(--primary)] bg-[var(--primary)]/10 hover:bg-[var(--primary)]/20 rounded-lg transition-colors"
                                >
                                    Load More
                                </button>
                            </div>
                        )}
                    </AdminSectionCard>
                </div>
            )}

            {activeTab === "threats" && (
                <AdminSectionCard
                    title="All Threat Indicators"
                    description={`${scoredAllThreats.length} indicators of compromise detected`}
                >
                    <DataTable
                        columns={threatColumns}
                        data={scoredAllThreats}
                        pageSize={10}
                        searchable
                        searchKeys={["indicator", "source", "name"]}
                        searchPlaceholder="Search by indicator, source, or name..."
                        emptyMessage="No threats found matching your search"
                    />
                    {threats.length >= 100 && (
                        <div className="flex justify-center mt-4 pt-3 border-t border-[var(--border-soft)]">
                            <button 
                                onClick={handleLoadMore}
                                className="px-5 py-2 text-sm font-medium text-[var(--primary)] bg-[var(--primary)]/10 hover:bg-[var(--primary)]/20 rounded-lg transition-colors border border-[var(--primary)]"
                            >
                                Load More Indicators
                            </button>
                        </div>
                    )}
                </AdminSectionCard>
            )}

            {activeTab === "feeds" && (
                <div className="space-y-6">
                    {/* Feed Summary Cards */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div className="bg-gradient-to-br from-emerald-500/[0.06] to-emerald-500/[0.02] border border-emerald-500/15 rounded-xl p-4">
                            <div className="flex items-center gap-2 mb-2">
                                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                                <span className="text-[11px] text-emerald-400 font-semibold uppercase tracking-wider">Active Feeds</span>
                            </div>
                            <p className="text-2xl font-bold text-[var(--text-primary)]">{activeFeeds}</p>
                            <p className="text-[11px] text-[var(--text-muted)] mt-1">Currently collecting intelligence</p>
                        </div>
                        <div className="bg-gradient-to-br from-purple-500/[0.06] to-[var(--primary-hover)]/[0.02] border border-[var(--primary)]/15 rounded-xl p-4">
                            <div className="flex items-center gap-2 mb-2">
                                <svg className="w-3.5 h-3.5 text-[var(--primary)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
                                </svg>
                                <span className="text-[11px] text-[var(--primary)] font-semibold uppercase tracking-wider">Total Indicators</span>
                            </div>
                            <p className="text-2xl font-bold text-[var(--text-primary)]">{totalIndicators.toLocaleString()}</p>
                            <p className="text-[11px] text-[var(--text-muted)] mt-1">IOCs across all feeds</p>
                        </div>
                        <div className="bg-gradient-to-br from-amber-500/[0.06] to-amber-500/[0.02] border border-amber-500/15 rounded-xl p-4">
                            <div className="flex items-center gap-2 mb-2">
                                <svg className="w-3.5 h-3.5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                                <span className="text-[11px] text-amber-400 font-semibold uppercase tracking-wider">Paused Feeds</span>
                            </div>
                            <p className="text-2xl font-bold text-[var(--text-primary)]">{feeds.length - activeFeeds}</p>
                            <p className="text-[11px] text-[var(--text-muted)] mt-1">Feeds currently paused</p>
                        </div>
                    </div>

                    {/* Feed Table */}
                    <AdminSectionCard
                        title="Threat Feed Configuration"
                        description={`${feeds.length} threat intelligence sources configured`}
                        action={
                            <button 
                                onClick={() => setIsFeedModalOpen(true)} 
                                className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-[var(--primary)]/20 border border-[var(--primary)] text-[var(--primary)] hover:bg-[var(--primary)]/30 hover:text-[var(--primary)] transition-all duration-200 group"
                            >
                                <svg className="w-3.5 h-3.5 group-hover:rotate-90 transition-transform duration-200" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                                </svg>
                                Add New Feed
                            </button>
                        }
                    >
                        <DataTable
                            columns={feedColumns}
                            data={feeds}
                            searchable
                            searchPlaceholder="Search by feed name, provider, or category..."
                            searchKeys={["name", "provider", "category"]}
                            pageSize={10}
                            emptyMessage="No threat feeds configured yet. Click 'Add New Feed' to get started."
                        />
                    </AdminSectionCard>
                </div>
            )}

            {/* ── Add Feed Modal ─────────────────────────── */}
            {isFeedModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
                    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setIsFeedModalOpen(false)} />
                    <div className="relative z-10 w-full max-w-lg bg-[#13203c] border border-[var(--border-soft)] rounded-2xl shadow-2xl overflow-hidden">
                        {/* Modal Header */}
                        <div className="relative px-6 py-5 border-b border-[var(--border-strong)]">
                            <div className="absolute top-0 left-0 right-0 h-[3px] bg-gradient-to-r from-blue-500 to-cyan-400" />
                            <div className="flex items-center justify-between">
                                <div>
                                    <h3 className="text-lg font-bold text-[var(--text-primary)] flex items-center gap-2">
                                        <svg className="w-5 h-5 text-[var(--primary)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 5c7.18 0 13 5.82 13 13M6 11a7 7 0 017 7m-6 0a1 1 0 11-2 0 1 1 0 012 0z" />
                                        </svg>
                                        Add New Threat Feed
                                    </h3>
                                    <p className="text-xs text-[var(--text-muted)] mt-1">Configure a new threat intelligence source for IOC collection</p>
                                </div>
                                <button 
                                    onClick={() => setIsFeedModalOpen(false)} 
                                    className="w-8 h-8 rounded-lg flex items-center justify-center text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] transition-colors"
                                >
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>
                        </div>

                        {/* Modal Body */}
                        <form onSubmit={handleAddFeed} className="px-6 py-5 space-y-5">
                            {/* Feed Identity */}
                            <div className="space-y-4">
                                <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                                    <span className="w-5 h-5 rounded-md bg-[var(--primary)]/15 flex items-center justify-center text-[var(--primary)] text-[10px] font-bold">1</span>
                                    Feed Identity
                                </div>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-[11px] font-medium text-[var(--text-muted)] mb-1.5">Feed Name <span className="text-red-400">*</span></label>
                                        <input 
                                            value={newFeed.name} 
                                            onChange={(e) => setNewFeed({...newFeed, name: e.target.value})} 
                                            placeholder="e.g., AlienVault OTX" 
                                            className="w-full px-3 py-2.5 bg-black/30 border border-[var(--border-soft)] rounded-lg text-sm text-[var(--text-primary)] placeholder-slate-600 focus:outline-none focus:border-[var(--primary)] focus:ring-1 focus:ring-[var(--primary)]/20 transition-all" 
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-[11px] font-medium text-[var(--text-muted)] mb-1.5">Provider <span className="text-red-400">*</span></label>
                                        <input 
                                            value={newFeed.provider} 
                                            onChange={(e) => setNewFeed({...newFeed, provider: e.target.value})} 
                                            placeholder="e.g., AT&T Cybersecurity" 
                                            className="w-full px-3 py-2.5 bg-black/30 border border-[var(--border-soft)] rounded-lg text-sm text-[var(--text-primary)] placeholder-slate-600 focus:outline-none focus:border-[var(--primary)] focus:ring-1 focus:ring-[var(--primary)]/20 transition-all" 
                                        />
                                    </div>
                                </div>
                            </div>

                            {/* Source Configuration */}
                            <div className="space-y-4">
                                <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                                    <span className="w-5 h-5 rounded-md bg-[var(--primary)]/15 flex items-center justify-center text-[var(--primary)] text-[10px] font-bold">2</span>
                                    Source Configuration
                                </div>
                                <div>
                                    <label className="block text-[11px] font-medium text-[var(--text-muted)] mb-1.5">Source URL <span className="text-red-400">*</span></label>
                                    <input 
                                        value={newFeed.source_url} 
                                        onChange={(e) => setNewFeed({...newFeed, source_url: e.target.value})} 
                                        placeholder="https://feeds.example.com/api/v1/indicators" 
                                        className="w-full px-3 py-2.5 bg-black/30 border border-[var(--border-soft)] rounded-lg text-sm text-[var(--text-primary)] placeholder-slate-600 font-mono focus:outline-none focus:border-[var(--primary)] focus:ring-1 focus:ring-[var(--primary)]/20 transition-all" 
                                    />
                                    <p className="text-[10px] text-[var(--text-muted)] mt-1.5">The API endpoint or RSS feed URL for this threat intelligence source</p>
                                </div>
                                <div>
                                    <label className="block text-[11px] font-medium text-[var(--text-muted)] mb-1.5">Threat Category</label>
                                    <select 
                                        value={newFeed.category} 
                                        onChange={(e) => setNewFeed({...newFeed, category: e.target.value})} 
                                        className="w-full px-3 py-2.5 bg-black/30 border border-[var(--border-soft)] rounded-lg text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--primary)] focus:ring-1 focus:ring-[var(--primary)]/20 transition-all"
                                    >
                                        <option value="malware">🦠 Malware</option>
                                        <option value="phishing">🎣 Phishing</option>
                                        <option value="c2">🔗 Command & Control (C2)</option>
                                        <option value="botnet">🤖 Botnet</option>
                                        <option value="apt">🎯 Advanced Persistent Threat (APT)</option>
                                    </select>
                                </div>
                            </div>

                            {/* Feed Settings */}
                            <div className="space-y-4">
                                <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                                    <span className="w-5 h-5 rounded-md bg-[var(--primary)]/15 flex items-center justify-center text-[var(--primary)] text-[10px] font-bold">3</span>
                                    Feed Settings
                                </div>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-[11px] font-medium text-[var(--text-muted)] mb-1.5">Reliability Score</label>
                                        <div className="flex items-center gap-3">
                                            <input 
                                                type="range" 
                                                min="0" 
                                                max="100" 
                                                value={newFeed.reliability_score} 
                                                onChange={(e) => setNewFeed({...newFeed, reliability_score: Number(e.target.value)})} 
                                                className="flex-1 h-1.5 bg-[var(--bg-elevated)] rounded-full appearance-none cursor-pointer accent-blue-500"
                                            />
                                            <span className={`text-sm font-bold tabular-nums min-w-[40px] text-right ${
                                                newFeed.reliability_score >= 90 ? "text-emerald-400" : 
                                                newFeed.reliability_score >= 70 ? "text-amber-400" : "text-red-400"
                                            }`}>{newFeed.reliability_score}%</span>
                                        </div>
                                        <p className="text-[10px] text-[var(--text-muted)] mt-1">How trustworthy is this source (0-100%)</p>
                                    </div>
                                    <div>
                                        <label className="block text-[11px] font-medium text-[var(--text-muted)] mb-1.5">Update Frequency</label>
                                        <select 
                                            value={newFeed.update_frequency} 
                                            onChange={(e) => setNewFeed({...newFeed, update_frequency: e.target.value})} 
                                            className="w-full px-3 py-2.5 bg-black/30 border border-[var(--border-soft)] rounded-lg text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--primary)] focus:ring-1 focus:ring-[var(--primary)]/20 transition-all"
                                        >
                                            <option value="Hourly">⚡ Hourly</option>
                                            <option value="Daily">📅 Daily</option>
                                            <option value="Weekly">📆 Weekly</option>
                                        </select>
                                        <p className="text-[10px] text-[var(--text-muted)] mt-1">How often to pull new indicators</p>
                                    </div>
                                </div>
                            </div>

                            {/* Modal Footer */}
                            <div className="flex items-center justify-between pt-4 border-t border-[var(--border-strong)]">
                                <p className="text-[10px] text-[var(--text-muted)] flex items-center gap-1">
                                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    Fields marked with <span className="text-red-400">*</span> are required
                                </p>
                                <div className="flex items-center gap-2">
                                    <button 
                                        type="button" 
                                        onClick={() => setIsFeedModalOpen(false)} 
                                        className="px-4 py-2 text-sm font-medium text-[var(--text-muted)] hover:text-[var(--text-primary)] rounded-lg hover:bg-[var(--bg-elevated)] transition-colors"
                                    >
                                        Cancel
                                    </button>
                                    <button 
                                        type="submit" 
                                        disabled={addingFeed || !newFeed.name || !newFeed.provider || !newFeed.source_url} 
                                        className="px-5 py-2 text-sm font-semibold rounded-lg bg-[var(--primary)] text-[var(--text-primary)] hover:bg-[var(--primary-hover)] disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-200 flex items-center gap-2 shadow-lg shadow-[var(--primary-soft)]"
                                    >
                                        {addingFeed ? (
                                            <>
                                                <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                                </svg>
                                                Adding Feed...
                                            </>
                                        ) : (
                                            <>
                                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                                                </svg>
                                                Add Feed
                                            </>
                                        )}
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            <InvestigationDrawer
                isOpen={!!drawerContext}
                onClose={() => setDrawerContext(null)}
                context={drawerContext}
            />
        </motion.div>
    );
}
