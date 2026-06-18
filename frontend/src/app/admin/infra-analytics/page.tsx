"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useAuth } from "@/hooks/useAuth";
import {
  AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";
import {
  StatCard,
  AdminSectionCard
} from "../components";
import Link from "next/link";
import { Globe, Clock, ShieldAlert, Cpu, Activity, Play, TrendingUp, Skull, HelpCircle } from "lucide-react";

// ─── Custom Tooltip ─────────────────────────────────────────
function CustomTooltip({ active, payload, label }: { active?: boolean; payload?: any[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-[var(--bg-main)]/95 backdrop-blur-xl border border-[var(--border-strong)] rounded-lg px-3.5 py-2.5 shadow-2xl shadow-black/5">
      <p className="text-[11px] font-medium text-[var(--text-secondary)] mb-1.5 border-b border-[var(--border-strong)] pb-1.5">{label}</p>
      {payload.map((entry, i) => (
        <div key={i} className="flex items-center gap-2 py-0.5">
          <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color || entry.stroke }} />
          <span className="text-[10px] text-[var(--text-muted)] capitalize">{entry.name}</span>
          <span className="text-[11px] font-bold text-[var(--text-primary)] ml-auto tabular-nums">{entry.value.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Threat Level Badge ─────────────────────────────────────
function RiskScoreBadge({ score }: { score: number }) {
  const styles =
    score >= 75 ? "bg-red-500/15 text-red-400 border border-red-500/20" :
    score >= 50 ? "bg-orange-500/15 text-orange-400 border border-orange-500/20" :
    score >= 25 ? "bg-amber-500/15 text-amber-400 border border-amber-500/20" :
    "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20";
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono tracking-wide ${styles}`}>
      {Math.round(score)} / 100
    </span>
  );
}

export default function InfraAnalyticsPage() {
  const { token } = useAuth();
  
  const [stats, setStats] = useState({
    total: 0,
    today: 0,
    running: 0,
    completed: 0,
    failed: 0,
    avgRiskScore: 0.0,
    highRiskCount: 0
  });

  const [iocDistribution, setIocDistribution] = useState<any[]>([]);
  const [trends, setTrends] = useState<any[]>([]);
  const [topIocs, setTopIocs] = useState<any[]>([]);
  const [topHighRisk, setTopHighRisk] = useState<any[]>([]);
  const [recent, setRecent] = useState<any[]>([]);

  const [isLoading, setIsLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [timeRange, setTimeRange] = useState<"7d" | "30d">("7d");

  const fetchData = async () => {
    if (!token) return;
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/infra-analytics`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const d = await res.json();
        setStats(d.stats);
        
        // Define clean colors for IOC types
        const typeColors: Record<string, string> = {
          IP: "#06b6d4",
          DOMAIN: "#a855f7",
          URL: "#3b82f6",
          HASH: "#eab308",
          EMAIL: "#ef4444"
        };
        const coloredDistribution = (d.iocDistribution || []).map((item: any) => ({
          ...item,
          color: typeColors[item.name] || "#6b7280"
        }));
        setIocDistribution(coloredDistribution);
        setTrends(d.trends || []);
        setTopIocs(d.topIocs || []);
        setTopHighRisk(d.topHighRisk || []);
        setRecent(d.recent || []);
      }
    } catch (err) {
      console.error("Failed to fetch infra analytics:", err);
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

  // Filter trends based on selected range (7d / 30d)
  const filteredTrends = trends.slice(timeRange === "7d" ? -7 : -30);

  if (isLoading) {
    return (
      <div className="space-y-6 max-w-[1400px] animate-pulse">
        <div className="flex items-center justify-between">
          <div>
            <div className="h-7 w-64 bg-[var(--bg-elevated)] rounded-lg" />
            <div className="h-4 w-96 bg-[var(--bg-elevated)] rounded mt-2" />
          </div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4">
          {Array.from({ length: 7 }).map((_, i) => (
            <div key={i} className="h-28 rounded-xl bg-[var(--bg-elevated)] border border-[var(--border-soft)]" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 h-80 rounded-xl bg-[var(--bg-elevated)] border border-[var(--border-soft)]" />
          <div className="h-80 rounded-xl bg-[var(--bg-elevated)] border border-[var(--border-soft)]" />
        </div>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="space-y-6 max-w-[1400px]"
    >
      {/* ── Page Header ─────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-2xl font-bold text-[var(--text-primary)]">Infrastructure Intelligence Analytics</h1>
            <span className="px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-widest bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border border-cyan-500/20 text-cyan-400 rounded-full">
              Flow 2
            </span>
          </div>
          <p className="text-sm text-[var(--text-muted)]">Analysis metrics, IOC distributions, trends, and risk tracking for passive threat profiling</p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-soft)] text-[var(--text-secondary)] hover:bg-[var(--bg-elevated)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-50"
        >
          <svg className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          {refreshing ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {/* ── Metric Cards Grid (7 Columns on wide screens) ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-4 z-10">
        <StatCard label="Total Investigations" value={stats.total} icon={<Activity className="w-5 h-5" />} color="blue" delay={0} />
        <StatCard label="Started Today" value={stats.today} icon={<Clock className="w-5 h-5" />} color="cyan" delay={100} />
        <StatCard label="Running Now" value={stats.running} icon={<Play className="w-5 h-5 animate-pulse" />} color="green" delay={200} />
        <StatCard label="Completed Jobs" value={stats.completed} icon={<Cpu className="w-5 h-5" />} color="blue" delay={300} />
        <StatCard label="Failed Jobs" value={stats.failed} icon={<ShieldAlert className="w-5 h-5" />} color="red" delay={400} />
        <StatCard label="Average Risk" value={`${Math.round(stats.avgRiskScore)}/100`} icon={<TrendingUp className="w-5 h-5" />} color="amber" delay={500} />
        <StatCard label="High-Risk Alerts" value={stats.highRiskCount} icon={<Skull className="w-5 h-5" />} color="purple" delay={600} />
      </div>

      {/* ── Charts: Trends & IOC Distribution ────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Daily Trends Chart */}
        <AdminSectionCard
          title="Investigation Trends"
          description="Daily overview of total scan runs and high-risk findings"
          className="lg:col-span-2"
          action={
            <div className="flex bg-[var(--bg-card)] border border-[var(--border-soft)] p-0.5 rounded-lg">
              <button
                onClick={() => setTimeRange("7d")}
                className={`px-3 py-1 text-[10px] font-bold rounded-md transition-colors ${
                  timeRange === "7d" ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                }`}
              >
                7 Days
              </button>
              <button
                onClick={() => setTimeRange("30d")}
                className={`px-3 py-1 text-[10px] font-bold rounded-md transition-colors ${
                  timeRange === "30d" ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                }`}
              >
                30 Days
              </button>
            </div>
          }
        >
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={filteredTrends} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gradCount" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradHighRisk" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#64748b" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: "#64748b" }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="count" name="Total Runs" stroke="#3b82f6" fill="url(#gradCount)" strokeWidth={2} dot={false} animationDuration={1200} />
              <Area type="monotone" dataKey="high_risk" name="High Risk Alerts" stroke="#ef4444" fill="url(#gradHighRisk)" strokeWidth={1.5} dot={false} animationDuration={1400} />
            </AreaChart>
          </ResponsiveContainer>
        </AdminSectionCard>

        {/* IOC Type Distribution Chart */}
        <AdminSectionCard
          title="IOC Type Distribution"
          description="Breakdown of indicator types investigated"
        >
          {iocDistribution.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie
                  data={iocDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius="55%"
                  outerRadius="80%"
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                  animationDuration={1200}
                >
                  {iocDistribution.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;
                    const d = payload[0];
                    return (
                      <div className="bg-[var(--bg-main)]/95 backdrop-blur-xl border border-[var(--border-strong)] rounded-lg px-3.5 py-2.5 shadow-2xl">
                        <div className="flex items-center gap-2">
                          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.payload?.color }} />
                          <span className="text-xs text-[var(--text-primary)] font-medium">{d.name}</span>
                        </div>
                        <p className="text-lg font-bold text-[var(--text-primary)] mt-1">{(d.value as number).toLocaleString()} runs</p>
                      </div>
                    );
                  }}
                />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  content={({ payload }) => (
                    <div className="flex flex-wrap justify-center gap-x-3 gap-y-1 mt-2">
                      {payload?.map((entry, i) => (
                        <span key={i} className="flex items-center gap-1.5 text-[10px] text-[var(--text-muted)] font-semibold uppercase">
                          <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color }} />
                          {entry.value}
                        </span>
                      ))}
                    </div>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="py-20 text-center text-[var(--text-muted)] text-sm">No data available</div>
          )}
        </AdminSectionCard>
      </div>

      {/* ── Tables Grid: Top IOCs + High-Risk Alerts ───────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Top Investigated IOCs */}
        <AdminSectionCard
          title="Top Investigated IOCs"
          description="Most frequently scanned targets"
          className="lg:col-span-1"
        >
          <div className="space-y-3 max-h-[360px] overflow-y-auto pr-1">
            {topIocs.length > 0 ? (
              topIocs.map((ioc, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3 px-3 py-2 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-soft)] hover:bg-[var(--bg-elevated)] transition-colors group"
                >
                  <span className={`flex-shrink-0 w-6 h-6 rounded-md flex items-center justify-center text-[10px] font-black ${
                    i < 3 ? "bg-cyan-500/15 text-cyan-400" : "bg-[var(--bg-elevated)] text-[var(--text-muted)]"
                  }`}>
                    {i + 1}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-[var(--text-primary)] font-mono truncate group-hover:text-[var(--text-primary)] transition-colors">{ioc.target}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[9px] font-bold text-cyan-400 bg-cyan-500/10 px-1 rounded uppercase tracking-wider">
                        {ioc.type}
                      </span>
                      <span className="text-[10px] text-[var(--text-muted)]">{ioc.count} investigations</span>
                    </div>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <RiskScoreBadge score={ioc.max_risk} />
                  </div>
                </div>
              ))
            ) : (
              <div className="py-20 text-center text-[var(--text-muted)] text-xs">No records found.</div>
            )}
          </div>
        </AdminSectionCard>

        {/* Top High-Risk Investigations */}
        <AdminSectionCard
          title="Critical Alerts (Score ≥ 60)"
          description="Top high-risk threat infrastructures detected"
          className="lg:col-span-2"
        >
          <div className="overflow-x-auto max-h-[360px] overflow-y-auto">
            {topHighRisk.length > 0 ? (
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[var(--border-strong)] text-[var(--text-muted)] font-semibold text-[10px] uppercase tracking-wider bg-[var(--bg-page)]/20">
                    <th className="py-2 px-3">Target Indicator</th>
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Risk Index</th>
                    <th className="py-2 px-3">Analyst</th>
                    <th className="py-2 px-3 text-right">Job Date</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.04]">
                  {topHighRisk.map((inv) => (
                    <tr
                      key={inv.id}
                      className="hover:bg-[var(--bg-elevated)] transition-colors cursor-pointer"
                      onClick={() => window.open(`/dashboard/infra-investigations/${inv.id}`, "_blank")}
                    >
                      <td className="py-3 px-3 font-mono text-[var(--text-primary)] max-w-[200px] truncate">{inv.target}</td>
                      <td className="py-3 px-3">
                        <span className="text-[9px] font-bold bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 rounded text-cyan-400 uppercase">
                          {inv.type}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <RiskScoreBadge score={inv.risk_score} />
                      </td>
                      <td className="py-3 px-3 text-[var(--text-muted)]">{inv.analyst}</td>
                      <td className="py-3 px-3 text-right text-[var(--text-muted)] font-mono">
                        {inv.started_at ? new Date(inv.started_at).toLocaleDateString() : "System"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="py-20 text-center text-[var(--text-muted)] text-xs">No high-risk investigations found.</div>
            )}
          </div>
        </AdminSectionCard>
      </div>

      {/* ── Table: Recent Investigations ─────────────────── */}
      <AdminSectionCard
        title="Recent Infrastructure Investigations"
        description="Chronological log of the latest threat profiling runs across the platform"
      >
        <div className="overflow-x-auto">
          {recent.length > 0 ? (
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--border-strong)] text-[var(--text-muted)] font-semibold text-[10px] uppercase tracking-wider bg-[var(--bg-page)]/20">
                  <th className="py-2.5 px-4">Target IOC</th>
                  <th className="py-2.5 px-4">Type</th>
                  <th className="py-2.5 px-4">Risk score</th>
                  <th className="py-2.5 px-4">Current Stage</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Initiated By</th>
                  <th className="py-2.5 px-4 text-right">Started Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {recent.map((inv) => {
                  const statusColors: Record<string, string> = {
                    completed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
                    failed: "bg-red-500/10 text-red-400 border-red-500/20",
                    running: "bg-[var(--primary)]/10 text-[var(--primary)] border-[var(--primary)] animate-pulse",
                    pending: "bg-[var(--bg-elevated)] text-[var(--text-muted)] border-[var(--border-strong)]",
                    stopped: "bg-amber-500/10 text-amber-400 border-amber-500/20",
                  };
                  return (
                    <tr
                      key={inv.id}
                      className="hover:bg-[var(--bg-elevated)] transition-colors cursor-pointer"
                      onClick={() => window.open(`/dashboard/infra-investigations/${inv.id}`, "_blank")}
                    >
                      <td className="py-3 px-4 font-mono text-[var(--text-primary)] max-w-[240px] truncate">{inv.target}</td>
                      <td className="py-3 px-4">
                        <span className="text-[9px] font-bold bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 rounded text-cyan-400 uppercase">
                          {inv.type}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {inv.status === "completed" ? (
                          <RiskScoreBadge score={inv.risk_score} />
                        ) : (
                          <span className="text-[var(--text-muted)] font-mono">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-[var(--text-muted)] font-medium">{inv.current_stage || "Queued"}</td>
                      <td className="py-3 px-4">
                        <span className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded border ${
                          statusColors[inv.status] || "bg-[var(--bg-elevated)] text-[var(--text-muted)] border-[var(--border-strong)]"
                        }`}>
                          {inv.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[var(--text-secondary)] font-medium">{inv.analyst}</td>
                      <td className="py-3 px-4 text-right text-[var(--text-muted)] font-mono">
                        {inv.started_at ? new Date(inv.started_at).toLocaleString() : "System"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <div className="py-20 text-center text-[var(--text-muted)] text-sm">No investigations found.</div>
          )}
        </div>
      </AdminSectionCard>
    </motion.div>
  );
}
