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
import { TibsaRefreshButton } from "@/components/ui";
import { Globe, Clock, ShieldAlert, Cpu, Activity, Play, TrendingUp, Skull, HelpCircle } from "lucide-react";

// ─── Custom Tooltip ─────────────────────────────────────────
function CustomTooltip({ active, payload, label }: { active?: boolean; payload?: any[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white/95 backdrop-blur-xl border border-[#E6DDD2] rounded-lg px-3.5 py-2.5 shadow-md">
      <p className="text-[11px] font-bold text-[#1F2933] mb-1.5 border-b border-[#E6DDD2] pb-1.5">{label}</p>
      {payload.map((entry, i) => (
        <div key={i} className="flex items-center gap-2 py-0.5">
          <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color || entry.stroke }} />
          <span className="text-[10px] text-[#7C6F64] capitalize font-medium">{entry.name}</span>
          <span className="text-[11px] font-bold text-[#1F2933] ml-auto tabular-nums">{entry.value.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Threat Level Badge ─────────────────────────────────────
function RiskScoreBadge({ score }: { score: number }) {
  const styles =
    score >= 75 ? "bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/20" :
    score >= 50 ? "bg-[#F97316]/15 text-[#F97316] border border-[#F97316]/20" :
    score >= 25 ? "bg-[#F97316]/15 text-[#F97316] border border-[#F97316]/20" :
    "bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/20";
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
        
        // Define clean colors for IOC types using our primary palette
        const typeColors: Record<string, string> = {
          IP: "#00A884",
          DOMAIN: "#A855F7",
          URL: "#2F80ED",
          HASH: "#F97316",
          EMAIL: "#EF4444"
        };
        const coloredDistribution = (d.iocDistribution || []).map((item: any) => ({
          ...item,
          color: typeColors[item.name] || "#7C6F64"
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
      <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] text-[#1F2933] space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="h-7 w-64 bg-[#FAF7F1] border border-[#E6DDD2] rounded-lg animate-pulse" />
            <div className="h-4 w-96 bg-[#FAF7F1] border border-[#E6DDD2] rounded mt-2 animate-pulse" />
          </div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4">
          {Array.from({ length: 7 }).map((_, i) => (
            <div key={i} className="h-28 rounded-xl bg-white border border-[#E6DDD2] animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 h-80 rounded-xl bg-white border border-[#E6DDD2] animate-pulse" />
          <div className="h-80 rounded-xl bg-white border border-[#E6DDD2] animate-pulse" />
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
        className="space-y-6 w-full max-w-[1600px] mx-auto animate-fade-in"
      >
        {/* ── Page Header ─────────────────────────────────── */}
        <div 
          style={{
            background: "linear-gradient(90deg, #FFFCF7 0%, #F4EFE7 45%, #E9EDF3 100%)"
          }}
          className="border border-[#E6DDD2] p-6 md:p-8 rounded-[24px] shadow-sm relative overflow-hidden flex flex-col md:flex-row justify-between items-start md:items-center gap-6"
        >
          <div className="flex items-start gap-4">
            <div className="p-2.5 bg-[#00A884]/10 rounded-xl border border-[#00A884]/20 text-[#00A884] shadow-sm shrink-0 mt-1">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[10px] font-bold text-[#00A884] uppercase tracking-widest">
                  Flow 2
                </span>
              </div>
              <h1 className="text-2xl font-black text-[#1F2933] tracking-tight">Infrastructure Intelligence Analytics</h1>
              <p className="text-[#7C6F64] mt-1 max-w-xl text-sm leading-relaxed font-medium">
                Analysis metrics, IOC distributions, trends, and risk tracking for passive threat profiling.
              </p>
            </div>
          </div>
          <TibsaRefreshButton
            onClick={handleRefresh}
            isRefreshing={refreshing}
          />
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
              <div className="flex bg-[#FAF7F1] border border-[#E6DDD2] p-0.5 rounded-lg">
                <button
                  onClick={() => setTimeRange("7d")}
                  className={`px-3 py-1 text-[10px] font-bold rounded-md transition-colors cursor-pointer ${
                    timeRange === "7d" ? "bg-[#00A884]/15 text-[#00A884] border border-[#00A884]/20" : "text-[#7C6F64] hover:text-[#1F2933]"
                  }`}
                >
                  7 Days
                </button>
                <button
                  onClick={() => setTimeRange("30d")}
                  className={`px-3 py-1 text-[10px] font-bold rounded-md transition-colors cursor-pointer ${
                    timeRange === "30d" ? "bg-[#00A884]/15 text-[#00A884] border border-[#00A884]/20" : "text-[#7C6F64] hover:text-[#1F2933]"
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
                    <stop offset="5%" stopColor="#2F80ED" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#2F80ED" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradHighRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#E6DDD2" />
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: "#7C6F64" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "#7C6F64" }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="count" name="Total Runs" stroke="#2F80ED" fill="url(#gradCount)" strokeWidth={2} dot={false} animationDuration={1200} />
                <Area type="monotone" dataKey="high_risk" name="High Risk Alerts" stroke="#EF4444" fill="url(#gradHighRisk)" strokeWidth={1.5} dot={false} animationDuration={1400} />
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
                        <div className="bg-white border border-[#E6DDD2] rounded-lg px-3.5 py-2.5 shadow-md">
                          <div className="flex items-center gap-2">
                            <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.payload?.color }} />
                            <span className="text-xs text-[#1F2933] font-bold">{d.name}</span>
                          </div>
                          <p className="text-lg font-black text-[#1F2933] mt-1">{(d.value as number).toLocaleString()} runs</p>
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
                          <span key={i} className="flex items-center gap-1.5 text-[10px] text-[#7C6F64] font-bold uppercase">
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
              <div className="py-20 text-center text-[#7C6F64] text-sm font-semibold">No data available</div>
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
                    className="flex items-center gap-3 px-3 py-2 rounded-xl bg-white border border-[#E6DDD2] hover:bg-[#FAF7F1] transition-colors group shadow-sm"
                  >
                    <span className={`flex-shrink-0 w-6 h-6 rounded-md flex items-center justify-center text-[10px] font-black ${
                      i < 3 ? "bg-[#00A884]/15 text-[#00A884]" : "bg-[#FAF7F1] text-[#7C6F64] border border-[#E6DDD2]"
                    }`}>
                      {i + 1}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-[#1F2933] font-mono truncate transition-colors">{ioc.target}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[9px] font-bold text-[#00A884] bg-[#00A884]/10 px-1 rounded uppercase tracking-wider">
                          {ioc.type}
                        </span>
                        <span className="text-[10px] text-[#7C6F64] font-medium">{ioc.count} investigations</span>
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <RiskScoreBadge score={ioc.max_risk} />
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-20 text-center text-[#7C6F64] text-xs font-semibold">No records found.</div>
              )}
            </div>
          </AdminSectionCard>

          {/* Top High-Risk Investigations */}
          <AdminSectionCard
            title="Critical Alerts (Score ≥ 60)"
            description="Top high-risk threat infrastructures detected"
            className="lg:col-span-2"
          >
            <div className="overflow-x-auto max-h-[360px] overflow-y-auto border border-[#E6DDD2] rounded-xl">
              {topHighRisk.length > 0 ? (
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-[#E6DDD2] text-[#7C6F64] font-bold text-[10px] uppercase tracking-wider bg-[#FAF7F1]">
                      <th className="py-3 px-3">Target Indicator</th>
                      <th className="py-3 px-3">Type</th>
                      <th className="py-3 px-3">Risk Index</th>
                      <th className="py-3 px-3">Analyst</th>
                      <th className="py-3 px-3 text-right">Job Date</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E6DDD2] text-[#1F2933]">
                    {topHighRisk.map((inv) => (
                      <tr
                        key={inv.id}
                        className="hover:bg-[#FAF7F1] transition-colors cursor-pointer"
                        onClick={() => window.open(`/dashboard/infra-investigations/${inv.id}`, "_blank")}
                      >
                        <td className="py-3 px-3 font-mono text-[#1F2933] font-semibold max-w-[200px] truncate">{inv.target}</td>
                        <td className="py-3 px-3">
                          <span className="text-[9px] font-bold bg-[#00A884]/10 border border-[#00A884]/20 px-1.5 py-0.5 rounded text-[#00A884] uppercase">
                            {inv.type}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <RiskScoreBadge score={inv.risk_score} />
                        </td>
                        <td className="py-3 px-3 text-[#7C6F64] font-medium">{inv.analyst}</td>
                        <td className="py-3 px-3 text-right text-[#7C6F64] font-mono">
                          {inv.started_at ? new Date(inv.started_at).toLocaleDateString() : "System"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="py-20 text-center text-[#7C6F64] text-xs font-semibold">No high-risk investigations found.</div>
              )}
            </div>
          </AdminSectionCard>
        </div>

        {/* ── Table: Recent Investigations ─────────────────── */}
        <AdminSectionCard
          title="Recent Infrastructure Investigations"
          description="Chronological log of the latest threat profiling runs across the platform"
        >
          <div className="overflow-x-auto border border-[#E6DDD2] rounded-[20px] overflow-hidden">
            {recent.length > 0 ? (
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#E6DDD2] text-[#7C6F64] font-bold text-[10px] uppercase tracking-wider bg-[#FAF7F1]">
                    <th className="py-3 px-4">Target IOC</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Risk score</th>
                    <th className="py-3 px-4">Current Stage</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Initiated By</th>
                    <th className="py-3 px-4 text-right">Started Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E6DDD2] text-[#1F2933]">
                  {recent.map((inv) => {
                    const statusColors: Record<string, string> = {
                      completed: "bg-[#10B981]/15 text-[#10B981] border-[#10B981]/20",
                      failed: "bg-[#EF4444]/15 text-[#EF4444] border-[#EF4444]/20",
                      running: "bg-[#2F80ED]/15 text-[#2F80ED] border-[#2F80ED]/20 animate-pulse",
                      pending: "bg-[#FAF7F1] text-[#7C6F64] border-[#E6DDD2]",
                      stopped: "bg-[#F97316]/15 text-[#F97316] border-[#F97316]/20",
                    };
                    return (
                      <tr
                        key={inv.id}
                        className="hover:bg-[#FAF7F1] transition-colors cursor-pointer"
                        onClick={() => window.open(`/dashboard/infra-investigations/${inv.id}`, "_blank")}
                      >
                        <td className="py-3 px-4 font-mono text-[#1F2933] font-semibold max-w-[240px] truncate">{inv.target}</td>
                        <td className="py-3 px-4">
                          <span className="text-[9px] font-bold bg-[#00A884]/10 border border-[#00A884]/20 px-1.5 py-0.5 rounded text-[#00A884] uppercase">
                            {inv.type}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          {inv.status === "completed" ? (
                            <RiskScoreBadge score={inv.risk_score} />
                          ) : (
                            <span className="text-[#7C6F64] font-mono">—</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-[#7C6F64] font-medium">{inv.current_stage || "Queued"}</td>
                        <td className="py-3 px-4">
                          <span className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded border ${
                            statusColors[inv.status] || "bg-[#FAF7F1] text-[#7C6F64] border-[#E6DDD2]"
                          }`}>
                            {inv.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-[#7C6F64] font-bold">{inv.analyst}</td>
                        <td className="py-3 px-4 text-right text-[#7C6F64] font-mono">
                          {inv.started_at ? new Date(inv.started_at).toLocaleString() : "System"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <div className="py-20 text-center text-[#7C6F64] text-sm font-semibold">No investigations found.</div>
            )}
          </div>
        </AdminSectionCard>
      </motion.div>
    </div>
  );
}
