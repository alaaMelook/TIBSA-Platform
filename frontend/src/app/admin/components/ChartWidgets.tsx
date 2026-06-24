"use client";

import { motion } from "framer-motion";
import {
    AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, LineChart, Line,
    XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import type { ThreatTrend, ScanVolumeData, ThreatDistribution, UserGrowthData, SystemMetric } from "../types";

// ─── Custom Tooltip ─────────────────────────────────────────
function CustomTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
    if (!active || !payload?.length) return null;
    return (
        <div className="bg-white/95 backdrop-blur-xl border border-[#E6DDD2] rounded-lg px-3.5 py-2.5 shadow-lg">
            <p className="text-[11px] font-medium text-[#7C6F64] mb-1.5 border-b border-[#E6DDD2] pb-1.5">{label}</p>
            {payload.map((entry, i) => (
                <div key={i} className="flex items-center gap-2 py-0.5">
                    <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color }} />
                    <span className="text-[10px] text-[#7C6F64] capitalize">{entry.name}</span>
                    <span className="text-[11px] font-bold text-[#1F2933] ml-auto tabular-nums">{entry.value.toLocaleString()}</span>
                </div>
            ))}
        </div>
    );
}

// ─── Chart Animation Wrapper ────────────────────────────────
function ChartWrapper({ children, className = "" }: { children: React.ReactNode; className?: string }) {
    return (
        <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className={className}
        >
            {children}
        </motion.div>
    );
}

const AXIS_STYLE = { fontSize: 10, fill: "#7C6F64" };
const GRID_STYLE = { strokeDasharray: "3 3", stroke: "rgba(0,0,0,0.06)" };

// ─── 1. Threat Trend Chart (Stacked Area) ───────────────────
export function ThreatTrendChart({ data }: { data: ThreatTrend[] }) {
    return (
        <ChartWrapper>
            <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                    <defs>
                        <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#f97316" stopOpacity={0.2} />
                            <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="gradMedium" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#eab308" stopOpacity={0.15} />
                            <stop offset="95%" stopColor="#eab308" stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <CartesianGrid {...GRID_STYLE} />
                    <XAxis dataKey="date" tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                    <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#gradCritical)" strokeWidth={2} dot={false} animationDuration={1200} />
                    <Area type="monotone" dataKey="high" stroke="#f97316" fill="url(#gradHigh)" strokeWidth={1.5} dot={false} animationDuration={1400} />
                    <Area type="monotone" dataKey="medium" stroke="#eab308" fill="url(#gradMedium)" strokeWidth={1.5} dot={false} animationDuration={1600} />
                </AreaChart>
            </ResponsiveContainer>
        </ChartWrapper>
    );
}

// ─── 2. Scan Volume Chart (Bar) ─────────────────────────────
export function ScanVolumeChart({ data }: { data: ScanVolumeData[] }) {
    return (
        <ChartWrapper>
            <ResponsiveContainer width="100%" height={280}>
                <BarChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }} barGap={2}>
                    <CartesianGrid {...GRID_STYLE} />
                    <XAxis dataKey="date" tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                    <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                    <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.02)" }} />
                    <Bar dataKey="url_scans" name="URL Scans" fill="#3b82f6" radius={[4, 4, 0, 0]} animationDuration={1000} />
                    <Bar dataKey="file_scans" name="File Scans" fill="#a855f7" radius={[4, 4, 0, 0]} animationDuration={1200} />
                    <Bar dataKey="malware_analysis" name="AI Analysis" fill="#06b6d4" radius={[4, 4, 0, 0]} animationDuration={1400} />
                </BarChart>
            </ResponsiveContainer>
        </ChartWrapper>
    );
}

// ─── 3. Threat Distribution (Donut) ─────────────────────────
export function ThreatDistributionChart({ data }: { data: ThreatDistribution[] }) {
    return (
        <ChartWrapper>
            <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                    <Pie
                        data={data}
                        cx="50%"
                        cy="50%"
                        innerRadius="55%"
                        outerRadius="80%"
                        paddingAngle={3}
                        dataKey="value"
                        stroke="none"
                        animationDuration={1200}
                        animationBegin={200}
                    >
                        {data.map((entry, index) => (
                            <Cell key={index} fill={entry.color} />
                        ))}
                    </Pie>
                    <Tooltip
                        content={({ active, payload }) => {
                            if (!active || !payload?.length) return null;
                            const d = payload[0];
                            return (
                                <div className="bg-white/95 backdrop-blur-xl border border-[#E6DDD2] rounded-lg px-3.5 py-2.5 shadow-lg">
                                    <div className="flex items-center gap-2">
                                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.payload?.color }} />
                                        <span className="text-xs text-[#1F2933] font-medium">{d.name}</span>
                                    </div>
                                    <p className="text-lg font-bold text-[#1F2933] mt-1">{(d.value as number).toLocaleString()}</p>
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
                                    <span key={i} className="flex items-center gap-1.5 text-[10px] text-[#7C6F64]">
                                        <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color }} />
                                        {entry.value}
                                    </span>
                                ))}
                            </div>
                        )}
                    />
                </PieChart>
            </ResponsiveContainer>
        </ChartWrapper>
    );
}

// ─── 4. User Growth Chart (Dual Area) ───────────────────────
export function UserGrowthChart({ data }: { data: UserGrowthData[] }) {
    return (
        <ChartWrapper>
            <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                    <defs>
                        <linearGradient id="gradUsers" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#2F80ED" stopOpacity={0.2} />
                            <stop offset="95%" stopColor="#2F80ED" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="gradActive" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#10B981" stopOpacity={0.2} />
                            <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                        </linearGradient>
                    </defs>
                    <CartesianGrid {...GRID_STYLE} />
                    <XAxis dataKey="month" tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                    <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area type="monotone" dataKey="users" name="Total" stroke="#2F80ED" fill="url(#gradUsers)" strokeWidth={2} dot={{ r: 3, fill: "#2F80ED", strokeWidth: 0 }} animationDuration={1200} />
                    <Area type="monotone" dataKey="active" name="Active" stroke="#10B981" fill="url(#gradActive)" strokeWidth={2} dot={{ r: 3, fill: "#10B981", strokeWidth: 0 }} animationDuration={1400} />
                </AreaChart>
            </ResponsiveContainer>
        </ChartWrapper>
    );
}

// ─── 5. System Metrics Chart (Multi-Line) ───────────────────
export function SystemMetricsChart({ data }: { data: SystemMetric[] }) {
    return (
        <ChartWrapper>
            <ResponsiveContainer width="100%" height={280}>
                <LineChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                    <CartesianGrid {...GRID_STYLE} />
                    <XAxis dataKey="timestamp" tick={AXIS_STYLE} axisLine={false} tickLine={false} />
                    <YAxis tick={AXIS_STYLE} axisLine={false} tickLine={false} domain={[0, 100]} />
                    <Tooltip content={<CustomTooltip />} />
                    <Line type="monotone" dataKey="cpu" name="CPU" stroke="#3b82f6" strokeWidth={2} dot={false} animationDuration={1200} />
                    <Line type="monotone" dataKey="memory" name="Memory" stroke="#a855f7" strokeWidth={2} dot={false} animationDuration={1400} />
                    <Line type="monotone" dataKey="network" name="Network" stroke="#06b6d4" strokeWidth={1.5} dot={false} strokeDasharray="4 4" animationDuration={1600} />
                </LineChart>
            </ResponsiveContainer>
        </ChartWrapper>
    );
}
