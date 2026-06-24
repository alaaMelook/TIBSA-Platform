"use client";

import { TibsaRefreshButton } from "@/components/ui";
import { useState, useMemo, useEffect } from "react";
import { motion } from "framer-motion";
import { useAuth } from "@/hooks/useAuth";
import {
    StatCard,
    AdminSectionCard,
    DataTable,
    InvestigationDrawer,
    SOCFilterBar,
} from "../components";
import type { Column } from "../components";
import type { InvestigationContext } from "../components/InvestigationDrawer";
import type { SOCFilters } from "../components/SOCFilterBar";
import type { AuditLogEntry } from "../types";
// Removed mock imports

// ─── Icons ──────────────────────────────────────────────────
const IconAudit = () => (
    <svg className="w-5 h-5 text-[#2F80ED]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
    </svg>
);
const IconSuccess = () => (
    <svg className="w-5 h-5 text-[#10B981]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
);
const IconFail = () => (
    <svg className="w-5 h-5 text-[#EF4444]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
);
const IconWarn = () => (
    <svg className="w-5 h-5 text-[#F97316]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
);

// ─── Action Style Map ───────────────────────────────────────
const ACTION_STYLES: Record<string, { bg: string; text: string }> = {
    LOGIN: { bg: "bg-[#2F80ED]/10", text: "text-[#2F80ED]" },
    LOGIN_FAILED: { bg: "bg-[#EF4444]/10", text: "text-[#EF4444]" },
    SIGNUP: { bg: "bg-[#10B981]/10", text: "text-[#10B981]" },
    SIGNUP_FAILED: { bg: "bg-[#EF4444]/10", text: "text-[#EF4444]" },
    SCAN_CREATED: { bg: "bg-[#2F80ED]/10", text: "text-[#2F80ED]" },
    USER_ROLE_CHANGE: { bg: "bg-[#A855F7]/10", text: "text-[#A855F7]" },
    THREAT_FEED_UPDATE: { bg: "bg-[#F97316]/10", text: "text-[#F97316]" },
    REPORT_EXPORTED: { bg: "bg-[#10B981]/10", text: "text-[#10B981]" },
    SYSTEM_CONFIG_CHANGE: { bg: "bg-[#F97316]/10", text: "text-[#F97316]" },
    ACCOUNT_DEACTIVATED: { bg: "bg-[#EF4444]/10", text: "text-[#EF4444]" },
    API_KEY_GENERATED: { bg: "bg-[#A855F7]/10", text: "text-[#A855F7]" },
};

export default function AuditLogPage() {
    const [socFilters, setSocFilters] = useState<SOCFilters>({
        dateRange: "24h",
        severity: "all",
        action: "all",
        user: "all",
        ipSearch: "",
    });
    const [drawerContext, setDrawerContext] = useState<InvestigationContext | null>(null);
    const [isExporting, setIsExporting] = useState(false);

    const [logs, setLogs] = useState<AuditLogEntry[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [pageOffset, setPageOffset] = useState(0);
    const [refreshing, setRefreshing] = useState(false);
    const { token } = useAuth();

    const fetchLogs = async (offset = 0, append = false) => {
        if (!token) return;
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/audit/list?limit=100&offset=${offset}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setLogs(prev => append ? [...prev, ...data.logs] : data.logs);
            }
        } catch (err) {
            console.error(err);
        } finally {
            setIsLoading(false);
        }
    };

    const handleRefresh = async () => {
        setRefreshing(true);
        await fetchLogs(0, false);
        setRefreshing(false);
    };

    const [isLive, setIsLive] = useState(() => {
        if (typeof window !== "undefined") {
            return localStorage.getItem("tibsa_live_audit") !== "false";
        }
        return true;
    });

    useEffect(() => {
        if (typeof window !== "undefined") {
            localStorage.setItem("tibsa_live_audit", String(isLive));
        }
    }, [isLive]);

    useEffect(() => {
        if (!token) return;

        // First mount shows the spinner
        setIsLoading(true);
        fetchLogs(0);

        // Silent refresh every 3 seconds in the background only if auto-refresh is active
        if (!isLive) return;
        const interval = setInterval(() => {
            fetchLogs(0, false);
        }, 3000);

        return () => clearInterval(interval);
    }, [token, isLive]);

    const handleLoadMore = () => {
        const nextOffset = pageOffset + 100;
        setPageOffset(nextOffset);
        fetchLogs(nextOffset, true);
    };

    const filteredLogs = logs.filter((l) => {
        // 1. Date Range Filter
        const logTime = new Date(l.timestamp).getTime();
        const now = Date.now();
        let cutoff = 0;
        if (socFilters.dateRange === "1h") cutoff = now - 60 * 60 * 1000;
        else if (socFilters.dateRange === "24h") cutoff = now - 24 * 60 * 60 * 1000;
        else if (socFilters.dateRange === "7d") cutoff = now - 7 * 24 * 60 * 60 * 1000;
        else if (socFilters.dateRange === "30d") cutoff = now - 30 * 24 * 60 * 60 * 1000;
        
        if (cutoff > 0 && logTime < cutoff) return false;

        // 2. Severity Filter
        if (socFilters.severity !== "all" && l.status !== socFilters.severity) return false;

        // 3. Action Filter
        if (socFilters.action !== "all" && l.action !== socFilters.action) return false;

        // 4. User Filter (admin, system, all)
        if (socFilters.user === "admin" && l.user_role !== "admin") return false;
        if (socFilters.user === "system" && l.user_role !== "system" && l.user_name.toLowerCase() !== "system") return false;

        // 5. IP Address Filter
        if (socFilters.ipSearch && !l.ip_address.includes(socFilters.ipSearch)) return false;

        return true;
    });

    const successCount = logs.filter((l) => l.status === "success").length;
    const failureCount = logs.filter((l) => l.status === "failure").length;
    const warningCount = logs.filter((l) => l.status === "warning").length;

    const columns: Column<AuditLogEntry>[] = [
        {
            key: "timestamp",
            label: "Time",
            sortable: true,
            render: (entry) => (
                <div className="space-y-0.5">
                    <p className="text-xs text-[#1F2933] font-bold tabular-nums">
                        {new Date(entry.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </p>
                    <p className="text-[10px] text-[#7C6F64] font-medium font-mono">
                        {new Date(entry.timestamp).toLocaleDateString()}
                    </p>
                </div>
            ),
        },
        {
            key: "user_name",
            label: "User",
            sortable: true,
            render: (entry) => (
                <div 
                    className="flex items-center gap-2 cursor-pointer group hover:bg-[#FAF7F1] p-1.5 -m-1.5 rounded-lg transition-colors"
                    onClick={() => setDrawerContext({ type: "user", value: entry.user_name })}
                >
                    <div className="w-7 h-7 rounded-full bg-gradient-to-br from-[#2F80ED] to-[#A855F7] flex items-center justify-center flex-shrink-0 shadow-sm">
                        <span className="text-[10px] font-black text-white">{entry.user_name.charAt(0).toUpperCase()}</span>
                    </div>
                    <div>
                        <p className="text-sm font-bold text-[#1F2933] group-hover:text-[#00A884] transition-colors">{entry.user_name}</p>
                        <p className="text-[10px] text-[#7C6F64] font-medium">{entry.user_email}</p>
                    </div>
                </div>
            ),
        },
        {
            key: "action",
            label: "Action",
            sortable: true,
            render: (entry) => {
                const style = ACTION_STYLES[entry.action] || { bg: "bg-[#FAF7F1]", text: "text-[#7C6F64]" };
                return (
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border border-current/10 ${style.bg} ${style.text}`}>
                        {entry.action}
                    </span>
                );
            },
        },
        {
            key: "details",
            label: "Details",
            render: (entry) => (
                <div className="space-y-0.5 max-w-[350px]">
                    <p className="text-xs text-[#1F2933] font-medium whitespace-normal" title={entry.details}>
                        {entry.details}
                    </p>
                    {entry.user_agent && entry.user_agent !== "Unknown Device" && (
                        <p className="text-[10px] text-[#7C6F64] flex items-center gap-1 font-mono" title="Device Details">
                            <span className="w-1.5 h-1.5 rounded-full bg-[#E6DDD2]" />
                            {entry.user_agent}
                        </p>
                    )}
                </div>
            ),
        },
        {
            key: "ip_address",
            label: "IP Address",
            render: (entry) => (
                <span 
                    className="text-xs text-[#00A884] font-bold font-mono cursor-pointer hover:underline"
                    onClick={() => setDrawerContext({ type: "ip", value: entry.ip_address })}
                >
                    {entry.ip_address}
                </span>
            ),
        },
        {
            key: "status",
            label: "Status",
            sortable: true,
            render: (entry) => (
                <span className={`flex items-center gap-1.5 text-xs font-bold ${
                    entry.status === "success" ? "text-[#10B981]" :
                    entry.status === "failure" ? "text-[#EF4444]" : "text-[#F97316]"
                }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${
                        entry.status === "success" ? "bg-[#10B981]" :
                        entry.status === "failure" ? "bg-[#EF4444]" : "bg-[#F97316]"
                    }`} />
                    {entry.status}
                </span>
            ),
        },
    ];

    const handleExport = () => {
        setIsExporting(true);
        setTimeout(() => {
            const headers = ["ID", "Timestamp", "User", "Email", "Action", "Status", "IP Address", "Details"];
            const csvRows = filteredLogs.map((l) => 
                [l.id, l.timestamp, l.user_name, l.user_email, l.action, l.status, l.ip_address, `"${l.details}"`].join(",")
            );
            const csvContent = [headers.join(","), ...csvRows].join("\n");
            
            const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", `tibsa_audit_export_${new Date().getTime()}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            setIsExporting(false);
        }, 1000);
    };

    return (
        <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] text-[#1F2933]">
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.4 }}
                className="space-y-6 w-full max-w-[1600px] mx-auto animate-fade-in"
            >
                {/* ── Header ─────────────────────────────────── */}
                <div 
                    style={{
                        background: "linear-gradient(90deg, #FFFCF7 0%, #F4EFE7 45%, #E9EDF3 100%)"
                    }}
                    className="border border-[#E6DDD2] p-6 md:p-8 rounded-[24px] shadow-sm relative overflow-hidden flex flex-col md:flex-row justify-between items-start md:items-center gap-6"
                >
                    <div className="flex items-start gap-4">
                        <div className="p-2.5 bg-[#2F80ED]/10 rounded-xl border border-[#2F80ED]/20 text-[#2F80ED] shadow-sm shrink-0 mt-1">
                            <IconAudit />
                        </div>
                        <div>
                            <div className="flex items-center gap-2 mb-1.5">
                                <span className="px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-widest bg-gradient-to-r from-amber-500/10 to-orange-500/10 border border-amber-500/20 text-amber-600 rounded-full">
                                    Security
                                </span>
                            </div>
                            <h1 className="text-2xl font-black text-[#1F2933] tracking-tight">Security Event Timeline</h1>
                            <p className="text-[#7C6F64] mt-1 max-w-xl text-sm leading-relaxed font-medium">
                                Track all security events, admin actions, and system changes in real-time.
                            </p>
                        </div>
                    </div>
                    
                    <div className="flex items-center gap-4 bg-white border border-[#E6DDD2] rounded-xl p-2 shadow-sm">
                        <TibsaRefreshButton
                            onClick={handleRefresh}
                            isRefreshing={refreshing}
                        />
                        <div className="w-px h-4 bg-[#E6DDD2]" />
                        <div className="flex items-center gap-2 text-xs">
                            <span className="text-[#7C6F64] font-bold">AUTO-REFRESH</span>
                            <button 
                                onClick={() => setIsLive(!isLive)}
                                className={`w-8 h-4 rounded-full transition-colors relative cursor-pointer ${isLive ? 'bg-[#10B981]/80 shadow-[0_0_8px_rgba(16,185,129,0.4)]' : 'bg-gray-200'}`}
                            >
                                <span className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform ${isLive ? 'translate-x-4' : 'translate-x-0'}`} />
                            </button>
                        </div>
                    </div>
                </div>

                {/* ── Stats ──────────────────────────────────── */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatCard label="Total Events" value={logs.length} icon={<IconAudit />} color="blue" delay={0} />
                    <StatCard label="Successful" value={successCount} icon={<IconSuccess />} color="green" delay={100} />
                    <StatCard label="Failed" value={failureCount} icon={<IconFail />} color="red" delay={200} />
                    <StatCard label="Warnings" value={warningCount} icon={<IconWarn />} color="amber" delay={300} />
                </div>

                {/* ── Filters ────────────────────────────────── */}
                <SOCFilterBar 
                    filters={socFilters}
                    onFilterChange={setSocFilters}
                    onExport={handleExport}
                    isExporting={isExporting}
                />

                {/* ── Audit Log Table ────────────────────────── */}
                <AdminSectionCard
                    title="Event Timeline"
                    description={`Showing ${filteredLogs.length} events matching filters`}
                >
                    <DataTable
                        columns={columns}
                        data={filteredLogs}
                        searchable
                        searchPlaceholder="Search by user, action, or details..."
                        searchKeys={["user_name", "user_email", "action", "details", "ip_address"]}
                        pageSize={10}
                        emptyMessage={isLoading ? "Loading audit logs..." : "No audit logs found matching your filters."}
                    />
                        
                    {logs.length >= 100 && (
                        <div className="flex justify-center mt-4">
                            <button 
                                onClick={handleLoadMore}
                                className="px-4 py-2 text-sm text-[#F97316] bg-[#F97316]/10 hover:bg-[#F97316]/20 border border-[#F97316]/20 rounded-lg transition-colors cursor-pointer font-bold"
                            >
                                Load More
                            </button>
                        </div>
                    )}
                </AdminSectionCard>

                <InvestigationDrawer
                    isOpen={!!drawerContext}
                    onClose={() => setDrawerContext(null)}
                    context={drawerContext}
                />
            </motion.div>
        </div>
    );
}
