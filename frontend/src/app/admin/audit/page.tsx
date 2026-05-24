"use client";

import { useState, useMemo } from "react";
import { motion } from "framer-motion";
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
import { mockAuditLog } from "../mock";

// ─── Icons ──────────────────────────────────────────────────
const IconAudit = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
    </svg>
);
const IconSuccess = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
);
const IconFail = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
);
const IconWarn = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
);

// ─── Action Style Map ───────────────────────────────────────
const ACTION_STYLES: Record<string, { bg: string; text: string }> = {
    LOGIN: { bg: "bg-blue-500/10", text: "text-blue-400" },
    LOGIN_FAILED: { bg: "bg-red-500/10", text: "text-red-400" },
    SCAN_CREATED: { bg: "bg-cyan-500/10", text: "text-cyan-400" },
    USER_ROLE_CHANGE: { bg: "bg-purple-500/10", text: "text-purple-400" },
    THREAT_FEED_UPDATE: { bg: "bg-amber-500/10", text: "text-amber-400" },
    REPORT_EXPORTED: { bg: "bg-emerald-500/10", text: "text-emerald-400" },
    SYSTEM_CONFIG_CHANGE: { bg: "bg-orange-500/10", text: "text-orange-400" },
    ACCOUNT_DEACTIVATED: { bg: "bg-red-500/10", text: "text-red-400" },
    API_KEY_GENERATED: { bg: "bg-indigo-500/10", text: "text-indigo-400" },
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

    const logs = mockAuditLog;

    const filteredLogs = logs.filter((l) => {
        if (socFilters.severity !== "all" && l.status !== socFilters.severity) return false;
        if (socFilters.action !== "all" && l.action !== socFilters.action) return false;
        if (socFilters.user === "admin" && l.user_name.toLowerCase() === "unknown") return false; // Mock logic
        if (socFilters.user === "system" && l.user_name.toLowerCase() !== "system") return false;
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
                    <p className="text-xs text-slate-300 tabular-nums">
                        {new Date(entry.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </p>
                    <p className="text-[10px] text-slate-500">
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
                    className="flex items-center gap-2 cursor-pointer group hover:bg-white/[0.04] p-1.5 -m-1.5 rounded transition-colors"
                    onClick={() => setDrawerContext({ type: "user", value: entry.user_name })}
                >
                    <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center flex-shrink-0">
                        <span className="text-[10px] font-bold text-white">{entry.user_name.charAt(0)}</span>
                    </div>
                    <div>
                        <p className="text-sm text-slate-200 group-hover:text-blue-400 transition-colors">{entry.user_name}</p>
                        <p className="text-[10px] text-slate-500">{entry.user_email}</p>
                    </div>
                </div>
            ),
        },
        {
            key: "action",
            label: "Action",
            sortable: true,
            render: (entry) => {
                const style = ACTION_STYLES[entry.action] || { bg: "bg-slate-500/10", text: "text-slate-400" };
                return (
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${style.bg} ${style.text}`}>
                        {entry.action}
                    </span>
                );
            },
        },
        {
            key: "details",
            label: "Details",
            render: (entry) => (
                <p className="text-xs text-slate-400 max-w-[300px] truncate" title={entry.details}>
                    {entry.details}
                </p>
            ),
        },
        {
            key: "ip_address",
            label: "IP Address",
            render: (entry) => (
                <span 
                    className="text-xs text-blue-400 font-mono cursor-pointer hover:underline"
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
                <span className={`flex items-center gap-1.5 text-xs font-medium ${
                    entry.status === "success" ? "text-emerald-400" :
                    entry.status === "failure" ? "text-red-400" : "text-amber-400"
                }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${
                        entry.status === "success" ? "bg-emerald-400" :
                        entry.status === "failure" ? "bg-red-400" : "bg-amber-400"
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
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }} className="space-y-6 max-w-[1400px]">
            {/* ── Header ─────────────────────────────────── */}
            <div>
                <div className="flex items-center gap-3 mb-1">
                    <h1 className="text-2xl font-bold text-white">Security Event Timeline</h1>
                    <span className="px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-widest bg-gradient-to-r from-amber-500/20 to-orange-500/20 border border-amber-500/20 text-amber-400 rounded-full">
                        Security
                    </span>
                </div>
                <p className="text-sm text-slate-400">Track all security events, admin actions, and system changes</p>
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
                    emptyMessage="No audit events found matching your filters"
                />
            </AdminSectionCard>

            <InvestigationDrawer
                isOpen={!!drawerContext}
                onClose={() => setDrawerContext(null)}
                context={drawerContext}
            />
        </motion.div>
    );
}
