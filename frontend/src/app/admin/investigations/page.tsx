"use client";

import { TibsaRefreshButton } from "@/components/ui";
import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { motion } from "framer-motion";
import { LightAdminDropdown } from "../components";
import {
    Shield,
    Clock,
    ArrowRight,
    Search,
    Globe,
    RefreshCw,
    AlertOctagon,
    User
} from "lucide-react";

interface InvestigationItem {
    id: string;
    scan_id: string;
    target: string;
    status: string;
    risk_score: number;
    current_stage: string;
    started_at: string;
    completed_at: string | null;
    analyst_name: string;
}

export default function AdminInvestigationsPage() {
    const router = useRouter();
    const { token } = useAuth();

    const [investigations, setInvestigations] = useState<InvestigationItem[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [searchQuery, setSearchQuery] = useState("");
    const [statusFilter, setStatusFilter] = useState("all");

    const fetchInvestigations = useCallback(async () => {
        if (!token) return;
        try {
            setIsLoading(true);
            setError(null);
            const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
            const res = await fetch(`${API_BASE_URL}/api/v1/admin/investigations`, {
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });

            if (!res.ok) {
                throw new Error(`Failed to fetch investigations (Status: ${res.status})`);
            }

            const data = await res.json();
            setInvestigations(data.investigations || []);
        } catch (err: any) {
            console.error(err);
            setError(err.message || "Failed to load investigations.");
        } finally {
            setIsLoading(false);
        }
    }, [token]);

    useEffect(() => {
        fetchInvestigations();
    }, [fetchInvestigations]);

    const getStatusBadge = (status: string) => {
        const common = "px-2 py-1 rounded-full text-[10px] font-bold uppercase border tracking-wider";
        switch (status) {
            case "completed":
                return <span className={`${common} border-[#10B981]/20 bg-[#10B981]/10 text-[#10B981]`}>Completed</span>;
            case "failed":
                return <span className={`${common} border-[#EF4444]/20 bg-[#EF4444]/10 text-[#EF4444]`}>Failed</span>;
            case "stopped":
                return <span className={`${common} border-orange-500/20 bg-orange-500/10 text-orange-600`}>Stopped</span>;
            case "pending":
            case "created":
                return <span className={`${common} border-orange-500/20 bg-orange-500/10 text-orange-600`}>Pending</span>;
            default:
                return <span className={`${common} border-[#2F80ED]/20 bg-[#2F80ED]/10 text-[#2F80ED] animate-pulse`}>{status || "Running"}</span>;
        }
    };

    const filteredInvestigations = investigations.filter((inv) => {
        const matchesSearch =
            inv.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
            inv.scan_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
            inv.analyst_name.toLowerCase().includes(searchQuery.toLowerCase());

        const matchesStatus =
            statusFilter === "all" ||
            inv.status === statusFilter;

        return matchesSearch && matchesStatus;
    });

    return (
        <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] text-[#1F2933]">
            <div className="space-y-6 max-w-[1600px] mx-auto">
                {/* Header */}
                <motion.div 
                    initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}
                    style={{ background: "linear-gradient(90deg, #FFFCF7 0%, #F4EFE7 45%, #E9EDF3 100%)" }}
                    className="border border-[#E6DDD2] p-[32px] rounded-[24px] shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-6"
                >
                    <div className="flex items-start gap-4">
                        <div className="p-2.5 bg-[#edf8f3] rounded-xl border border-[#0f9d76]/30 shadow-sm shrink-0 mt-1">
                            <Shield className="w-5 h-5 text-[#10B981]" />
                        </div>
                        <div>
                            <div className="flex items-center gap-2 mb-1.5">
                                <span className="text-[10px] font-bold text-[#0f9d76] uppercase tracking-widest">
                                    SECURITY OPERATIONS CENTER
                                </span>
                            </div>
                            <h1 className="text-2xl font-black text-[#1d1d1d] tracking-tight">Standard Investigations Logs</h1>
                            <p className="text-[#7C6F64] mt-1 max-w-xl text-sm leading-relaxed font-medium">
                                Audit and inspect all security investigations initiated by platform analysts across target web assets.
                            </p>
                        </div>
                    </div>
                    <TibsaRefreshButton
                        onClick={fetchInvestigations}
                        isRefreshing={isLoading}
                        label="Refresh Logs"
                    />
                </motion.div>

                {/* Filters */}
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.1 }} className="flex flex-col sm:flex-row gap-4 bg-white border border-[#E6DDD2] p-4 rounded-[18px] shadow-sm">
                    <div className="relative flex-1">
                        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-[#7C6F64]" />
                        <input
                            type="text"
                            placeholder="Search by target, Scan ID, or analyst name..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full bg-white border border-[#E6DDD2] rounded-xl pl-10 pr-4 h-[40px] text-[#1F2933] placeholder-[#7C6F64] text-sm focus:outline-none focus:border-[#10B981] focus:ring-[3px] focus:ring-[#10B981]/15 transition-all shadow-sm"
                        />
                    </div>
                    <LightAdminDropdown
                        value={statusFilter}
                        onChange={(val) => setStatusFilter(val)}
                        options={[
                            { value: "all", label: "All Statuses" },
                            { value: "completed", label: "Completed" },
                            { value: "failed", label: "Failed" },
                            { value: "stopped", label: "Stopped" },
                            { value: "running", label: "Running" },
                            { value: "pending", label: "Pending" },
                        ]}
                        className="w-[180px]"
                    />
                </motion.div>

            {error && (
                <div className="flex flex-col items-center justify-center py-12 border border-[#EF4444]/20 bg-[#EF4444]/5 rounded-[20px] text-center shadow-sm">
                    <AlertOctagon className="w-10 h-10 text-[#EF4444] mb-3" />
                    <p className="text-[#EF4444] text-sm font-semibold">{error}</p>
                    <button onClick={fetchInvestigations} className="mt-4 px-4 py-2 bg-[#EF4444]/10 hover:bg-[#EF4444]/20 text-[#EF4444] rounded-lg text-xs font-bold transition-colors">
                        Retry Loading
                    </button>
                </div>
            )}

            {!error && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.2 }} className="bg-white border border-[#E6DDD2] rounded-[20px] shadow-sm overflow-hidden">
                    {isLoading ? (
                        <div className="py-24 text-center text-[#7C6F64] font-medium flex items-center justify-center gap-2">
                            <span className="inline-block animate-spin h-4 w-4 border-2 border-[#10B981] border-t-transparent rounded-full" />
                            Loading unified investigations logs...
                        </div>
                    ) : filteredInvestigations.length === 0 ? (
                        <div className="py-16 text-center text-[#7C6F64] text-sm">
                            No matching security investigations found in history.
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-left text-sm">
                                <thead>
                                    <tr className="border-b border-[#E6DDD2] bg-[#FAF7F1] text-[#7C6F64] font-semibold text-xs uppercase tracking-wider">
                                        <th className="py-3 px-4">Scan ID / Ingestion</th>
                                        <th className="py-3 px-4">Target</th>
                                        <th className="py-3 px-4">Risk Score</th>
                                        <th className="py-3 px-4">Active Stage</th>
                                        <th className="py-3 px-4">Status</th>
                                        <th className="py-3 px-4">Analyst</th>
                                        <th className="py-3 px-4">Date Started</th>
                                        <th className="py-3 px-4"></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filteredInvestigations.map((inv, idx) => (
                                        <motion.tr
                                            key={inv.id}
                                            initial={{ opacity: 0, x: -8 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            transition={{ duration: 0.25, delay: idx * 0.03 }}
                                            onClick={() => router.push(`/admin/investigations/${inv.id}`)}
                                            className="hover:bg-[#F8FDFB] border-b border-[#E6DDD2] cursor-pointer transition-colors group"
                                        >
                                            <td className="py-4 px-4 font-mono text-xs font-semibold text-[#1F2933]">
                                                <div>{inv.scan_id || "SCAN-INF"}</div>
                                                <div className="text-[10px] text-[#7C6F64] uppercase mt-0.5 font-sans">
                                                    ID: {inv.id.substring(0, 8)}
                                                </div>
                                            </td>
                                            <td className="py-4 px-4 text-[#2F80ED] font-medium truncate max-w-[240px]">
                                                {inv.target}
                                            </td>
                                            <td className="py-4 px-4">
                                                <span className={`font-bold font-mono text-xs ${
                                                    inv.status === "failed" ? "text-[#7C6F64]" :
                                                    inv.risk_score > 60 ? "text-[#EF4444]" :
                                                    inv.risk_score > 30 ? "text-orange-500" : "text-[#10B981]"
                                                }`}>
                                                    {inv.status === "failed" ? "—" : Math.round(inv.risk_score)}
                                                </span>
                                            </td>
                                            <td className="py-4 px-4 text-xs text-[#7C6F64] font-medium">
                                                {inv.current_stage || "Queued"}
                                            </td>
                                            <td className="py-4 px-4">{getStatusBadge(inv.status)}</td>
                                            <td className="py-4 px-4 text-xs text-[#1F2933] font-medium">
                                                <div className="flex items-center gap-1.5">
                                                    <User className="w-3.5 h-3.5 text-[#10B981]" />
                                                    {inv.analyst_name}
                                                </div>
                                            </td>
                                            <td className="py-4 px-4 text-xs text-[#7C6F64]">
                                                {new Date(inv.started_at).toLocaleString()}
                                            </td>
                                            <td className="py-4 px-4 text-right">
                                                <div className="inline-flex w-8 h-8 rounded-full items-center justify-center group-hover:bg-[#10B981]/10 transition-colors">
                                                    <ArrowRight className="w-4 h-4 text-[#7C6F64] group-hover:text-[#10B981] group-hover:translate-x-1 transition-all" />
                                                </div>
                                            </td>
                                        </motion.tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </motion.div>
            )}
        </div>
        </div>
    );
}
