"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { Card } from "@/components/ui";
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
        const common = "px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border tracking-wider";
        switch (status) {
            case "completed":
                return <span className={`${common} border-emerald-500/20 bg-emerald-500/10 text-emerald-400`}>Completed</span>;
            case "failed":
                return <span className={`${common} border-red-500/20 bg-red-500/10 text-red-400`}>Failed</span>;
            case "stopped":
                return <span className={`${common} border-amber-500/20 bg-amber-500/10 text-amber-400`}>Stopped</span>;
            case "pending":
            case "created":
                return <span className={`${common} border-slate-700 bg-slate-800 text-slate-400`}>Pending</span>;
            default:
                return <span className={`${common} border-blue-500/20 bg-blue-500/10 text-blue-400 animate-pulse`}>{status || "Running"}</span>;
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
        <div className="space-y-6 max-w-[1400px]">
            {/* Header */}
            <div className="bg-gradient-to-r from-blue-900/10 via-[#1c2942]/20 to-[#0f172a] border border-white/[0.04] p-6 rounded-xl shadow-md flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <div className="flex items-center gap-2 mb-2">
                        <Shield className="w-4 h-4 text-blue-500" />
                        <span className="text-[10px] font-bold text-blue-400 uppercase tracking-widest">
                            Security Operations Center
                        </span>
                    </div>
                    <h1 className="text-2xl font-black text-white tracking-tight">Standard Investigations Logs</h1>
                    <p className="text-slate-400 mt-1 max-w-xl text-sm leading-relaxed">
                        Audit and inspect all security investigations initiated by platform analysts across target web assets.
                    </p>
                </div>
                <button
                    onClick={fetchInvestigations}
                    disabled={isLoading}
                    className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-blue-500/10 text-blue-400 hover:bg-blue-500/25 border border-blue-500/20 transition-all text-xs font-bold cursor-pointer disabled:opacity-50"
                >
                    <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
                    Refresh Logs
                </button>
            </div>

            {/* Filters */}
            <div className="flex flex-col sm:flex-row gap-4 bg-slate-900/25 border border-white/[0.04] p-4 rounded-xl">
                <div className="relative flex-1">
                    <Search className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-500" />
                    <input
                        type="text"
                        placeholder="Search by target, Scan ID, or analyst name..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full bg-[#0b0f19] border border-white/[0.08] rounded-lg pl-10 pr-4 py-2 text-slate-200 placeholder-slate-500 text-xs font-semibold focus:outline-none focus:border-blue-500/40 transition-colors"
                    />
                </div>
                <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="bg-[#0b0f19] border border-white/[0.08] rounded-lg px-4 py-2 text-slate-200 text-xs font-bold focus:outline-none focus:border-blue-500/40 transition-colors cursor-pointer"
                >
                    <option value="all">All Statuses</option>
                    <option value="completed">Completed</option>
                    <option value="failed">Failed</option>
                    <option value="stopped">Stopped</option>
                    <option value="running">Running</option>
                    <option value="pending">Pending</option>
                </select>
            </div>

            {error && (
                <div className="flex flex-col items-center justify-center py-12 border border-red-500/20 bg-red-950/10 rounded-xl text-center">
                    <AlertOctagon className="w-10 h-10 text-red-500 mb-3" />
                    <p className="text-red-400 text-sm font-semibold">{error}</p>
                    <button onClick={fetchInvestigations} className="mt-4 px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded text-xs font-bold transition">
                        Retry Loading
                    </button>
                </div>
            )}

            {!error && (
                <Card>
                    {isLoading ? (
                        <div className="py-24 text-center text-slate-500 font-medium flex items-center justify-center gap-2">
                            <span className="inline-block animate-spin h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full" />
                            Loading unified investigations logs...
                        </div>
                    ) : filteredInvestigations.length === 0 ? (
                        <div className="py-16 text-center text-slate-500 text-sm">
                            No matching security investigations found in history.
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-left text-sm">
                                <thead>
                                    <tr className="border-b border-white/[0.06] text-slate-400 font-semibold bg-slate-900/10">
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
                                <tbody className="divide-y divide-white/[0.04]">
                                    {filteredInvestigations.map((inv) => (
                                        <tr
                                            key={inv.id}
                                            onClick={() => router.push(`/admin/investigations/${inv.id}`)}
                                            className="hover:bg-white/[0.02] cursor-pointer transition-colors group"
                                        >
                                            <td className="py-4 px-4 font-mono text-xs font-semibold text-slate-300">
                                                <div>{inv.scan_id || "SCAN-INF"}</div>
                                                <div className="text-[10px] text-slate-500 uppercase mt-0.5 font-sans">
                                                    ID: {inv.id.substring(0, 8)}
                                                </div>
                                            </td>
                                            <td className="py-4 px-4 text-slate-200 font-medium truncate max-w-[240px]">
                                                {inv.target}
                                            </td>
                                            <td className="py-4 px-4">
                                                <span className={`font-bold font-mono text-xs ${
                                                    inv.status === "failed" ? "text-slate-500" :
                                                    inv.risk_score > 60 ? "text-red-400" :
                                                    inv.risk_score > 30 ? "text-orange-400" : "text-emerald-400"
                                                }`}>
                                                    {inv.status === "failed" ? "—" : Math.round(inv.risk_score)}
                                                </span>
                                            </td>
                                            <td className="py-4 px-4 text-xs text-slate-400 font-medium">
                                                {inv.current_stage || "Queued"}
                                            </td>
                                            <td className="py-4 px-4">{getStatusBadge(inv.status)}</td>
                                            <td className="py-4 px-4 text-xs text-slate-300 font-medium">
                                                <div className="flex items-center gap-1.5">
                                                    <User className="w-3.5 h-3.5 text-slate-500" />
                                                    {inv.analyst_name}
                                                </div>
                                            </td>
                                            <td className="py-4 px-4 text-xs text-slate-500">
                                                {new Date(inv.started_at).toLocaleString()}
                                            </td>
                                            <td className="py-4 px-4 text-right">
                                                <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-blue-400 group-hover:translate-x-1 transition-all" />
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </Card>
            )}
        </div>
    );
}
