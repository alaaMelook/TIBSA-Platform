"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useAuth } from "@/hooks/useAuth";

export type EntityType = "ip" | "user" | "threat";

export interface InvestigationContext {
    type: EntityType;
    value: string;
}

interface InvestigationDrawerProps {
    isOpen: boolean;
    onClose: () => void;
    context: InvestigationContext | null;
}

export function InvestigationDrawer({ isOpen, onClose, context }: InvestigationDrawerProps) {
    const { token } = useAuth();
    const [data, setData] = useState<any>(null);
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        if (isOpen && context && token) {
            setIsLoading(true);
            setData(null);
            fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/investigate/${context.type}/${encodeURIComponent(context.value)}`, {
                headers: { Authorization: `Bearer ${token}` }
            })
            .then(res => res.ok ? res.json() : null)
            .then(json => {
                setData(json);
            })
            .catch(err => console.error(err))
            .finally(() => setIsLoading(false));
        }
    }, [isOpen, context, token]);

    if (!context) return null;

    const renderContent = () => {
        if (isLoading) {
            return (
                <div className="flex flex-col items-center justify-center py-20 text-[var(--text-muted)]">
                    <svg className="w-8 h-8 animate-spin mb-4 text-[var(--primary)]" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <p className="text-sm">Fetching real-time intelligence...</p>
                </div>
            );
        }

        if (!data) {
            return <div className="text-sm text-[var(--text-muted)] py-10 text-center">No data available for this context.</div>;
        }

        return (
            <div className="space-y-6">
                {/* GEO OR ROLE INFO */}
                {data.geo && (
                    <div>
                        <h4 className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                            {context.type === "ip" ? (
                                <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                            ) : (
                                <svg className="w-3.5 h-3.5 text-[var(--primary)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                </svg>
                            )}
                            {context.type === "ip" ? "Geo Intelligence" : "Account Details"}
                        </h4>
                        <div className="grid grid-cols-1 gap-3">
                            <div className="bg-[var(--bg-elevated)] border border-[var(--border-strong)] p-3.5 rounded-lg">
                                <p className="text-[10px] text-[var(--text-muted)] mb-1.5 uppercase tracking-wider font-semibold">{context.type === "ip" ? "ISP / Organization" : "Email"}</p>
                                <p className="text-sm font-medium text-[var(--text-primary)] break-all leading-relaxed">{data.geo.isp}</p>
                            </div>
                            <div className="bg-[var(--bg-elevated)] border border-[var(--border-strong)] p-3.5 rounded-lg">
                                <p className="text-[10px] text-[var(--text-muted)] mb-1.5 uppercase tracking-wider font-semibold">{context.type === "ip" ? "Location" : "Status & Role"}</p>
                                <p className="text-sm font-medium text-[var(--text-primary)] break-words leading-relaxed">{data.geo.location}</p>
                            </div>
                        </div>
                    </div>
                )}

                {/* DETECTED DEVICES */}
                {data.devices && data.devices.length > 0 && (
                    <div>
                        <h4 className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                            <svg className="w-3.5 h-3.5 text-[var(--primary)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                            </svg>
                            Detected Devices
                        </h4>
                        <div className="space-y-2">
                            {data.devices.map((device: any, i: number) => (
                                <details key={i} className="group bg-[var(--primary)]/5 border border-[var(--primary)] rounded-lg overflow-hidden transition-all duration-200">
                                    <summary className="flex items-center justify-between px-3 py-2 cursor-pointer list-none select-none text-xs text-[var(--primary)] hover:bg-[var(--primary)]/10 font-mono transition-colors">
                                        <div className="flex items-center gap-2">
                                            <span className="w-1.5 h-1.5 rounded-full bg-[var(--primary)]" />
                                            <span>{device.name}</span>
                                        </div>
                                        <span className="text-[10px] text-[var(--primary)] font-medium group-open:rotate-180 transition-transform flex items-center gap-1">
                                            details
                                            <svg className="w-3 h-3 transition-transform duration-200" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                                            </svg>
                                        </span>
                                    </summary>
                                    <div className="px-3 py-2.5 bg-black/40 border-t border-[var(--primary)] text-[10px] text-[var(--text-muted)] font-mono break-all leading-normal whitespace-pre-wrap">
                                        {device.raw}
                                    </div>
                                </details>
                            ))}
                        </div>
                    </div>
                )}

                {/* INTERNAL HITS */}
                {data.internal_hits && data.internal_hits.length > 0 && (
                    <div>
                        <h4 className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider mb-3">Internal Flags</h4>
                        <div className="space-y-2">
                            {data.internal_hits.map((hit: any, i: number) => (
                                <div key={i} className="flex flex-col gap-1 bg-red-500/[0.04] border border-red-500/15 p-3 rounded-lg">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                                            <span className="text-xs font-semibold text-red-400 uppercase tracking-wide">{hit.type}</span>
                                        </div>
                                        {hit.timestamp && (
                                            <span className="text-[10px] text-[var(--text-muted)] font-mono">
                                                {new Date(hit.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                            </span>
                                        )}
                                    </div>
                                    <p className="text-xs text-[var(--text-secondary)] pl-3.5 whitespace-normal break-words leading-relaxed">
                                        {hit.details}
                                    </p>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* RECENT ACTIVITY */}
                {data.recent_activity && data.recent_activity.length > 0 && (
                    <div>
                        <h4 className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                            <svg className="w-3.5 h-3.5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            Recent Activity
                        </h4>
                        <div className="text-xs text-[var(--text-secondary)] space-y-3 border-l-2 border-[var(--border-strong)] pl-4 ml-1">
                            {data.recent_activity.map((act: any, i: number) => (
                                <div key={i} className="relative space-y-1 pb-1">
                                    <span className={`absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full ring-2 ring-slate-900 ${
                                        act.status === "critical" || act.status === "failure" ? "bg-red-500 animate-pulse" :
                                        act.status === "warning" ? "bg-amber-500" :
                                        act.status === "success" ? "bg-emerald-500" : "bg-[var(--primary)]"
                                    }`} />
                                    <p className="font-mono text-[10px] text-[var(--text-muted)]">
                                        {new Date(act.timestamp).toLocaleString()}
                                    </p>
                                    <p className="font-semibold text-[var(--text-primary)] break-words leading-relaxed">{act.action}</p>
                                    {act.user_agent && act.user_agent !== "Unknown Device" && (
                                        <p className="text-[10px] text-[var(--text-muted)] flex items-start gap-1.5 font-mono leading-relaxed break-all">
                                            <span className="w-1.5 h-1.5 rounded-full bg-[var(--bg-elevated)] flex-shrink-0 mt-1" />
                                            <span>{act.user_agent}</span>
                                        </p>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* INFRA INVESTIGATIONS */}
                {data.infra_investigations && data.infra_investigations.length > 0 && (
                    <div>
                        <h4 className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                            <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                            </svg>
                            Infra Intelligence Investigations ({data.infra_investigations.length})
                        </h4>
                        <div className="space-y-2">
                            {data.infra_investigations.map((inv: any, i: number) => {
                                const riskColor =
                                    inv.risk_score >= 75 ? "text-red-400" :
                                    inv.risk_score >= 60 ? "text-orange-400" :
                                    inv.risk_score >= 40 ? "text-amber-400" : "text-emerald-400";
                                const statusColors: Record<string, string> = {
                                    completed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
                                    failed: "bg-red-500/10 text-red-400 border-red-500/20",
                                    running: "bg-[var(--primary)]/10 text-[var(--primary)] border-[var(--primary)] animate-pulse",
                                    pending: "bg-[var(--bg-elevated)] text-[var(--text-muted)] border-[var(--border-strong)]",
                                    stopped: "bg-amber-500/10 text-amber-400 border-amber-500/20",
                                };
                                return (
                                    <div key={i} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-cyan-500/[0.03] border border-cyan-500/10 hover:bg-cyan-500/[0.06] transition-colors">
                                        <div className="flex-1 min-w-0">
                                            <p className="text-xs font-mono text-[var(--text-primary)] truncate">{inv.target}</p>
                                            <div className="flex items-center gap-2 mt-0.5">
                                                <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                                                    {inv.target_type}
                                                </span>
                                                {inv.started_at && (
                                                    <span className="text-[10px] text-[var(--text-muted)] font-mono">
                                                        {new Date(inv.started_at).toLocaleDateString()}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2 flex-shrink-0">
                                            {inv.status === "completed" && (
                                                <span className={`text-sm font-black font-mono ${riskColor}`}>{Math.round(inv.risk_score)}</span>
                                            )}
                                            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${statusColors[inv.status] || statusColors.pending}`}>
                                                {inv.status}
                                            </span>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                )}
            </div>
        );
    };

    return (
        <AnimatePresence>
            {isOpen && (
                <>
                    {/* Backdrop */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={onClose}
                        className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm"
                    />

                    {/* Drawer */}
                    <motion.div
                        initial={{ x: "100%" }}
                        animate={{ x: 0 }}
                        exit={{ x: "100%" }}
                        transition={{ type: "spring", damping: 25, stiffness: 200 }}
                        className="fixed top-0 right-0 z-50 w-full max-w-md h-full bg-[var(--bg-card)] border-l border-[var(--border-soft)] shadow-2xl flex flex-col"
                    >
                        {/* Header */}
                        <div className="flex items-center justify-between p-5 border-b border-[var(--border-strong)] bg-black/20">
                            <div>
                                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest bg-[var(--primary)]/20 text-[var(--primary)] mb-2 inline-block">
                                    {context.type} Context
                                </span>
                                <h2 className="text-lg font-bold text-[var(--text-primary)] font-mono break-all pr-4 leading-snug">{context.value}</h2>
                            </div>
                            <button
                                onClick={onClose}
                                className="w-8 h-8 rounded-full bg-[var(--bg-elevated)] hover:bg-[var(--bg-elevated)] flex items-center justify-center text-[var(--text-muted)] transition-colors shrink-0"
                            >
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        </div>

                        {/* Content Scrollable Area */}
                        <div className="flex-1 overflow-y-auto p-5">
                            {renderContent()}
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    );
}
