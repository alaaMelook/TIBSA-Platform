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
                <div className="flex flex-col items-center justify-center py-20 text-slate-500">
                    <svg className="w-8 h-8 animate-spin mb-4 text-blue-500" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <p className="text-sm">Fetching real-time intelligence...</p>
                </div>
            );
        }

        if (!data) {
            return <div className="text-sm text-slate-400 py-10 text-center">No data available for this context.</div>;
        }

        return (
            <div className="space-y-6">
                {/* GEO OR ROLE INFO */}
                {data.geo && (
                    <div>
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                            {context.type === "ip" ? "Geo Intelligence" : "Account Details"}
                        </h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="bg-white/[0.02] border border-white/[0.06] p-3 rounded-lg">
                                <p className="text-[10px] text-slate-500 mb-1">{context.type === "ip" ? "ISP / Organization" : "Email"}</p>
                                <p className="text-sm font-medium text-slate-200 truncate" title={data.geo.isp}>{data.geo.isp}</p>
                            </div>
                            <div className="bg-white/[0.02] border border-white/[0.06] p-3 rounded-lg">
                                <p className="text-[10px] text-slate-500 mb-1">{context.type === "ip" ? "Location" : "Status & Role"}</p>
                                <p className="text-sm font-medium text-slate-200 truncate" title={data.geo.location}>{data.geo.location}</p>
                            </div>
                        </div>
                    </div>
                )}

                {/* DETECTED DEVICES */}
                {data.devices && data.devices.length > 0 && (
                    <div>
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                            <svg className="w-3.5 h-3.5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                            </svg>
                            Detected Devices
                        </h4>
                        <div className="space-y-2">
                            {data.devices.map((device: any, i: number) => (
                                <details key={i} className="group bg-blue-500/5 border border-blue-500/10 rounded-lg overflow-hidden transition-all duration-200">
                                    <summary className="flex items-center justify-between px-3 py-2 cursor-pointer list-none select-none text-xs text-blue-400 hover:bg-blue-500/10 font-mono transition-colors">
                                        <div className="flex items-center gap-2">
                                            <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                                            <span>{device.name}</span>
                                        </div>
                                        <span className="text-[10px] text-blue-500 font-medium group-open:rotate-180 transition-transform flex items-center gap-1">
                                            details
                                            <svg className="w-3 h-3 transition-transform duration-200" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                                            </svg>
                                        </span>
                                    </summary>
                                    <div className="px-3 py-2.5 bg-black/40 border-t border-blue-500/10 text-[10px] text-slate-400 font-mono break-all leading-normal whitespace-pre-wrap">
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
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Internal Flags</h4>
                        <div className="space-y-2">
                            {data.internal_hits.map((hit: any, i: number) => (
                                <div key={i} className="flex flex-col gap-1 bg-red-500/[0.04] border border-red-500/15 p-3 rounded-lg">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                                            <span className="text-xs font-semibold text-red-400 uppercase tracking-wide">{hit.type}</span>
                                        </div>
                                        {hit.timestamp && (
                                            <span className="text-[10px] text-slate-500 font-mono">
                                                {new Date(hit.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                            </span>
                                        )}
                                    </div>
                                    <p className="text-xs text-slate-300 pl-3.5 whitespace-normal break-words leading-relaxed">
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
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Recent Activity</h4>
                        <div className="text-xs text-slate-300 space-y-4 border-l-2 border-white/[0.1] pl-3 ml-1">
                            {data.recent_activity.map((act: any, i: number) => (
                                <div key={i} className="relative space-y-0.5">
                                    <span className={`absolute -left-[17px] top-1.5 w-2 h-2 rounded-full ${
                                        act.status === "critical" || act.status === "failure" ? "bg-red-500 animate-pulse" :
                                        act.status === "warning" ? "bg-amber-500" :
                                        act.status === "success" ? "bg-emerald-500" : "bg-blue-500"
                                    }`} />
                                    <p className="font-mono text-[10px] text-slate-500">
                                        {new Date(act.timestamp).toLocaleString()}
                                    </p>
                                    <p className="font-semibold text-slate-200">{act.action}</p>
                                    {act.user_agent && act.user_agent !== "Unknown Device" && (
                                        <p className="text-[10px] text-slate-500 flex items-center gap-1 font-mono leading-none">
                                            <span className="w-1.5 h-1.5 rounded-full bg-slate-700" />
                                            {act.user_agent}
                                        </p>
                                    )}
                                </div>
                            ))}
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
                        className="fixed top-0 right-0 z-50 w-full max-w-md h-full bg-slate-900 border-l border-white/[0.08] shadow-2xl flex flex-col"
                    >
                        {/* Header */}
                        <div className="flex items-center justify-between p-5 border-b border-white/[0.06] bg-black/20">
                            <div>
                                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest bg-blue-500/20 text-blue-400 mb-2 inline-block">
                                    {context.type} Context
                                </span>
                                <h2 className="text-xl font-bold text-white font-mono truncate pr-4">{context.value}</h2>
                            </div>
                            <button
                                onClick={onClose}
                                className="w-8 h-8 rounded-full bg-white/[0.05] hover:bg-white/[0.1] flex items-center justify-center text-slate-400 transition-colors shrink-0"
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
