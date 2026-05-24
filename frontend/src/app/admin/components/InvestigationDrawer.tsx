"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

export type EntityType = "ip" | "user" | "threat";

export interface InvestigationContext {
    type: EntityType;
    value: string;
    data?: any;
}

interface InvestigationDrawerProps {
    isOpen: boolean;
    onClose: () => void;
    context: InvestigationContext | null;
}

export function InvestigationDrawer({ isOpen, onClose, context }: InvestigationDrawerProps) {
    const [isInvestigating, setIsInvestigating] = useState(false);
    const [isResolved, setIsResolved] = useState(false);

    // Reset states when context changes
    useState(() => {
        setIsInvestigating(false);
        setIsResolved(false);
    });

    if (!context) return null;

    const renderMockContent = () => {
        if (context.type === "ip") {
            return (
                <div className="space-y-6">
                    <div>
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">WHOIS & Geo Intelligence</h4>
                        <div className="grid grid-cols-2 gap-4">
                            <div className="bg-white/[0.02] border border-white/[0.06] p-3 rounded-lg">
                                <p className="text-[10px] text-slate-500 mb-1">ISP / Organization</p>
                                <p className="text-sm font-medium text-slate-200">DigitalOcean, LLC</p>
                            </div>
                            <div className="bg-white/[0.02] border border-white/[0.06] p-3 rounded-lg">
                                <p className="text-[10px] text-slate-500 mb-1">Location</p>
                                <p className="text-sm font-medium text-slate-200">Frankfurt, Germany</p>
                            </div>
                        </div>
                    </div>
                    <div>
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Threat Feed Hits</h4>
                        <div className="space-y-2">
                            <div className="flex items-center justify-between bg-red-500/[0.05] border border-red-500/20 p-3 rounded-lg">
                                <div className="flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                                    <span className="text-sm font-medium text-red-400">AbuseIPDB</span>
                                </div>
                                <span className="text-xs text-red-500">100% Confidence</span>
                            </div>
                            <div className="flex items-center justify-between bg-amber-500/[0.05] border border-amber-500/20 p-3 rounded-lg">
                                <div className="flex items-center gap-2">
                                    <span className="w-2 h-2 rounded-full bg-amber-500" />
                                    <span className="text-sm font-medium text-amber-400">AlienVault OTX</span>
                                </div>
                                <span className="text-xs text-amber-500">2 Pulses</span>
                            </div>
                        </div>
                    </div>
                    <div>
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Recent Activity from IP</h4>
                        <div className="text-xs text-slate-300 space-y-2 border-l-2 border-white/[0.1] pl-3 ml-1">
                            <p><span className="text-slate-500">10 mins ago</span> — Failed Login Attempt (admin)</p>
                            <p><span className="text-slate-500">12 mins ago</span> — Failed Login Attempt (root)</p>
                            <p><span className="text-slate-500">15 mins ago</span> — Port Scan Detected (TCP 22)</p>
                        </div>
                    </div>
                </div>
            );
        }

        if (context.type === "user") {
            return (
                <div className="space-y-6">
                    <div>
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Account Details</h4>
                        <div className="space-y-3">
                            <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.06] p-3 rounded-lg">
                                <span className="text-xs text-slate-400">Account Status</span>
                                <span className="text-xs font-medium text-emerald-400 bg-emerald-500/20 px-2 py-0.5 rounded-full">Active</span>
                            </div>
                            <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.06] p-3 rounded-lg">
                                <span className="text-xs text-slate-400">MFA Enabled</span>
                                <span className="text-xs font-medium text-blue-400">Yes (Authenticator App)</span>
                            </div>
                            <div className="flex items-center justify-between bg-white/[0.02] border border-white/[0.06] p-3 rounded-lg">
                                <span className="text-xs text-slate-400">Last Login</span>
                                <span className="text-xs font-medium text-slate-300">Just now</span>
                            </div>
                        </div>
                    </div>
                    <div>
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Recent Actions</h4>
                        <div className="text-xs text-slate-300 space-y-2 border-l-2 border-white/[0.1] pl-3 ml-1">
                            <p><span className="text-slate-500">2 mins ago</span> — Viewed Audit Logs</p>
                            <p><span className="text-slate-500">1 hr ago</span> — Exported Scan Report PDF</p>
                            <p><span className="text-slate-500">3 hrs ago</span> — Logged in successfully</p>
                        </div>
                    </div>
                </div>
            );
        }

        if (context.type === "threat") {
            return (
                <div className="space-y-6">
                    <div className="bg-red-500/[0.05] border border-red-500/20 p-4 rounded-xl">
                        <p className="text-xs text-red-400 mb-1">Threat Indicator Detected</p>
                        <p className="text-lg font-mono text-red-300 break-all">{context.value}</p>
                    </div>
                    <div>
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Malware Analysis</h4>
                        <div className="space-y-3">
                            <div className="bg-white/[0.02] border border-white/[0.06] p-3 rounded-lg">
                                <p className="text-[10px] text-slate-500 mb-1">Family / Type</p>
                                <p className="text-sm font-medium text-slate-200">Trojan.Generic.KD</p>
                            </div>
                            <div className="bg-white/[0.02] border border-white/[0.06] p-3 rounded-lg">
                                <p className="text-[10px] text-slate-500 mb-1">Detection Engine Ratio</p>
                                <div className="flex items-center gap-3">
                                    <div className="flex-1 h-1.5 bg-white/[0.1] rounded-full overflow-hidden">
                                        <div className="h-full bg-red-500 w-[85%]" />
                                    </div>
                                    <span className="text-xs font-bold text-red-400">51 / 60</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            );
        }

        return null;
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
                            {renderMockContent()}
                        </div>

                        {/* Footer / Investigation Actions */}
                        <div className="p-5 border-t border-white/[0.06] bg-black/20 space-y-3">
                            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">SOC Actions</h4>
                            <div className="grid grid-cols-2 gap-3">
                                <button
                                    onClick={() => setIsInvestigating(!isInvestigating)}
                                    className={`px-4 py-2 text-xs font-medium rounded-lg border transition-all ${
                                        isInvestigating
                                            ? "bg-amber-500/20 border-amber-500/40 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.15)]"
                                            : "bg-white/[0.02] border-white/[0.08] text-slate-300 hover:bg-white/[0.06]"
                                    }`}
                                >
                                    {isInvestigating ? "Investigating..." : "Mark Investigating"}
                                </button>
                                <button
                                    onClick={() => setIsResolved(true)}
                                    disabled={isResolved}
                                    className={`px-4 py-2 text-xs font-medium rounded-lg border transition-all ${
                                        isResolved
                                            ? "bg-emerald-500/20 border-emerald-500/40 text-emerald-400 cursor-not-allowed"
                                            : "bg-white/[0.02] border-white/[0.08] text-slate-300 hover:bg-white/[0.06]"
                                    }`}
                                >
                                    {isResolved ? "Resolved" : "Mark as Resolved"}
                                </button>
                                <button className="col-span-2 px-4 py-2 text-xs font-medium rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all flex items-center justify-center gap-2">
                                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                    </svg>
                                    Escalate Incident
                                </button>
                            </div>
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    );
}
