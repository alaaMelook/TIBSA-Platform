"use client";

import { motion } from "framer-motion";
import type { RecentActivity } from "../types";

// ─── Severity Style Map ──────────────────────────────────────
const SEVERITY_STYLES: Record<string, { border: string; bg: string; text: string; pulse: string }> = {
    critical: { border: "border-l-red-500",     bg: "bg-red-500/[0.04]",     text: "text-red-400",     pulse: "bg-red-400" },
    warning:  { border: "border-l-amber-500",   bg: "bg-amber-500/[0.03]",   text: "text-amber-400",   pulse: "bg-amber-400" },
    success:  { border: "border-l-emerald-500",  bg: "bg-emerald-500/[0.03]", text: "text-emerald-400",  pulse: "bg-emerald-400" },
    info:     { border: "border-l-blue-500",     bg: "bg-blue-500/[0.03]",    text: "text-blue-400",     pulse: "bg-blue-400" },
};

// ─── Type Icon Map ───────────────────────────────────────────
const TYPE_ICONS: Record<string, React.ReactNode> = {
    threat: (
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
    ),
    scan: (
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
            <circle cx="11" cy="11" r="8" /><path strokeLinecap="round" d="M21 21l-4.35-4.35" />
        </svg>
    ),
    user: (
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
        </svg>
    ),
    system: (
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
        </svg>
    ),
    auth: (
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
    ),
};

function timeAgo(dateStr: string): string {
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
}

interface ActivityFeedProps {
    activities: RecentActivity[];
    maxItems?: number;
}

const container = {
    hidden: { opacity: 0 },
    show: {
        opacity: 1,
        transition: { staggerChildren: 0.06 }
    }
};

const item = {
    hidden: { opacity: 0, x: -12 },
    show: { opacity: 1, x: 0 }
};

export function ActivityFeed({ activities, maxItems = 8 }: ActivityFeedProps) {
    const items = activities.slice(0, maxItems);

    if (items.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-12 text-center">
                <div className="w-12 h-12 rounded-full bg-white/[0.03] border border-white/[0.06] flex items-center justify-center mb-3">
                    <svg className="w-5 h-5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                </div>
                <p className="text-sm text-slate-500">No recent activity</p>
            </div>
        );
    }

    return (
        <motion.div
            variants={container}
            initial="hidden"
            animate="show"
            className="space-y-1"
        >
            {items.map((activity) => {
                const style = SEVERITY_STYLES[activity.severity] || SEVERITY_STYLES.info;
                const icon = TYPE_ICONS[activity.type] || TYPE_ICONS.system;

                return (
                    <motion.div
                        key={activity.id}
                        variants={item}
                        whileHover={{ x: 2, transition: { duration: 0.15 } }}
                        className={`flex items-start gap-3 px-3 py-2.5 rounded-lg border-l-2 ${style.border} ${style.bg} hover:bg-white/[0.03] transition-colors duration-150 cursor-default group`}
                    >
                        {/* Severity dot + Icon */}
                        <div className="relative flex-shrink-0 mt-0.5">
                            <span className={`flex items-center justify-center w-7 h-7 rounded-lg ${style.bg} ${style.text}`}>
                                {icon}
                            </span>
                            {activity.severity === "critical" && (
                                <span className="absolute -top-0.5 -right-0.5">
                                    <span className={`block w-2 h-2 rounded-full ${style.pulse} animate-ping opacity-50`} />
                                    <span className={`absolute top-0 left-0 block w-2 h-2 rounded-full ${style.pulse}`} />
                                </span>
                            )}
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0">
                            <p className="text-[13px] text-slate-300 leading-relaxed group-hover:text-slate-200 transition-colors">
                                {activity.message}
                            </p>
                            <div className="flex items-center gap-2 mt-1">
                                <span className="text-[10px] text-slate-500">{timeAgo(activity.timestamp)}</span>
                                {activity.user && (
                                    <>
                                        <span className="text-[10px] text-slate-600">•</span>
                                        <span className="text-[10px] text-slate-400 font-medium">{activity.user}</span>
                                    </>
                                )}
                            </div>
                        </div>

                        {/* Severity badge */}
                        <span className={`flex-shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${style.text} opacity-60 group-hover:opacity-100 transition-opacity`}>
                            {activity.severity}
                        </span>
                    </motion.div>
                );
            })}
        </motion.div>
    );
}
