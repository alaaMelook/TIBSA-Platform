"use client";

import { useEffect, useState, useRef } from "react";
import { motion } from "framer-motion";

interface StatCardProps {
    label: string;
    value: string | number;
    change?: number;
    changeLabel?: string;
    icon: React.ReactNode;
    color: "blue" | "green" | "red" | "amber" | "purple" | "cyan";
    trend?: "up" | "down" | "neutral";
    delay?: number;
}

const COLOR_MAP = {
    blue:   { bg: "bg-blue-500/[0.07]", border: "border-blue-500/20",   text: "text-blue-400",   glow: "shadow-blue-500/10",   accent: "#3b82f6" },
    green:  { bg: "bg-emerald-500/[0.07]", border: "border-emerald-500/20", text: "text-emerald-400", glow: "shadow-emerald-500/10", accent: "#10b981" },
    red:    { bg: "bg-red-500/[0.07]",     border: "border-red-500/20",     text: "text-red-400",     glow: "shadow-red-500/10",     accent: "#ef4444" },
    amber:  { bg: "bg-amber-500/[0.07]",   border: "border-amber-500/20",   text: "text-amber-400",   glow: "shadow-amber-500/10",   accent: "#f59e0b" },
    purple: { bg: "bg-purple-500/[0.07]",  border: "border-purple-500/20",  text: "text-purple-400",  glow: "shadow-purple-500/10",  accent: "#a855f7" },
    cyan:   { bg: "bg-cyan-500/[0.07]",    border: "border-cyan-500/20",    text: "text-cyan-400",    glow: "shadow-cyan-500/10",    accent: "#06b6d4" },
};

function AnimatedNumber({ value, duration = 1400 }: { value: number; duration?: number }) {
    const [display, setDisplay] = useState(0);
    const ref = useRef<number>(0);

    useEffect(() => {
        const startTime = performance.now();
        const startVal = ref.current;

        function animate(currentTime: number) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 4);
            const current = Math.floor(eased * (value - startVal) + startVal);
            setDisplay(current);
            if (progress < 1) {
                requestAnimationFrame(animate);
            } else {
                ref.current = value;
            }
        }

        requestAnimationFrame(animate);
    }, [value, duration]);

    return <>{display.toLocaleString()}</>;
}

export function StatCard({ label, value, change, changeLabel, icon, color, trend, delay = 0 }: StatCardProps) {
    const colors = COLOR_MAP[color];
    const isNumeric = typeof value === "number";

    return (
        <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.5, delay: delay / 1000, ease: [0.25, 0.46, 0.45, 0.94] }}
            whileHover={{ y: -2, scale: 1.02, transition: { duration: 0.2 } }}
            className={`relative overflow-hidden rounded-xl border ${colors.border} backdrop-blur-md p-5 shadow-lg ${colors.glow} cursor-default group`}
            style={{ background: `linear-gradient(135deg, rgba(26,39,68,0.8) 0%, rgba(15,23,42,0.9) 100%)` }}
        >
            {/* Animated gradient accent line at top */}
            <div
                className="absolute top-0 left-0 right-0 h-[2px] opacity-60 group-hover:opacity-100 transition-opacity duration-300"
                style={{ background: `linear-gradient(90deg, transparent, ${colors.accent}, transparent)` }}
            />

            {/* Subtle radial glow */}
            <div
                className="absolute -top-16 -right-16 w-32 h-32 rounded-full opacity-[0.04] group-hover:opacity-[0.08] transition-opacity duration-500"
                style={{ background: `radial-gradient(circle, ${colors.accent}, transparent)` }}
            />

            <div className="relative flex items-start justify-between">
                <div className="space-y-2">
                    <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{label}</p>
                    <p className={`text-2xl font-bold ${colors.text} tracking-tight`}>
                        {isNumeric ? <AnimatedNumber value={value as number} /> : value}
                    </p>
                    {change !== undefined && (
                        <motion.div
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: (delay / 1000) + 0.3, duration: 0.4 }}
                            className="flex items-center gap-1.5"
                        >
                            {trend === "up" && (
                                <svg className="w-3.5 h-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M7 17l9.2-9.2M17 17V7H7" />
                                </svg>
                            )}
                            {trend === "down" && (
                                <svg className="w-3.5 h-3.5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M17 7l-9.2 9.2M7 7v10h10" />
                                </svg>
                            )}
                            <span className={`text-[11px] font-semibold tabular-nums ${
                                trend === "up" ? "text-emerald-400" : trend === "down" ? "text-red-400" : "text-slate-500"
                            }`}>
                                {change > 0 ? "+" : ""}{change}%
                            </span>
                            {changeLabel && <span className="text-[10px] text-slate-500">{changeLabel}</span>}
                        </motion.div>
                    )}
                </div>
                <motion.div
                    whileHover={{ rotate: 5, scale: 1.1 }}
                    transition={{ duration: 0.2 }}
                    className={`flex items-center justify-center w-11 h-11 rounded-xl ${colors.bg} ${colors.border} border backdrop-blur-sm`}
                >
                    <span className={colors.text}>{icon}</span>
                </motion.div>
            </div>
        </motion.div>
    );
}
