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
    children?: React.ReactNode;
}


const COLOR_MAP = {
    blue:   { bg: "bg-[#2F80ED]/10", border: "border-[#2F80ED]/20",   text: "text-[#2F80ED]",   glow: "shadow-[#2F80ED]/10",   accent: "#2F80ED" },
    green:  { bg: "bg-[#10B981]/10", border: "border-[#10B981]/20", text: "text-[#10B981]", glow: "shadow-[#10B981]/10", accent: "#10B981" },
    red:    { bg: "bg-[#EF4444]/10",     border: "border-[#EF4444]/20",     text: "text-[#EF4444]",     glow: "shadow-[#EF4444]/10",     accent: "#EF4444" },
    amber:  { bg: "bg-amber-500/10",   border: "border-amber-500/20",   text: "text-amber-500",   glow: "shadow-amber-500/10",   accent: "#f59e0b" },
    purple: { bg: "bg-purple-500/10",  border: "border-purple-500/20",  text: "text-purple-600",  glow: "shadow-purple-500/10",  accent: "#a855f7" },
    cyan:   { bg: "bg-[#00A884]/10",    border: "border-[#00A884]/20",    text: "text-[#00A884]",    glow: "shadow-[#00A884]/10",    accent: "#00A884" },
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

export function StatCard({ label, value, change, changeLabel, icon, color, trend, delay = 0, children }: StatCardProps) {
    const colors = COLOR_MAP[color];
    const isNumeric = typeof value === "number";

    return (
        <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.5, delay: delay / 1000, ease: [0.25, 0.46, 0.45, 0.94] }}
            whileHover={{ y: -4, scale: 1.01, transition: { duration: 0.2 } }}
            className={`relative overflow-hidden rounded-[18px] border border-[#E6DDD2] bg-white p-5 shadow-sm hover:shadow-md hover:border-[#10B981]/50 cursor-default group`}
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
                    <p className="text-xs font-semibold text-[#7C6F64] uppercase tracking-wider">{label}</p>
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
                                <svg className="w-3.5 h-3.5 text-[#10B981]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M7 17l9.2-9.2M17 17V7H7" />
                                </svg>
                            )}
                            {trend === "down" && (
                                <svg className="w-3.5 h-3.5 text-[#EF4444]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M17 7l-9.2 9.2M7 7v10h10" />
                                </svg>
                            )}
                            <span className={`text-[11px] font-semibold tabular-nums ${
                                trend === "up" ? "text-[#10B981]" : trend === "down" ? "text-[#EF4444]" : "text-[#7C6F64]"
                            }`}>
                                {change > 0 ? "+" : ""}{change}%
                            </span>
                            {changeLabel && <span className="text-[10px] text-[#7C6F64]/70">{changeLabel}</span>}
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
            {children}
        </motion.div>
    );
}

