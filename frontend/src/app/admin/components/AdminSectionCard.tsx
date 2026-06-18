"use client";

import { motion } from "framer-motion";

interface AdminSectionCardProps {
    title: string | React.ReactNode;
    description?: string;
    children: React.ReactNode;
    action?: React.ReactNode;
    className?: string;
    noPadding?: boolean;
    delay?: number;
}

export function AdminSectionCard({ title, description, children, action, className = "", noPadding = false, delay = 0 }: AdminSectionCardProps) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: delay * 0.1, ease: [0.25, 0.46, 0.45, 0.94] }}
            className={`relative overflow-hidden rounded-xl border border-[var(--border-strong)] shadow-xl shadow-black/5 backdrop-blur-md group/card ${className}`}
            style={{ background: "linear-gradient(135deg, rgba(26,39,68,0.6) 0%, rgba(15,23,42,0.7) 100%)" }}
        >
            {/* Subtle shimmer on hover */}
            <div className="absolute inset-0 opacity-0 group-hover/card:opacity-100 transition-opacity duration-700 pointer-events-none"
                 style={{ background: "linear-gradient(135deg, rgba(59,130,246,0.02), transparent, rgba(168,85,247,0.02))" }} />

            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border-strong)]">
                <div>
                    <h3 className="text-sm font-semibold text-[var(--text-primary)] tracking-wide">{title}</h3>
                    {description && <p className="text-[11px] text-[var(--text-muted)] mt-0.5">{description}</p>}
                </div>
                {action && <div>{action}</div>}
            </div>
            {/* Content */}
            <div className={noPadding ? "" : "px-5 py-4"}>
                {children}
            </div>
        </motion.div>
    );
}
