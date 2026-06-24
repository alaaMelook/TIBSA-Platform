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
            className={`relative overflow-hidden rounded-[20px] border border-[#E6DDD2] shadow-sm bg-white group/card ${className}`}
        >
            {/* Subtle shimmer on hover */}
            <div className="absolute inset-0 opacity-0 group-hover/card:opacity-100 transition-opacity duration-700 pointer-events-none"
                 style={{ background: "linear-gradient(135deg, rgba(16,185,129,0.01), transparent, rgba(47,128,237,0.01))" }} />

            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#E6DDD2]">
                <div>
                    <h3 className="text-sm font-semibold text-[#1F2933] tracking-wide">{title}</h3>
                    {description && <p className="text-[11px] text-[#7C6F64] mt-0.5">{description}</p>}
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
