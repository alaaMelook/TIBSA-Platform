"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import React from "react";

interface LightActionLinkProps {
    href?: string;
    onClick?: (e?: any) => void;
    children: React.ReactNode;
    className?: string;
    showArrow?: boolean;
}

export function LightActionLink({ href, onClick, children, className = "", showArrow = true }: LightActionLinkProps) {
    const isLink = !!href;
    
    const baseClass = `relative inline-flex items-center gap-[6px] h-[34px] px-3 rounded-[12px] bg-white border border-[#D9F5EA] text-[#00A884] font-semibold text-[13px] shadow-[0_6px_16px_rgba(0,168,132,0.08)] transition-all duration-200 ease-out group overflow-hidden focus:outline-none focus:ring-2 focus:ring-[#10B981]/30 hover:-translate-y-[2px] hover:shadow-[0_10px_24px_rgba(16,185,129,0.18)] hover:bg-gradient-to-br hover:from-[#ECFDF5] hover:to-white hover:border-[#10B981] hover:text-[#047857] active:translate-y-0 active:scale-[0.98] active:shadow-sm ${className}`;

    const content = (
        <>
            {/* Subtle diagonal shine effect using CSS transitions */}
            <div className="absolute inset-0 w-full h-full pointer-events-none overflow-hidden rounded-[12px]">
                <div className="absolute top-0 -left-[150%] w-[150%] h-full bg-gradient-to-r from-transparent via-white/80 to-transparent -skew-x-12 transition-all duration-700 ease-in-out group-hover:left-[150%]" />
            </div>
            
            <span className="relative z-10 flex items-center gap-[6px]">
                {children}
                {showArrow && (
                    <svg 
                        className="w-3.5 h-3.5 transition-transform duration-200 group-hover:translate-x-[3px] group-hover:opacity-100 opacity-90" 
                        fill="none" 
                        viewBox="0 0 24 24" 
                        stroke="currentColor" 
                        strokeWidth={2.5}
                    >
                        <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                    </svg>
                )}
            </span>
        </>
    );

    if (isLink) {
        return (
            <Link href={href!} className={baseClass} onClick={onClick}>
                {content}
            </Link>
        );
    }

    return (
        <button onClick={onClick} className={baseClass}>
            {content}
        </button>
    );
}
