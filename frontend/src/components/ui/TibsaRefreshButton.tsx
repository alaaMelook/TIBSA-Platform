import React from "react";

interface TibsaRefreshButtonProps {
    isRefreshing?: boolean;
    onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void | Promise<void>;
    label?: string;
    loadingLabel?: string;
    icon?: React.ReactNode;
    disabled?: boolean;
    className?: string;
}

export function TibsaRefreshButton({
    isRefreshing = false,
    onClick,
    label = "Refresh",
    loadingLabel = "Refreshing...",
    icon,
    disabled = false,
    className = "",
}: TibsaRefreshButtonProps) {
    
    // Default refresh icon SVG
    const defaultIcon = (
        <svg 
            className={`w-3.5 h-3.5 transition-transform duration-500 group-hover:rotate-180 ${isRefreshing ? "animate-spin" : ""}`} 
            fill="none" 
            viewBox="0 0 24 24" 
            stroke="currentColor" 
            strokeWidth={2.5}
        >
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 7.89H18" />
        </svg>
    );

    return (
        <button
            onClick={onClick}
            disabled={disabled || isRefreshing}
            className={`
                group relative overflow-hidden flex items-center justify-center gap-2 
                px-5 h-[40px] rounded-xl font-semibold text-xs text-white 
                bg-gradient-to-br from-[#10B981] to-[#00A884]
                shadow-[0_4px_14px_rgba(16,185,129,0.25)] hover:shadow-[0_6px_20px_rgba(16,185,129,0.38)]
                hover:-translate-y-[2px] active:scale-[0.98] active:translate-y-0
                disabled:opacity-80 disabled:cursor-not-allowed
                transition-all duration-300 ease-out
                ${isRefreshing ? "animate-pulse shadow-[0_0_15px_rgba(16,185,129,0.4)]" : ""}
                ${className}
            `}
        >
            {/* Gloss sweep effect */}
            <div className="absolute inset-0 w-[200%] h-full bg-gradient-to-r from-transparent via-white/20 to-transparent -skew-x-[25deg] -translate-x-full group-hover:translate-x-full transition-transform duration-700 ease-in-out pointer-events-none" />

            {/* Icon */}
            <span className={`flex-shrink-0 transition-transform duration-300 ${isRefreshing ? "" : "group-hover:scale-110"}`}>
                {icon !== undefined ? (
                    <span className={isRefreshing ? "animate-spin block" : "block"}>
                        {icon}
                    </span>
                ) : (
                    defaultIcon
                )}
            </span>

            {/* Label */}
            <span className="relative z-10 select-none">
                {isRefreshing ? loadingLabel : label}
            </span>
        </button>
    );
}
