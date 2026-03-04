import React from "react";

interface CardProps {
    children: React.ReactNode;
    className?: string;
    title?: string;
    description?: string;
}

export function Card({ children, className = "", title, description }: CardProps) {
    return (
        <div className={`bg-[#263554] rounded-xl border border-white/[0.08] shadow-lg shadow-black/25 ${className}`}>
            {(title || description) && (
                <div className="px-6 py-4 border-b border-white/[0.06]">
                    {title && <h3 className="text-lg font-semibold text-white">{title}</h3>}
                    {description && <p className="text-sm text-slate-400 mt-1">{description}</p>}
                </div>
            )}
            <div className="px-6 py-4">{children}</div>
        </div>
    );
}
