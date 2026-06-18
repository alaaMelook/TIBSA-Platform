import React from "react";

interface CardProps {
    children: React.ReactNode;
    className?: string;
    title?: string;
    description?: string;
}

export function Card({ children, className = "", title, description }: CardProps) {
    return (
        <div className={`bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] shadow-md shadow-black/5 ${className}`}>
            {(title || description) && (
                <div className="px-6 py-4 border-b border-[var(--border-strong)]">
                    {title && <h3 className="text-lg font-semibold text-[var(--text-primary)]">{title}</h3>}
                    {description && <p className="text-sm text-[var(--text-muted)] mt-1">{description}</p>}
                </div>
            )}
            <div className="px-6 py-4">{children}</div>
        </div>
    );
}
