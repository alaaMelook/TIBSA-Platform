import React from "react";

interface CardProps {
    children: React.ReactNode;
    className?: string;
    title?: string;
    description?: string;
}

export function Card({ children, className = "", title, description }: CardProps) {
    return (
        <div className={`bg-white rounded-xl border border-gray-200 shadow-sm ${className}`}>
            {(title || description) && (
                <div className="px-6 py-4 border-b border-gray-100">
                    {title && <h3 className="text-lg font-semibold text-gray-900">{title}</h3>}
                    {description && <p className="text-sm text-gray-500 mt-1">{description}</p>}
                </div>
            )}
            <div className="px-6 py-4">{children}</div>
        </div>
    );
}
