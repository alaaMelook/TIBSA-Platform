import React from "react";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label?: string;
    error?: string;
}

export function Input({ label, error, className = "", id, ...props }: InputProps) {
    const inputId = id || label?.toLowerCase().replace(/\s+/g, "-");

    return (
        <div className="w-full">
            {label && (
                <label htmlFor={inputId} className="block text-sm font-medium text-[var(--text-secondary)] mb-1">
                    {label}
                </label>
            )}
            <input
                id={inputId}
                className={`w-full px-3 py-2.5 border rounded-lg text-sm text-[var(--text-primary)] bg-[var(--bg-elevated)] placeholder-[var(--text-muted)] transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--primary)] focus:border-[var(--primary)] ${
                    error ? "border-red-500/50" : "border-[var(--border-strong)]"
                } ${className}`}
                {...props}
            />
            {error && <p className="mt-1 text-sm text-red-400">{error}</p>}
        </div>
    );
}
