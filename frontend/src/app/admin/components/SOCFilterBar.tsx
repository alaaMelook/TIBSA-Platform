"use client";

import { useState } from "react";

export interface SOCFilters {
    dateRange: string;
    severity: string;
    action: string;
    user: string;
    ipSearch: string;
}

interface SOCFilterBarProps {
    filters: SOCFilters;
    onFilterChange: (filters: SOCFilters) => void;
    onExport: () => void;
    isExporting?: boolean;
}

export function SOCFilterBar({ filters, onFilterChange, onExport, isExporting }: SOCFilterBarProps) {
    const handleChange = (key: keyof SOCFilters, value: string) => {
        onFilterChange({ ...filters, [key]: value });
    };

    return (
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 bg-[var(--bg-card)]/50 border border-[var(--border-soft)] rounded-xl shadow-lg backdrop-blur-md">
            <div className="flex flex-wrap items-center gap-3 flex-1">
                {/* Date Range Picker (Mock) */}
                <div className="flex items-center bg-black/40 border border-[var(--border-strong)] rounded-lg p-1">
                    {["1h", "24h", "7d", "30d"].map((range) => (
                        <button
                            key={range}
                            onClick={() => handleChange("dateRange", range)}
                            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                                filters.dateRange === range
                                    ? "bg-[var(--primary)]/20 text-[var(--primary)]"
                                    : "text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)]"
                            }`}
                        >
                            {range}
                        </button>
                    ))}
                </div>

                <div className="w-px h-6 bg-[var(--bg-elevated)]" />

                {/* Severity Dropdown */}
                <select
                    value={filters.severity}
                    onChange={(e) => handleChange("severity", e.target.value)}
                    className="bg-black/40 border border-[var(--border-strong)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-[var(--primary)]"
                >
                    <option value="all">All Severities</option>
                    <option value="success">Success</option>
                    <option value="warning">Warning</option>
                    <option value="failure">Failure / Critical</option>
                </select>

                {/* Action Dropdown */}
                <select
                    value={filters.action}
                    onChange={(e) => handleChange("action", e.target.value)}
                    className="bg-black/40 border border-[var(--border-strong)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-[var(--primary)]"
                >
                    <option value="all">All Actions</option>
                    <option value="LOGIN">Logins</option>
                    <option value="LOGIN_FAILED">Failed Logins</option>
                    <option value="SIGNUP">Signups</option>
                    <option value="SIGNUP_FAILED">Failed Signups</option>
                    <option value="USER_ROLE_CHANGE">Role Changes</option>
                    <option value="system_config_update">System Config</option>
                </select>

                {/* User Dropdown */}
                <select
                    value={filters.user}
                    onChange={(e) => handleChange("user", e.target.value)}
                    className="bg-black/40 border border-[var(--border-strong)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-[var(--primary)]"
                >
                    <option value="all">All Users</option>
                    <option value="admin">Admins Only</option>
                    <option value="system">System Generated</option>
                </select>

                {/* IP Search */}
                <div className="relative">
                    <svg className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <input
                        type="text"
                        placeholder="Search IP..."
                        value={filters.ipSearch}
                        onChange={(e) => handleChange("ipSearch", e.target.value)}
                        className="bg-black/40 border border-[var(--border-strong)] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[var(--text-secondary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--primary)] w-32 focus:w-48 transition-all"
                    />
                </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3">
                <button
                    onClick={onExport}
                    disabled={isExporting}
                    className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
                >
                    {isExporting ? (
                        <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                    ) : (
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                        </svg>
                    )}
                    {isExporting ? "Exporting..." : "Export CSV"}
                </button>
            </div>
        </div>
    );
}
