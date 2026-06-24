"use client";

import { useState } from "react";
import { LightAdminDropdown } from "./LightAdminDropdown";

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
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 bg-white border border-[#E6DDD2] rounded-[20px] shadow-sm">
            <div className="flex flex-wrap items-center gap-3 flex-1">
                {/* Date Range Picker */}
                <div className="flex items-center bg-[#FAF7F1] border border-[#E6DDD2] rounded-xl p-1 h-[40px]">
                    {["1h", "24h", "7d", "30d"].map((range) => (
                        <button
                            key={range}
                            type="button"
                            onClick={() => handleChange("dateRange", range)}
                            className={`px-3 h-full flex items-center justify-center text-xs font-bold rounded-lg transition-colors cursor-pointer ${
                                filters.dateRange === range
                                    ? "bg-[#00A884]/15 text-[#00A884] border border-[#00A884]/20 shadow-sm"
                                    : "text-[#7C6F64] hover:text-[#1F2933] border border-transparent"
                            }`}
                        >
                            {range}
                        </button>
                    ))}
                </div>

                <div className="w-px h-6 bg-[#E6DDD2]" />

                {/* Severity Dropdown */}
                <LightAdminDropdown
                    value={filters.severity}
                    onChange={(val) => handleChange("severity", val)}
                    options={[
                        { value: "all", label: "All Severities" },
                        { value: "success", label: "Success" },
                        { value: "warning", label: "Warning" },
                        { value: "failure", label: "Failure / Critical" },
                    ]}
                    className="w-36"
                />

                {/* Action Dropdown */}
                <LightAdminDropdown
                    value={filters.action}
                    onChange={(val) => handleChange("action", val)}
                    options={[
                        { value: "all", label: "All Actions" },
                        { value: "LOGIN", label: "Logins" },
                        { value: "LOGIN_FAILED", label: "Failed Logins" },
                        { value: "SIGNUP", label: "Signups" },
                        { value: "SIGNUP_FAILED", label: "Failed Signups" },
                        { value: "USER_ROLE_CHANGE", label: "Role Changes" },
                        { value: "system_config_update", label: "System Config" },
                    ]}
                    className="w-40"
                />

                {/* User Dropdown */}
                <LightAdminDropdown
                    value={filters.user}
                    onChange={(val) => handleChange("user", val)}
                    options={[
                        { value: "all", label: "All Users" },
                        { value: "admin", label: "Admins Only" },
                        { value: "system", label: "System Generated" },
                    ]}
                    className="w-36"
                />

                {/* IP Search */}
                <div className="relative">
                    <svg className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#7C6F64]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <input
                        type="text"
                        placeholder="Search IP..."
                        value={filters.ipSearch}
                        onChange={(e) => handleChange("ipSearch", e.target.value)}
                        className="bg-white border border-[#E6DDD2] rounded-xl pl-9 pr-3 h-[40px] text-xs text-[#1F2933] font-medium placeholder:text-[#7C6F64] focus:outline-none focus:border-[#00A884] focus:ring-[3px] focus:ring-[#10B981]/15 w-32 focus:w-48 transition-all"
                    />
                </div>
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3">
                <button
                    type="button"
                    onClick={onExport}
                    disabled={isExporting}
                    className="flex items-center gap-1.5 px-4 h-[40px] text-xs font-bold rounded-xl bg-gradient-to-br from-[#10B981]/10 to-[#00A884]/10 border border-[#10B981]/20 text-[#10B981] hover:from-[#10B981]/15 hover:to-[#00A884]/15 hover:border-[#10B981]/30 hover:-translate-y-[1px] transition-all cursor-pointer disabled:opacity-50 disabled:hover:translate-y-0 relative overflow-hidden group shadow-sm"
                >
                    {isExporting ? (
                        <svg className="w-3.5 h-3.5 animate-spin text-[#10B981]" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                    ) : (
                        <svg className="w-3.5 h-3.5 text-[#10B981]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                        </svg>
                    )}
                    {isExporting ? "Exporting..." : "Export CSV"}
                    <div className="absolute inset-0 w-1/2 h-full bg-gradient-to-r from-transparent via-white/40 to-transparent -skew-x-12 -translate-x-full group-hover:translate-x-[300%] transition-transform duration-1000 ease-out pointer-events-none" />
                </button>
            </div>
        </div>
    );
}
