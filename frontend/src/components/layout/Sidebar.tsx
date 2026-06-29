"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import type { ReactNode } from "react";

interface SidebarLink {
    href: string;
    label: string;
    icon: ReactNode;
    adminOnly?: boolean;
}

// ─── Icons ────────────────────────────────────────────────────────────────────

const IconDashboard = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
);

const IconInvestigations = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M17 11A6 6 0 1 1 5 11a6 6 0 0 1 12 0z" />
    </svg>
);

const IconScans = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" />
    </svg>
);

const IconWebsiteScanner = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
);



const IconThreatModeling = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M4 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1v-4zM14 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
    </svg>
);

const IconAIAnalysis = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17H3a2 2 0 01-2-2V5a2 2 0 012-2h14a2 2 0 012 2v10a2 2 0 01-2 2h-2" />
    </svg>
);

const IconReports = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
);

const IconProfile = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
    </svg>
);

const IconInfra = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
    </svg>
);

// ─── Admin Icons ──────────────────────────────────────────────────────────────

const IconOverview = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
    </svg>
);

const IconUsers = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
);

const IconShield = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
);

const IconAnalytics = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
);

const IconHeart = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" />
    </svg>
);

const IconAudit = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
    </svg>
);

const IconSettings = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><circle cx="12" cy="12" r="3" />
    </svg>
);

// ─── Link Definitions ─────────────────────────────────────────────────────────

const sidebarLinks: SidebarLink[] = [
    { href: "/dashboard", label: "Dashboard", icon: <IconDashboard /> },
    { href: "/dashboard/investigations", label: "Investigations", icon: <IconInvestigations /> },
    { href: "/dashboard/infra-investigations", label: "Infra Intelligence", icon: <IconInfra /> },
    { href: "/dashboard/scans", label: "Scans", icon: <IconScans /> },
    { href: "/dashboard/website-scanner", label: "Penetration Testing", icon: <IconWebsiteScanner /> },
    { href: "/dashboard/threat-modeling", label: "Threat Modeling", icon: <IconThreatModeling /> },
    { href: "/dashboard/ai-malware-analysis", label: "AI Analysis", icon: <IconAIAnalysis /> },
    { href: "/dashboard/reports", label: "Reports History", icon: <IconReports /> },
    { href: "/dashboard/profile", label: "Profile", icon: <IconProfile /> },
];



const adminLinks: SidebarLink[] = [
    { href: "/admin", label: "Overview", icon: <IconOverview />, adminOnly: true },
    { href: "/admin/users", label: "User Management", icon: <IconUsers />, adminOnly: true },
    { href: "/admin/investigations", label: "Investigations", icon: <IconInvestigations />, adminOnly: true },
    { href: "/admin/malware-analysis", label: "Malware Analysis", icon: <IconAIAnalysis />, adminOnly: true },
    { href: "/admin/analytics", label: "Analytics", icon: <IconAnalytics />, adminOnly: true },
    { href: "/admin/infra-analytics", label: "Infra Analytics", icon: <IconInfra />, adminOnly: true },
    { href: "/admin/system", label: "System Health", icon: <IconHeart />, adminOnly: true },
    { href: "/admin/audit", label: "Audit Log", icon: <IconAudit />, adminOnly: true },
];

// ─── Component ────────────────────────────────────────────────────────────────

export function Sidebar() {
    const pathname = usePathname();
    const { user } = useAuth();

    // Collapsed state — default true, persisted in localStorage
    const [isCollapsed, setIsCollapsed] = useState(true);

    useEffect(() => {
        try {
            const saved = localStorage.getItem("tibsa_sidebar_collapsed");
            if (saved !== null) setIsCollapsed(JSON.parse(saved));
        } catch {
            // fallback quietly
        }
    }, []);

    const handleToggle = () => {
        setIsCollapsed((prev) => {
            const next = !prev;
            try { localStorage.setItem("tibsa_sidebar_collapsed", JSON.stringify(next)); } catch { }
            return next;
        });
    };

    const isAdmin = user?.role === "admin";
    const isAdminSection = pathname.startsWith("/admin");

    // Pick which link set to render
    const links = isAdminSection && isAdmin ? adminLinks : sidebarLinks;

    // Section title shown when expanded
    const sectionTitle = isAdminSection ? "TIBSA SOC Nexus" : "TIBSA Shield";

    return (
        <aside
            className={`min-h-screen bg-[var(--bg-sidebar)] border-r border-[var(--border-strong)] p-3 flex flex-col justify-between transition-all duration-300 ease-in-out ${isCollapsed ? "w-16" : "w-64"
                }`}
        >
            <div className="space-y-6">

                {/* ── Header & Toggle ── */}
                <div className={`flex items-center justify-between min-h-[32px] ${isCollapsed ? "justify-center" : "px-2"}`}>
                    {!isCollapsed && (
                        <h2 className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-widest animate-fadeIn truncate">
                            {sectionTitle}
                        </h2>
                    )}
                    <button
                        onClick={handleToggle}
                        className="p-1.5 rounded-lg border border-[var(--border-soft)] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] transition-all cursor-pointer flex-shrink-0"
                        title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
                    >
                        {isCollapsed ? (
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M13 5l7 7-7 7M5 5l7 7-7 7" />
                            </svg>
                        ) : (
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M11 19l-7-7 7-7M19 19l-7-7 7-7" />
                            </svg>
                        )}
                    </button>
                </div>

                {/* ── Navigation Links ── */}
                <nav className="space-y-1.5">
                    {links.map((link) => {
                        const isActive =
                            link.href === "/dashboard"
                                ? pathname === "/dashboard"
                                : pathname === link.href || pathname.startsWith(link.href + "/");
                        return (
                            <Link
                                key={link.href}
                                href={link.href}
                                className={`flex items-center rounded-lg text-xs font-bold transition-all duration-200 relative group cursor-pointer sidebar-btn ${isCollapsed ? "justify-center p-2.5" : "gap-3 px-3 py-2.5"
                                    } ${isActive
                                        ? "bg-[var(--primary)] text-white shadow-md shadow-[var(--primary-soft)]"
                                        : "text-[var(--text-muted)] hover:bg-[var(--bg-elevated)] hover:text-[var(--primary)]"
                                    }`}
                                title={isCollapsed ? link.label : undefined}
                            >
                                <span className={isActive ? "text-white" : "text-[var(--text-muted)] group-hover:text-[var(--primary)]"}>
                                    {link.icon}
                                </span>
                                {!isCollapsed && (
                                    <span className="animate-fadeIn truncate whitespace-nowrap">
                                        {link.label}
                                    </span>
                                )}
                            </Link>
                        );
                    })}
                </nav>

            </div>

        </aside>
    );
}
