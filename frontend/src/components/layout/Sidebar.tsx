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

const IconDashboard = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
        <rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
    </svg>
);

const IconInfra = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
    </svg>
);

const IconOverview = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>
    </svg>
);

const IconUsers = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
    </svg>
);

const IconShield = () => (
    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
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

const sidebarLinks: SidebarLink[] = [
    { href: "/dashboard",                       label: "Dashboard",          icon: <IconDashboard /> },
    { href: "/dashboard/infra-investigations",  label: "Infra Intelligence", icon: <IconInfra /> },
];

const adminLinks: SidebarLink[] = [
    { href: "/admin",            label: "Overview",           icon: <IconOverview />,   adminOnly: true },
    { href: "/admin/users",      label: "User Management",    icon: <IconUsers />,      adminOnly: true },
    { href: "/admin/threats",    label: "Threat Feeds",       icon: <IconShield />,     adminOnly: true },
    { href: "/admin/analytics",  label: "Analytics",          icon: <IconAnalytics />,  adminOnly: true },
    { href: "/admin/system",     label: "System Health",      icon: <IconHeart />,      adminOnly: true },
    { href: "/admin/audit",      label: "Audit Log",          icon: <IconAudit />,      adminOnly: true },
    { href: "/admin/settings",   label: "Settings",           icon: <IconSettings />,   adminOnly: true },
];

export function Sidebar() {
    const pathname = usePathname();
    const { user } = useAuth();

    // ── Collapsible State (Defaults to true: Collapsed) ──
    const [isCollapsed, setIsCollapsed] = useState(true);

    // Load from localStorage on mount
    useEffect(() => {
        try {
            const saved = localStorage.getItem("tibsa_sidebar_collapsed");
            if (saved !== null) {
                setIsCollapsed(JSON.parse(saved));
            }
        } catch {
            // fallback quietly
        }
    }, []);

    // Toggle and persist collapsing state
    const handleToggle = () => {
        setIsCollapsed((prev) => {
            const next = !prev;
            try {
                localStorage.setItem("tibsa_sidebar_collapsed", JSON.stringify(next));
            } catch {
                // ignore
            }
            return next;
        });
    };

    const isAdmin = user?.role === "admin";
    const isAdminSection = pathname.startsWith("/admin");

    const links = isAdminSection && isAdmin ? adminLinks : sidebarLinks;

    return (
        <aside 
            className={`min-h-screen bg-[#0f172a] border-r border-white/[0.08] p-3 flex flex-col justify-between transition-all duration-300 ease-in-out ${
                isCollapsed ? "w-16" : "w-64"
            }`}
        >
            <div className="space-y-6">
                
                {/* ── Sidebar Header & Collapsible Trigger ── */}
                <div className={`flex items-center justify-between min-h-[32px] ${isCollapsed ? "justify-center" : "px-2"}`}>
                    {!isCollapsed && (
                        <h2 className="text-xs font-bold text-slate-500 uppercase tracking-widest animate-fadeIn truncate">
                            {isAdminSection ? "TIBSA SOC Nexus" : "TIBSA Shield"}
                        </h2>
                    )}
                    <button
                        onClick={handleToggle}
                        className="p-1.5 rounded-lg border border-white/[0.08] text-slate-500 hover:text-slate-200 hover:bg-white/[0.04] transition-all cursor-pointer flex-shrink-0"
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
                        const isActive = pathname === link.href;
                        return (
                            <Link
                                key={link.href}
                                href={link.href}
                                className={`flex items-center rounded-lg text-xs font-bold transition-all duration-200 relative group cursor-pointer ${
                                    isCollapsed 
                                        ? "justify-center p-2.5" 
                                        : "gap-3 px-3 py-2.5"
                                } ${
                                    isActive
                                        ? "bg-[#3b82f6]/15 text-blue-400 border border-blue-500/20"
                                        : "text-slate-400 hover:bg-white/[0.06] hover:text-slate-200"
                                }`}
                                title={isCollapsed ? link.label : undefined}
                            >
                                <span className={isActive ? "text-blue-400" : "text-slate-500"}>
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

            {/* ── Switcher between User and Admin ── */}
            {isAdmin && (
                <div className="pt-4 border-t border-white/[0.08]">
                    <Link
                        href={isAdminSection ? "/dashboard" : "/admin"}
                        className={`flex items-center text-xs text-slate-500 hover:text-slate-300 transition-colors ${
                            isCollapsed ? "justify-center p-2" : "gap-2 px-3 py-2"
                        }`}
                        title={isCollapsed ? (isAdminSection ? "TIBSA Shield" : "TIBSA SOC Nexus") : undefined}
                    >
                        {isCollapsed ? (
                            isAdminSection ? (
                                <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12"/>
                                </svg>
                            ) : (
                                <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
                                </svg>
                            )
                        ) : (
                            isAdminSection ? (
                                <>
                                    <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12"/>
                                    </svg>
                                    TIBSA Shield
                                </>
                            ) : (
                                <>
                                    TIBSA SOC Nexus
                                    <svg className="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
                                    </svg>
                                </>
                            )
                        )}
                    </Link>
                </div>
            )}
        </aside>
    );
}
