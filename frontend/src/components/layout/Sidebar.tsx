"use client";

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
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
        <rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
    </svg>
);
const IconScans = () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/>
    </svg>
);
const IconThreats = () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
    </svg>
);
const IconReports = () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
    </svg>
);
const IconProfile = () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
    </svg>
);
const IconOverview = () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>
    </svg>
);
const IconUsers = () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
    </svg>
);
const IconShield = () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
    </svg>
);
const IconSettings = () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/>
    </svg>
);

const IconThreatModeling = () => (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
    </svg>
);

const sidebarLinks: SidebarLink[] = [
    { href: "/dashboard",                   label: "Dashboard",       icon: <IconDashboard /> },
    { href: "/dashboard/scans",             label: "Scans",           icon: <IconScans /> },
    { href: "/dashboard/threats",           label: "Threats",         icon: <IconThreats /> },
    { href: "/dashboard/threat-modeling",   label: "Threat Modeling", icon: <IconThreatModeling /> },
    { href: "/dashboard/reports",           label: "Reports",         icon: <IconReports /> },
    { href: "/dashboard/profile",           label: "Profile",         icon: <IconProfile /> },
];

const adminLinks: SidebarLink[] = [
    { href: "/admin",         label: "Overview",         icon: <IconOverview />, adminOnly: true },
    { href: "/admin/users",   label: "User Management",  icon: <IconUsers />,    adminOnly: true },
    { href: "/admin/threats", label: "Threat Feeds",     icon: <IconShield />,   adminOnly: true },
    { href: "/admin/system",  label: "System",           icon: <IconSettings />, adminOnly: true },
];

export function Sidebar() {
    const pathname = usePathname();
    const { user } = useAuth();

    const isAdmin = user?.role === "admin";
    const isAdminSection = pathname.startsWith("/admin");

    const links = isAdminSection && isAdmin ? adminLinks : sidebarLinks;

    return (
        <aside className="w-64 min-h-screen bg-gray-50 border-r border-gray-200 p-4">
            <div className="mb-6">
                <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider px-3">
                    {isAdminSection ? "Admin Panel" : "Navigation"}
                </h2>
            </div>

            <nav className="space-y-1">
                {links.map((link) => {
                    const isActive = pathname === link.href;
                    return (
                        <Link
                            key={link.href}
                            href={link.href}
                            className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${isActive
                                    ? "bg-blue-50 text-blue-700 font-medium"
                                    : "text-gray-500 hover:bg-gray-100 hover:text-gray-900"
                                }`}
                        >
                            <span className={isActive ? "text-blue-600" : "text-gray-400"}>{link.icon}</span>
                            <span>{link.label}</span>
                        </Link>
                    );
                })}
            </nav>

            {/* Switch between user/admin */}
            {isAdmin && (
                <div className="mt-8 pt-4 border-t border-gray-200">
                    <Link
                        href={isAdminSection ? "/dashboard" : "/admin"}
                        className="flex items-center gap-2 px-3 py-2 text-xs text-gray-400 hover:text-gray-600 transition-colors"
                    >
                        {isAdminSection ? (
                            <>
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12"/></svg>
                                User Dashboard
                            </>
                        ) : (
                            <>
                                Admin Panel
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6"/></svg>
                            </>
                        )}
                    </Link>
                </div>
            )}
        </aside>
    );
}
