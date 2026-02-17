"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";

interface SidebarLink {
    href: string;
    label: string;
    icon: string;
    adminOnly?: boolean;
}

const sidebarLinks: SidebarLink[] = [
    { href: "/dashboard", label: "Dashboard", icon: "📊" },
    { href: "/dashboard/scans", label: "Scans", icon: "🔍" },
    { href: "/dashboard/threats", label: "Threats", icon: "⚠️" },
    { href: "/dashboard/reports", label: "Reports", icon: "📄" },
    { href: "/dashboard/profile", label: "Profile", icon: "👤" },
];

const adminLinks: SidebarLink[] = [
    { href: "/admin", label: "Overview", icon: "🏠", adminOnly: true },
    { href: "/admin/users", label: "User Management", icon: "👥", adminOnly: true },
    { href: "/admin/threats", label: "Threat Feeds", icon: "🛡️", adminOnly: true },
    { href: "/admin/system", label: "System", icon: "⚙️", adminOnly: true },
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
                            className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${isActive
                                    ? "bg-blue-50 text-blue-700 font-medium"
                                    : "text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                                }`}
                        >
                            <span>{link.icon}</span>
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
                        className="flex items-center gap-2 px-3 py-2 text-sm text-gray-500 hover:text-gray-700 transition-colors"
                    >
                        <span>{isAdminSection ? "← User Dashboard" : "Admin Panel →"}</span>
                    </Link>
                </div>
            )}
        </aside>
    );
}
