"use client";

import { useState, useRef, useEffect } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";

// ── Page title map ───────────────────────────────────────────
const PAGE_TITLES: Record<string, string> = {
    "/dashboard":                "Dashboard",
    "/dashboard/scans":          "Security Scans",
    "/dashboard/threats":        "Threat Intelligence",
    "/dashboard/threat-modeling": "Threat Modeling",
    "/dashboard/reports":        "Reports",
    "/dashboard/profile":        "Profile Settings",
    "/admin":                    "Admin Overview",
    "/admin/users":              "User Management",
    "/admin/threats":            "Threat Feeds",
    "/admin/system":             "System Settings",
};

// ── Notification mock data ───────────────────────────────────
interface Notification {
    id: string;
    title: string;
    body: string;
    time: string;
    read: boolean;
    type: "threat" | "scan" | "system";
}

const MOCK_NOTIFICATIONS: Notification[] = [
    { id: "1", title: "High-severity threat detected",   body: "Scan #4821 flagged a critical vulnerability.",       time: "2 min ago",  read: false, type: "threat" },
    { id: "2", title: "Scan completed",                  body: "URL scan for example.com finished successfully.",     time: "18 min ago", read: false, type: "scan" },
    { id: "3", title: "System update available",          body: "TIBSA Platform v2.4.1 is ready to install.",         time: "1 hr ago",   read: true,  type: "system" },
];

const NOTIF_ICON_COLOR: Record<string, string> = {
    threat: "text-red-400 bg-red-500/15",
    scan:   "text-blue-400 bg-blue-500/15",
    system: "text-amber-400 bg-amber-500/15",
};

export function DashboardHeader() {
    const pathname = usePathname();
    const { user, logout } = useAuth();

    const [profileOpen, setProfileOpen] = useState(false);
    const [notifOpen, setNotifOpen] = useState(false);
    const [notifications, setNotifications] = useState(MOCK_NOTIFICATIONS);

    const profileRef = useRef<HTMLDivElement>(null);
    const notifRef = useRef<HTMLDivElement>(null);

    const unread = notifications.filter((n) => !n.read).length;

    // Derive page title from pathname
    const pageTitle = PAGE_TITLES[pathname] ?? "Dashboard";

    // First letter for avatar
    const initial = user?.full_name?.charAt(0)?.toUpperCase() || "U";

    // Close dropdowns on outside click
    useEffect(() => {
        function handleClick(e: MouseEvent) {
            if (profileRef.current && !profileRef.current.contains(e.target as Node)) setProfileOpen(false);
            if (notifRef.current && !notifRef.current.contains(e.target as Node)) setNotifOpen(false);
        }
        document.addEventListener("mousedown", handleClick);
        return () => document.removeEventListener("mousedown", handleClick);
    }, []);

    const markAllRead = () => setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));

    // ── Render ───────────────────────────────────────────────
    return (
        <header className="sticky top-0 z-50 w-full">
            {/* Glow layer behind the bar */}
            <div className="absolute inset-0 bg-gradient-to-r from-blue-600/[0.06] via-transparent to-blue-600/[0.06] pointer-events-none" />
            <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-blue-400/20 to-transparent" />

            {/* Main bar */}
            <div className="relative flex items-center h-16 px-6 bg-[#0f172a]/95 backdrop-blur-xl border-b border-white/[0.08]">

                {/* ── LEFT: Logo ────────────────────────────── */}
                <Link href="/dashboard" className="flex items-center gap-2.5 group mr-8 flex-shrink-0">
                    <div className="relative">
                        <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center shadow-lg shadow-blue-600/20 group-hover:shadow-blue-500/30 transition-shadow">
                            <svg className="w-[18px] h-[18px] text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                        </div>
                        {/* Subtle pulse dot */}
                        <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-40" />
                            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-400 border-2 border-[#0f172a]" />
                        </span>
                    </div>
                    <div className="hidden sm:flex flex-col">
                        <span className="text-[15px] font-bold tracking-tight text-white leading-none">TIBSA</span>
                        <span className="text-[10px] font-medium text-blue-400/70 tracking-widest uppercase leading-none mt-0.5">Platform</span>
                    </div>
                </Link>

                {/* ── CENTER: Page title ─────────────────────── */}
                <div className="flex-1 flex justify-center">
                    <div className="flex items-center gap-2.5">
                        <div className="hidden md:flex h-6 w-6 rounded-md bg-white/[0.04] border border-white/[0.06] items-center justify-center">
                            <div className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                        </div>
                        <h1 className="text-[15px] font-semibold text-[#f1f5f9] tracking-wide">
                            {pageTitle}
                        </h1>
                    </div>
                </div>

                {/* ── RIGHT: Actions ─────────────────────────── */}
                <div className="flex items-center gap-1 flex-shrink-0">

                    {/* ─ Notification Bell ── */}
                    <div ref={notifRef} className="relative">
                        <button
                            onClick={() => { setNotifOpen((v) => !v); setProfileOpen(false); }}
                            className="relative flex items-center justify-center w-9 h-9 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] transition-all"
                            aria-label="Notifications"
                        >
                            <svg className="w-[18px] h-[18px]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
                            </svg>
                            {/* Badge */}
                            {unread > 0 && (
                                <span className="absolute top-1 right-1 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white px-1 shadow-lg shadow-red-500/30 ring-2 ring-[#0f172a]">
                                    {unread}
                                </span>
                            )}
                        </button>

                        {/* Notification dropdown */}
                        {notifOpen && (
                            <div className="absolute right-0 top-full mt-2 w-80 rounded-xl bg-[#1a2744] border border-white/[0.08] shadow-2xl shadow-black/40 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200">
                                <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
                                    <span className="text-sm font-semibold text-white">Notifications</span>
                                    {unread > 0 && (
                                        <button onClick={markAllRead} className="text-xs text-blue-400 hover:text-blue-300 transition-colors font-medium">
                                            Mark all read
                                        </button>
                                    )}
                                </div>
                                <div className="max-h-72 overflow-y-auto divide-y divide-white/[0.04]">
                                    {notifications.map((n) => (
                                        <button
                                            key={n.id}
                                            onClick={() => setNotifications((prev) => prev.map((x) => x.id === n.id ? { ...x, read: true } : x))}
                                            className={`w-full text-left px-4 py-3 flex gap-3 hover:bg-white/[0.03] transition-colors ${!n.read ? "bg-blue-500/[0.04]" : ""}`}
                                        >
                                            <div className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${NOTIF_ICON_COLOR[n.type]}`}>
                                                {n.type === "threat" && (
                                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                                                )}
                                                {n.type === "scan" && (
                                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                                                )}
                                                {n.type === "system" && (
                                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                                                )}
                                            </div>
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2">
                                                    <p className={`text-sm font-medium truncate ${!n.read ? "text-white" : "text-slate-300"}`}>{n.title}</p>
                                                    {!n.read && <span className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-blue-400" />}
                                                </div>
                                                <p className="text-xs text-slate-500 truncate mt-0.5">{n.body}</p>
                                                <p className="text-[10px] text-slate-600 mt-1">{n.time}</p>
                                            </div>
                                        </button>
                                    ))}
                                </div>
                                <div className="border-t border-white/[0.06] px-4 py-2.5">
                                    <button className="text-xs text-blue-400 hover:text-blue-300 transition-colors font-medium w-full text-center">
                                        View all notifications
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Divider */}
                    <div className="h-6 w-px bg-white/[0.08] mx-2" />

                    {/* ─ Profile Area ── */}
                    <div ref={profileRef} className="relative">
                        <button
                            onClick={() => { setProfileOpen((v) => !v); setNotifOpen(false); }}
                            className="flex items-center gap-2.5 pl-1 pr-2 py-1.5 rounded-lg hover:bg-white/[0.06] transition-all group"
                        >
                            {/* Avatar */}
                            <div className="relative flex-shrink-0">
                                <div className="h-8 w-8 rounded-full bg-gradient-to-br from-[#3b82f6] to-[#2563eb] flex items-center justify-center shadow-md shadow-blue-600/20 ring-2 ring-white/[0.08]">
                                    <span className="text-[13px] font-bold text-white leading-none">{initial}</span>
                                </div>
                                {/* Online indicator */}
                                <span className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-green-400 border-2 border-[#0f172a]" />
                            </div>
                            {/* Name + role */}
                            <div className="hidden lg:flex flex-col items-start">
                                <span className="text-[13px] font-medium text-[#f1f5f9] leading-tight">{user?.full_name || "User"}</span>
                                <span className="text-[10px] text-slate-500 capitalize leading-tight">{user?.role || "user"}</span>
                            </div>
                            {/* Dropdown arrow */}
                            <svg className={`w-3.5 h-3.5 text-slate-500 transition-transform duration-200 ${profileOpen ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                            </svg>
                        </button>

                        {/* Profile dropdown */}
                        {profileOpen && (
                            <div className="absolute right-0 top-full mt-2 w-56 rounded-xl bg-[#1a2744] border border-white/[0.08] shadow-2xl shadow-black/40 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200">
                                {/* User info header */}
                                <div className="px-4 py-3 border-b border-white/[0.06]">
                                    <p className="text-sm font-medium text-white truncate">{user?.full_name}</p>
                                    <p className="text-xs text-slate-500 truncate">{user?.email}</p>
                                </div>
                                {/* Menu items */}
                                <div className="py-1">
                                    <Link href="/dashboard/profile" onClick={() => setProfileOpen(false)}
                                        className="flex items-center gap-3 px-4 py-2.5 text-sm text-slate-300 hover:bg-white/[0.06] hover:text-white transition-colors">
                                        <svg className="w-4 h-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                                        </svg>
                                        Profile Settings
                                    </Link>
                                    {user?.role === "admin" && (
                                        <Link href="/admin" onClick={() => setProfileOpen(false)}
                                            className="flex items-center gap-3 px-4 py-2.5 text-sm text-slate-300 hover:bg-white/[0.06] hover:text-white transition-colors">
                                            <svg className="w-4 h-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><circle cx="12" cy="12" r="3"/>
                                            </svg>
                                            Admin Panel
                                        </Link>
                                    )}
                                </div>
                                {/* Logout */}
                                <div className="border-t border-white/[0.06] py-1">
                                    <button
                                        onClick={() => { setProfileOpen(false); logout(); }}
                                        className="flex items-center gap-3 w-full px-4 py-2.5 text-sm text-red-400 hover:bg-red-500/10 transition-colors"
                                    >
                                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                                        </svg>
                                        Sign Out
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </header>
    );
}
