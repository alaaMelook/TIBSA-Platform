"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { motion, AnimatePresence } from "framer-motion";

// ── Page title map ───────────────────────────────────────────
const PAGE_TITLES: Record<string, string> = {
    "/dashboard": "Dashboard",
    "/dashboard/scans": "Security Scans",
    "/dashboard/threat-modeling": "Threat Modeling",
    "/dashboard/reports": "Reports History",
    "/dashboard/profile": "Profile Settings",
    "/admin": "Admin Overview",
    "/admin/users": "User Management",
    "/admin/threats": "Threat Feeds",
    "/admin/analytics": "Platform Analytics",
    "/admin/system": "System Health",
    "/admin/audit": "Audit Log",
    "/admin/settings": "System Settings",
};

// ── Notification types ───────────────────────────────────────
interface Notification {
    id: string;
    title: string;
    body: string;
    type: "threat" | "scan" | "system";
    read: boolean;
    scan_id: string | null;
    created_at: string;
}

function timeAgo(dateStr: string): string {
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins} min ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs} hr ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
}

const NOTIF_ICON_COLOR: Record<string, string> = {
    threat: "text-red-400 bg-red-500/15",
    scan: "text-[var(--primary)] bg-[var(--primary)]/15",
    system: "text-amber-400 bg-amber-500/15",
};

function getBreadcrumbs(pathname: string): string[] {
    if (pathname === "/dashboard") return ["TIBSA", "Dashboard"];
    if (pathname === "/dashboard/scans") return ["TIBSA", "Security Scans"];
    if (pathname === "/dashboard/threat-modeling") return ["TIBSA", "Threat Modeling"];
    if (pathname === "/dashboard/reports") return ["TIBSA", "Reports History"];
    if (pathname === "/dashboard/profile") return ["TIBSA", "Profile Settings"];
    if (pathname === "/dashboard/investigations") return ["TIBSA", "Investigations"];
    if (pathname.startsWith("/dashboard/investigations/")) return ["TIBSA", "Investigations", "Workspace"];
    if (pathname === "/admin") return ["TIBSA", "Admin Overview"];
    if (pathname === "/admin/users") return ["TIBSA", "Admin", "Users"];
    if (pathname === "/admin/threats") return ["TIBSA", "Admin", "Threats"];
    if (pathname === "/admin/system") return ["TIBSA", "Admin", "System"];

    const parts = pathname.split("/").filter(Boolean);
    return ["TIBSA", ...parts.map(p => p.charAt(0).toUpperCase() + p.slice(1))];
}

export function DashboardHeader() {
    const pathname = usePathname();
    const { user, token, logout } = useAuth();

    const [profileOpen, setProfileOpen] = useState(false);
    const [notifOpen, setNotifOpen] = useState(false);
    const [isNotificationsModalOpen, setIsNotificationsModalOpen] = useState(false);
    const [notifications, setNotifications] = useState<Notification[]>([]);

    const profileRef = useRef<HTMLDivElement>(null);
    const notifRef = useRef<HTMLDivElement>(null);

    const unread = notifications.filter((n) => !n.read).length;
    const visibleNotifications = notifications.slice(0, 5);
    const remainingCount = Math.max(0, notifications.length - 5);

    // Close modal on Escape
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === "Escape") setIsNotificationsModalOpen(false);
        };
        if (isNotificationsModalOpen) {
            window.addEventListener("keydown", handleKeyDown);
        }
        return () => window.removeEventListener("keydown", handleKeyDown);
    }, [isNotificationsModalOpen]);

    // First letter for avatar
    const initial = user?.full_name?.charAt(0)?.toUpperCase() || "U";

    // ── Fetch notifications from API ─────────────────────────
    const fetchNotifications = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<Notification[]>("/api/v1/notifications/", token);
            setNotifications(data);
        } catch {
            // silently ignore — notifications are non-critical
        }
    }, [token]);

    // Initial fetch + poll every 15 seconds
    useEffect(() => {
        fetchNotifications();
        const timer = setInterval(fetchNotifications, 15000);
        return () => clearInterval(timer);
    }, [fetchNotifications]);

    // Close dropdowns on outside click
    useEffect(() => {
        function handleClick(e: MouseEvent) {
            if (profileRef.current && !profileRef.current.contains(e.target as Node)) setProfileOpen(false);
            if (notifRef.current && !notifRef.current.contains(e.target as Node)) setNotifOpen(false);
        }
        document.addEventListener("mousedown", handleClick);
        return () => document.removeEventListener("mousedown", handleClick);
    }, []);

    const markOneRead = async (id: string) => {
        setNotifications((prev) => prev.map((x) => x.id === id ? { ...x, read: true } : x));
        if (token) {
            try { await api.patch(`/api/v1/notifications/${id}/read`, {}, token); } catch { /* ignore */ }
        }
    };

    const markAllRead = async () => {
        setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
        if (token) {
            try { await api.patch("/api/v1/notifications/read-all", {}, token); } catch { /* ignore */ }
        }
    };

    // ── Render ───────────────────────────────────────────────
    return (
        <header className="sticky top-0 z-50 w-full">
            {/* Glow layer behind the bar */}
            <div className="absolute inset-0 bg-gradient-to-r from-[var(--primary)]/[0.04] via-transparent to-[var(--primary)]/[0.04] pointer-events-none" />
            <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-[var(--primary)]/20 to-transparent" />

            {/* Main bar */}
            <div className="relative flex items-center h-16 px-6 bg-[var(--bg-main)]/95 backdrop-blur-xl border-b border-[var(--border-soft)]">

                {/* ── LEFT: Logo ────────────────────────────── */}
                <Link href="/dashboard" className="flex items-center gap-2.5 group mr-8 flex-shrink-0">
                    <div className="relative">
                        <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] flex items-center justify-center shadow-lg shadow-[var(--primary-soft)] group-hover:shadow-[var(--primary-soft)] transition-shadow">
                            <svg className="w-[18px] h-[18px] text-[var(--text-primary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round">
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
                        <span className="text-[15px] font-bold tracking-tight text-[var(--text-primary)] leading-none">TIBSA</span>
                        <span className="text-[10px] font-medium text-[var(--primary)]/70 tracking-widest uppercase leading-none mt-0.5">
                            {pathname.startsWith("/admin") ? "SOC Nexus" : "Shield"}
                        </span>
                    </div>
                </Link>

                {/* ── CENTER: Breadcrumbs ─────────────────────── */}
                <div className="flex-1 flex justify-center">
                    <div className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-[var(--bg-elevated)] border border-[var(--border-soft)] backdrop-blur-md shadow-inner shadow-white/[0.01]">
                        {getBreadcrumbs(pathname).map((crumb, idx, arr) => (
                            <div key={idx} className="flex items-center gap-1.5">
                                {idx > 0 && (
                                    <svg className="w-3 h-3 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                                    </svg>
                                )}
                                <span className={`text-[12px] font-semibold tracking-wide transition-colors ${idx === arr.length - 1
                                        ? "text-[var(--primary)] font-extrabold"
                                        : "text-[var(--text-muted)]/80 hover:text-[var(--text-secondary)]"
                                    }`}>
                                    {crumb}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* ── RIGHT: Actions ─────────────────────────── */}
                <div className="flex items-center gap-1 flex-shrink-0">

                    {/* ─ Notification Bell ── */}
                    <div ref={notifRef} className="relative">
                        <button
                            onClick={() => { setNotifOpen((v) => !v); setProfileOpen(false); }}
                            className={`relative flex items-center justify-center w-9 h-9 rounded-lg transition-all duration-180 active:scale-96 ${
                                notifOpen
                                    ? "bg-[#0f9d76] border border-[#0f9d76] text-[#ffffff]"
                                    : "bg-[#ffffff] border border-[#e7ddd1] text-[#4f4a45] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76] hover:-translate-y-[1px] hover:shadow-[0_8px_20px_rgba(15,157,118,0.16)]"
                            }`}
                            aria-label="Notifications"
                        >
                            <svg className="w-[18px] h-[18px]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
                            </svg>
                            {/* Badge */}
                            {unread > 0 && (
                                <span className="absolute -top-1 -right-1 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-[#dc2626] text-[10px] font-bold text-white px-1 shadow-sm ring-2 ring-[#ffffff] animate-in zoom-in-90 duration-180">
                                    {unread}
                                </span>
                            )}
                        </button>

                        {/* Notification dropdown */}
                        {notifOpen && (
                            <div className="absolute right-0 top-full mt-2 w-80 rounded-xl bg-[var(--bg-elevated)] border border-[var(--border-soft)] shadow-2xl shadow-black/5 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200">
                                <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-strong)]">
                                    <span className="text-sm font-semibold text-[var(--text-primary)]">Notifications</span>
                                    {unread > 0 && (
                                        <button onClick={markAllRead} className="text-xs text-[var(--primary)] hover:text-[var(--primary)] transition-colors font-medium">
                                            Mark all read
                                        </button>
                                    )}
                                </div>
                                <div className="max-h-72 overflow-y-auto divide-y divide-white/[0.04]">
                                    {visibleNotifications.length === 0 ? (
                                        <div className="px-4 py-8 text-center text-[var(--text-muted)] text-sm">
                                            No notifications yet
                                        </div>
                                    ) : visibleNotifications.map((n) => (
                                        <button
                                            key={n.id}
                                            onClick={() => markOneRead(n.id)}
                                            className={`w-full text-left px-4 py-3 flex gap-3 hover:bg-[var(--bg-elevated)] transition-colors ${!n.read ? "bg-[var(--primary)]/[0.04]" : ""}`}
                                        >
                                            <div className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${NOTIF_ICON_COLOR[n.type] || NOTIF_ICON_COLOR.system}`}>
                                                {n.type === "threat" && (
                                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                                                )}
                                                {n.type === "scan" && (
                                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8" /><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35" /></svg>
                                                )}
                                                {n.type === "system" && (
                                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                                                )}
                                            </div>
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2">
                                                    <p className={`text-sm font-medium truncate ${!n.read ? "text-[var(--text-primary)]" : "text-[var(--text-secondary)]"}`}>{n.title}</p>
                                                    {!n.read && <span className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-[var(--primary)]" />}
                                                </div>
                                                <p className="text-xs text-[var(--text-muted)] truncate mt-0.5">{n.body}</p>
                                                <p className="text-[10px] text-[var(--text-muted)] mt-1">{timeAgo(n.created_at)}</p>
                                            </div>
                                        </button>
                                    ))}
                                </div>
                                <div className="border-t border-[var(--border-strong)] px-2 py-2">
                                    <button 
                                        onClick={() => {
                                            setIsNotificationsModalOpen(true);
                                            setNotifOpen(false);
                                        }}
                                        className="flex items-center justify-center gap-1.5 w-full py-2 px-4 rounded-lg text-xs font-semibold text-[#0f9d76] bg-transparent hover:bg-[#edf8f3] hover:text-[#0b7d5d] transition-all duration-180 hover:-translate-y-[1px] active:scale-98"
                                    >
                                        View all notifications
                                        {remainingCount > 0 && (
                                            <span className="bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/25 px-1.5 py-0.5 rounded-full text-[9px] font-bold tracking-wide">
                                                +{remainingCount}
                                            </span>
                                        )}
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Divider */}
                    <div className="h-6 w-px bg-[var(--bg-elevated)] mx-2" />

                    {/* ─ Profile Area ── */}
                    <div ref={profileRef} className="relative">
                        <button
                            onClick={() => { setProfileOpen((v) => !v); setNotifOpen(false); }}
                            className={`flex items-center gap-2.5 pl-1.5 pr-3 py-1.5 rounded-2xl border transition-all duration-200 group ${
                                profileOpen
                                    ? "bg-[#edf8f3] border-[#0f9d76]"
                                    : "bg-[#ffffff] border-[#e7ddd1] hover:bg-[#edf8f3] hover:border-[#0f9d76]"
                            }`}
                        >
                            {/* Avatar */}
                            <div className="relative flex-shrink-0">
                                <div className="h-8 w-8 rounded-full bg-[#0f9d76] flex items-center justify-center shadow-sm">
                                    <span className="text-[13px] font-bold text-white leading-none">{initial}</span>
                                </div>
                                {/* Online indicator */}
                                <span className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-green-500 border-2 border-[#ffffff]" />
                            </div>
                            {/* Name + role */}
                            <div className="hidden lg:flex flex-col items-start">
                                <span className="text-[13px] font-bold text-[#1d1d1d] leading-tight">{user?.full_name || "User"}</span>
                                <span className="text-[10px] font-semibold text-[#4f4a45] capitalize leading-tight mt-0.5">{user?.role || "user"}</span>
                            </div>
                            {/* Dropdown arrow */}
                            <svg className={`w-3.5 h-3.5 text-[#4f4a45] transition-transform duration-200 ml-1 ${profileOpen ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                            </svg>
                        </button>

                        {/* Profile dropdown */}
                        <AnimatePresence>
                            {profileOpen && (
                                <motion.div
                                    initial={{ opacity: 0, scale: 0.95, y: -8 }}
                                    animate={{ opacity: 1, scale: 1, y: 0 }}
                                    exit={{ opacity: 0, scale: 0.95, y: -8 }}
                                    transition={{ duration: 0.15, ease: "easeOut" }}
                                    className="absolute right-0 top-full mt-2 w-64 rounded-2xl bg-white/95 backdrop-blur-xl border border-[#edf8f3] shadow-[0_20px_50px_rgba(15,157,118,0.15)] overflow-hidden"
                                >
                                    {/* User info header */}
                                    <div className="px-4 py-4 border-b border-[#e7ddd1]/60 bg-gradient-to-b from-[#fcf9f5]/80 to-[#ffffff]/90 flex items-center gap-3">
                                        <div className="h-10 w-10 rounded-full bg-gradient-to-br from-[#0f9d76] to-[#0b7d5d] flex items-center justify-center shadow-md">
                                            <span className="text-sm font-extrabold text-white leading-none">{initial}</span>
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-1.5 flex-wrap">
                                                <p className="text-sm font-bold text-[#1d1d1d] truncate">{user?.full_name}</p>
                                                <span className="px-1.5 py-0.5 rounded-full text-[9px] font-extrabold bg-[#edf8f3] text-[#0f9d76] uppercase tracking-wide border border-[#0f9d76]/20">
                                                    {user?.role || "user"}
                                                </span>
                                            </div>
                                            <p className="text-xs font-semibold text-[#8a8178] truncate mt-0.5">{user?.email}</p>
                                        </div>
                                    </div>

                                    {/* Menu items */}
                                    <div className="p-1.5 space-y-1">
                                        <Link href="/dashboard/profile" onClick={() => setProfileOpen(false)}
                                            className="flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-semibold text-[#4f4a45] hover:bg-[#edf8f3] hover:text-[#0f9d76] hover:translate-x-0.5 transition-all duration-200 group/item">
                                            <svg className="w-4 h-4 text-[#8a8178] group-hover/item:text-[#0f9d76] transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.2}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                            </svg>
                                            Profile Settings
                                        </Link>
                                        {user?.role === "admin" && (
                                            pathname.startsWith("/admin") ? (
                                                <Link href="/dashboard" onClick={() => setProfileOpen(false)}
                                                    className="flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-semibold text-[#4f4a45] hover:bg-[#edf8f3] hover:text-[#0f9d76] hover:translate-x-0.5 transition-all duration-200 group/item">
                                                    <svg className="w-4 h-4 text-[#8a8178] group-hover/item:text-[#0f9d76] transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.2}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
                                                    </svg>
                                                    Back to User
                                                </Link>
                                            ) : (
                                                <Link href="/admin" onClick={() => setProfileOpen(false)}
                                                    className="flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-semibold text-[#4f4a45] hover:bg-[#edf8f3] hover:text-[#0f9d76] hover:translate-x-0.5 transition-all duration-200 group/item">
                                                    <svg className="w-4 h-4 text-[#8a8178] group-hover/item:text-[#0f9d76] transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.2}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><circle cx="12" cy="12" r="3" />
                                                    </svg>
                                                    TIBSA SOC Nexus
                                                </Link>
                                            )
                                        )}
                                    </div>

                                    {/* Logout */}
                                    <div className="border-t border-[#e7ddd1]/60 p-1.5 bg-[#fcf9f5]/40">
                                        <button
                                            onClick={() => { setProfileOpen(false); logout(); }}
                                            className="flex items-center gap-3 w-full px-3.5 py-2.5 rounded-xl text-sm font-semibold text-red-600 hover:bg-red-50 hover:text-red-700 hover:translate-x-0.5 transition-all duration-200 group/logout"
                                        >
                                            <svg className="w-4 h-4 text-red-400 group-hover/logout:text-red-600 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.2}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                                            </svg>
                                            Sign Out
                                        </button>
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                </div>
            </div>

            {/* Modal for All Notifications */}
            {isNotificationsModalOpen && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
                    {/* Backdrop */}
                    <div 
                        className="absolute inset-0 bg-[#1f1717]/25 backdrop-blur-[8px] animate-in fade-in duration-200"
                        onClick={() => setIsNotificationsModalOpen(false)}
                    />
                    {/* Modal Card */}
                    <div className="relative w-full max-w-[680px] max-h-[75vh] flex flex-col bg-[#fffaf4] border border-[#e7ddd1] rounded-[20px] shadow-[0_24px_70px_rgba(31,23,23,0.18)] overflow-hidden animate-in fade-in zoom-in-95 duration-200">
                        {/* Header */}
                        <div className="flex items-start justify-between px-6 py-5 border-b border-[#e7ddd1] bg-[#ffffff] shrink-0">
                            <div>
                                <h2 className="text-xl font-bold text-[#1d1d1d]">All Notifications</h2>
                                <p className="text-xs text-[#4f4a45] mt-1">Review recent platform and security updates</p>
                            </div>
                            <button 
                                onClick={() => setIsNotificationsModalOpen(false)}
                                className="p-1.5 rounded-lg text-[#8a8178] hover:bg-[#edf8f3] hover:text-[#0f9d76] transition-colors"
                            >
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        </div>
                        {/* List */}
                        <div className="flex-1 overflow-y-auto p-2">
                            {notifications.length === 0 ? (
                                <div className="py-20 text-center text-[#8a8178]">
                                    No notifications found.
                                </div>
                            ) : (
                                <div className="space-y-1">
                                    {notifications.map((n) => (
                                        <button
                                            key={n.id}
                                            onClick={() => markOneRead(n.id)}
                                            className={`w-full text-left px-4 py-4 rounded-xl flex gap-4 hover:bg-[#ffffff] border border-transparent transition-colors ${!n.read ? "bg-[#0f9d76]/[0.04] border-[#0f9d76]/20" : ""}`}
                                        >
                                            <div className={`flex-shrink-0 w-10 h-10 rounded-xl flex items-center justify-center ${NOTIF_ICON_COLOR[n.type] || NOTIF_ICON_COLOR.system}`}>
                                                {n.type === "threat" && (
                                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                                                )}
                                                {n.type === "scan" && (
                                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8" /><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35" /></svg>
                                                )}
                                                {n.type === "system" && (
                                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                                                )}
                                            </div>
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-2">
                                                    <p className={`text-sm font-bold truncate ${!n.read ? "text-[#1d1d1d]" : "text-[#4f4a45]"}`}>{n.title}</p>
                                                    {!n.read && <span className="flex-shrink-0 w-2 h-2 rounded-full bg-[#0f9d76] shadow-[0_0_8px_rgba(15,157,118,0.5)]" />}
                                                </div>
                                                <p className="text-xs text-[#8a8178] mt-1 leading-relaxed line-clamp-2">{n.body}</p>
                                                <p className="text-[10px] font-semibold text-[#8a8178] mt-2 uppercase tracking-wider">{timeAgo(n.created_at)}</p>
                                            </div>
                                        </button>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </header>
    );
}
