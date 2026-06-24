"use client";

import { TibsaRefreshButton } from "@/components/ui";
import { useState, useMemo, useEffect } from "react";
import { motion } from "framer-motion";
import { useAuth } from "@/hooks/useAuth";
import {
    StatCard,
    DataTable,
    AdminSectionCard,
    UserGrowthChart,
    LightActionLink,
} from "../components";
import type { Column } from "../components";
import type { AdminUser } from "../types";
// Removed mock imports

// ─── Icons ──────────────────────────────────────────────────
const IconUsers = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
);
const IconActive = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
);
const IconAdmin = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
);
const IconInactive = () => (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
);

function timeAgo(dateStr: string | null): string {
    if (!dateStr) return "Never";
    const diff = Math.max(0, Date.now() - new Date(dateStr).getTime());
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "Just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
}

export default function UsersManagementPage() {
    const [users, setUsers] = useState<AdminUser[]>([]);
    const [growth, setGrowth] = useState<any[]>([]);
    const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null);
    const [onlineDetailsOpen, setOnlineDetailsOpen] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [pageOffset, setPageOffset] = useState(0);
    const [refreshing, setRefreshing] = useState(false);
    const { token } = useAuth();

    // User active sessions state
    const [userSessions, setUserSessions] = useState<any[]>([]);
    const [loadingSessions, setLoadingSessions] = useState(false);

    useEffect(() => {
        if (!selectedUser || !token) return;
        const fetchSessions = async () => {
            setLoadingSessions(true);
            try {
                const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/users/${selectedUser.id}/sessions`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                if (res.ok) {
                    const data = await res.json();
                    setUserSessions(data);
                }
            } catch (err) {
                console.error("Failed to fetch sessions:", err);
            } finally {
                setLoadingSessions(false);
            }
        };
        fetchSessions();
    }, [selectedUser, token]);

    const handleRevokeSession = async (tokenSig: string) => {
        if (!token || !selectedUser) return;
        if (!confirm("Are you sure you want to terminate this active login session?")) return;
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/users/${selectedUser.id}/sessions/revoke`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({ token_signature: tokenSig })
            });
            if (res.ok) {
                setUserSessions((prev) => prev.filter((s) => s.token_signature !== tokenSig));
                alert("Session terminated successfully.");
            } else {
                alert("Failed to terminate session.");
            }
        } catch (err) {
            console.error("Failed to revoke session:", err);
            alert("Error revoking session");
        }
    };

    const sortedOnlineAndRecent = useMemo(() => {
        return [...users]
            .filter((u) => u.last_login !== null)
            .sort((a, b) => {
                const aOnline = a.is_online ?? (a.last_login ? (Date.now() - new Date(a.last_login).getTime() <= 30000) : false);
                const bOnline = b.is_online ?? (b.last_login ? (Date.now() - new Date(b.last_login).getTime() <= 30000) : false);
                if (aOnline && !bOnline) return -1;
                if (!aOnline && bOnline) return 1;
                const aTime = a.last_login ? new Date(a.last_login).getTime() : 0;
                const bTime = b.last_login ? new Date(b.last_login).getTime() : 0;
                return bTime - aTime;
            });
    }, [users]);


    const fetchUsers = async (offset = 0, append = false) => {
        if (!token) return;
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/users/list?limit=100&offset=${offset}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setUsers(prev => append ? [...prev, ...data.users] : data.users);
            }
        } catch (err) {
            console.error(err);
        }
    };

    const fetchGrowth = async () => {
        if (!token) return;
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/users/growth`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.ok) {
                const data = await res.json();
                setGrowth(data.growth);
            }
        } catch (err) {
            console.error(err);
        }
    };

    const [isLive, setIsLive] = useState(() => {
        if (typeof window !== "undefined") {
            return localStorage.getItem("tibsa_live_users") !== "false";
        }
        return true;
    });

    useEffect(() => {
        if (typeof window !== "undefined") {
            localStorage.setItem("tibsa_live_users", String(isLive));
        }
    }, [isLive]);

    useEffect(() => {
        if (!token) return;

        setIsLoading(true);
        Promise.all([fetchUsers(0), fetchGrowth()]).finally(() => setIsLoading(false));

        // Background polling every 3 seconds only if auto-refresh is active
        if (!isLive) return;
        const interval = setInterval(() => {
            fetchUsers(pageOffset, false);
        }, 3000);

        return () => clearInterval(interval);
    }, [token, pageOffset, isLive]);

    const handleLoadMore = () => {
        const nextOffset = pageOffset + 100;
        setPageOffset(nextOffset);
        fetchUsers(nextOffset, true);
    };

    const handleRefresh = async () => {
        setRefreshing(true);
        await Promise.all([fetchUsers(0, false), fetchGrowth()]);
        setRefreshing(false);
    };

    const totalUsers = users.length;
    const activeUsers = users.filter((u) => u.is_active).length;
    const adminCount = users.filter((u) => u.role === "admin").length;
    const inactiveUsers = users.filter((u) => !u.is_active).length;
    const onlineCount = users.filter((u) => u.is_online ?? (u.last_login ? (Date.now() - new Date(u.last_login).getTime() <= 30000) : false)).length;

    const handleRoleToggle = async (userId: string) => {
        if (!token) {
            alert("No authentication token found");
            return;
        }
        const currentUserObj = users.find((u) => u.id === userId);
        if (!currentUserObj) return;
        const newRole = currentUserObj.role === "admin" ? "user" : "admin";
        
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/users/${userId}/role`, {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({ role: newRole })
            });
            if (res.ok) {
                setUsers((prev) =>
                    prev.map((u) =>
                        u.id === userId ? { ...u, role: newRole } : u
                    )
                );
                alert(`User role updated to ${newRole}`);
            } else {
                const errData = await res.json();
                alert(`Failed to update role: ${errData.detail || res.statusText}`);
            }
        } catch (err) {
            console.error("Failed to update user role:", err);
            alert("Error updating user role");
        }
    };

    const handleStatusToggle = async (userId: string) => {
        if (!token) {
            alert("No authentication token found");
            return;
        }
        const currentUserObj = users.find((u) => u.id === userId);
        if (!currentUserObj) return;
        const newActiveState = !currentUserObj.is_active;
        
        try {
            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/users/${userId}/status`, {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({ is_active: newActiveState })
            });
            if (res.ok) {
                setUsers((prev) =>
                    prev.map((u) =>
                        u.id === userId ? { ...u, is_active: newActiveState } : u
                    )
                );
                alert(`User account ${newActiveState ? "enabled" : "disabled"}`);
            } else {
                const errData = await res.json();
                alert(`Failed to update status: ${errData.detail || res.statusText}`);
            }
        } catch (err) {
            console.error("Failed to update user active status:", err);
            alert("Error updating user status");
        }
    };

    const columns: Column<AdminUser>[] = [
        {
            key: "full_name",
            label: "User",
            sortable: true,
            render: (user) => {
                const isOnline = user.is_online ?? (user.last_login ? (Date.now() - new Date(user.last_login).getTime() <= 30000) : false);
                return (
                    <div className="flex items-center gap-3">
                        <div className="relative flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                            <span className="text-xs font-bold text-white">{user.full_name.charAt(0)}</span>
                            {isOnline && (
                                <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-[#10B981] border-2 border-white animate-pulse" />
                            )}
                        </div>
                        <div>
                            <div className="flex items-center gap-1.5">
                                <p className="text-sm font-medium text-[#1F2933]">{user.full_name}</p>
                                {isOnline && (
                                    <span className="px-1.5 py-0.5 rounded text-[8px] font-semibold bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/20 uppercase tracking-wide animate-pulse">
                                        online
                                    </span>
                                )}
                            </div>
                            <p className="text-xs text-[#7C6F64]">{user.email}</p>
                        </div>
                    </div>
                );
            },
        },
        {
            key: "role",
            label: "Role",
            sortable: true,
            render: (user) => (
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    user.role === "admin"
                        ? "bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/20"
                        : "bg-purple-500/10 text-purple-600 border border-purple-500/20"
                }`}>
                    {user.role === "admin" ? "⚡ Admin" : "👤 User"}
                </span>
            ),
        },
        {
            key: "is_active",
            label: "Status",
            sortable: true,
            render: (user) => (
                <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${user.is_active ? "bg-[#10B981]" : "bg-[#EF4444]"}`} />
                    <span className={`text-xs font-medium ${user.is_active ? "text-[#10B981]" : "text-[#EF4444]"}`}>
                        {user.is_active ? "Active" : "Inactive"}
                    </span>
                </div>
            ),
        },
        {
            key: "total_scans",
            label: "Scans",
            sortable: true,
            render: (user) => (
                <span className="text-sm text-[#1F2933] tabular-nums">{user.total_scans.toLocaleString()}</span>
            ),
        },
        {
            key: "threats_found",
            label: "Threats",
            sortable: true,
            render: (user) => (
                <span className={`text-sm tabular-nums ${user.threats_found > 100 ? "text-[#EF4444]" : "text-[#1F2933]"}`}>
                    {user.threats_found}
                </span>
            ),
        },
        {
            key: "last_login",
            label: "Last Active",
            sortable: true,
            render: (user) => (
                <span className="text-xs text-[#7C6F64]">{timeAgo(user.last_login)}</span>
            ),
        },
        {
            key: "actions",
            label: "Actions",
            render: (user) => (
                <div className="flex items-center gap-1">
                    <button
                        onClick={(e) => { e.stopPropagation(); handleRoleToggle(user.id); }}
                        className="px-2.5 py-1 text-xs rounded-md bg-white border border-[#E6DDD2] text-[#10B981] hover:bg-[#10B981]/10 hover:shadow-sm hover:-translate-y-px transition-all"
                        title={user.role === "admin" ? "Demote to user" : "Promote to admin"}
                    >
                        {user.role === "admin" ? "Demote" : "Promote"}
                    </button>
                    <button
                        onClick={(e) => { e.stopPropagation(); handleStatusToggle(user.id); }}
                        className={`px-2.5 py-1 text-xs rounded-md border transition-all hover:shadow-sm hover:-translate-y-px ${
                            user.is_active
                                ? "bg-white border-[#EF4444]/50 text-[#EF4444] hover:bg-[#EF4444]/10"
                                : "bg-white border-[#10B981]/50 text-[#10B981] hover:bg-[#10B981]/10"
                        }`}
                    >
                        {user.is_active ? "Disable" : "Enable"}
                    </button>
                </div>
            ),
        },
    ];

    return (
        <div className="-m-6 p-6 md:p-8 min-h-[calc(100vh-64px)] bg-[#FAF7F1] text-[#1F2933]">
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }} className="space-y-6 w-full max-w-[1600px] mx-auto">
                {/* ── Header ─────────────────────────────────── */}
                <div 
                    style={{
                      background: "linear-gradient(90deg, #FFFCF7 0%, #F4EFE7 45%, #E9EDF3 100%)"
                    }}
                    className="border border-[#E6DDD2] p-[32px] rounded-[24px] shadow-sm relative overflow-hidden flex flex-col md:flex-row md:items-center justify-between gap-6"
                >
                    <div className="flex items-start gap-4">
                        <div className="p-2.5 bg-[#edf8f3] rounded-xl border border-[#0f9d76]/30 shadow-sm shrink-0 mt-1">
                            <IconUsers />
                        </div>
                        <div>
                            <div className="flex items-center gap-2 mb-1.5">
                                <span className="text-[10px] font-bold text-[#0f9d76] uppercase tracking-widest">
                                    USER MANAGEMENT
                                </span>
                                <span className="px-2 py-0.5 text-[8px] font-bold uppercase tracking-widest bg-[#10B981]/10 border border-[#10B981]/20 text-[#10B981] rounded-full shadow-sm">
                                    Admin Badge
                                </span>
                            </div>
                            <h1 className="text-2xl font-black text-[#1d1d1d] tracking-tight">Admin Users</h1>
                            <p className="text-[#7C6F64] mt-1 max-w-xl text-sm leading-relaxed font-medium">
                                Manage user accounts, roles, and permissions across the TIBSA platform.
                            </p>
                        </div>
                    </div>
                    {/* Refresh and Auto-refresh controls */}
                    <div className="flex items-center gap-4 bg-white/60 border border-[#E6DDD2] rounded-xl p-2 shadow-sm backdrop-blur-md">
                        <TibsaRefreshButton
                            onClick={handleRefresh}
                            isRefreshing={refreshing}
                        />
                        <div className="w-px h-5 bg-[#E6DDD2]" />
                        <div className="flex items-center gap-2 text-xs">
                            <span className="text-[#7C6F64] font-mono font-medium">LIVE</span>
                            <button 
                                onClick={() => setIsLive(!isLive)}
                                className={`w-9 h-5 rounded-full transition-colors relative ${isLive ? 'bg-[#10B981] shadow-sm' : 'bg-slate-200 border border-slate-300'}`}
                            >
                                <span className={`absolute top-[2px] left-[2px] w-4 h-4 rounded-full bg-white transition-transform ${isLive ? 'translate-x-4' : 'translate-x-0'}`} />
                            </button>
                        </div>
                    </div>
                </div>

            {/* ── Stats ──────────────────────────────────── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                <StatCard label="Total Users" value={totalUsers} icon={<IconUsers />} color="blue" change={12.5} changeLabel="vs last month" trend="up" delay={0} />
                <StatCard 
                    label="Online Now" 
                    value={onlineCount} 
                    icon={
                        <span className="relative flex h-2.5 w-2.5">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                        </span>
                    } 
                    color="green" 
                    delay={100}
                >
                    <div className="mt-3 pt-2 border-t border-emerald-500/10 flex justify-between items-center">
                        <LightActionLink onClick={(e: any) => { e.stopPropagation(); setOnlineDetailsOpen(true); }}>details</LightActionLink>
                    </div>
                </StatCard>
                <StatCard label="Active Users" value={activeUsers} icon={<IconActive />} color="cyan" change={8.3} changeLabel="vs last month" trend="up" delay={200} />
                <StatCard label="Admins" value={adminCount} icon={<IconAdmin />} color="purple" delay={300} />
                <StatCard label="Inactive" value={inactiveUsers} icon={<IconInactive />} color="red" delay={400} />
            </div>

            {/* ── User Growth Chart ──────────────────────── */}
            <AdminSectionCard title="User Growth" description="Registrations over the last 6 months">
                <UserGrowthChart data={growth} />
            </AdminSectionCard>

            {/* ── Users Table ────────────────────────────── */}
            <AdminSectionCard
                title="All Users"
                description={`${totalUsers} users total`}
            >
                <DataTable
                    columns={columns}
                    data={users}
                    searchable
                    searchPlaceholder="Search by name or email..."
                    searchKeys={["full_name", "email"]}
                    pageSize={8}
                    emptyMessage={isLoading ? "Loading users..." : "No users found"}
                    onRowClick={(user) => setSelectedUser(user)}
                />
                {users.length >= 100 && (
                    <div className="flex justify-center mt-4">
                        <button 
                            onClick={handleLoadMore}
                            className="px-4 py-2 text-sm font-semibold text-[#10B981] bg-[#10B981]/10 border border-[#10B981]/20 hover:bg-gradient-to-br hover:from-[#ECFDF5] hover:to-white hover:shadow-sm hover:-translate-y-px rounded-xl transition-all"
                        >
                            Load More
                        </button>
                    </div>
                )}
            </AdminSectionCard>

            {/* ── User Detail Drawer ─────────────────────── */}
            {selectedUser && (
                <div className="fixed inset-0 z-50 flex justify-end" onClick={() => setSelectedUser(null)}>
                    <div className="absolute inset-0 bg-black/20 backdrop-blur-sm" />
                    <div
                        className="relative w-full max-w-md bg-white border-l border-[#E6DDD2] shadow-2xl overflow-y-auto animate-in slide-in-from-right duration-300"
                        onClick={(e) => e.stopPropagation()}
                    >
                        {/* Header */}
                        <div className="sticky top-0 bg-white/80 backdrop-blur-lg border-b border-[#E6DDD2] px-6 py-4 flex items-center justify-between z-10">
                            <h3 className="text-lg font-semibold text-[#1F2933]">User Details</h3>
                            <button
                                onClick={() => setSelectedUser(null)}
                                className="w-8 h-8 rounded-lg flex items-center justify-center text-[#7C6F64] hover:text-[#1F2933] hover:bg-[#FAF7F1] transition-colors"
                            >
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        </div>

                        <div className="px-6 py-6 space-y-6">
                            {/* Profile */}
                            <div className="flex items-center gap-4">
                                <div className="relative w-14 h-14 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg">
                                    <span className="text-xl font-bold text-white">{selectedUser.full_name.charAt(0)}</span>
                                    {selectedUser.is_online ?? (selectedUser.last_login ? (Date.now() - new Date(selectedUser.last_login).getTime() <= 30000) : false) ? (
                                        <span className="absolute bottom-0 right-0 w-3.5 h-3.5 rounded-full bg-[#10B981] border-2 border-white animate-pulse" />
                                    ) : null}
                                </div>
                                <div>
                                    <div className="flex items-center gap-2">
                                        <p className="text-lg font-semibold text-[#1F2933]">{selectedUser.full_name}</p>
                                        {(selectedUser.is_online ?? (selectedUser.last_login ? (Date.now() - new Date(selectedUser.last_login).getTime() <= 30000) : false)) && (
                                            <span className="px-1.5 py-0.5 rounded text-[8px] font-semibold bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/20 uppercase tracking-wide">
                                                online
                                            </span>
                                        )}
                                    </div>
                                    <p className="text-sm text-[#7C6F64]">{selectedUser.email}</p>
                                </div>
                            </div>

                            {/* Badges */}
                            <div className="flex gap-2">
                                <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                                    selectedUser.role === "admin"
                                        ? "bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/20"
                                        : "bg-purple-500/10 text-purple-600 border border-purple-500/20"
                                }`}>
                                    {selectedUser.role}
                                </span>
                                <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                                    selectedUser.is_active
                                        ? "bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/20"
                                        : "bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/20"
                                }`}>
                                    {selectedUser.is_active ? "Active" : "Inactive"}
                                </span>
                            </div>

                            {/* Stats Grid */}
                            <div className="grid grid-cols-2 gap-3">
                                {[
                                    { label: "Total Scans", value: selectedUser.total_scans.toLocaleString(), color: "text-[#2F80ED]" },
                                    { label: "Threats Found", value: selectedUser.threats_found.toString(), color: "text-[#EF4444]" },
                                    { label: "Storage Used", value: `${selectedUser.storage_used} MB`, color: "text-[#10B981]" },
                                    { label: "Last Login", value: timeAgo(selectedUser.last_login), color: "text-amber-500" },
                                ].map((stat) => (
                                    <div key={stat.label} className="bg-[#FAF7F1] rounded-lg border border-[#E6DDD2] p-3 shadow-sm">
                                        <p className="text-[11px] text-[#7C6F64]">{stat.label}</p>
                                        <p className={`text-lg font-bold ${stat.color} mt-0.5`}>{stat.value}</p>
                                    </div>
                                ))}
                            </div>

                            {/* Dates */}
                            <div className="space-y-3">
                                <div className="flex items-center justify-between py-2 border-b border-[#E6DDD2]">
                                    <span className="text-xs text-[#7C6F64]">Created</span>
                                    <span className="text-xs text-[#1F2933]">{new Date(selectedUser.created_at).toLocaleDateString()}</span>
                                </div>
                                <div className="flex items-center justify-between py-2 border-b border-[#E6DDD2]">
                                    <span className="text-xs text-[#7C6F64]">Last Updated</span>
                                    <span className="text-xs text-[#1F2933]">{new Date(selectedUser.updated_at).toLocaleDateString()}</span>
                                </div>
                                <div className="flex items-center justify-between py-2">
                                    <span className="text-xs text-[#7C6F64]">User ID</span>
                                    <span className="text-xs text-[#7C6F64] font-mono">{selectedUser.id}</span>
                                </div>
                            </div>

                            {/* Active Sessions Manager */}
                            <div className="border-t border-[#E6DDD2] pt-4 space-y-3">
                                <h4 className="text-xs font-semibold text-[#7C6F64] uppercase tracking-wider flex items-center gap-1.5">
                                    <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] animate-pulse" />
                                    Active Sessions ({userSessions.length})
                                </h4>
                                {loadingSessions ? (
                                    <p className="text-xs text-[#7C6F64] animate-pulse">Loading sessions...</p>
                                ) : userSessions.length === 0 ? (
                                    <p className="text-xs text-[#7C6F64] italic">No active tracked sessions.</p>
                                ) : (
                                    <div className="space-y-2">
                                        {userSessions.map((session) => (
                                            <div key={session.token_signature} className="flex items-center justify-between p-2.5 rounded-lg bg-[#FAF7F1] border border-[#E6DDD2] text-xs font-medium">
                                                <div className="min-w-0 flex-1 pr-2">
                                                    <div className="flex items-center gap-1 text-[#1F2933] font-mono">
                                                        <span>IP: {session.ip_address}</span>
                                                    </div>
                                                    <span className="text-[10px] text-[#7C6F64] truncate block mt-0.5" title={session.user_agent}>
                                                        Device: {session.user_agent}
                                                    </span>
                                                </div>
                                                <button
                                                    onClick={() => handleRevokeSession(session.token_signature)}
                                                    className="px-2 py-1 text-[10px] font-semibold rounded bg-[#EF4444]/10 border border-[#EF4444]/20 text-[#EF4444] hover:bg-[#EF4444]/20 transition-colors flex-shrink-0"
                                                >
                                                    Revoke
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>

                            {/* Actions */}
                            <div className="space-y-2 pt-2">
                                <button
                                    onClick={() => { handleRoleToggle(selectedUser.id); setSelectedUser({ ...selectedUser, role: selectedUser.role === "admin" ? "user" : "admin" }); }}
                                    className="w-full px-4 py-2.5 text-sm rounded-lg bg-white border border-[#E6DDD2] text-[#10B981] hover:bg-[#10B981]/10 transition-colors shadow-sm"
                                >
                                    {selectedUser.role === "admin" ? "Demote to User" : "Promote to Admin"}
                                </button>
                                <button
                                    onClick={() => { handleStatusToggle(selectedUser.id); setSelectedUser({ ...selectedUser, is_active: !selectedUser.is_active }); }}
                                    className={`w-full px-4 py-2.5 text-sm rounded-lg border transition-colors shadow-sm ${
                                        selectedUser.is_active
                                            ? "bg-white border-[#EF4444]/50 text-[#EF4444] hover:bg-[#EF4444]/10"
                                            : "bg-white border-[#10B981]/50 text-[#10B981] hover:bg-[#10B981]/10"
                                    }`}
                                >
                                    {selectedUser.is_active ? "Deactivate Account" : "Reactivate Account"}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
            {/* ── Active Sessions Tracker Modal ──────────── */}
            {onlineDetailsOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={() => setOnlineDetailsOpen(false)}>
                    <div className="absolute inset-0 bg-black/60 backdrop-blur-md" />
                    <div
                        className="relative w-full max-w-lg bg-white border border-[#E6DDD2] rounded-2xl shadow-xl overflow-hidden flex flex-col max-h-[80vh] animate-in zoom-in-95 duration-200"
                        onClick={(e) => e.stopPropagation()}
                    >
                        {/* Top decorative accent */}
                        <div className="absolute top-0 left-0 right-0 h-[4px] bg-gradient-to-r from-[#10B981] to-teal-400" />

                        {/* Header */}
                        <div className="px-6 py-5 border-b border-[#E6DDD2] flex items-center justify-between bg-[#FAF7F1]/50">
                            <div>
                                <h3 className="text-lg font-bold text-[#1F2933] flex items-center gap-2">
                                    <span className="relative flex h-2.5 w-2.5">
                                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#10B981] opacity-75"></span>
                                        <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#10B981]"></span>
                                    </span>
                                    Active Sessions Tracker
                                </h3>
                                <p className="text-xs text-[#7C6F64] mt-1">Real-time analyst & user presence inside TIBSA SOC</p>
                            </div>
                            <button
                                onClick={() => setOnlineDetailsOpen(false)}
                                className="w-8 h-8 rounded-lg flex items-center justify-center text-[#7C6F64] hover:text-[#1F2933] hover:bg-[#E6DDD2] transition-colors cursor-pointer"
                            >
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        </div>

                        {/* Presence Stats summary */}
                        <div className="px-6 py-3 bg-[#10B981]/5 border-b border-[#E6DDD2] flex items-center justify-between text-xs text-[#7C6F64]">
                            <span>Total Online: <strong className="text-[#10B981] font-semibold">{onlineCount}</strong></span>
                            <span>Active History: <strong className="text-[#2F80ED] font-semibold">{sortedOnlineAndRecent.length} accounts</strong></span>
                        </div>

                        {/* Users List */}
                        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-3 custom-scrollbar">
                            {sortedOnlineAndRecent.length === 0 ? (
                                <div className="py-8 text-center">
                                    <p className="text-sm text-[#7C6F64]">No active or past sessions tracked.</p>
                                </div>
                            ) : (
                                sortedOnlineAndRecent.map((user) => {
                                    const isOnline = user.is_online ?? (user.last_login ? (Date.now() - new Date(user.last_login).getTime() <= 30000) : false);
                                    return (
                                        <div 
                                            key={user.id}
                                            className="flex items-center justify-between p-3 rounded-xl bg-white border border-[#E6DDD2] hover:bg-[#FAF7F1] hover:border-[#E6DDD2] transition-all duration-200 shadow-sm"
                                        >
                                            <div className="flex items-center gap-3">
                                                <div className="relative flex-shrink-0 w-9 h-9 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center font-bold text-white shadow-inner">
                                                    {user.full_name.charAt(0)}
                                                    {isOnline && (
                                                        <span className="absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full bg-[#10B981] border-2 border-white animate-pulse" />
                                                    )}
                                                </div>
                                                <div>
                                                    <div className="flex items-center gap-1.5">
                                                        <span className="text-sm font-semibold text-[#1F2933]">{user.full_name}</span>
                                                        {isOnline ? (
                                                            <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/20 uppercase tracking-wider animate-pulse">
                                                                online
                                                            </span>
                                                        ) : (
                                                            <span className="px-1.5 py-0.5 rounded text-[8px] font-bold bg-gray-100 text-gray-500 border border-gray-200 uppercase tracking-wider">
                                                                offline
                                                            </span>
                                                        )}
                                                    </div>
                                                    <span className="text-xs text-[#7C6F64] block leading-tight">{user.email}</span>
                                                </div>
                                            </div>

                                            <div className="flex flex-col items-end gap-1">
                                                <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                                                    user.role === "admin"
                                                        ? "bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/20"
                                                        : "bg-purple-500/10 text-purple-600 border border-purple-500/20"
                                                }`}>
                                                    {user.role === "admin" ? "⚡ Admin" : "👤 User"}
                                                </span>
                                                <span className="text-[10px] text-[#7C6F64] flex items-center gap-1">
                                                    <svg className="w-3.5 h-3.5 text-[#10B981] animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                                                    </svg>
                                                    {isOnline ? "Active now" : timeAgo(user.last_login)}
                                                </span>
                                            </div>
                                        </div>
                                    );
                                })
                            )}
                        </div>

                        {/* Footer */}
                        <div className="px-6 py-4 border-t border-[#E6DDD2] bg-[#FAF7F1] flex justify-end">
                            <button
                                onClick={() => setOnlineDetailsOpen(false)}
                                className="px-4 py-2 text-xs font-semibold rounded-lg bg-white border border-[#E6DDD2] text-[#1F2933] hover:bg-[#E6DDD2] transition-colors cursor-pointer shadow-sm"
                            >
                                Close Tracker
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </motion.div>
        </div>
    );
}
