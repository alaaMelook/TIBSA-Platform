"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
    StatCard,
    DataTable,
    AdminSectionCard,
    UserGrowthChart,
} from "../components";
import type { Column } from "../components";
import type { AdminUser } from "../types";
import { mockAdminUsers, mockUserGrowth } from "../mock";

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
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "Just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
}

export default function UsersManagementPage() {
    const [users, setUsers] = useState<AdminUser[]>(mockAdminUsers);
    const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null);

    const totalUsers = users.length;
    const activeUsers = users.filter((u) => u.is_active).length;
    const adminCount = users.filter((u) => u.role === "admin").length;
    const inactiveUsers = users.filter((u) => !u.is_active).length;

    // TODO: Replace with actual API call
    const handleRoleToggle = (userId: string) => {
        setUsers((prev) =>
            prev.map((u) =>
                u.id === userId ? { ...u, role: u.role === "admin" ? "user" : "admin" } : u
            )
        );
    };

    // TODO: Replace with actual API call
    const handleStatusToggle = (userId: string) => {
        setUsers((prev) =>
            prev.map((u) =>
                u.id === userId ? { ...u, is_active: !u.is_active } : u
            )
        );
    };

    const columns: Column<AdminUser>[] = [
        {
            key: "full_name",
            label: "User",
            sortable: true,
            render: (user) => (
                <div className="flex items-center gap-3">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                        <span className="text-xs font-bold text-white">{user.full_name.charAt(0)}</span>
                    </div>
                    <div>
                        <p className="text-sm font-medium text-white">{user.full_name}</p>
                        <p className="text-xs text-slate-500">{user.email}</p>
                    </div>
                </div>
            ),
        },
        {
            key: "role",
            label: "Role",
            sortable: true,
            render: (user) => (
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                    user.role === "admin"
                        ? "bg-purple-500/15 text-purple-400 border border-purple-500/20"
                        : "bg-blue-500/15 text-blue-400 border border-blue-500/20"
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
                    <span className={`w-2 h-2 rounded-full ${user.is_active ? "bg-emerald-400" : "bg-red-400"}`} />
                    <span className={`text-xs font-medium ${user.is_active ? "text-emerald-400" : "text-red-400"}`}>
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
                <span className="text-sm text-slate-300 tabular-nums">{user.total_scans.toLocaleString()}</span>
            ),
        },
        {
            key: "threats_found",
            label: "Threats",
            sortable: true,
            render: (user) => (
                <span className={`text-sm tabular-nums ${user.threats_found > 100 ? "text-red-400" : "text-slate-300"}`}>
                    {user.threats_found}
                </span>
            ),
        },
        {
            key: "last_login",
            label: "Last Active",
            sortable: true,
            render: (user) => (
                <span className="text-xs text-slate-500">{timeAgo(user.last_login)}</span>
            ),
        },
        {
            key: "actions",
            label: "Actions",
            render: (user) => (
                <div className="flex items-center gap-1">
                    <button
                        onClick={(e) => { e.stopPropagation(); handleRoleToggle(user.id); }}
                        className="px-2.5 py-1 text-xs rounded-md bg-white/[0.04] border border-white/[0.08] text-slate-300 hover:bg-white/[0.08] hover:text-white transition-colors"
                        title={user.role === "admin" ? "Demote to user" : "Promote to admin"}
                    >
                        {user.role === "admin" ? "Demote" : "Promote"}
                    </button>
                    <button
                        onClick={(e) => { e.stopPropagation(); handleStatusToggle(user.id); }}
                        className={`px-2.5 py-1 text-xs rounded-md border transition-colors ${
                            user.is_active
                                ? "bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20"
                                : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20"
                        }`}
                    >
                        {user.is_active ? "Disable" : "Enable"}
                    </button>
                </div>
            ),
        },
    ];

    return (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }} className="space-y-6 max-w-[1400px]">
            {/* ── Header ─────────────────────────────────── */}
            <div>
                <div className="flex items-center gap-3 mb-1">
                    <h1 className="text-2xl font-bold text-white">User Management</h1>
                    <span className="px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-widest bg-gradient-to-r from-blue-500/20 to-purple-500/20 border border-blue-500/20 text-blue-400 rounded-full">
                        Admin
                    </span>
                </div>
                <p className="text-sm text-slate-400">Manage user accounts, roles, and permissions</p>
            </div>

            {/* ── Stats ──────────────────────────────────── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard label="Total Users" value={totalUsers} icon={<IconUsers />} color="blue" change={12.5} changeLabel="vs last month" trend="up" delay={0} />
                <StatCard label="Active Users" value={activeUsers} icon={<IconActive />} color="green" change={8.3} changeLabel="vs last month" trend="up" delay={100} />
                <StatCard label="Admins" value={adminCount} icon={<IconAdmin />} color="purple" delay={200} />
                <StatCard label="Inactive" value={inactiveUsers} icon={<IconInactive />} color="red" delay={300} />
            </div>

            {/* ── User Growth Chart ──────────────────────── */}
            <AdminSectionCard title="User Growth" description="Registrations over the last 6 months">
                <UserGrowthChart data={mockUserGrowth} />
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
                    emptyMessage="No users found"
                    onRowClick={(user) => setSelectedUser(user)}
                />
            </AdminSectionCard>

            {/* ── User Detail Drawer ─────────────────────── */}
            {selectedUser && (
                <div className="fixed inset-0 z-50 flex justify-end" onClick={() => setSelectedUser(null)}>
                    <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" />
                    <div
                        className="relative w-full max-w-md bg-[#1a2744] border-l border-white/[0.08] shadow-2xl overflow-y-auto animate-in slide-in-from-right duration-300"
                        onClick={(e) => e.stopPropagation()}
                    >
                        {/* Header */}
                        <div className="sticky top-0 bg-[#1a2744]/95 backdrop-blur-lg border-b border-white/[0.06] px-6 py-4 flex items-center justify-between z-10">
                            <h3 className="text-lg font-semibold text-white">User Details</h3>
                            <button
                                onClick={() => setSelectedUser(null)}
                                className="w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:text-white hover:bg-white/[0.06] transition-colors"
                            >
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        </div>

                        <div className="px-6 py-6 space-y-6">
                            {/* Profile */}
                            <div className="flex items-center gap-4">
                                <div className="w-14 h-14 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg">
                                    <span className="text-xl font-bold text-white">{selectedUser.full_name.charAt(0)}</span>
                                </div>
                                <div>
                                    <p className="text-lg font-semibold text-white">{selectedUser.full_name}</p>
                                    <p className="text-sm text-slate-400">{selectedUser.email}</p>
                                </div>
                            </div>

                            {/* Badges */}
                            <div className="flex gap-2">
                                <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                                    selectedUser.role === "admin"
                                        ? "bg-purple-500/15 text-purple-400 border border-purple-500/20"
                                        : "bg-blue-500/15 text-blue-400 border border-blue-500/20"
                                }`}>
                                    {selectedUser.role}
                                </span>
                                <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                                    selectedUser.is_active
                                        ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20"
                                        : "bg-red-500/15 text-red-400 border border-red-500/20"
                                }`}>
                                    {selectedUser.is_active ? "Active" : "Inactive"}
                                </span>
                            </div>

                            {/* Stats Grid */}
                            <div className="grid grid-cols-2 gap-3">
                                {[
                                    { label: "Total Scans", value: selectedUser.total_scans.toLocaleString(), color: "text-blue-400" },
                                    { label: "Threats Found", value: selectedUser.threats_found.toString(), color: "text-red-400" },
                                    { label: "Storage Used", value: `${selectedUser.storage_used} MB`, color: "text-purple-400" },
                                    { label: "Last Login", value: timeAgo(selectedUser.last_login), color: "text-amber-400" },
                                ].map((stat) => (
                                    <div key={stat.label} className="bg-white/[0.03] rounded-lg border border-white/[0.06] p-3">
                                        <p className="text-[11px] text-slate-500">{stat.label}</p>
                                        <p className={`text-lg font-bold ${stat.color} mt-0.5`}>{stat.value}</p>
                                    </div>
                                ))}
                            </div>

                            {/* Dates */}
                            <div className="space-y-3">
                                <div className="flex items-center justify-between py-2 border-b border-white/[0.04]">
                                    <span className="text-xs text-slate-500">Created</span>
                                    <span className="text-xs text-slate-300">{new Date(selectedUser.created_at).toLocaleDateString()}</span>
                                </div>
                                <div className="flex items-center justify-between py-2 border-b border-white/[0.04]">
                                    <span className="text-xs text-slate-500">Last Updated</span>
                                    <span className="text-xs text-slate-300">{new Date(selectedUser.updated_at).toLocaleDateString()}</span>
                                </div>
                                <div className="flex items-center justify-between py-2">
                                    <span className="text-xs text-slate-500">User ID</span>
                                    <span className="text-xs text-slate-400 font-mono">{selectedUser.id}</span>
                                </div>
                            </div>

                            {/* Actions */}
                            <div className="space-y-2 pt-2">
                                <button
                                    onClick={() => { handleRoleToggle(selectedUser.id); setSelectedUser({ ...selectedUser, role: selectedUser.role === "admin" ? "user" : "admin" }); }}
                                    className="w-full px-4 py-2.5 text-sm rounded-lg bg-purple-500/10 border border-purple-500/20 text-purple-400 hover:bg-purple-500/20 transition-colors"
                                >
                                    {selectedUser.role === "admin" ? "Demote to User" : "Promote to Admin"}
                                </button>
                                <button
                                    onClick={() => { handleStatusToggle(selectedUser.id); setSelectedUser({ ...selectedUser, is_active: !selectedUser.is_active }); }}
                                    className={`w-full px-4 py-2.5 text-sm rounded-lg border transition-colors ${
                                        selectedUser.is_active
                                            ? "bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20"
                                            : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20"
                                    }`}
                                >
                                    {selectedUser.is_active ? "Deactivate Account" : "Reactivate Account"}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </motion.div>
    );
}
