"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Button, Card } from "@/components/ui";
import type { User, UserRole } from "@/types";

export default function UsersManagementPage() {
    const { token } = useAuth();
    const [users, setUsers] = useState<User[]>([]);
    const [isLoading, setIsLoading] = useState(true);

    const fetchUsers = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<User[]>("/api/v1/users", token);
            setUsers(data);
        } catch (error) {
            console.error("Failed to fetch users:", error);
        } finally {
            setIsLoading(false);
        }
    }, [token]);

    useEffect(() => {
        fetchUsers();
    }, [fetchUsers]);

    const handleRoleChange = async (userId: string, newRole: UserRole) => {
        if (!token) return;
        try {
            await api.patch(`/api/v1/users/${userId}/role`, { role: newRole }, token);
            setUsers((prev) =>
                prev.map((u) => (u.id === userId ? { ...u, role: newRole } : u))
            );
        } catch (error) {
            console.error("Failed to update role:", error);
        }
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-white">User Management</h1>
                <p className="text-slate-400 mt-1">Manage user accounts and roles</p>
            </div>

            <Card>
                {isLoading ? (
                    <div className="text-center py-8 text-slate-500">Loading users...</div>
                ) : users.length === 0 ? (
                    <div className="text-center py-8 text-slate-500">No users found.</div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-left border-b border-white/[0.08]">
                                    <th className="pb-3 font-medium text-slate-400">Name</th>
                                    <th className="pb-3 font-medium text-slate-400">Email</th>
                                    <th className="pb-3 font-medium text-slate-400">Role</th>
                                    <th className="pb-3 font-medium text-slate-400">Status</th>
                                    <th className="pb-3 font-medium text-slate-400">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/[0.06]">
                                {users.map((user) => (
                                    <tr key={user.id} className="hover:bg-white/[0.03]">
                                        <td className="py-3 font-medium text-white">{user.full_name}</td>
                                        <td className="py-3 text-slate-300">{user.email}</td>
                                        <td className="py-3">
                                            <span
                                                className={`px-2 py-1 rounded-full text-xs font-medium ${user.role === "admin"
                                                        ? "bg-purple-500/15 text-purple-400"
                                                        : "bg-blue-500/15 text-blue-400"
                                                    }`}
                                            >
                                                {user.role}
                                            </span>
                                        </td>
                                        <td className="py-3">
                                            <span
                                                className={`px-2 py-1 rounded-full text-xs font-medium ${user.is_active
                                                        ? "bg-green-500/15 text-green-400"
                                                        : "bg-red-500/15 text-red-400"
                                                    }`}
                                            >
                                                {user.is_active ? "Active" : "Inactive"}
                                            </span>
                                        </td>
                                        <td className="py-3">
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                onClick={() =>
                                                    handleRoleChange(
                                                        user.id,
                                                        user.role === "admin" ? "user" : "admin"
                                                    )
                                                }
                                            >
                                                {user.role === "admin" ? "Make User" : "Make Admin"}
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </Card>
        </div>
    );
}
