"use client";

import { useAuth } from "@/hooks/useAuth";
import { Card, Button } from "@/components/ui";
import Link from "next/link";

export default function ProfilePage() {
    const { user } = useAuth();

    return (
        <div className="space-y-6">
            <div 
              style={{
                background: "linear-gradient(90deg, rgba(230,226,220,0.95) 0%, rgba(156,158,160,0.75) 55%, #0f172a 100%)"
              }}
              className="border border-[var(--border-soft)] p-[32px] rounded-[20px] shadow-xl relative overflow-hidden animate-[cardFadeIn_300ms_ease-out_forwards] motion-reduce:animate-none"
            >
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[10px] font-bold text-[#0f9d76] uppercase tracking-widest">
                    ACCOUNT SETTINGS
                  </span>
                </div>
                <h1 className="text-2xl font-black text-[#1d1d1d] tracking-tight">Profile</h1>
                <p className="text-[#4f4a45] mt-1 max-w-xl text-sm leading-relaxed font-medium">Your account information</p>
            </div>

            <div className="max-w-2xl space-y-6">
                <Card>
                    <div className="space-y-6">
                        {/* Avatar and Name */}
                        <div className="flex items-center gap-4">
                            <div className="h-16 w-16 rounded-full bg-[var(--primary-hover)] flex items-center justify-center text-[var(--text-primary)] text-2xl font-bold">
                                {user?.full_name?.charAt(0)?.toUpperCase() || "U"}
                            </div>
                            <div>
                                <h2 className="text-xl font-bold text-[var(--text-primary)]">{user?.full_name}</h2>
                                <p className="text-[var(--text-muted)] text-sm">{user?.email}</p>
                            </div>
                        </div>

                        <hr className="border-[var(--border-strong)]" />

                        {/* Info Grid */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <label className="block text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Full Name</label>
                                <p className="text-[var(--text-primary)] mt-1">{user?.full_name || "—"}</p>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Email</label>
                                <p className="text-[var(--text-primary)] mt-1">{user?.email || "—"}</p>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Role</label>
                                <p className="mt-1">
                                    <span
                                        className={`px-2 py-1 rounded-full text-xs font-medium ${user?.role === "admin"
                                                ? "bg-[var(--primary-soft)] text-[var(--primary)]"
                                                : "bg-[var(--primary)]/15 text-[var(--primary)]"
                                            }`}
                                    >
                                        {user?.role || "user"}
                                    </span>
                                </p>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Status</label>
                                <p className="mt-1">
                                    <span
                                        className={`px-2 py-1 rounded-full text-xs font-medium ${user?.is_active
                                                ? "bg-green-500/15 text-green-400"
                                                : "bg-red-500/15 text-red-400"
                                            }`}
                                    >
                                        {user?.is_active ? "Active" : "Inactive"}
                                    </span>
                                </p>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Joined</label>
                                <p className="text-[var(--text-primary)] mt-1">
                                    {user?.created_at
                                        ? new Date(user.created_at).toLocaleDateString("en-US", {
                                            year: "numeric",
                                            month: "long",
                                            day: "numeric",
                                        })
                                        : "—"}
                                </p>
                            </div>
                        </div>
                    </div>
                </Card>

                <Card>
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                        <div>
                            <h3 className="text-lg font-medium text-[var(--text-primary)]">Security & Authentication</h3>
                            <p className="text-sm text-[var(--text-muted)] mt-1">Manage Two-Factor Authentication (2FA) and password settings.</p>
                        </div>
                        <Link href="/dashboard/settings/security">
                            <Button variant="primary" className="whitespace-nowrap">
                                Security Settings & 2FA
                            </Button>
                        </Link>
                    </div>
                </Card>
            </div>
        </div>
    );
}
