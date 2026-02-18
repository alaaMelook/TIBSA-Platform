"use client";

import { useAuth } from "@/hooks/useAuth";
import { Card } from "@/components/ui";

export default function ProfilePage() {
    const { user } = useAuth();

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900">Profile</h1>
                <p className="text-gray-500 mt-1">Your account information</p>
            </div>

            <div className="max-w-2xl">
                <Card>
                    <div className="space-y-6">
                        {/* Avatar and Name */}
                        <div className="flex items-center gap-4">
                            <div className="h-16 w-16 rounded-full bg-blue-600 flex items-center justify-center text-white text-2xl font-bold">
                                {user?.full_name?.charAt(0)?.toUpperCase() || "U"}
                            </div>
                            <div>
                                <h2 className="text-xl font-bold text-gray-900">{user?.full_name}</h2>
                                <p className="text-gray-500 text-sm">{user?.email}</p>
                            </div>
                        </div>

                        <hr className="border-gray-100" />

                        {/* Info Grid */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider">Full Name</label>
                                <p className="text-gray-900 mt-1">{user?.full_name || "—"}</p>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider">Email</label>
                                <p className="text-gray-900 mt-1">{user?.email || "—"}</p>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider">Role</label>
                                <p className="mt-1">
                                    <span
                                        className={`px-2 py-1 rounded-full text-xs font-medium ${user?.role === "admin"
                                                ? "bg-purple-100 text-purple-700"
                                                : "bg-blue-100 text-blue-700"
                                            }`}
                                    >
                                        {user?.role || "user"}
                                    </span>
                                </p>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider">Status</label>
                                <p className="mt-1">
                                    <span
                                        className={`px-2 py-1 rounded-full text-xs font-medium ${user?.is_active
                                                ? "bg-green-100 text-green-700"
                                                : "bg-red-100 text-red-700"
                                            }`}
                                    >
                                        {user?.is_active ? "Active" : "Inactive"}
                                    </span>
                                </p>
                            </div>
                            <div>
                                <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider">Joined</label>
                                <p className="text-gray-900 mt-1">
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
            </div>
        </div>
    );
}
