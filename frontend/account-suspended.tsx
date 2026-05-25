"use client";

import { useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import Link from "next/link";
import { motion } from "framer-motion";
import { useRouter } from "next/navigation";

export const metadata = {
  title: "Account Suspended",
  description: "Your account has been suspended",
};

export default function AccountSuspendedPage() {
    const { user, logout } = useAuth();
    const router = useRouter();

    useEffect(() => {
        if (user?.is_active) {
            router.push("/dashboard");
        }
    }, [user?.is_active, router]);

    const handleLogout = async () => {
        await logout();
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
            <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.4 }}
                className="w-full max-w-md"
            >
                <div className="bg-slate-800/50 border border-red-500/20 backdrop-blur-xl rounded-2xl p-8 shadow-2xl shadow-red-500/10">
                    {/* Icon */}
                    <div className="flex justify-center mb-6">
                        <div className="w-16 h-16 rounded-full bg-red-500/20 border border-red-500/30 flex items-center justify-center">
                            <svg className="w-8 h-8 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4v2m0 4v2m-6.773-4h13.546a2 2 0 002-2V7a2 2 0 00-2-2H5.227a2 2 0 00-2 2v12a2 2 0 002 2z" />
                            </svg>
                        </div>
                    </div>

                    {/* Title */}
                    <h1 className="text-2xl font-bold text-white text-center mb-2">Account Suspended</h1>
                    <p className="text-sm text-slate-400 text-center mb-6">
                        Your account has been deactivated by an administrator.
                    </p>

                    {/* Details */}
                    <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 mb-6 space-y-2">
                        <div className="flex items-start gap-3">
                            <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4v.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <div>
                                <p className="text-sm font-medium text-red-400">Account Inactive</p>
                                <p className="text-xs text-red-300/70 mt-1">
                                    You cannot access your account while it's deactivated. Please contact support if you believe this is an error.
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* User Info */}
                    {user && (
                        <div className="bg-white/5 border border-white/10 rounded-lg p-4 mb-6 space-y-1">
                            <p className="text-xs text-slate-500">Email:</p>
                            <p className="text-sm font-mono text-slate-300 break-all">{user.email}</p>
                        </div>
                    )}

                    {/* Actions */}
                    <div className="space-y-3">
                        <button
                            onClick={handleLogout}
                            className="w-full px-4 py-2 bg-red-500/20 border border-red-500/30 text-red-400 hover:bg-red-500/30 transition-colors rounded-lg text-sm font-medium"
                        >
                            Sign Out
                        </button>
                        <Link
                            href="/"
                            className="w-full px-4 py-2 bg-slate-700/50 border border-slate-600/50 text-slate-300 hover:bg-slate-700 transition-colors rounded-lg text-sm font-medium text-center inline-block"
                        >
                            Return Home
                        </Link>
                    </div>

                    {/* Support Info */}
                    <div className="mt-6 p-4 bg-slate-700/20 rounded-lg border border-slate-600/20">
                        <p className="text-xs text-slate-400 text-center">
                            <span className="font-medium text-slate-300">Need help?</span>
                            <br />
                            Contact support@tibsa.com or your administrator.
                        </p>
                    </div>
                </div>
            </motion.div>
        </div>
    );
}
