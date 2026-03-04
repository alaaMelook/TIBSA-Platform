"use client";

import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";

export function Header() {
    const { user, isAuthenticated, logout } = useAuth();

    return (
        <header className="sticky top-0 z-50 w-full border-b border-white/[0.08] bg-[#0f172a]/95 backdrop-blur-md">
            <div className="container mx-auto flex h-16 items-center justify-between px-4">
                {/* Logo */}
                <Link href="/" className="flex items-center gap-2">
                    <div className="h-8 w-8 rounded-lg bg-blue-600 flex items-center justify-center">
                        <span className="text-white font-bold text-sm">T</span>
                    </div>
                    <span className="text-xl font-bold text-white">TIBSA</span>
                </Link>

                {/* Navigation */}
                <nav className="flex items-center gap-4">
                    {isAuthenticated ? (
                        <>
                            <Link href="/dashboard" className="text-sm text-slate-400 hover:text-white transition-colors">
                                Dashboard
                            </Link>
                            {user?.role === "admin" && (
                                <Link href="/admin" className="text-sm text-slate-400 hover:text-white transition-colors">
                                    Admin Panel
                                </Link>
                            )}
                            <div className="flex items-center gap-3 ml-4 pl-4 border-l border-white/[0.08]">
                                <span className="text-sm text-slate-400">{user?.full_name}</span>
                                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-400 font-medium uppercase border border-blue-500/25">
                                    {user?.role}
                                </span>
                                <button
                                    onClick={logout}
                                    className="text-sm text-red-400 hover:text-red-300 transition-colors"
                                >
                                    Logout
                                </button>
                            </div>
                        </>
                    ) : (
                        <>
                            <Link href="/login" className="text-sm text-slate-400 hover:text-white transition-colors">
                                Login
                            </Link>
                            <Link
                                href="/register"
                                className="text-sm bg-[#3b82f6] hover:bg-[#60a5fa] text-white px-4 py-2 rounded-lg transition-colors shadow-lg shadow-blue-600/25"
                            >
                                Get Started
                            </Link>
                        </>
                    )}
                </nav>
            </div>
        </header>
    );
}
