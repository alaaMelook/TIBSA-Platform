"use client";

import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";

export function Header() {
    const { user, isAuthenticated, logout } = useAuth();

    return (
        <header className="sticky top-0 z-50 w-full border-b border-gray-200 bg-white/80 backdrop-blur-md">
            <div className="container mx-auto flex h-16 items-center justify-between px-4">
                {/* Logo */}
                <Link href="/" className="flex items-center gap-2">
                    <div className="h-8 w-8 rounded-lg bg-blue-600 flex items-center justify-center">
                        <span className="text-white font-bold text-sm">T</span>
                    </div>
                    <span className="text-xl font-bold text-gray-900">TIBSA</span>
                </Link>

                {/* Navigation */}
                <nav className="flex items-center gap-4">
                    {isAuthenticated ? (
                        <>
                            <Link href="/dashboard" className="text-sm text-gray-600 hover:text-gray-900 transition-colors">
                                Dashboard
                            </Link>
                            {user?.role === "admin" && (
                                <Link href="/admin" className="text-sm text-gray-600 hover:text-gray-900 transition-colors">
                                    Admin Panel
                                </Link>
                            )}
                            <div className="flex items-center gap-3 ml-4 pl-4 border-l border-gray-200">
                                <span className="text-sm text-gray-500">{user?.full_name}</span>
                                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 font-medium uppercase">
                                    {user?.role}
                                </span>
                                <button
                                    onClick={logout}
                                    className="text-sm text-red-600 hover:text-red-800 transition-colors"
                                >
                                    Logout
                                </button>
                            </div>
                        </>
                    ) : (
                        <>
                            <Link href="/login" className="text-sm text-gray-600 hover:text-gray-900 transition-colors">
                                Login
                            </Link>
                            <Link
                                href="/register"
                                className="text-sm bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                            >
                                Register
                            </Link>
                        </>
                    )}
                </nav>
            </div>
        </header>
    );
}
