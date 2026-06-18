"use client";

import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";

export function Header() {
    const { user, isAuthenticated, logout } = useAuth();

    return (
        <header className="sticky top-0 z-50 w-full border-b border-[var(--border-soft)] bg-[var(--bg-main)]/95 backdrop-blur-md">
            <div className="container mx-auto flex h-16 items-center justify-between px-4">
                {/* Logo */}
                <Link href="/" className="flex items-center gap-2">
                    <div className="h-8 w-8 rounded-lg bg-[var(--primary-hover)] flex items-center justify-center">
                        <span className="text-[var(--text-primary)] font-bold text-sm">T</span>
                    </div>
                    <span className="text-xl font-bold text-[var(--text-primary)]">TIBSA</span>
                </Link>

                {/* Navigation */}
                <nav className="flex items-center gap-4">
                    {isAuthenticated ? (
                        <>
                            <Link href="/dashboard" className="text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors">
                                Dashboard
                            </Link>
                            {user?.role === "admin" && (
                                <Link href="/admin" className="text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors">
                                    Admin Panel
                                </Link>
                            )}
                            <div className="flex items-center gap-3 ml-4 pl-4 border-l border-[var(--border-soft)]">
                                <span className="text-sm text-[var(--text-muted)]">{user?.full_name}</span>
                                <span className="text-xs px-2 py-0.5 rounded-full bg-[var(--primary)]/15 text-[var(--primary)] font-medium uppercase border border-[var(--primary)]">
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
                            <Link href="/login" className="text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors">
                                Login
                            </Link>
                            <Link
                                href="/register"
                                className="text-sm bg-[var(--primary)] hover:bg-[var(--primary-hover)] text-[var(--text-primary)] px-4 py-2 rounded-lg transition-colors shadow-lg shadow-[var(--primary-soft)]"
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
