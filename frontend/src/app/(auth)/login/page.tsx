"use client";

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";
import { Button, Input } from "@/components/ui";
import { supabase } from "@/lib/supabase";
import { notifyError, notifySuccess } from "@/lib/notify";

// ── Google SVG Icon ────────────────────────────────────────────
function GoogleIcon() {
    return (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none">
            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05" />
            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
        </svg>
    );
}

// ── GitHub SVG Icon ────────────────────────────────────────────
function GitHubIcon() {
    return (
        <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
        </svg>
    );
}

// ── OAuth Button ───────────────────────────────────────────────
function OAuthButton({
    provider,
    onClick,
    isLoading,
}: {
    provider: "google" | "github";
    onClick: () => void;
    isLoading: boolean;
}) {
    const isGoogle = provider === "google";
    return (
        <button
            type="button"
            onClick={onClick}
            disabled={isLoading}
            className={`
                group relative flex items-center justify-center gap-3 w-full px-4 py-2.5 rounded-xl
                text-sm font-bold btn-animated btn-secondary-soft
                disabled:opacity-50 disabled:cursor-not-allowed
                focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[var(--bg-page)] focus:ring-[var(--primary)]/50
            `}
        >
            {isLoading ? (
                <svg className="animate-spin w-4 h-4 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
            ) : isGoogle ? (
                <GoogleIcon />
            ) : (
                <GitHubIcon />
            )}
            <span>{isGoogle ? "Continue with Google" : "Continue with GitHub"}</span>
        </button>
    );
}

function LoginForm() {
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [oauthLoading, setOauthLoading] = useState<"google" | "github" | null>(null);
    const [mfaRequired, setMfaRequired] = useState(false);
    const [mfaCode, setMfaCode] = useState("");
    const [factorId, setFactorId] = useState("");
    const [tempToken, setTempToken] = useState("");
    const { login, verifyMfa, loginWithOAuth, isAuthenticated } = useAuth();
    const router = useRouter();
    const searchParams = useSearchParams();
    const redirect = searchParams.get("redirect") || "/dashboard";

    useEffect(() => {
        if (isAuthenticated) {
            router.push(redirect);
        }
    }, [isAuthenticated, redirect, router]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);

        const target = e.target as HTMLFormElement;
        const emailInput = target.querySelector('input[type="email"]') as HTMLInputElement;
        const passwordInput = target.querySelector('input[type="password"]') as HTMLInputElement;

        const submittedEmail = email || emailInput?.value || "";
        const submittedPassword = password || passwordInput?.value || "";

        try {
            const res = await login({ email: submittedEmail, password: submittedPassword });
            if (res && res.mfa_required) {
                setMfaRequired(true);
                setFactorId(res.factor_id || "");
                setTempToken(res.mfa_token || "");
                setIsLoading(false);
            }
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : "Login failed";
            if (errorMessage.toLowerCase().includes("too many requests") || errorMessage.includes("429")) {
                notifyError("Too many failed login attempts.", "Please try again after 30 minutes.");
            } else {
                notifyError("Login Error", errorMessage);
            }
            setIsLoading(false);
        }
    };

    const handleVerifyMfa = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);

        try {
            console.log("before verifyMfa");
            await verifyMfa(factorId, mfaCode, tempToken);
            console.log("after verifyMfa success");
            
            notifySuccess("Login successful");
            console.log("before redirect");
            router.replace("/dashboard");
            
            // Fallback redirect if router.replace hangs
            setTimeout(() => {
                if (window.location.pathname !== "/dashboard") {
                    window.location.href = "/dashboard";
                }
            }, 2000);
        } catch (err) {
            console.warn("MFA Verification Exception:", err);
            notifyError("Verification Failed", err instanceof Error ? err.message : "Invalid code");
            setMfaCode("");
        } finally {
            setIsLoading(false);
        }
    };

    const handleOAuth = async (provider: "google" | "github") => {
        setOauthLoading(provider);
        try {
            await loginWithOAuth(provider);
            // Supabase will redirect the page; no need to navigate manually
        } catch (err) {
            notifyError("Sign-in Failed", err instanceof Error ? err.message : `${provider} sign-in failed`);
            setOauthLoading(null);
        }
    };

    if (mfaRequired) {
        return (
            <div className="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-soft)] shadow-2xl shadow-[var(--primary)]/5 overflow-hidden animate-[fadeIn_0.5s_ease-out]">
                <form onSubmit={handleVerifyMfa} className="p-6 pt-5 space-y-5">
                    <div>
                        <h3 className="text-xl font-bold text-[var(--text-primary)] mb-1">Two-Factor Authentication</h3>
                        <p className="text-sm text-[var(--text-muted)] font-medium">Enter the 6-digit code from your authenticator app.</p>
                    </div>

                    <Input
                        label="Authenticator Code"
                        type="text"
                        placeholder="123456"
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        required
                        maxLength={6}
                        pattern="\d{6}"
                        className="bg-white border-[var(--border-soft)] focus:border-[var(--primary)] focus:ring-[var(--primary)]/20 text-center tracking-[0.2em] text-lg font-mono"
                    />

                    <div className="pt-2 space-y-3">
                        <Button type="submit" className="w-full btn-animated btn-primary-emerald font-bold rounded-xl py-3 shadow-md border-0" isLoading={isLoading}>
                            Verify Code
                        </Button>
                        
                        <button 
                            type="button" 
                            onClick={() => setMfaRequired(false)} 
                            className="w-full text-sm font-semibold text-[var(--text-muted)] transition-all hover:text-[var(--text-primary)] py-2 rounded-xl btn-animated btn-ghost-soft border border-transparent"
                        >
                            Cancel
                        </button>
                    </div>
                </form>
            </div>
        );
    }

    return (
        <div className="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-soft)] shadow-2xl shadow-[var(--primary)]/5 overflow-hidden animate-[fadeIn_0.5s_ease-out]">
            {/* OAuth Section */}
            <div className="p-6 pb-5 space-y-3 bg-white/40">
                <OAuthButton
                    provider="google"
                    onClick={() => handleOAuth("google")}
                    isLoading={oauthLoading === "google"}
                />
                <OAuthButton
                    provider="github"
                    onClick={() => handleOAuth("github")}
                    isLoading={oauthLoading === "github"}
                />
            </div>

            {/* Divider */}
            <div className="flex items-center gap-3 px-8 py-2">
                <div className="h-px flex-1 bg-[var(--border-soft)]" />
                <span className="text-[11px] text-[var(--text-muted)] font-bold tracking-widest uppercase">OR CONTINUE WITH EMAIL</span>
                <div className="h-px flex-1 bg-[var(--border-soft)]" />
            </div>

            {/* Email/Password Form */}
            <form onSubmit={handleSubmit} className="p-6 pt-3 space-y-4">
                <div className="space-y-4">
                    <Input
                        label="Email"
                        type="email"
                        placeholder="you@example.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        className="bg-white border-[var(--border-soft)] focus:border-[var(--primary)] focus:ring-[var(--primary)]/20"
                    />

                    <div className="space-y-2">
                        <Input
                            label="Password"
                            type="password"
                            placeholder="••••••••"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            className="bg-white border-[var(--border-soft)] focus:border-[var(--primary)] focus:ring-[var(--primary)]/20"
                        />
                        <div className="flex justify-center pt-1">
                            <Link href="/forgot-password" className="text-xs text-[var(--primary)] hover:text-[var(--primary-hover)] font-semibold transition-all inline-flex items-center hover:-translate-y-[1px]">
                                Forgot Password?
                            </Link>
                        </div>
                    </div>
                </div>

                <div>
                    <Button type="submit" className="w-full btn-animated btn-primary-emerald font-bold rounded-xl py-3 shadow-md border-0" isLoading={isLoading}>
                        Sign In
                    </Button>
                </div>
            </form>

            {/* Clean Footer Area */}
            <div className="bg-[var(--bg-elevated)] border-t border-[var(--border-soft)] p-5 flex flex-col items-center justify-center gap-2">
                <p className="text-sm text-[var(--text-muted)] font-medium">
                    Don&apos;t have an account?{" "}
                    <Link href="/register" className="text-[var(--primary)] font-semibold transition-all hover:text-[var(--primary-hover)] inline-flex items-center hover:-translate-y-[1px]">
                        Register
                    </Link>
                </p>
            </div>
        </div>
    );
}

export default function LoginPage() {
    return (
        <div className="min-h-screen flex items-center justify-center bg-[var(--bg-main)] px-4 py-12 relative overflow-hidden">
            {/* Background decoration */}
            <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-[-20%] left-[-10%] w-[600px] h-[600px] rounded-full bg-[var(--primary)]/[0.04] blur-3xl" />
                <div className="absolute bottom-[-20%] right-[-10%] w-[500px] h-[500px] rounded-full bg-[var(--primary-hover)]/[0.04] blur-3xl" />
            </div>

            <div className="w-full max-w-md relative animate-[fadeIn_0.5s_ease-out]">
                {/* Logo & Heading */}
                <div className="text-center mb-8">
                    <div className="inline-flex h-14 w-14 rounded-2xl bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] items-center justify-center mb-5 shadow-lg shadow-[var(--primary)]/20">
                        <span className="text-white font-black text-2xl tracking-tighter">T</span>
                    </div>
                    <h1 className="text-3xl font-black text-[var(--text-primary)] tracking-tight mb-2">Welcome back</h1>
                    <p className="text-[var(--text-muted)] text-sm font-medium">Sign in to your TIBSA account</p>
                </div>

                <Suspense fallback={<div className="text-center text-[var(--text-muted)] py-8 font-medium animate-pulse">Loading secure environment...</div>}>
                    <LoginForm />
                </Suspense>

                <p className="text-center text-xs text-[var(--text-muted)] mt-6 font-medium">
                    By signing in, you agree to our{" "}
                    <span className="text-[var(--text-secondary)] hover:text-[var(--primary)] cursor-pointer transition-colors">Terms of Service</span> and{" "}
                    <span className="text-[var(--text-secondary)] hover:text-[var(--primary)] cursor-pointer transition-colors">Privacy Policy</span>
                </p>
            </div>
        </div>
    );
}
