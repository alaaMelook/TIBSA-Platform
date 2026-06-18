"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/hooks/useAuth";
import { Button, Input } from "@/components/ui";
import { PasswordStrengthMeter } from "@/components/ui/PasswordStrengthMeter";
import { toast } from "sonner";
import { CheckCircle2, Circle, AlertCircle } from "lucide-react";

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

export default function RegisterPage() {
    const [fullName, setFullName] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [isPasswordFocused, setIsPasswordFocused] = useState(false);
    const [hasAttemptedSubmit, setHasAttemptedSubmit] = useState(false);
    
    const [isLoading, setIsLoading] = useState(false);
    const [oauthLoading, setOauthLoading] = useState<"google" | "github" | null>(null);
    const { register, loginWithOAuth } = useAuth();
    const router = useRouter();

    // Password validation rules
    const reqLength = password.length >= 12;
    const reqUpper = /[A-Z]/.test(password);
    const reqLower = /[a-z]/.test(password);
    const reqNum = /[0-9]/.test(password);
    const reqSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    const passwordValid = reqLength && reqUpper && reqLower && reqNum && reqSpecial;
    
    const showChecklist = isPasswordFocused || password.length > 0 || (hasAttemptedSubmit && !passwordValid);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setHasAttemptedSubmit(true);

        if (!passwordValid) {
            toast.error("Registration Error", { description: "Please meet all password requirements" });
            return;
        }

        if (password !== confirmPassword) {
            toast.error("Registration Error", { description: "Passwords do not match" });
            return;
        }

        setIsLoading(true);

        try {
            await register({ email, password, full_name: fullName });
            router.push("/dashboard");
        } catch (err) {
            toast.error("Registration Failed", { description: err instanceof Error ? err.message : "An error occurred during registration" });
        } finally {
            setIsLoading(false);
        }
    };

    const handleOAuth = async (provider: "google" | "github") => {
        setOauthLoading(provider);
        try {
            await loginWithOAuth(provider);
            // Supabase will redirect the page
        } catch (err) {
            toast.error("Sign-in Failed", { description: err instanceof Error ? err.message : `${provider} sign-in failed` });
            setOauthLoading(null);
        }
    };

    const confirmValid = confirmPassword.length > 0 && confirmPassword === password;
    const showConfirmError = (hasAttemptedSubmit || confirmPassword.length > 0) && !confirmValid;

    return (
        <div className="min-h-screen flex items-center justify-center bg-[var(--bg-main)] px-4 py-12 relative overflow-hidden">
            {/* Background decoration */}
            <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-[-20%] right-[-10%] w-[600px] h-[600px] rounded-full bg-[var(--primary)]/[0.04] blur-3xl" />
                <div className="absolute bottom-[-20%] left-[-10%] w-[500px] h-[500px] rounded-full bg-[var(--primary-hover)]/[0.04] blur-3xl" />
            </div>

            <div className="w-full max-w-md relative animate-[fadeIn_0.5s_ease-out]">
                {/* Logo & Heading */}
                <div className="text-center mb-8">
                    <div className="inline-flex h-14 w-14 rounded-2xl bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] items-center justify-center mb-5 shadow-lg shadow-[var(--primary)]/20">
                        <span className="text-white font-black text-2xl tracking-tighter">T</span>
                    </div>
                    <h1 className="text-3xl font-black text-[var(--text-primary)] tracking-tight mb-2">Create an account</h1>
                    <p className="text-[var(--text-muted)] text-sm font-medium">Get started with TIBSA today</p>
                </div>

                <div className="bg-[var(--bg-card)] rounded-2xl border border-[var(--border-soft)] shadow-2xl shadow-[var(--primary)]/5 overflow-hidden">
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
                        <span className="text-[11px] text-[var(--text-muted)] font-bold tracking-widest uppercase">OR REGISTER WITH EMAIL</span>
                        <div className="h-px flex-1 bg-[var(--border-soft)]" />
                    </div>

                    {/* Email Registration Form */}
                    <form onSubmit={handleSubmit} className="p-6 pt-3 space-y-5">
                        <div className="space-y-4">
                            <Input
                                label="Full Name"
                                type="text"
                                placeholder="John Doe"
                                value={fullName}
                                onChange={(e) => setFullName(e.target.value)}
                                required
                                className="bg-white border-[var(--border-soft)] focus:border-[var(--primary)] focus:ring-[var(--primary)]/20"
                            />

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
                                    placeholder="••••••••••••"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    onFocus={() => setIsPasswordFocused(true)}
                                    onBlur={() => setIsPasswordFocused(false)}
                                    required
                                    className={`bg-white focus:ring-[var(--primary)]/20 ${hasAttemptedSubmit && !passwordValid ? "border-[var(--danger)] focus:border-[var(--danger)]" : "border-[var(--border-soft)] focus:border-[var(--primary)]"}`}
                                />
                                <div className="px-1">
                                    <PasswordStrengthMeter password={password} />
                                </div>
                                
                                {/* Animated Password Checklist */}
                                <div className={`overflow-hidden transition-all duration-300 ease-in-out ${showChecklist ? "max-h-48 opacity-100 mt-2" : "max-h-0 opacity-0 m-0"}`}>
                                    {passwordValid ? (
                                        <div className="flex items-center gap-1.5 text-[var(--success)] text-xs font-semibold px-1">
                                            <CheckCircle2 className="w-4 h-4" />
                                            <span>Strong password</span>
                                        </div>
                                    ) : (
                                        <ul className="space-y-1.5 text-xs px-1">
                                            <li className={`flex items-center gap-2 ${reqLength ? "text-[var(--success)]" : "text-[var(--text-muted)]"}`}>
                                                {reqLength ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Circle className="w-3.5 h-3.5 opacity-50" />}
                                                <span>At least 12 characters</span>
                                            </li>
                                            <li className={`flex items-center gap-2 ${reqUpper ? "text-[var(--success)]" : "text-[var(--text-muted)]"}`}>
                                                {reqUpper ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Circle className="w-3.5 h-3.5 opacity-50" />}
                                                <span>Contains uppercase letter</span>
                                            </li>
                                            <li className={`flex items-center gap-2 ${reqLower ? "text-[var(--success)]" : "text-[var(--text-muted)]"}`}>
                                                {reqLower ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Circle className="w-3.5 h-3.5 opacity-50" />}
                                                <span>Contains lowercase letter</span>
                                            </li>
                                            <li className={`flex items-center gap-2 ${reqNum ? "text-[var(--success)]" : "text-[var(--text-muted)]"}`}>
                                                {reqNum ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Circle className="w-3.5 h-3.5 opacity-50" />}
                                                <span>Contains number</span>
                                            </li>
                                            <li className={`flex items-center gap-2 ${reqSpecial ? "text-[var(--success)]" : "text-[var(--text-muted)]"}`}>
                                                {reqSpecial ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Circle className="w-3.5 h-3.5 opacity-50" />}
                                                <span>Contains special character</span>
                                            </li>
                                        </ul>
                                    )}
                                </div>
                            </div>

                            <div className="space-y-1">
                                <Input
                                    label="Confirm Password"
                                    type="password"
                                    placeholder="••••••••••••"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    required
                                    className={`bg-white focus:ring-[var(--primary)]/20 ${showConfirmError ? "border-[var(--danger)] focus:border-[var(--danger)] focus:ring-[var(--danger)]/20" : confirmValid ? "border-[var(--success)] focus:border-[var(--success)] focus:ring-[var(--success)]/20" : "border-[var(--border-soft)] focus:border-[var(--primary)]"}`}
                                />
                                {showConfirmError && (
                                    <div className="flex items-center gap-1.5 text-[var(--danger)] text-xs font-semibold px-1 mt-1.5 animate-in fade-in slide-in-from-top-1">
                                        <AlertCircle className="w-3.5 h-3.5" />
                                        <span>Passwords do not match</span>
                                    </div>
                                )}
                                {confirmValid && confirmPassword.length > 0 && (
                                    <div className="flex items-center gap-1.5 text-[var(--success)] text-xs font-semibold px-1 mt-1.5 animate-in fade-in slide-in-from-top-1">
                                        <CheckCircle2 className="w-3.5 h-3.5" />
                                        <span>Passwords match</span>
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="pt-2">
                            <Button type="submit" className="w-full btn-animated btn-primary-emerald font-bold rounded-xl py-3 shadow-md border-0" isLoading={isLoading}>
                                Create Account
                            </Button>
                        </div>
                    </form>
                    
                    {/* Clean Footer Area */}
                    <div className="bg-[var(--bg-elevated)] border-t border-[var(--border-soft)] p-5 flex flex-col items-center justify-center gap-2">
                        <p className="text-sm text-[var(--text-muted)] font-medium">
                            Already have an account?{" "}
                            <Link href="/login" className="text-[var(--primary)] font-semibold transition-all hover:text-[var(--primary-hover)] inline-flex items-center hover:-translate-y-[1px]">
                                Sign In
                            </Link>
                        </p>
                    </div>
                </div>

                <p className="text-center text-xs text-[var(--text-muted)] mt-6 font-medium">
                    By creating an account, you agree to our{" "}
                    <span className="text-[var(--text-secondary)] hover:text-[var(--primary)] cursor-pointer transition-colors">Terms of Service</span> and{" "}
                    <span className="text-[var(--text-secondary)] hover:text-[var(--primary)] cursor-pointer transition-colors">Privacy Policy</span>
                </p>
            </div>
        </div>
    );
}
