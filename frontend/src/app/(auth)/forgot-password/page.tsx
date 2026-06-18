"use client";

import { useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabase";
import { Button, Input } from "@/components/ui";
import { toast } from "sonner";

export default function ForgotPasswordPage() {
    const [email, setEmail] = useState("");
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);

        try {
            const { error } = await supabase.auth.resetPasswordForEmail(email, {
                redirectTo: `${window.location.origin}/update-password`,
            });

            if (error) throw error;

            toast.success("Link Sent", { description: "Password reset link sent to your email." });
        } catch (err: any) {
            toast.error("Failed", { description: err.message || "Failed to send reset link." });
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-[var(--bg-main)] px-4 relative overflow-hidden">
            <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-[-20%] left-[-10%] w-[600px] h-[600px] rounded-full bg-[var(--primary-hover)]/[0.04] blur-3xl" />
                <div className="absolute bottom-[-20%] right-[-10%] w-[500px] h-[500px] rounded-full bg-indigo-600/[0.04] blur-3xl" />
            </div>

            <div className="w-full max-w-md relative">
                <div className="text-center mb-8">
                    <div className="inline-flex h-14 w-14 rounded-2xl bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] items-center justify-center mb-5 shadow-lg shadow-[var(--primary-soft)]">
                        <span className="text-[var(--text-primary)] font-bold text-xl">T</span>
                    </div>
                    <h1 className="text-2xl font-bold text-[var(--text-primary)] tracking-tight">Reset Password</h1>
                    <p className="text-[var(--text-muted)] mt-1.5 text-sm">Enter your email to receive a reset link</p>
                </div>

                <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] shadow-2xl shadow-black/5 overflow-hidden">
                    <form onSubmit={handleSubmit} className="p-6 space-y-4">

                        <Input
                            label="Email"
                            type="email"
                            placeholder="you@example.com"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />

                        <Button type="submit" className="w-full" isLoading={isLoading}>
                            Send Reset Link
                        </Button>

                        <div className="text-center pt-2">
                            <Link href="/login" className="text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors">
                                Back to login
                            </Link>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    );
}
