"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { Button, Input } from "@/components/ui";
import { PasswordStrengthMeter } from "@/components/ui/PasswordStrengthMeter";
import { toast } from "sonner";

export default function UpdatePasswordPage() {
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const router = useRouter();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (password !== confirmPassword) {
            toast.error("Error", { description: "Passwords do not match." });
            return;
        }

        setIsLoading(true);

        try {
            const { error } = await supabase.auth.updateUser({
                password: password,
            });

            if (error) throw error;

            toast.success("Success", { description: "Password updated successfully! Redirecting..." });
            
            setTimeout(() => {
                router.push("/dashboard");
            }, 2000);
        } catch (err: any) {
            toast.error("Failed", { description: err.message || "Failed to update password." });
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
                    <h1 className="text-2xl font-bold text-[var(--text-primary)] tracking-tight">Set New Password</h1>
                    <p className="text-[var(--text-muted)] mt-1.5 text-sm">Enter your new password below</p>
                </div>

                <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] shadow-2xl shadow-black/5 overflow-hidden">
                    <form onSubmit={handleSubmit} className="p-6 space-y-4">

                        <div className="space-y-1">
                            <Input
                                label="New Password"
                                type="password"
                                placeholder="••••••••••••"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                                minLength={12}
                            />
                            <PasswordStrengthMeter password={password} />
                            <p className="text-[10px] text-[var(--text-muted)] pl-0.5">
                                Must be at least 12 characters, including uppercase, lowercase, number, and special character.
                            </p>
                        </div>

                        <Input
                            label="Confirm New Password"
                            type="password"
                            placeholder="••••••••••••"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                            minLength={12}
                        />

                        <Button type="submit" className="w-full" isLoading={isLoading}>
                            Update Password
                        </Button>
                    </form>
                </div>
            </div>
        </div>
    );
}
