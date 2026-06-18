"use client";

import { useState, useEffect } from "react";
import { Button, Input } from "@/components/ui";
import { QRCodeSVG } from "qrcode.react";
import { CheckCircle2, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";

export function MFAEnrollment() {
    const [factorId, setFactorId] = useState<string | null>(null);
    const [qrCode, setQrCode] = useState<string | null>(null);
    const [totpSecret, setTotpSecret] = useState<string | null>(null);
    const [verifyCode, setVerifyCode] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [isEnrolled, setIsEnrolled] = useState(false);
    const [isChecking, setIsChecking] = useState(true);

    const { token } = useAuth();

    // Check if user is already enrolled
    useEffect(() => {
        const checkMfaStatus = async () => {
            if (!token) return;
            try {
                const data = await api.get<{ is_enrolled: boolean }>("/api/v1/auth/mfa/status", token);
                if (data && data.is_enrolled) {
                    setIsEnrolled(true);
                }
            } catch (error) {
                console.error("Failed to fetch MFA status", error);
            } finally {
                setIsChecking(false);
            }
        };
        checkMfaStatus();
    }, [token]);

    const handleEnroll = async () => {
        setIsLoading(true);
        try {
            if (!token) throw new Error("Not authenticated");

            // 1. Unenroll any unverified TOTP factors to avoid garbage
            try {
                await api.delete("/api/v1/auth/mfa/unenroll-unverified", token);
            } catch (e) {
                console.warn("Could not clean up unverified factors", e);
            }

            // 2. Enroll via backend
            const payload = { refresh_token: localStorage.getItem("tibsa_refresh_token") || "dummy" };
            const data = await api.post<any>("/api/v1/auth/mfa/enroll", payload, token);

            if (!data.factor_id || !data.totp_uri) {
                throw new Error("Invalid response from server");
            }

            setFactorId(data.factor_id);
            setQrCode(data.totp_uri); // The URI used for QRCodeSVG
            setTotpSecret(data.secret || (data.totp_uri ? new URL(data.totp_uri).searchParams.get("secret") : null));
        } catch (err: any) {
            toast.error("Enrollment Failed", { description: err.message || "Failed to initiate MFA enrollment" });
        } finally {
            setIsLoading(false);
        }
    };

    const handleVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!factorId || !token) return;

        setIsLoading(true);

        try {
            const payloadBase = { refresh_token: localStorage.getItem("tibsa_refresh_token") || "dummy" };

            // First challenge the factor
            const challengeData = await api.post<{ challenge_id: string }>("/api/v1/auth/mfa/challenge", {
                factor_id: factorId,
                ...payloadBase
            }, token);

            if (!challengeData.challenge_id) throw new Error("Failed to create challenge");

            // Then verify
            await api.post("/api/v1/auth/mfa/verify-enrollment", {
                factor_id: factorId,
                challenge_id: challengeData.challenge_id,
                code: verifyCode,
                ...payloadBase
            }, token);

            setIsEnrolled(true);
            setFactorId(null);
            setQrCode(null);
            setVerifyCode("");
            toast.success("Authenticator App Linked", { description: "Two-Factor Authentication is now active." });
        } catch (err: any) {
            toast.error("Verification Failed", { description: err.message || "Failed to verify code" });
        } finally {
            setIsLoading(false);
        }
    };

    if (isChecking) {
        return (
            <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] p-6 flex items-center justify-center min-h-[160px]">
                <svg className="animate-spin h-6 w-6 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
            </div>
        );
    }

    if (isEnrolled) {
        return (
            <div className="bg-[var(--bg-card)] rounded-xl border border-emerald-500/30 p-6 flex items-start gap-4 shadow-lg shadow-black/5">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 flex-shrink-0 mt-0.5" />
                <div>
                    <h3 className="text-lg font-medium text-[var(--text-primary)] mb-1">Two-Factor Authentication is Active</h3>
                    <p className="text-sm text-[var(--text-muted)]">
                        Your account is secured with MFA. You will be prompted for a code from your authenticator app when logging in.
                    </p>
                </div>
            </div>
        );
    }

    if (!factorId || !qrCode) {
        return (
            <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] p-6 shadow-lg shadow-black/5">
                <div className="flex items-start gap-4 mb-6">
                    <div className="bg-[var(--primary)]/10 p-2.5 rounded-xl border border-[var(--primary)] flex-shrink-0">
                        <ShieldAlert className="w-6 h-6 text-[var(--primary)]" />
                    </div>
                    <div>
                        <h3 className="text-lg font-medium text-[var(--text-primary)] mb-1">Enable Two-Factor Authentication</h3>
                        <p className="text-sm text-[var(--text-muted)]">
                            Add an extra layer of security to your account by requiring a code from your authenticator app (like Google Authenticator or Authy) to sign in.
                        </p>
                    </div>
                </div>
                <Button onClick={handleEnroll} isLoading={isLoading}>
                    Set up Authenticator App
                </Button>
            </div>
        );
    }

    return (
        <div className="bg-[var(--bg-card)] rounded-xl border border-[var(--border-soft)] p-6 shadow-lg shadow-black/5 max-w-md">
            <h3 className="text-lg font-medium text-[var(--text-primary)] mb-2">Scan the QR Code</h3>
            <p className="text-sm text-[var(--text-muted)] mb-6">
                Open your authenticator app and scan this QR code. If you can&apos;t scan it, you can manually enter the secret key below.
            </p>

            <div className="flex justify-center mb-6 p-4 bg-white rounded-xl mx-auto w-fit">
                <QRCodeSVG value={qrCode} size={200} />
            </div>

            {totpSecret && (
                <div className="mb-6">
                    <p className="text-xs text-[var(--text-muted)] mb-1">Manual Entry Secret</p>
                    <code className="block p-2 rounded-lg bg-black/20 border border-[var(--border-soft)] text-[var(--text-secondary)] text-center tracking-widest text-sm font-mono break-all">
                        {totpSecret}
                    </code>
                </div>
            )}

            <form onSubmit={handleVerify} className="space-y-4">
                
                <Input
                    label="Verification Code"
                    type="text"
                    placeholder="Enter 6-digit code"
                    value={verifyCode}
                    onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    required
                    maxLength={6}
                    pattern="\d{6}"
                />

                <div className="flex gap-3">
                    <Button type="button" variant="secondary" onClick={() => setFactorId(null)} className="w-full">
                        Cancel
                    </Button>
                    <Button type="submit" className="w-full" isLoading={isLoading}>
                        Verify Code
                    </Button>
                </div>
            </form>
        </div>
    );
}
