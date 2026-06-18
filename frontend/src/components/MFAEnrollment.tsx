"use client";

import { useState, useEffect } from "react";
import { supabase } from "@/lib/supabase";
import { Button, Input } from "@/components/ui";
import { QRCodeSVG } from "qrcode.react";
import { CheckCircle2, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

export function MFAEnrollment() {
    const [factorId, setFactorId] = useState<string | null>(null);
    const [qrCode, setQrCode] = useState<string | null>(null);
    const [totpSecret, setTotpSecret] = useState<string | null>(null);
    const [verifyCode, setVerifyCode] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [isEnrolled, setIsEnrolled] = useState(false);
    const [isChecking, setIsChecking] = useState(true);

    // Check if user is already enrolled
    useEffect(() => {
        const checkMfaStatus = async () => {
            try {
                const { data, error } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
                if (error) {
                    console.error("Failed to fetch MFA status", error);
                    return;
                }
                
                // Fetch user factors to see if any TOTP factor is verified
                const { data: factorsData, error: factorsError } = await supabase.auth.mfa.listFactors();
                if (factorsError) {
                    console.error("Failed to list factors", factorsError);
                    return;
                }
                
                const hasVerifiedTotp = factorsData?.totp?.some(factor => factor.status === 'verified');
                
                if (data?.currentLevel === "aal2" || data?.nextLevel === "aal2" || hasVerifiedTotp) {
                    setIsEnrolled(true);
                }
            } finally {
                setIsChecking(false);
            }
        };
        checkMfaStatus();
    }, []);

    const handleEnroll = async () => {
        setIsLoading(true);
        try {
            // 1. Fetch existing factors
            const { data: factorsData, error: factorsError } = await supabase.auth.mfa.listFactors();
            if (factorsError) throw factorsError;

            // 2. Unenroll any unverified TOTP factors
            if (factorsData?.totp) {
                const unverifiedFactors = factorsData.totp.filter(factor => factor.status === "unverified");
                for (const factor of unverifiedFactors) {
                    const { error: unenrollError } = await supabase.auth.mfa.unenroll({ factorId: factor.id });
                    if (unenrollError) {
                        console.error("Failed to unenroll previous factor:", unenrollError);
                    }
                }
            }

            // 3. Enroll with a unique friendly name
            const { data, error } = await supabase.auth.mfa.enroll({
                factorType: "totp",
                friendlyName: `TIBSA-Authenticator-${Date.now()}`,
            });

            if (error) throw error;

            setFactorId(data.id);
            setQrCode(data.totp.uri);
            setTotpSecret(data.totp.secret);
        } catch (err: any) {
            toast.error("Enrollment Failed", { description: err.message || "Failed to initiate MFA enrollment" });
        } finally {
            setIsLoading(false);
        }
    };

    const handleVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!factorId) return;

        setIsLoading(true);

        try {
            // First challenge the factor
            const { data: challengeData, error: challengeError } = await supabase.auth.mfa.challenge({
                factorId,
            });

            if (challengeError) throw challengeError;

            // Then verify
            const { error: verifyError } = await supabase.auth.mfa.verify({
                factorId,
                challengeId: challengeData.id,
                code: verifyCode,
            });

            if (verifyError) throw verifyError;

            setIsEnrolled(true);
            setFactorId(null);
            setQrCode(null);
            setVerifyCode("");
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
