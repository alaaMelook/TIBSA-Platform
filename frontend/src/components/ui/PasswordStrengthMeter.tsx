"use client";

import React, { useMemo } from "react";

interface PasswordStrengthMeterProps {
    password: string;
}

export function PasswordStrengthMeter({ password }: PasswordStrengthMeterProps) {
    const strength = useMemo(() => {
        let score = 0;
        if (!password) return score;

        if (password.length > 8) score += 1;
        if (password.length >= 12) score += 1;
        if (/[A-Z]/.test(password)) score += 1;
        if (/[a-z]/.test(password)) score += 1;
        if (/[0-9]/.test(password)) score += 1;
        if (/[^A-Za-z0-9]/.test(password)) score += 1;

        // Normalize score to max 4 for the UI
        return Math.min(score, 4);
    }, [password]);

    const getColor = () => {
        switch (strength) {
            case 0:
            case 1:
                return "bg-red-500";
            case 2:
                return "bg-orange-500";
            case 3:
                return "bg-yellow-500";
            case 4:
                return "bg-green-500";
            default:
                return "bg-[var(--bg-elevated)]";
        }
    };

    const getLabel = () => {
        switch (strength) {
            case 0:
                return "Too Weak";
            case 1:
                return "Weak";
            case 2:
                return "Fair";
            case 3:
                return "Good";
            case 4:
                return "Strong";
            default:
                return "";
        }
    };

    if (!password) return null;

    return (
        <div className="mt-2 space-y-1">
            <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-[var(--bg-elevated)]/50">
                <div
                    className={`h-full transition-all duration-300 ease-in-out ${getColor()}`}
                    style={{ width: `${(strength / 4) * 100}%` }}
                />
            </div>
            <p className={`text-[10px] font-medium text-right ${getColor().replace("bg-", "text-")}`}>
                {getLabel()}
            </p>
        </div>
    );
}
