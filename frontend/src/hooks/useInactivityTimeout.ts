"use client";

import { useEffect, useRef } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useRouter } from "next/navigation";

const INACTIVITY_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

export function useInactivityTimeout() {
    const { logout, isAuthenticated } = useAuth();
    const router = useRouter();
    const timerRef = useRef<NodeJS.Timeout | null>(null);

    useEffect(() => {
        if (!isAuthenticated) return;

        const handleInactivity = async () => {
            await logout();
            router.push("/login?reason=timeout");
        };

        const resetTimer = () => {
            if (timerRef.current) clearTimeout(timerRef.current);
            timerRef.current = setTimeout(handleInactivity, INACTIVITY_TIMEOUT_MS);
        };

        // Events that indicate user activity
        const events = ["mousedown", "mousemove", "keydown", "scroll", "touchstart"];

        // Attach listeners
        events.forEach((event) => window.addEventListener(event, resetTimer));

        // Start timer initially
        resetTimer();

        return () => {
            if (timerRef.current) clearTimeout(timerRef.current);
            events.forEach((event) => window.removeEventListener(event, resetTimer));
        };
    }, [isAuthenticated, logout, router]);
}
