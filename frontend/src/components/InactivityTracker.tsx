"use client";

import { useInactivityTimeout } from "@/hooks/useInactivityTimeout";

export function InactivityTracker({ children }: { children: React.ReactNode }) {
    useInactivityTimeout();
    return <>{children}</>;
}
