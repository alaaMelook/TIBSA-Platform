"use client";

import { useAuth } from "@/hooks/useAuth";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import type { UserRole } from "@/types";
import { LoadingSpinner } from "./LoadingSpinner";

interface RoleGuardProps {
    children: React.ReactNode;
    allowedRoles: UserRole[];
    fallbackUrl?: string;
}

/**
 * Protects pages based on user role.
 * Redirects to fallbackUrl if user doesn't have the required role.
 */
export function RoleGuard({ children, allowedRoles, fallbackUrl = "/dashboard" }: RoleGuardProps) {
    const { user, isLoading, isAuthenticated } = useAuth();
    const router = useRouter();

    useEffect(() => {
        if (!isLoading) {
            if (!isAuthenticated) {
                router.push("/login");
            } else if (user && !allowedRoles.includes(user.role)) {
                router.push(fallbackUrl);
            }
        }
    }, [user, isLoading, isAuthenticated, allowedRoles, fallbackUrl, router]);

    if (isLoading) {
        return (
            <div className="flex items-center justify-center min-h-screen">
                <LoadingSpinner size="lg" />
            </div>
        );
    }

    if (!isAuthenticated || !user || !allowedRoles.includes(user.role)) {
        return null;
    }

    return <>{children}</>;
}
