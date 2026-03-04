"use client";

import { DashboardHeader } from "@/components/layout/DashboardHeader";
import { Sidebar } from "@/components/layout/Sidebar";
import { Footer } from "@/components/layout/Footer";
import { RoleGuard } from "@/components/shared/RoleGuard";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
    return (
        <RoleGuard allowedRoles={["user", "admin"]}>
            <div className="min-h-screen flex flex-col">
                <DashboardHeader />
                <div className="flex flex-1">
                    <Sidebar />
                    <main className="flex-1 p-6 bg-[#0f172a]">{children}</main>
                </div>
                <Footer />
            </div>
        </RoleGuard>
    );
}
