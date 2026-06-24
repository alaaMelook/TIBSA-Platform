"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import Link from "next/link";
import { api } from "@/lib/api";

interface DashboardStats {
    total_scans: number;
    active_scans: number;
    threats_detected: number;
    completed_scans: number;
    recent_scans: any[];
}

export default function DashboardPage() {
    const { user, token } = useAuth();
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    // First letter for profile fallback if user has no avatar
    const userDisplayName = user?.full_name || "kr";

    const fetchStats = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<DashboardStats>("/api/v1/users/dashboard/stats", token);
            setStats(data);
        } catch (error: any) {
            const errorMsg = error?.message || "";
            // Check if account is deactivated
            if (errorMsg.includes("deactivated") || errorMsg.includes("inactive")) {
                // Clear auth and redirect to suspended-account page
                window.location.href = "/suspended-account";
                return;
            }
            console.error("Failed to fetch stats:", error);
        } finally {
            setIsLoading(false);
        }
    }, [token]);

    useEffect(() => {
        fetchStats();
    }, [fetchStats]);

    const threatColor = (level: string | null) => {
        const colors: Record<string, string> = {
            safe: "text-green-400",
            low: "text-yellow-400",
            medium: "text-orange-400",
            high: "text-red-400",
            critical: "text-red-500",
        };
        return colors[level || "safe"] || "text-[var(--text-muted)]";
    };

    const statusBadge = (status: string) => {
        const styles: Record<string, string> = {
            pending: "bg-yellow-500/15 text-yellow-400",
            running: "bg-[var(--primary)]/15 text-[var(--primary)]",
            completed: "bg-green-500/15 text-green-400",
            failed: "bg-red-500/15 text-red-400",
        };
        return styles[status] || "bg-[var(--bg-elevated)] text-[var(--text-muted)]";
    };

    return (
        <div 
            className="min-h-screen flex flex-col justify-between py-16 px-4 md:px-8 relative overflow-hidden"
            style={{
                background: `
                    radial-gradient(circle at 50% 0%, rgba(15, 157, 118, 0.16), transparent 32%),
                    radial-gradient(circle at 15% 35%, rgba(15, 157, 118, 0.08), transparent 28%),
                    radial-gradient(circle at 85% 40%, rgba(11, 125, 93, 0.08), transparent 30%),
                    linear-gradient(180deg, #f8f3eb 0%, #f6f0e7 100%)
                `
            }}
        >
            {/* Very subtle grid texture with soft emerald tint */}
            <div 
                className="absolute inset-0 z-0 pointer-events-none opacity-[0.02] mix-blend-multiply transition-opacity duration-1000 motion-reduce:transition-none"
                style={{
                    backgroundImage: `linear-gradient(rgba(15, 157, 118, 0.8) 1px, transparent 1px), linear-gradient(90deg, rgba(15, 157, 118, 0.8) 1px, transparent 1px)`,
                    backgroundSize: '32px 32px'
                }}
            />

            <div className="max-w-7xl mx-auto w-full space-y-20 relative z-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
                
                {/* ── Welcome Banner ─────────────────────────────────── */}
                <div className="flex flex-col items-center text-center space-y-6 pt-4">
                    <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#ffffff] border border-[#e7ddd1] text-[#4f4a45] text-xs font-semibold shadow-sm">
                        <span>Welcome back, {userDisplayName}</span>
                        <span className="text-amber-500">👋</span>
                    </div>
                    
                    <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight max-w-3xl leading-tight text-[#1d1d1d]">
                        TIBSA Unified <span className="text-[#0f9d76]">Cyber Security</span> & Intelligent Defense Platform
                    </h1>
                    
                    <p className="text-[#4f4a45] max-w-3xl text-sm md:text-base font-medium leading-relaxed">
                        TIBSA integrates automated penetration testing, multi-stage threat correlation, machine learning-driven malware sandboxing, and real-time threat intelligence enrichment to map complex attack vectors, assess security posture, and generate automated response roadmaps.
                    </p>
                </div>

                {/* ── Section: Investigation Flows ───────────────────── */}
                <div>
                    <div className="flex items-center justify-center gap-4 mb-8">
                        <div className="h-px w-20 bg-gradient-to-r from-transparent to-[#0f9d76]/40" />
                        <span className="text-xs font-bold text-[#0f9d76] tracking-widest uppercase">• INVESTIGATION FLOWS •</span>
                        <div className="h-px w-20 bg-gradient-to-l from-transparent to-[#0f9d76]/40" />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        
                        {/* Card 01: Investigation & Correlation */}
                        <div className="relative group bg-[#ffffff] border border-[#e7ddd1] rounded-[20px] p-6 transition-all duration-300 hover:border-[#0f9d76] shadow-[0_4px_12px_rgba(0,0,0,0.02)] hover:shadow-[0_12px_32px_rgba(15,157,118,0.12)] hover:-translate-y-1 active:scale-[0.99] flex flex-col justify-between min-h-[380px]">
                            {/* Card badge */}
                            <div className="absolute top-4 left-4 border border-[#0f9d76]/30 bg-[#edf8f3] rounded-lg px-2.5 py-0.5 text-xs font-bold text-[#0f9d76] tracking-wider">
                                01
                            </div>

                            <div className="mt-8 text-center space-y-6 flex-1 flex flex-col justify-center">
                                {/* SVG Icon */}
                                <div className="h-20 flex items-center justify-center text-[#0f9d76] group-hover:scale-105 transition-transform duration-300">
                                    <svg className="w-16 h-16 drop-shadow-[0_0_10px_rgba(15,157,118,0.3)]" viewBox="0 0 100 100" fill="none">
                                        <circle cx="50" cy="50" r="40" stroke="currentColor" strokeWidth="0.5" strokeDasharray="3 3" opacity="0.3" />
                                        <circle cx="50" cy="50" r="30" stroke="currentColor" strokeWidth="0.8" opacity="0.5" />
                                        <circle cx="50" cy="50" r="20" stroke="currentColor" strokeWidth="1" opacity="0.7" />
                                        <circle cx="50" cy="50" r="10" stroke="currentColor" strokeWidth="1.2" opacity="0.9" />
                                        <line x1="50" y1="10" x2="50" y2="90" stroke="currentColor" strokeWidth="0.5" opacity="0.3" />
                                        <line x1="10" y1="50" x2="90" y2="50" stroke="currentColor" strokeWidth="0.5" opacity="0.3" />
                                        <path d="M50 50 L50 20 A30 30 0 0 1 76 35 Z" fill="url(#emerald-sweep)" opacity="0.4" />
                                        <circle cx="70" cy="38" r="2.5" fill="#34d399" className="animate-pulse" />
                                        <circle cx="35" cy="65" r="1.5" fill="#34d399" opacity="0.7" />
                                        <defs>
                                            <radialGradient id="emerald-sweep" cx="50%" cy="50%" r="50%">
                                                <stop offset="0%" stopColor="#0f9d76" stopOpacity="1" />
                                                <stop offset="100%" stopColor="#0b7d5d" stopOpacity="0" />
                                            </radialGradient>
                                        </defs>
                                    </svg>
                                </div>
                                <div className="space-y-1">
                                    <h3 className="text-xl font-bold text-[#1d1d1d] tracking-wide">Investigation & Correlation</h3>
                                    <p className="text-xs font-semibold text-[#0f9d76] tracking-wider uppercase">(Penetration Testing & Security Assessment)</p>
                                </div>
                                <p className="text-[#8a8178] text-sm leading-relaxed px-4">
                                    Run security assessments and correlate findings with threat intelligence to uncover risks, attack paths, and business impact.
                                </p>
                            </div>

                            <div className="mt-6">
                                <Link href="/dashboard/investigations" className="w-full flex items-center justify-center gap-2 py-3 btn-animated btn-primary-emerald font-semibold rounded-xl text-sm transition-all">
                                    <span>Start Investigation</span>
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                    </svg>
                                </Link>
                            </div>
                        </div>

                        {/* Card 02: Threat Intelligence Layer */}
                        <div className="relative group bg-[#ffffff] border border-[#e7ddd1] rounded-[20px] p-6 transition-all duration-300 hover:border-[#0f9d76] shadow-[0_4px_12px_rgba(0,0,0,0.02)] hover:shadow-[0_12px_32px_rgba(15,157,118,0.12)] hover:-translate-y-1 active:scale-[0.99] flex flex-col justify-between min-h-[380px]">
                            {/* Card badge */}
                            <div className="absolute top-4 left-4 border border-[#0f9d76]/30 bg-[#edf8f3] rounded-lg px-2.5 py-0.5 text-xs font-bold text-[#0f9d76] tracking-wider">
                                02
                            </div>

                            <div className="mt-8 text-center space-y-6 flex-1 flex flex-col justify-center">
                                {/* SVG Icon */}
                                <div className="h-20 flex items-center justify-center text-[#0f9d76] group-hover:scale-105 transition-transform duration-300">
                                    <svg className="w-16 h-16 drop-shadow-[0_0_10px_rgba(15,157,118,0.3)]" viewBox="0 0 100 100" fill="none">
                                        <circle cx="50" cy="50" r="35" stroke="currentColor" strokeWidth="1.5" />
                                        <ellipse cx="50" cy="50" rx="35" ry="12" stroke="currentColor" strokeWidth="1.0" opacity="0.8" />
                                        <ellipse cx="50" cy="50" rx="12" ry="35" stroke="currentColor" strokeWidth="1.0" opacity="0.8" />
                                        <line x1="15" y1="50" x2="85" y2="50" stroke="currentColor" strokeWidth="1.0" opacity="0.8" />
                                        <line x1="50" y1="15" x2="50" y2="85" stroke="currentColor" strokeWidth="1.0" opacity="0.8" />
                                        <circle cx="28" cy="32" r="2.5" fill="#0f9d76" />
                                        <circle cx="72" cy="32" r="2.5" fill="#0f9d76" />
                                        <circle cx="50" cy="50" r="3" fill="#0f9d76" className="animate-ping" />
                                        <circle cx="50" cy="50" r="2" fill="#0f9d76" />
                                        <circle cx="35" cy="68" r="2.5" fill="#0f9d76" />
                                        <circle cx="65" cy="68" r="2.5" fill="#0f9d76" />
                                        <path d="M28 32 L50 50 L72 32 M35 68 L50 50 L65 68" stroke="#0f9d76" strokeWidth="0.5" opacity="0.4" />
                                    </svg>
                                </div>
                                <h3 className="text-xl font-bold text-[#1d1d1d] tracking-wide">Threat Intelligence Layer</h3>
                                <p className="text-[#8a8178] text-sm leading-relaxed px-4">
                                    Explore global threat intelligence, indicators of compromise, campaigns, and adversary activity in real time.
                                </p>
                            </div>

                            <div className="mt-6">
                                <Link href="/dashboard/infra-investigations" className="w-full flex items-center justify-center gap-2 py-3 btn-animated btn-primary-emerald font-semibold rounded-xl text-sm transition-all">
                                    <span>Start Investigation</span>
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                    </svg>
                                </Link>
                            </div>
                        </div>

                        {/* Card 03: Malware & Threat Analysis Layer */}
                        <div className="relative group bg-[#ffffff] border border-[#e7ddd1] rounded-[20px] p-6 transition-all duration-300 hover:border-[#0f9d76] shadow-[0_4px_12px_rgba(0,0,0,0.02)] hover:shadow-[0_12px_32px_rgba(15,157,118,0.12)] hover:-translate-y-1 active:scale-[0.99] flex flex-col justify-between min-h-[380px]">
                            {/* Card badge */}
                            <div className="absolute top-4 left-4 border border-[#0f9d76]/30 bg-[#edf8f3] rounded-lg px-2.5 py-0.5 text-xs font-bold text-[#0f9d76] tracking-wider">
                                03
                            </div>
                            
                            <div className="mt-8 text-center space-y-6 flex-1 flex flex-col justify-center">
                                {/* SVG Icon */}
                                <div className="h-20 flex items-center justify-center text-[#0f9d76] group-hover:scale-105 transition-transform duration-300">
                                    <svg className="w-16 h-16 drop-shadow-[0_0_10px_rgba(15,157,118,0.3)]" viewBox="0 0 100 100" fill="none">
                                        <rect x="42" y="32" width="16" height="24" rx="8" stroke="currentColor" strokeWidth="1.8" opacity="0.7" />
                                        <circle cx="46" cy="40" r="1.5" fill="currentColor" />
                                        <circle cx="54" cy="40" r="1.5" fill="currentColor" />
                                        <path d="M36 38 Q40 40 42 40" stroke="currentColor" strokeWidth="1.8" />
                                        <path d="M34 44 Q40 44 42 44" stroke="currentColor" strokeWidth="1.8" />
                                        <path d="M36 50 Q40 48 42 48" stroke="currentColor" strokeWidth="1.8" />
                                        <path d="M64 38 Q60 40 58 40" stroke="currentColor" strokeWidth="1.8" />
                                        <path d="M66 44 Q60 44 58 44" stroke="currentColor" strokeWidth="1.8" />
                                        <path d="M64 50 Q60 48 58 48" stroke="currentColor" strokeWidth="1.8" />
                                        <path d="M46 32 Q44 26 40 26" stroke="currentColor" strokeWidth="1.8" />
                                        <path d="M54 32 Q56 26 60 26" stroke="currentColor" strokeWidth="1.8" />
                                        
                                        <circle cx="62" cy="60" r="14" stroke="#0f9d76" strokeWidth="2.5" fill="#0f9d76" fillOpacity="0.1" />
                                        <line x1="72" y1="70" x2="86" y2="86" stroke="#0f9d76" strokeWidth="3" strokeLinecap="round" />
                                        <path d="M53 53 A8 8 0 0 1 69 53" stroke="#0f9d76" strokeWidth="1" opacity="0.5" strokeLinecap="round" />
                                    </svg>
                                </div>
                                <h3 className="text-xl font-bold text-[#1d1d1d] tracking-wide">Malware & Threat Analysis Layer</h3>
                                <p className="text-[#8a8178] text-sm leading-relaxed px-4">
                                    Upload files, analyze malware behavior, and extract advanced indicators with sandboxing and static & dynamic analysis.
                                </p>
                            </div>

                            <div className="mt-6">
                                <Link href="/dashboard/ai-malware-analysis" className="w-full flex items-center justify-center gap-2 py-3 btn-animated btn-primary-emerald font-semibold rounded-xl text-sm transition-all">
                                    <span>Start Investigation</span>
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                    </svg>
                                </Link>
                            </div>
                        </div>

                    </div>
                </div>

                {/* ── Section: Standalone Services ─────────────────── */}
                <div>
                    <div className="flex items-center justify-center gap-4 mb-2">
                        <div className="h-px w-20 bg-gradient-to-r from-transparent to-[#0f9d76]/40" />
                        <span className="text-xs font-bold text-[#0f9d76] tracking-widest uppercase">• STANDALONE SERVICES •</span>
                        <div className="h-px w-20 bg-gradient-to-l from-transparent to-[#0f9d76]/40" />
                    </div>
                    <p className="text-[#8a8178] text-center text-xs mb-8">Access individual security tools and capabilities.</p>

                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                        
                        {/* Service 1: Scans */}
                        <Link href="/dashboard/scans" className="group bg-[#ffffff] border border-[#e7ddd1] rounded-xl p-4 text-center hover:bg-[#fffaf4] hover:border-[#0f9d76] transition-all duration-300 flex flex-col justify-between items-center min-h-[140px] hover:-translate-y-1 hover:shadow-[0_8px_20px_rgba(15,157,118,0.08)] active:scale-[0.98]">
                            <div className="p-2.5 rounded-lg bg-[#edf8f3] text-[#0f9d76] group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-[#1d1d1d]">Scans</h4>
                                <p className="text-[11px] text-[#8a8178] leading-tight">View and manage your scans</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-[#8a8178] group-hover:text-[#0f9d76] group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>

                        {/* Service 2: Pen Test */}
                        <Link href="/dashboard/website-scanner" className="group bg-[#ffffff] border border-[#e7ddd1] rounded-xl p-4 text-center hover:bg-[#fffaf4] hover:border-[#0f9d76] transition-all duration-300 flex flex-col justify-between items-center min-h-[140px] hover:-translate-y-1 hover:shadow-[0_8px_20px_rgba(15,157,118,0.08)] active:scale-[0.98]">
                            <div className="p-2.5 rounded-lg bg-[#edf8f3] text-[#0f9d76] group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-[#1d1d1d]">Penetration Testing</h4>
                                <p className="text-[11px] text-[#8a8178] leading-tight">Manual penetration testing</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-[#8a8178] group-hover:text-[#0f9d76] group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>


                        {/* Service 4: Threat Modeling */}
                        <Link href="/dashboard/threat-modeling" className="group bg-[#ffffff] border border-[#e7ddd1] rounded-xl p-4 text-center hover:bg-[#fffaf4] hover:border-[#0f9d76] transition-all duration-300 flex flex-col justify-between items-center min-h-[140px] hover:-translate-y-1 hover:shadow-[0_8px_20px_rgba(15,157,118,0.08)] active:scale-[0.98]">
                            <div className="p-2.5 rounded-lg bg-[#edf8f3] text-[#0f9d76] group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-[#1d1d1d]">Threat Modeling</h4>
                                <p className="text-[11px] text-[#8a8178] leading-tight">Create and manage threat models</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-[#8a8178] group-hover:text-[#0f9d76] group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>

                        {/* Service 6: Reports History */}
                        <Link href="/dashboard/reports" className="group bg-[#ffffff] border border-[#e7ddd1] rounded-xl p-4 text-center hover:bg-[#fffaf4] hover:border-[#0f9d76] transition-all duration-300 flex flex-col justify-between items-center min-h-[140px] hover:-translate-y-1 hover:shadow-[0_8px_20px_rgba(15,157,118,0.08)] active:scale-[0.98]">
                            <div className="p-2.5 rounded-lg bg-[#edf8f3] text-[#0f9d76] group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-[#1d1d1d]">Reports History</h4>
                                <p className="text-[11px] text-[#8a8178] leading-tight">View action logs and security histories</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-[#8a8178] group-hover:text-[#0f9d76] group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>

                    </div>
                </div>

                {/* ── Section: Features Footnotes ─────────────────────── */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 p-6 rounded-2xl bg-[#ffffff] border border-[#e7ddd1] shadow-sm">
                    
                    {/* Footnote 1 */}
                    <div className="flex gap-4 items-start">
                        <div className="p-2 bg-[#edf8f3] text-[#0f9d76] rounded-lg flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                        </div>
                        <div className="space-y-1">
                            <h5 className="text-sm font-bold text-[#1d1d1d] leading-snug">Unified Security Platform</h5>
                            <p className="text-xs text-[#8a8178] leading-normal">All-in-one cybersecurity investigation platform.</p>
                        </div>
                    </div>

                    {/* Footnote 2 */}
                    <div className="flex gap-4 items-start">
                        <div className="p-2 bg-[#edf8f3] text-[#0f9d76] rounded-lg flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                        </div>
                        <div className="space-y-1">
                            <h5 className="text-sm font-bold text-[#1d1d1d] leading-snug">AI-Powered Intelligence</h5>
                            <p className="text-xs text-[#8a8178] leading-normal">Advanced AI models for smarter threat detection and analysis.</p>
                        </div>
                    </div>

                    {/* Footnote 3 */}
                    <div className="flex gap-4 items-start">
                        <div className="p-2 bg-[#edf8f3] text-[#0f9d76] rounded-lg flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><path strokeLinecap="round" strokeLinejoin="round" d="M12 8V12l3 3"/></svg>
                        </div>
                        <div className="space-y-1">
                            <h5 className="text-sm font-bold text-[#1d1d1d] leading-snug">Real-time Threat Data</h5>
                            <p className="text-xs text-[#8a8178] leading-normal">Integrated with global intelligence sources and threat feeds.</p>
                        </div>
                    </div>

                    {/* Footnote 4 */}
                    <div className="flex gap-4 items-start">
                        <div className="p-2 bg-[#edf8f3] text-[#0f9d76] rounded-lg flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                        </div>
                        <div className="space-y-1">
                            <h5 className="text-sm font-bold text-[#1d1d1d] leading-snug">Enterprise Grade Security</h5>
                            <p className="text-xs text-[#8a8178] leading-normal">Built with security, privacy, and reliability in mind.</p>
                        </div>
                    </div>

                </div>
                
                {/* Copyright */}
                <div className="text-center text-xs text-[#8a8178] pt-6">
                    © 2026 TIBSA Platform. All rights reserved.
                </div>

            </div>
        </div>
    );
}
