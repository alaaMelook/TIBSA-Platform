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
        return colors[level || "safe"] || "text-slate-500";
    };

    const statusBadge = (status: string) => {
        const styles: Record<string, string> = {
            pending: "bg-yellow-500/15 text-yellow-400",
            running: "bg-blue-500/15 text-blue-400",
            completed: "bg-green-500/15 text-green-400",
            failed: "bg-red-500/15 text-red-400",
        };
        return styles[status] || "bg-white/5 text-slate-400";
    };

    return (
        <div className="min-h-screen bg-[#090d16] text-white flex flex-col justify-between py-6 px-4 md:px-8">
            <div className="max-w-7xl mx-auto w-full space-y-12">
                
                {/* ── Welcome Banner ─────────────────────────────────── */}
                <div className="flex flex-col items-center text-center space-y-4">
                    <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-slate-900/80 border border-slate-800/80 text-slate-200 text-sm shadow-inner">
                        <span>Welcome back, {userDisplayName}</span>
                        <span className="text-amber-400">👋</span>
                    </div>
                    
                    <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight max-w-4xl leading-tight">
                        TIBSA Unified <span className="bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 bg-clip-text text-transparent">Cyber Security</span> & Intelligent Defense Platform
                    </h1>
                    
                    <p className="text-slate-400 max-w-4xl text-sm md:text-base font-normal leading-relaxed">
                        TIBSA integrates automated penetration testing, multi-stage threat correlation, machine learning-driven malware sandboxing, and real-time threat intelligence enrichment to map complex attack vectors, assess security posture, and generate automated response roadmaps.
                    </p>
                </div>

                {/* ── Section: Investigation Flows ───────────────────── */}
                <div>
                    <div className="flex items-center justify-center gap-4 mb-8">
                        <div className="h-px w-20 bg-gradient-to-r from-transparent to-blue-500/30" />
                        <span className="text-xs font-bold text-blue-400/80 tracking-widest uppercase">• INVESTIGATION FLOWS •</span>
                        <div className="h-px w-20 bg-gradient-to-l from-transparent to-blue-500/30" />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        
                        {/* Card 01: Investigation & Correlation */}
                        <div className="relative group bg-[#0e1626]/90 border border-white/[0.06] rounded-2xl p-6 transition-all duration-300 hover:border-blue-500/50 hover:shadow-[0_0_30px_rgba(59,130,246,0.15)] flex flex-col justify-between min-h-[380px]">
                            {/* Card badge */}
                            <div className="absolute top-4 left-4 border border-blue-500/30 bg-blue-500/10 rounded-lg px-2.5 py-0.5 text-xs font-bold text-blue-400 tracking-wider">
                                01
                            </div>
                            
                            {/* Glowing Background Glow effect on Hover */}
                            <div className="absolute inset-0 bg-blue-500/[0.01] group-hover:bg-blue-500/[0.02] rounded-2xl transition-colors pointer-events-none" />

                            <div className="mt-8 text-center space-y-6 flex-1 flex flex-col justify-center">
                                {/* SVG Icon */}
                                <div className="h-20 flex items-center justify-center text-blue-400 group-hover:scale-105 transition-transform duration-300">
                                    <svg className="w-16 h-16 drop-shadow-[0_0_10px_rgba(59,130,246,0.4)]" viewBox="0 0 100 100" fill="none">
                                        <circle cx="50" cy="50" r="40" stroke="currentColor" strokeWidth="0.5" strokeDasharray="3 3" opacity="0.3" />
                                        <circle cx="50" cy="50" r="30" stroke="currentColor" strokeWidth="0.8" opacity="0.5" />
                                        <circle cx="50" cy="50" r="20" stroke="currentColor" strokeWidth="1" opacity="0.7" />
                                        <circle cx="50" cy="50" r="10" stroke="currentColor" strokeWidth="1.2" opacity="0.9" />
                                        <line x1="50" y1="10" x2="50" y2="90" stroke="currentColor" strokeWidth="0.5" opacity="0.3" />
                                        <line x1="10" y1="50" x2="90" y2="50" stroke="currentColor" strokeWidth="0.5" opacity="0.3" />
                                        <path d="M50 50 L50 20 A30 30 0 0 1 76 35 Z" fill="url(#blue-sweep)" opacity="0.4" />
                                        <circle cx="70" cy="38" r="2.5" fill="#60a5fa" className="animate-pulse" />
                                        <circle cx="35" cy="65" r="1.5" fill="#60a5fa" opacity="0.7" />
                                        <defs>
                                            <radialGradient id="blue-sweep" cx="50%" cy="50%" r="50%">
                                                <stop offset="0%" stopColor="#3b82f6" stopOpacity="1" />
                                                <stop offset="100%" stopColor="#1e3a8a" stopOpacity="0" />
                                            </radialGradient>
                                        </defs>
                                    </svg>
                                </div>
                                <div className="space-y-1">
                                    <h3 className="text-xl font-bold text-white tracking-wide">Investigation & Correlation</h3>
                                    <p className="text-xs font-semibold text-blue-400 tracking-wider uppercase">(Penetration Testing & Security Assessment)</p>
                                </div>
                                <p className="text-slate-400 text-sm leading-relaxed px-4">
                                    Run security assessments and correlate findings with threat intelligence to uncover risks, attack paths, and business impact.
                                </p>
                            </div>

                            <div className="mt-6">
                                <Link href="/dashboard/investigations" className="w-full flex items-center justify-center gap-2 py-3 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 text-white font-semibold rounded-xl text-sm transition-all shadow-lg shadow-blue-900/40 hover:shadow-blue-500/35">
                                    <span>Start Investigation</span>
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                    </svg>
                                </Link>
                            </div>
                        </div>


                        {/* Card 03: Malware & Threat Analysis Layer */}
                        <div className="relative group bg-[#0e1626]/90 border border-white/[0.06] rounded-2xl p-6 transition-all duration-300 hover:border-purple-500/50 hover:shadow-[0_0_30px_rgba(168,85,247,0.15)] flex flex-col justify-between min-h-[380px]">
                            {/* Card badge */}
                            <div className="absolute top-4 left-4 border border-purple-500/30 bg-purple-500/10 rounded-lg px-2.5 py-0.5 text-xs font-bold text-purple-400 tracking-wider">
                                03
                            </div>
                            
                            {/* Glowing Background Glow effect on Hover */}
                            <div className="absolute inset-0 bg-purple-500/[0.01] group-hover:bg-purple-500/[0.02] rounded-2xl transition-colors pointer-events-none" />

                            <div className="mt-8 text-center space-y-6 flex-1 flex flex-col justify-center">
                                {/* SVG Icon */}
                                <div className="h-20 flex items-center justify-center text-purple-400 group-hover:scale-105 transition-transform duration-300">
                                    <svg className="w-16 h-16 drop-shadow-[0_0_10px_rgba(168,85,247,0.4)]" viewBox="0 0 100 100" fill="none">
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
                                        
                                        <circle cx="62" cy="60" r="14" stroke="#c084fc" strokeWidth="2.5" fill="#581c87" fillOpacity="0.2" />
                                        <line x1="72" y1="70" x2="86" y2="86" stroke="#c084fc" strokeWidth="3" strokeLinecap="round" />
                                        <path d="M53 53 A8 8 0 0 1 69 53" stroke="#e9d5ff" strokeWidth="1" opacity="0.5" strokeLinecap="round" />
                                    </svg>
                                </div>
                                <h3 className="text-xl font-bold text-white tracking-wide">Malware & Threat Analysis Layer</h3>
                                <p className="text-slate-400 text-sm leading-relaxed px-4">
                                    Upload files, analyze malware behavior, and extract advanced indicators with sandboxing and static & dynamic analysis.
                                </p>
                            </div>

                            <div className="mt-6">
                                <Link href="/dashboard/ai-malware-analysis" className="w-full flex items-center justify-center gap-2 py-3 bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-500 hover:to-purple-600 text-white font-semibold rounded-xl text-sm transition-all shadow-lg shadow-purple-900/40 hover:shadow-purple-500/35">
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
                        <div className="h-px w-20 bg-gradient-to-r from-transparent to-purple-500/30" />
                        <span className="text-xs font-bold text-purple-400/80 tracking-widest uppercase">• STANDALONE SERVICES •</span>
                        <div className="h-px w-20 bg-gradient-to-l from-transparent to-purple-500/30" />
                    </div>
                    <p className="text-slate-400 text-center text-xs mb-8">Access individual security tools and capabilities.</p>

                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                        
                        {/* Service 1: Scans */}
                        <Link href="/dashboard/scans" className="group bg-[#0e1626]/75 border border-white/[0.04] rounded-xl p-4 text-center hover:bg-slate-900/80 hover:border-blue-500/40 transition-all duration-300 flex flex-col justify-between items-center min-h-[140px]">
                            <div className="p-2.5 rounded-lg bg-blue-500/10 text-blue-400 group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="8"/><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-white">Scans</h4>
                                <p className="text-[11px] text-slate-400 leading-tight">View and manage your scans</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-slate-500 group-hover:text-blue-400 group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>

                        {/* Service 2: Pen Test */}
                        <Link href="/dashboard/website-scanner" className="group bg-[#0e1626]/75 border border-white/[0.04] rounded-xl p-4 text-center hover:bg-slate-900/80 hover:border-purple-500/40 transition-all duration-300 flex flex-col justify-between items-center min-h-[140px]">
                            <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-white">Penetration Testing</h4>
                                <p className="text-[11px] text-slate-400 leading-tight">Manual penetration testing</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>

                        {/* Service 3: Threats */}
                        <Link href="/dashboard/threats" className="group bg-[#0e1626]/75 border border-white/[0.04] rounded-xl p-4 text-center hover:bg-slate-900/80 hover:border-amber-500/40 transition-all duration-300 flex flex-col justify-between items-center min-h-[140px]">
                            <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-white">Threats</h4>
                                <p className="text-[11px] text-slate-400 leading-tight">Monitor and analyze threats</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-slate-500 group-hover:text-amber-400 group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>

                        {/* Service 4: Threat Modeling */}
                        <Link href="/dashboard/threat-modeling" className="group bg-[#0e1626]/75 border border-white/[0.04] rounded-xl p-4 text-center hover:bg-slate-900/80 hover:border-blue-500/40 transition-all duration-300 flex flex-col justify-between items-center min-h-[140px]">
                            <div className="p-2.5 rounded-lg bg-blue-500/10 text-blue-300 group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-white">Threat Modeling</h4>
                                <p className="text-[11px] text-slate-400 leading-tight">Create and manage threat models</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-slate-500 group-hover:text-blue-400 group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>

                        {/* Service 5: AI Analysis */}
                        <Link href="/dashboard/ai-malware-analysis" className="group bg-[#0e1626]/75 border border-white/[0.04] rounded-xl p-4 text-center hover:bg-slate-900/80 hover:border-emerald-500/40 transition-all duration-300 flex flex-col justify-between items-center min-h-[140px]">
                            <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-white">AI Analysis</h4>
                                <p className="text-[11px] text-slate-400 leading-tight">AI-powered security analysis</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-slate-500 group-hover:text-emerald-400 group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>

                        {/* Service 6: Reports History */}
                        <Link href="/dashboard/reports" className="group bg-[#0e1626]/75 border border-white/[0.04] rounded-xl p-4 text-center hover:bg-slate-900/80 hover:border-purple-500/40 transition-all duration-300 flex flex-col justify-between items-center min-h-[140px]">
                            <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 group-hover:scale-110 transition-transform duration-200">
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                            </div>
                            <div className="space-y-1">
                                <h4 className="text-sm font-semibold text-white">Reports History</h4>
                                <p className="text-[11px] text-slate-400 leading-tight">View action logs and security histories</p>
                            </div>
                            <svg className="w-3.5 h-3.5 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-0.5 transition-all mt-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
                        </Link>

                    </div>
                </div>

                {/* ── Section: Features Footnotes ─────────────────────── */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 p-6 rounded-2xl bg-[#0e1626]/40 border border-white/[0.04]">
                    
                    {/* Footnote 1 */}
                    <div className="flex gap-4 items-start">
                        <div className="p-2 bg-blue-500/10 text-blue-400 rounded-lg flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                        </div>
                        <div className="space-y-1">
                            <h5 className="text-sm font-bold text-white leading-snug">Unified Security Platform</h5>
                            <p className="text-xs text-slate-400 leading-normal">All-in-one cybersecurity investigation platform.</p>
                        </div>
                    </div>

                    {/* Footnote 2 */}
                    <div className="flex gap-4 items-start">
                        <div className="p-2 bg-blue-500/10 text-blue-400 rounded-lg flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                        </div>
                        <div className="space-y-1">
                            <h5 className="text-sm font-bold text-white leading-snug">AI-Powered Intelligence</h5>
                            <p className="text-xs text-slate-400 leading-normal">Advanced AI models for smarter threat detection and analysis.</p>
                        </div>
                    </div>

                    {/* Footnote 3 */}
                    <div className="flex gap-4 items-start">
                        <div className="p-2 bg-blue-500/10 text-blue-400 rounded-lg flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><path strokeLinecap="round" strokeLinejoin="round" d="M12 8V12l3 3"/></svg>
                        </div>
                        <div className="space-y-1">
                            <h5 className="text-sm font-bold text-white leading-snug">Real-time Threat Data</h5>
                            <p className="text-xs text-slate-400 leading-normal">Integrated with global intelligence sources and threat feeds.</p>
                        </div>
                    </div>

                    {/* Footnote 4 */}
                    <div className="flex gap-4 items-start">
                        <div className="p-2 bg-blue-500/10 text-blue-400 rounded-lg flex-shrink-0">
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                        </div>
                        <div className="space-y-1">
                            <h5 className="text-sm font-bold text-white leading-snug">Enterprise Grade Security</h5>
                            <p className="text-xs text-slate-400 leading-normal">Built with security, privacy, and reliability in mind.</p>
                        </div>
                    </div>

                </div>
                
                {/* Copyright */}
                <div className="text-center text-xs text-slate-600 pt-6">
                    © 2026 TIBSA Platform. All rights reserved.
                </div>

            </div>
        </div>
    );
}
