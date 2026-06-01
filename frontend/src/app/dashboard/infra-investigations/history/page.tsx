"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card, Button, Input } from "@/components/ui";
import { InfraSubHeader } from "@/components/infra-investigation/InfraSubHeader";
import {
  Globe,
  Clock,
  ArrowRight,
  ShieldAlert,
  Search,
  SlidersHorizontal,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  TrendingUp,
  Skull,
  Activity,
  HeartCrack,
} from "lucide-react";
import { InfraInvestigationListItem, InfraTargetType, InfraStatus } from "@/types/infra_investigation";

function StatusBadge({ status }: { status: string }) {
  const base = "px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border tracking-wider";
  switch (status) {
    case "completed": return <span className={`${base} border-emerald-500/20 bg-emerald-500/10 text-emerald-400`}>Completed</span>;
    case "failed":    return <span className={`${base} border-red-500/20 bg-red-500/10 text-red-400`}>Failed</span>;
    case "stopped":   return <span className={`${base} border-amber-500/20 bg-amber-500/10 text-amber-400`}>Stopped</span>;
    case "pending":   return <span className={`${base} border-slate-700 bg-slate-800 text-slate-400`}>Pending</span>;
    default:          return <span className={`${base} border-blue-500/20 bg-blue-500/10 text-blue-400 animate-pulse`}>{status || "Running"}</span>;
  }
}

export function InfraHistoryContent() {
  const router = useRouter();
  const { token } = useAuth();

  const [history, setHistory] = useState<InfraInvestigationListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<InfraTargetType[]>([]);
  const [selectedStatus, setSelectedStatus] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string>("all"); // 'all', 'critical', 'high', 'medium', 'clean'
  const [sortBy, setSortBy] = useState<"date" | "risk">("date");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  // Pagination state
  const PAGE_SIZE = 10;
  const [currentPage, setCurrentPage] = useState(1);

  // Fetch all history data
  const fetchHistory = useCallback(async () => {
    // Guard: auth hasn't loaded yet — reset loading so page doesn't
    // show the spinner indefinitely if the session never resolves.
    if (!token) {
      setIsLoading(false);
      return;
    }
    try {
      setIsLoading(true);
      setFetchError(null);
      const res = await api.infraInvestigations.list(token);
      if (res?.success && res?.data) {
        setHistory(res.data);
      } else {
        setHistory([]);
      }
    } catch (err: any) {
      const raw: string = err?.message ?? "Unknown error";
      // Translate the generic FastAPI 404 message into something actionable.
      const friendly =
        raw === "Not Found" || raw.includes("404")
          ? "API endpoint not found (404). Confirm the backend is running on port 8000 and the infra-investigations route is registered."
          : raw === "Failed to fetch" || raw.includes("ERR_CONNECTION_REFUSED")
          ? "Cannot reach the backend server. Make sure uvicorn is running on http://localhost:8000."
          : raw;
      setFetchError(friendly);
      console.error("[InfraHistory] fetchHistory failed:", err);
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  // Statistics calculation
  const stats = useMemo(() => {
    if (history.length === 0) {
      return { total: 0, critical: 0, averageRisk: 0, failedOrStopped: 0 };
    }
    const completedScans = history.filter((h) => h.status === "completed");
    const total = history.length;
    const critical = completedScans.filter((h) => h.risk_score >= 75).length;
    const failedOrStopped = history.filter((h) => h.status === "failed" || h.status === "stopped").length;
    
    const sumRisk = completedScans.reduce((sum, curr) => sum + curr.risk_score, 0);
    const averageRisk = completedScans.length > 0 ? Math.round(sumRisk / completedScans.length) : 0;

    return { total, critical, averageRisk, failedOrStopped };
  }, [history]);

  // Handle target type filter toggles
  const toggleTypeFilter = (type: InfraTargetType) => {
    setSelectedTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  // Filter & Sort core logic
  const filteredHistory = useMemo(() => {
    let result = [...history];

    // 1. Search Query Filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (h) =>
          h.target.toLowerCase().includes(q) ||
          h.target_type.toLowerCase().includes(q)
      );
    }

    // 2. Target Type Filters
    if (selectedTypes.length > 0) {
      result = result.filter((h) => selectedTypes.includes(h.target_type));
    }

    // 3. Status Filters
    if (selectedStatus !== "all") {
      result = result.filter((h) => h.status === selectedStatus);
    }

    // 4. Risk Level Filters
    if (riskFilter !== "all") {
      result = result.filter((h) => {
        if (h.status !== "completed") return false;
        if (riskFilter === "critical") return h.risk_score >= 75;
        if (riskFilter === "high")     return h.risk_score >= 50 && h.risk_score < 75;
        if (riskFilter === "medium")   return h.risk_score >= 25 && h.risk_score < 50;
        if (riskFilter === "clean")    return h.risk_score < 25;
        return true;
      });
    }

    // 5. Sorting
    result.sort((a, b) => {
      if (sortBy === "risk") {
        const scoreA = a.status === "completed" ? a.risk_score : -1;
        const scoreB = b.status === "completed" ? b.risk_score : -1;
        return sortOrder === "desc" ? scoreB - scoreA : scoreA - scoreB;
      } else {
        const timeA = new Date(a.started_at).getTime();
        const timeB = new Date(b.started_at).getTime();
        return sortOrder === "desc" ? timeB - timeA : timeA - timeB;
      }
    });

    return result;
  }, [history, searchQuery, selectedTypes, selectedStatus, riskFilter, sortBy, sortOrder]);

  // Reset page to 1 whenever filters/search change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, selectedTypes, selectedStatus, riskFilter, sortBy, sortOrder]);

  // Paginated slice
  const totalPages = Math.max(1, Math.ceil(filteredHistory.length / PAGE_SIZE));
  const paginatedHistory = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;
    return filteredHistory.slice(start, start + PAGE_SIZE);
  }, [filteredHistory, currentPage]);

  const canPrev = currentPage > 1;
  const canNext = currentPage < totalPages;

  return (
    <div className="space-y-6">
      {/* SubHeader Layout component */}
      <InfraSubHeader />

      {/* ── Error Banner ─────────────────────────────────────────── */}
      {fetchError && (
        <div className="flex items-start gap-3 p-4 rounded-xl border border-red-500/30 bg-red-500/[0.06] text-red-400">
          <ShieldAlert className="w-5 h-5 flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold leading-tight">Failed to load investigation history</p>
            <p className="text-xs text-red-400/70 mt-0.5 break-words">{fetchError}</p>
          </div>
          <button
            type="button"
            onClick={fetchHistory}
            className="flex-shrink-0 px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-xs font-bold hover:bg-red-500/20 transition-colors cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Statistics Summary Cards ── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          {
            label: "Total Investigations",
            value: stats.total,
            color: "text-cyan-400",
            bg: "bg-cyan-500/5 border-cyan-500/20",
            icon: <Activity className="w-5 h-5 text-cyan-400" />,
            desc: "Active & completed scans"
          },
          {
            label: "Average Risk Score",
            value: `${stats.averageRisk}/100`,
            color: stats.averageRisk >= 60 ? "text-red-400" : stats.averageRisk >= 30 ? "text-orange-400" : "text-emerald-400",
            bg: "bg-amber-500/5 border-amber-500/20",
            icon: <TrendingUp className="w-5 h-5 text-amber-400" />,
            desc: "Platform average severity"
          },
          {
            label: "Critical Threats Detected",
            value: stats.critical,
            color: stats.critical > 0 ? "text-red-500" : "text-slate-400",
            bg: "bg-red-500/5 border-red-500/20",
            icon: <Skull className="w-5 h-5 text-red-500" />,
            desc: "Risk index ≥ 75"
          },
          {
            label: "Terminated / Errors",
            value: stats.failedOrStopped,
            color: "text-slate-400",
            bg: "bg-slate-500/5 border-slate-500/10",
            icon: <HeartCrack className="w-5 h-5 text-slate-400" />,
            desc: "Failed or manually stopped"
          }
        ].map((s, idx) => (
          <div key={idx} className={`border rounded-xl p-4 flex items-center justify-between shadow-sm ${s.bg}`}>
            <div className="space-y-1">
              <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{s.label}</p>
              <h3 className={`text-2xl font-black ${s.color}`}>{isLoading ? "—" : s.value}</h3>
              <p className="text-[9px] text-slate-500 leading-none">{s.desc}</p>
            </div>
            <div className="p-3 bg-slate-900/50 border border-white/[0.04] rounded-lg">{s.icon}</div>
          </div>
        ))}
      </div>

      {/* ── Advanced Filter Panel ── */}
      <Card title="Audit History Logs Filter" description="Drill down into specific target classes and profiles">
        <div className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            
            {/* Search */}
            <div className="lg:col-span-2 space-y-1.5">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                Fuzzy Search Value
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-3 w-4 h-4 text-slate-500" />
                <Input
                  placeholder="Filter by target value, domain, IP, or hash..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 bg-slate-950/40 border-white/[0.08]"
                />
              </div>
            </div>

            {/* Status Selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                Job Status
              </label>
              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                className="w-full h-10 px-3 border border-white/[0.08] rounded-lg text-xs bg-slate-950 text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                <option value="all">All States</option>
                <option value="completed">Completed</option>
                <option value="pending">Pending</option>
                <option value="running">Running</option>
                <option value="failed">Failed</option>
                <option value="stopped">Stopped</option>
              </select>
            </div>

            {/* Risk Category Selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                Risk Classification
              </label>
              <select
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                className="w-full h-10 px-3 border border-white/[0.08] rounded-lg text-xs bg-slate-950 text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                <option value="all">All Risk Levels</option>
                <option value="critical">Critical (≥ 75)</option>
                <option value="high">High (50 - 74)</option>
                <option value="medium">Medium (25 - 49)</option>
                <option value="clean">Clean (&lt; 25)</option>
              </select>
            </div>

          </div>

          <div className="flex flex-wrap items-center justify-between border-t border-white/[0.04] pt-4 gap-4">
            
            {/* Target Type Filter Toggles */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mr-2">
                IOC Classes:
              </span>
              {(["domain", "ip", "url", "hash", "email"] as InfraTargetType[]).map((t) => {
                const isSelected = selectedTypes.includes(t);
                return (
                  <button
                    key={t}
                    type="button"
                    onClick={() => toggleTypeFilter(t)}
                    className={`px-3 py-1.5 rounded-lg border text-[10px] font-bold capitalize transition-all cursor-pointer ${
                      isSelected
                        ? "border-cyan-500 bg-cyan-950/30 text-cyan-400"
                        : "border-white/[0.05] bg-slate-950/20 text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    {t}
                  </button>
                );
              })}
            </div>

            {/* Sort controls */}
            <div className="flex items-center gap-2 text-xs">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                Sort:
              </span>
              <button
                type="button"
                onClick={() => {
                  if (sortBy === "date") setSortOrder((o) => (o === "desc" ? "asc" : "desc"));
                  else setSortBy("date");
                }}
                className={`px-2.5 py-1.5 rounded border text-[10px] font-bold transition-all cursor-pointer ${
                  sortBy === "date"
                    ? "border-white/[0.1] bg-slate-900 text-slate-200"
                    : "border-transparent text-slate-500"
                }`}
              >
                Date {sortBy === "date" && (sortOrder === "desc" ? "↓" : "↑")}
              </button>
              <button
                type="button"
                onClick={() => {
                  if (sortBy === "risk") setSortOrder((o) => (o === "desc" ? "asc" : "desc"));
                  else setSortBy("risk");
                }}
                className={`px-2.5 py-1.5 rounded border text-[10px] font-bold transition-all cursor-pointer ${
                  sortBy === "risk"
                    ? "border-white/[0.1] bg-slate-900 text-slate-200"
                    : "border-transparent text-slate-500"
                }`}
              >
                Risk Score {sortBy === "risk" && (sortOrder === "desc" ? "↓" : "↑")}
              </button>
            </div>

          </div>
        </div>
      </Card>

      {/* ── Table / Grid View ── */}
      <Card title="Audited Scans Logging" description="Detailed registry of threat intelligence runs">
        {isLoading ? (
          <div className="py-20 text-center text-slate-500 font-medium">
            <span className="inline-block animate-spin mr-2 h-4 w-4 border-2 border-cyan-500 border-t-transparent rounded-full" />
            Loading historical scans...
          </div>
        ) : filteredHistory.length === 0 ? (
          <div className="py-20 text-center text-slate-500 flex flex-col items-center justify-center">
            <Globe className="w-8 h-8 mb-2 opacity-20" />
            <p className="text-sm font-semibold">No investigations match active filters.</p>
            <p className="text-xs text-slate-600 mt-1">Adjust search parameters or trigger a new scanning pipeline run.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-white/[0.06] text-slate-400 font-semibold bg-slate-900/10 text-[11px] uppercase tracking-wider">
                  <th className="py-3 px-4">Target Value</th>
                  <th className="py-3 px-4">IOC Class</th>
                  <th className="py-3 px-4">Threat Risk</th>
                  <th className="py-3 px-4">Last Phase</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Scan Date</th>
                  <th className="py-3 px-4" />
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {paginatedHistory.map((inv) => {
                  const isFailed    = inv.status === "failed";
                  const riskColor   =
                    isFailed        ? "text-slate-500" :
                    inv.risk_score >= 75 ? "text-red-500" :
                    inv.risk_score >= 50 ? "text-red-400" :
                    inv.risk_score >= 25 ? "text-orange-400" : "text-emerald-400";

                  return (
                    <tr
                      key={inv.id}
                      onClick={() => router.push(`/dashboard/infra-investigations/${inv.id}`)}
                      className="hover:bg-white/[0.02] cursor-pointer transition-colors group animate-fadeIn"
                    >
                      <td className="py-4 px-4 text-slate-200 font-medium max-w-[240px] truncate">
                        <div className="flex items-center gap-2">
                          <Globe className="w-3.5 h-3.5 text-cyan-500/60 flex-shrink-0" />
                          <span className="truncate font-mono">{inv.target}</span>
                        </div>
                      </td>
                      <td className="py-4 px-4">
                        <span className="text-[9px] font-extrabold uppercase px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                          {inv.target_type}
                        </span>
                      </td>
                      <td className="py-4 px-4">
                        {isFailed ? (
                          <span className="text-slate-600 font-semibold font-mono text-xs">—</span>
                        ) : (
                          <div className="flex items-center gap-1.5">
                            <span className={`font-black font-mono text-xs ${riskColor}`}>
                              {Math.round(inv.risk_score)}
                            </span>
                            <span className="text-[9px] text-slate-500 font-medium uppercase">/100</span>
                          </div>
                        )}
                      </td>
                      <td className="py-4 px-4 text-xs text-slate-400 font-medium">
                        {inv.current_stage || "Queued"}
                      </td>
                      <td className="py-4 px-4">
                        <StatusBadge status={inv.status} />
                      </td>
                      <td className="py-4 px-4 text-[10px] text-slate-500 font-medium">
                        <div className="flex items-center gap-1">
                          <Clock className="w-3.5 h-3.5" />
                          {new Date(inv.started_at).toLocaleString()}
                        </div>
                      </td>
                      <td className="py-4 px-4 text-right">
                        <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {/* ── Pagination Controls ── */}
            <div className="flex items-center justify-between border-t border-white/[0.06] pt-4 mt-2 px-2">
              {/* Left: record count */}
              <p className="text-[11px] text-slate-500 font-medium">
                Showing{" "}
                <span className="text-slate-300 font-bold">
                  {Math.min((currentPage - 1) * PAGE_SIZE + 1, filteredHistory.length)}
                </span>
                {"–"}
                <span className="text-slate-300 font-bold">
                  {Math.min(currentPage * PAGE_SIZE, filteredHistory.length)}
                </span>
                {" of "}
                <span className="text-slate-300 font-bold">{filteredHistory.length}</span>
                {" records"}
              </p>

              {/* Right: page nav */}
              <div className="flex items-center gap-1">
                {/* First */}
                <button
                  type="button"
                  disabled={!canPrev}
                  onClick={() => setCurrentPage(1)}
                  className={`p-1.5 rounded-lg border transition-all ${
                    canPrev
                      ? "border-white/[0.08] text-slate-400 hover:text-white hover:bg-white/[0.06] cursor-pointer"
                      : "border-transparent text-slate-700 cursor-not-allowed"
                  }`}
                  title="First page"
                >
                  <ChevronsLeft className="w-4 h-4" />
                </button>

                {/* Previous */}
                <button
                  type="button"
                  disabled={!canPrev}
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  className={`px-3 py-1.5 rounded-lg border text-xs font-bold transition-all ${
                    canPrev
                      ? "border-white/[0.08] text-slate-300 hover:text-white hover:bg-white/[0.06] cursor-pointer"
                      : "border-transparent text-slate-700 cursor-not-allowed"
                  }`}
                >
                  <span className="flex items-center gap-1">
                    <ChevronLeft className="w-3.5 h-3.5" /> Previous
                  </span>
                </button>

                {/* Page indicator */}
                <div className="flex items-center gap-1 mx-2">
                  {Array.from({ length: totalPages }, (_, i) => i + 1)
                    .filter((page) => {
                      // Show first, last, current, and neighbors
                      if (page === 1 || page === totalPages) return true;
                      if (Math.abs(page - currentPage) <= 1) return true;
                      return false;
                    })
                    .reduce<(number | "...")[]>((acc, page, idx, arr) => {
                      if (idx > 0 && page - (arr[idx - 1] as number) > 1) acc.push("...");
                      acc.push(page);
                      return acc;
                    }, [])
                    .map((item, idx) =>
                      item === "..." ? (
                        <span key={`dots-${idx}`} className="text-slate-600 text-xs px-1">…</span>
                      ) : (
                        <button
                          key={item}
                          type="button"
                          onClick={() => setCurrentPage(item as number)}
                          className={`w-8 h-8 rounded-lg text-xs font-bold transition-all cursor-pointer ${
                            currentPage === item
                              ? "bg-cyan-500/20 border border-cyan-500/40 text-cyan-400 shadow-sm shadow-cyan-500/10"
                              : "border border-white/[0.06] text-slate-500 hover:text-slate-200 hover:bg-white/[0.06]"
                          }`}
                        >
                          {item}
                        </button>
                      )
                    )}
                </div>

                {/* Next */}
                <button
                  type="button"
                  disabled={!canNext}
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  className={`px-3 py-1.5 rounded-lg border text-xs font-bold transition-all ${
                    canNext
                      ? "border-white/[0.08] text-slate-300 hover:text-white hover:bg-white/[0.06] cursor-pointer"
                      : "border-transparent text-slate-700 cursor-not-allowed"
                  }`}
                >
                  <span className="flex items-center gap-1">
                    Next <ChevronRight className="w-3.5 h-3.5" />
                  </span>
                </button>

                {/* Last */}
                <button
                  type="button"
                  disabled={!canNext}
                  onClick={() => setCurrentPage(totalPages)}
                  className={`p-1.5 rounded-lg border transition-all ${
                    canNext
                      ? "border-white/[0.08] text-slate-400 hover:text-white hover:bg-white/[0.06] cursor-pointer"
                      : "border-transparent text-slate-700 cursor-not-allowed"
                  }`}
                  title="Last page"
                >
                  <ChevronsRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

export default function InfraHistoryPage() {
  return <InfraHistoryContent />;
}
