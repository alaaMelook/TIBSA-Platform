"use client";

import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";

export interface Column<T> {
    key: Extract<keyof T, string> | (string & {});
    label: string;
    sortable?: boolean;
    render?: (row: T) => React.ReactNode;
}

interface DataTableProps<T> {
    columns: Column<T>[];
    data: T[];
    searchable?: boolean;
    searchPlaceholder?: string;
    searchKeys?: Extract<keyof T, string>[];
    pageSize?: number;
    emptyMessage?: string;
    onRowClick?: (row: T) => void;
    isLoading?: boolean;
}

// ─── Skeleton Row ───────────────────────────────────────────
function SkeletonRow({ columns }: { columns: number }) {
    return (
        <tr className="border-b border-white/[0.03]">
            {Array.from({ length: columns }).map((_, i) => (
                <td key={i} className="px-4 py-4">
                    <div className="h-4 bg-white/[0.04] rounded-md animate-pulse" style={{ width: `${60 + Math.random() * 30}%` }} />
                </td>
            ))}
        </tr>
    );
}

export function DataTable<T>({
    columns,
    data,
    searchable,
    searchPlaceholder = "Search...",
    searchKeys,
    pageSize = 8,
    emptyMessage = "No data found",
    onRowClick,
    isLoading = false,
}: DataTableProps<T>) {
    const [search, setSearch] = useState("");
    const [sortKey, setSortKey] = useState<keyof T | string | null>(null);
    const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
    const [page, setPage] = useState(1);

    const filtered = useMemo(() => {
        let result = [...data];

        if (search && searchKeys) {
            const q = search.toLowerCase();
            result = result.filter((row) =>
                searchKeys.some((key) => {
                    const val = row[key];
                    return typeof val === "string" && val.toLowerCase().includes(q);
                })
            );
        }

        if (sortKey) {
            result.sort((a, b) => {
                const aVal = a[sortKey as keyof T];
                const bVal = b[sortKey as keyof T];
                if (aVal == null || bVal == null) return 0;
                if (typeof aVal === "number" && typeof bVal === "number")
                    return sortDir === "asc" ? aVal - bVal : bVal - aVal;
                return sortDir === "asc"
                    ? String(aVal).localeCompare(String(bVal))
                    : String(bVal).localeCompare(String(aVal));
            });
        }

        return result;
    }, [data, search, sortKey, sortDir, searchKeys]);

    const totalPages = Math.ceil(filtered.length / pageSize);
    const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);

    const handleSort = (key: Extract<keyof T, string> | string) => {
        if (sortKey === key) {
            setSortDir((d) => (d === "asc" ? "desc" : "asc"));
        } else {
            setSortKey(key);
            setSortDir("asc");
        }
        setPage(1);
    };

    return (
        <div className="space-y-3">
            {/* Search Bar */}
            {searchable && (
                <div className="relative">
                    <svg className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <circle cx="11" cy="11" r="8" /><path strokeLinecap="round" d="M21 21l-4.35-4.35" />
                    </svg>
                    <input
                        type="text"
                        value={search}
                        onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                        placeholder={searchPlaceholder}
                        className="w-full pl-10 pr-4 py-2.5 bg-white/[0.03] border border-white/[0.08] rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500/40 focus:ring-1 focus:ring-blue-500/20 transition-all duration-200"
                    />
                    {search && (
                        <button
                            onClick={() => { setSearch(""); setPage(1); }}
                            className="absolute right-3 top-1/2 -translate-y-1/2 w-5 h-5 rounded-full bg-white/[0.06] flex items-center justify-center text-slate-400 hover:bg-white/[0.1] hover:text-white transition-colors"
                        >
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        </button>
                    )}
                </div>
            )}

            {/* Table */}
            <div className="overflow-x-auto rounded-lg border border-white/[0.04]">
                <table className="w-full text-left">
                    <thead>
                        <tr className="border-b border-white/[0.06] bg-white/[0.02]">
                            {columns.map((col) => (
                                <th
                                    key={col.key}
                                    className={`px-4 py-3 text-[11px] font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap ${
                                        col.sortable ? "cursor-pointer select-none hover:text-slate-200 transition-colors" : ""
                                    }`}
                                    onClick={() => col.sortable && handleSort(col.key)}
                                >
                                    <span className="flex items-center gap-1.5">
                                        {col.label}
                                        {col.sortable && sortKey === col.key && (
                                            <motion.svg
                                                initial={{ opacity: 0 }}
                                                animate={{ opacity: 1, rotate: sortDir === "desc" ? 180 : 0 }}
                                                className="w-3 h-3 text-blue-400"
                                                fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                                            >
                                                <path strokeLinecap="round" d="M5 15l7-7 7 7" />
                                            </motion.svg>
                                        )}
                                    </span>
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {isLoading ? (
                            Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} columns={columns.length} />)
                        ) : (
                            <AnimatePresence mode="popLayout">
                                {paginated.length > 0 ? (
                                    paginated.map((row, i) => (
                                        <motion.tr
                                            key={(row as Record<string, unknown>).id as string || i}
                                            initial={{ opacity: 0, x: -8 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            exit={{ opacity: 0, x: 8 }}
                                            transition={{ duration: 0.25, delay: i * 0.03 }}
                                            className={`border-b border-white/[0.03] transition-colors duration-150 ${
                                                onRowClick
                                                    ? "cursor-pointer hover:bg-blue-500/[0.04]"
                                                    : "hover:bg-white/[0.02]"
                                            }`}
                                            onClick={() => onRowClick?.(row)}
                                        >
                                            {columns.map((col) => (
                                                <td key={col.key as string} className="px-4 py-3.5 whitespace-nowrap">
                                                    {col.render ? col.render(row) : (String(row[col.key as keyof T] ?? ""))}
                                                </td>
                                            ))}
                                        </motion.tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan={columns.length} className="text-center py-16">
                                            <motion.div
                                                initial={{ opacity: 0, scale: 0.9 }}
                                                animate={{ opacity: 1, scale: 1 }}
                                                className="flex flex-col items-center gap-3"
                                            >
                                                <div className="w-14 h-14 rounded-full bg-white/[0.03] border border-white/[0.06] flex items-center justify-center">
                                                    <svg className="w-6 h-6 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                                                    </svg>
                                                </div>
                                                <p className="text-sm text-slate-500">{emptyMessage}</p>
                                                {search && (
                                                    <button
                                                        onClick={() => { setSearch(""); setPage(1); }}
                                                        className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                                                    >
                                                        Clear search
                                                    </button>
                                                )}
                                            </motion.div>
                                        </td>
                                    </tr>
                                )}
                            </AnimatePresence>
                        )}
                    </tbody>
                </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.2 }}
                    className="flex items-center justify-between pt-1"
                >
                    <p className="text-xs text-slate-500">
                        Showing <span className="text-slate-300 font-medium">{(page - 1) * pageSize + 1}–{Math.min(page * pageSize, filtered.length)}</span> of <span className="text-slate-300 font-medium">{filtered.length}</span>
                    </p>
                    <div className="flex items-center gap-1">
                        <button
                            onClick={() => setPage((p) => Math.max(1, p - 1))}
                            disabled={page === 1}
                            className="px-2.5 py-1.5 text-xs rounded-md border border-white/[0.06] text-slate-400 hover:bg-white/[0.06] hover:text-white disabled:opacity-30 disabled:pointer-events-none transition-all"
                        >
                            ‹ Prev
                        </button>
                        {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                            let pageNum: number;
                            if (totalPages <= 5) {
                                pageNum = i + 1;
                            } else if (page <= 3) {
                                pageNum = i + 1;
                            } else if (page >= totalPages - 2) {
                                pageNum = totalPages - 4 + i;
                            } else {
                                pageNum = page - 2 + i;
                            }
                            return (
                                <button
                                    key={pageNum}
                                    onClick={() => setPage(pageNum)}
                                    className={`w-8 h-8 text-xs rounded-md font-medium transition-all duration-200 ${
                                        page === pageNum
                                            ? "bg-blue-500/20 border border-blue-500/30 text-blue-400 shadow-sm shadow-blue-500/10"
                                            : "border border-transparent text-slate-400 hover:bg-white/[0.04] hover:text-slate-200"
                                    }`}
                                >
                                    {pageNum}
                                </button>
                            );
                        })}
                        <button
                            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                            disabled={page === totalPages}
                            className="px-2.5 py-1.5 text-xs rounded-md border border-white/[0.06] text-slate-400 hover:bg-white/[0.06] hover:text-white disabled:opacity-30 disabled:pointer-events-none transition-all"
                        >
                            Next ›
                        </button>
                    </div>
                </motion.div>
            )}
        </div>
    );
}
