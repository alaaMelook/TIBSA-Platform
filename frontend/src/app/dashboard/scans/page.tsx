"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card, Button, Input } from "@/components/ui";

interface Scan {
    id: string;
    scan_type: string;
    target: string;
    status: string;
    threat_level: string | null;
    created_at: string;
    completed_at: string | null;
}

export default function ScansPage() {
    const { token } = useAuth();
    const [scans, setScans] = useState<Scan[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [scanTarget, setScanTarget] = useState("");
    const [scanType, setScanType] = useState<"url" | "file">("url");
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    const fetchScans = useCallback(async () => {
        if (!token) return;
        try {
            const data = await api.get<Scan[]>("/api/v1/scans/", token);
            setScans(data);
        } catch (err) {
            console.error("Failed to fetch scans:", err);
        } finally {
            setIsLoading(false);
        }
    }, [token]);

    useEffect(() => {
        fetchScans();
    }, [fetchScans]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!token || !scanTarget.trim()) return;

        setIsSubmitting(true);
        setError("");
        setSuccess("");

        try {
            const endpoint = scanType === "url" ? "/api/v1/scans/url" : "/api/v1/scans/file";
            await api.post(endpoint, { target: scanTarget, scan_type: scanType }, token);
            setSuccess(`${scanType.toUpperCase()} scan submitted successfully!`);
            setScanTarget("");
            fetchScans();
        } catch (err) {
            setError(err instanceof Error ? err.message : "Scan submission failed");
        } finally {
            setIsSubmitting(false);
        }
    };

    const threatColor = (level: string | null) => {
        const colors: Record<string, string> = {
            safe: "text-green-600",
            low: "text-yellow-500",
            medium: "text-orange-500",
            high: "text-red-500",
            critical: "text-red-700",
        };
        return colors[level || "safe"] || "text-gray-400";
    };

    const statusBadge = (status: string) => {
        const styles: Record<string, string> = {
            pending: "bg-yellow-100 text-yellow-700",
            running: "bg-blue-100 text-blue-700",
            completed: "bg-green-100 text-green-700",
            failed: "bg-red-100 text-red-700",
        };
        return styles[status] || "bg-gray-100 text-gray-600";
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900">Security Scans</h1>
                <p className="text-gray-500 mt-1">Scan URLs and files for threats</p>
            </div>

            {/* New Scan Form */}
            <Card title="New Scan">
                <form onSubmit={handleSubmit} className="space-y-4">
                    {/* Scan Type Tabs */}
                    <div className="flex gap-2">
                        <button
                            type="button"
                            onClick={() => setScanType("url")}
                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${scanType === "url"
                                    ? "bg-blue-600 text-white"
                                    : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                                }`}
                        >
                            🔗 URL Scan
                        </button>
                        <button
                            type="button"
                            onClick={() => setScanType("file")}
                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${scanType === "file"
                                    ? "bg-blue-600 text-white"
                                    : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                                }`}
                        >
                            📄 File Hash Scan
                        </button>
                    </div>

                    <div className="flex gap-3">
                        <div className="flex-1">
                            <Input
                                placeholder={
                                    scanType === "url"
                                        ? "Enter URL to scan (e.g., https://example.com)"
                                        : "Enter file hash (SHA-256)"
                                }
                                value={scanTarget}
                                onChange={(e) => setScanTarget(e.target.value)}
                            />
                        </div>
                        <Button type="submit" disabled={isSubmitting || !scanTarget.trim()}>
                            {isSubmitting ? "Scanning..." : "Scan"}
                        </Button>
                    </div>

                    {error && (
                        <div className="text-sm text-red-600 bg-red-50 px-3 py-2 rounded-lg">{error}</div>
                    )}
                    {success && (
                        <div className="text-sm text-green-600 bg-green-50 px-3 py-2 rounded-lg">{success}</div>
                    )}
                </form>
            </Card>

            {/* Scan History */}
            <Card title="Scan History">
                {isLoading ? (
                    <div className="text-center py-8 text-gray-400">Loading scans...</div>
                ) : scans.length === 0 ? (
                    <div className="text-center py-8 text-gray-400">
                        <p>No scans yet.</p>
                        <p className="text-sm mt-1">Submit a URL or file hash above to get started.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-left border-b border-gray-200">
                                    <th className="pb-3 font-medium text-gray-500">Type</th>
                                    <th className="pb-3 font-medium text-gray-500">Target</th>
                                    <th className="pb-3 font-medium text-gray-500">Status</th>
                                    <th className="pb-3 font-medium text-gray-500">Threat Level</th>
                                    <th className="pb-3 font-medium text-gray-500">Date</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100">
                                {scans.map((scan) => (
                                    <tr key={scan.id} className="hover:bg-gray-50">
                                        <td className="py-3">
                                            <span className="text-lg mr-1">{scan.scan_type === "url" ? "🔗" : "📄"}</span>
                                            {scan.scan_type.toUpperCase()}
                                        </td>
                                        <td className="py-3 text-gray-600 max-w-xs truncate font-mono text-xs">
                                            {scan.target}
                                        </td>
                                        <td className="py-3">
                                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge(scan.status)}`}>
                                                {scan.status}
                                            </span>
                                        </td>
                                        <td className={`py-3 font-medium capitalize ${threatColor(scan.threat_level)}`}>
                                            {scan.threat_level || "—"}
                                        </td>
                                        <td className="py-3 text-gray-400 text-xs">
                                            {new Date(scan.created_at).toLocaleString()}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </Card>
        </div>
    );
}
