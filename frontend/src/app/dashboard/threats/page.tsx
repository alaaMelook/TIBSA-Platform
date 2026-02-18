"use client";

import { useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card, Button, Input } from "@/components/ui";

interface ReputationResult {
    target: string;
    reputation_score: number;
    threat_level: string;
    details: Record<string, unknown>;
    sources_checked: string[];
}

interface IOCResult {
    id: string;
    type: string;
    value: string;
    threat_level: string;
    source: string;
    last_seen: string;
}

export default function ThreatsPage() {
    const { token } = useAuth();

    // IOC Lookup state
    const [iocType, setIocType] = useState("ip");
    const [iocValue, setIocValue] = useState("");
    const [iocResults, setIocResults] = useState<IOCResult[]>([]);
    const [iocLoading, setIocLoading] = useState(false);
    const [iocSearched, setIocSearched] = useState(false);

    // Reputation Check state
    const [repTarget, setRepTarget] = useState("");
    const [repResult, setRepResult] = useState<ReputationResult | null>(null);
    const [repLoading, setRepLoading] = useState(false);
    const [repSearched, setRepSearched] = useState(false);

    const handleIOCLookup = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!token || !iocValue.trim()) return;
        setIocLoading(true);
        setIocSearched(true);
        try {
            const data = await api.post<IOCResult[]>(
                "/api/v1/threats/lookup",
                { indicator_type: iocType, value: iocValue },
                token
            );
            setIocResults(data);
        } catch (err) {
            console.error("IOC lookup failed:", err);
            setIocResults([]);
        } finally {
            setIocLoading(false);
        }
    };

    const handleReputationCheck = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!token || !repTarget.trim()) return;
        setRepLoading(true);
        setRepSearched(true);
        try {
            const data = await api.post<ReputationResult>(
                "/api/v1/threats/reputation",
                { target: repTarget },
                token
            );
            setRepResult(data);
        } catch (err) {
            console.error("Reputation check failed:", err);
            setRepResult(null);
        } finally {
            setRepLoading(false);
        }
    };

    const threatColor = (level: string) => {
        const colors: Record<string, string> = {
            safe: "text-green-600",
            low: "text-yellow-500",
            medium: "text-orange-500",
            high: "text-red-500",
            critical: "text-red-700",
        };
        return colors[level] || "text-gray-400";
    };

    const threatBg = (level: string) => {
        const colors: Record<string, string> = {
            safe: "bg-green-500",
            low: "bg-yellow-400",
            medium: "bg-orange-500",
            high: "bg-red-500",
            critical: "bg-red-700",
        };
        return colors[level] || "bg-gray-300";
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-gray-900">Threat Intelligence</h1>
                <p className="text-gray-500 mt-1">Look up IOCs and check reputation of domains, IPs, and URLs</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* IOC Lookup */}
                <Card title="🔎 IOC Lookup" description="Search for Indicators of Compromise">
                    <form onSubmit={handleIOCLookup} className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Indicator Type</label>
                            <select
                                value={iocType}
                                onChange={(e) => setIocType(e.target.value)}
                                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                            >
                                <option value="ip">IP Address</option>
                                <option value="domain">Domain</option>
                                <option value="url">URL</option>
                                <option value="hash">File Hash</option>
                                <option value="email">Email</option>
                            </select>
                        </div>
                        <Input
                            placeholder="Enter indicator value..."
                            value={iocValue}
                            onChange={(e) => setIocValue(e.target.value)}
                        />
                        <Button type="submit" disabled={iocLoading || !iocValue.trim()}>
                            {iocLoading ? "Searching..." : "Look Up"}
                        </Button>
                    </form>

                    {iocSearched && !iocLoading && (
                        <div className="mt-4 pt-4 border-t border-gray-100">
                            {iocResults.length === 0 ? (
                                <div className="text-center py-4 text-gray-400 text-sm">
                                    ✅ No threats found for this indicator
                                </div>
                            ) : (
                                <div className="space-y-3">
                                    <h4 className="text-sm font-medium text-gray-700">
                                        {iocResults.length} result(s) found
                                    </h4>
                                    {iocResults.map((result, i) => (
                                        <div key={i} className="bg-gray-50 p-3 rounded-lg text-sm">
                                            <div className="flex justify-between items-center">
                                                <span className="font-mono">{result.value}</span>
                                                <span className={`font-medium capitalize ${threatColor(result.threat_level)}`}>
                                                    {result.threat_level}
                                                </span>
                                            </div>
                                            <div className="text-gray-400 text-xs mt-1">
                                                Source: {result.source} · Type: {result.type}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}
                </Card>

                {/* Reputation Check */}
                <Card title="🛡️ Reputation Check" description="Check the reputation of a domain, IP, or URL">
                    <form onSubmit={handleReputationCheck} className="space-y-4">
                        <Input
                            placeholder="Enter domain, IP, or URL..."
                            value={repTarget}
                            onChange={(e) => setRepTarget(e.target.value)}
                        />
                        <Button type="submit" disabled={repLoading || !repTarget.trim()}>
                            {repLoading ? "Checking..." : "Check Reputation"}
                        </Button>
                    </form>

                    {repSearched && !repLoading && repResult && (
                        <div className="mt-4 pt-4 border-t border-gray-100">
                            <div className="text-center mb-4">
                                <div className="text-3xl font-bold mb-1">
                                    <span className={threatColor(repResult.threat_level)}>
                                        {repResult.reputation_score}
                                    </span>
                                    <span className="text-gray-300 text-lg">/100</span>
                                </div>
                                <div className={`inline-block px-3 py-1 rounded-full text-xs font-medium capitalize ${threatColor(repResult.threat_level)}`}>
                                    {repResult.threat_level}
                                </div>
                            </div>

                            {/* Score bar */}
                            <div className="w-full bg-gray-200 rounded-full h-3 mb-4">
                                <div
                                    className={`h-3 rounded-full transition-all ${threatBg(repResult.threat_level)}`}
                                    style={{ width: `${repResult.reputation_score}%` }}
                                />
                            </div>

                            <div className="text-xs text-gray-400">
                                <p><strong>Target:</strong> {repResult.target}</p>
                                <p><strong>Sources:</strong> {repResult.sources_checked.join(", ")}</p>
                                {repResult.details && Object.keys(repResult.details).length > 0 && (
                                    <p><strong>Matches:</strong> {JSON.stringify(repResult.details)}</p>
                                )}
                            </div>
                        </div>
                    )}

                    {repSearched && !repLoading && !repResult && (
                        <div className="mt-4 pt-4 border-t border-gray-100 text-center py-4 text-gray-400 text-sm">
                            Could not check reputation. Try again.
                        </div>
                    )}
                </Card>
            </div>
        </div>
    );
}
