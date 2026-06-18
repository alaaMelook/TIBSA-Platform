"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card, Button, Input } from "@/components/ui";
import { InfraSubHeader } from "@/components/infra-investigation/InfraSubHeader";
import {
  Sparkles,
  Search,
  Download,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
  Loader2,
  FileText,
  Copy,
  Check,
} from "lucide-react";
import { InfraInvestigationListItem, InfraInvestigationResults } from "@/types/infra_investigation";

export default function InfraReportsPage() {
  const router = useRouter();
  const { token } = useAuth();

  const [history, setHistory] = useState<InfraInvestigationListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Search filter
  const [searchQuery, setSearchQuery] = useState("");

  // Detailed dynamic report modal state
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [selectedReportDetails, setSelectedReportDetails] = useState<any | null>(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Fetch completed scanner results
  const fetchCompletedHistory = useCallback(async () => {
    if (!token) return;
    try {
      setIsLoading(true);
      const res = await api.infraInvestigations.list(token);
      if (res?.success && res?.data) {
        // Filter strictly completed
        const completed = res.data.filter((h: InfraInvestigationListItem) => h.status === "completed");
        setHistory(completed);
      }
    } catch (err) {
      console.error("Failed to load completed investigations:", err);
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchCompletedHistory();
  }, [fetchCompletedHistory]);

  // Handle fuzzy search
  const filteredReports = useMemo(() => {
    if (!searchQuery.trim()) return history;
    const q = searchQuery.toLowerCase();
    return history.filter((h) => h.target.toLowerCase().includes(q));
  }, [history, searchQuery]);

  // Load detailed report dynamically
  const handleViewReport = async (id: string) => {
    if (!token) return;
    setSelectedReportId(id);
    setIsDetailLoading(true);
    setSelectedReportDetails(null);
    try {
      const res = await api.infraInvestigations.get(id, token);
      if (res?.success && res?.data) {
        setSelectedReportDetails(res.data);
      }
    } catch (err) {
      console.error("Failed to load report detail:", err);
    } finally {
      setIsDetailLoading(false);
    }
  };

  // Copy report summary utility
  const handleCopySummary = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Download raw JSON
  const handleDownloadJson = (data: any) => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `TIBSA-Intelligence-Report-${data.target}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* SubHeader Component */}
      <InfraSubHeader />

      {/* Main Grid: List on Left, Detail Modal Panel on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Side: Reports List */}
        <div className="lg:col-span-1 space-y-4">
          <Card title="AI Intelligence Briefs" description="Select a completed pipeline scan to read its AI risk report summary">
            
            {/* Search input */}
            <div className="relative mb-4">
              <Search className="absolute left-3 top-3 w-4 h-4 text-[var(--text-muted)]" />
              <Input
                placeholder="Search report by target..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 bg-[var(--bg-page)]/40 border-[var(--border-soft)]"
              />
            </div>

            {isLoading ? (
              <div className="py-12 text-center text-[var(--text-muted)] font-medium">
                <span className="inline-block animate-spin mr-2 h-4 w-4 border-2 border-emerald-500 border-t-transparent rounded-full" />
                Loading reports...
              </div>
            ) : filteredReports.length === 0 ? (
              <div className="py-12 text-center text-[var(--text-muted)]">
                <FileText className="w-8 h-8 mx-auto mb-2 opacity-25" />
                <p className="text-sm font-semibold">No completed AI reports found.</p>
                <p className="text-[10px] text-[var(--text-muted)] mt-1">Complete an investigation with AI Summaries enabled to generate a report briefing.</p>
              </div>
            ) : (
              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                {filteredReports.map((report) => {
                  const isActive = selectedReportId === report.id;
                  const isHigh = report.risk_score >= 50;

                  return (
                    <div
                      key={report.id}
                      onClick={() => handleViewReport(report.id)}
                      className={`p-3 rounded-xl border transition-all cursor-pointer flex items-center justify-between group ${
                        isActive
                          ? "border-[var(--primary)]/50 bg-emerald-500/[0.04]"
                          : "border-[var(--border-soft)] bg-[var(--bg-page)]/20 hover:bg-[var(--bg-elevated)]"
                      }`}
                    >
                      <div className="min-w-0 space-y-1">
                        <p className="text-xs font-bold text-[var(--text-primary)] truncate font-mono">{report.target}</p>
                        <div className="flex items-center gap-1.5">
                          <span className="text-[8px] font-extrabold uppercase px-1 py-0.5 rounded bg-[var(--primary)]/10 border border-[var(--primary)]/20 text-[var(--primary)]">
                            {report.target_type}
                          </span>
                          <span className={`text-[10px] font-mono font-bold ${isHigh ? "text-red-400" : "text-emerald-400"}`}>
                            Risk: {Math.round(report.risk_score)}
                          </span>
                        </div>
                      </div>
                      <ChevronRight className={`w-4 h-4 text-[var(--text-muted)] transition-transform ${
                        isActive ? "translate-x-0.5 text-[var(--primary)]" : "group-hover:translate-x-0.5"
                      }`} />
                    </div>
                  );
                })}
              </div>
            )}
          </Card>
        </div>

        {/* Right Side: Detailed AI Executive Briefing View */}
        <div className="lg:col-span-2">
          {selectedReportId ? (
            <Card
              title="Intelligence Synthesis Report"
              description="Real-time multi-feed security analysis aggregated by OpenRouter AI"
            >
              {isDetailLoading ? (
                <div className="py-32 flex flex-col items-center justify-center space-y-3">
                  <Loader2 className="w-8 h-8 text-[var(--primary)] animate-spin" />
                  <p className="text-xs text-[var(--text-muted)]">Decrypting and assembling AI summaries...</p>
                </div>
              ) : selectedReportDetails ? (
                <div className="space-y-6 animate-fadeIn">
                  
                  {/* Detailed Summary Header */}
                  <div className="flex flex-wrap items-center justify-between bg-[var(--bg-page)]/50 border border-[var(--border-soft)] p-4 rounded-xl gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-[var(--text-primary)]">{selectedReportDetails.target}</span>
                        <span className="text-[8px] font-extrabold uppercase px-1.5 py-0.5 rounded bg-[var(--primary)]/10 border border-[var(--primary)]/20 text-[var(--primary)]">
                          {selectedReportDetails.target_type}
                        </span>
                      </div>
                      <p className="text-[10px] text-[var(--text-muted)]">
                        Scan ID: <span className="font-mono">{selectedReportDetails.id}</span>
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => handleDownloadJson(selectedReportDetails)}
                        className="!px-3 !py-1 text-[11px] font-bold gap-1"
                      >
                        <Download className="w-3.5 h-3.5" /> Export JSON
                      </Button>
                      <Button
                        variant="primary"
                        size="sm"
                        onClick={() => router.push(`/dashboard/infra-investigations/${selectedReportDetails.id}`)}
                        className="!px-3 !py-1 text-[11px] font-bold gap-1 !bg-emerald-600 hover:!bg-emerald-500 shadow-lg shadow-emerald-600/20"
                      >
                        <ExternalLink className="w-3.5 h-3.5" /> Open Workspace
                      </Button>
                    </div>
                  </div>

                  {/* AI Attribution Box */}
                  {selectedReportDetails.results?.ai_summary ? (
                    <div className="space-y-5">
                      
                      {/* Classification Badge Row */}
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                        <div className="bg-[var(--bg-card)] border border-[var(--border-strong)] rounded-lg p-3">
                          <p className="text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Classification</p>
                          <p className="text-xs font-bold text-[var(--text-primary)] mt-1">
                            {selectedReportDetails.results.ai_summary.threat_classification || "Unknown IOC"}
                          </p>
                        </div>
                        <div className="bg-[var(--bg-card)] border border-[var(--border-strong)] rounded-lg p-3">
                          <p className="text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-wider">Risk Level</p>
                          <p className={`text-xs font-extrabold mt-1 ${
                            selectedReportDetails.risk_score >= 75 ? "text-red-500" :
                            selectedReportDetails.risk_score >= 50 ? "text-red-400" : "text-emerald-400"
                          }`}>
                            {selectedReportDetails.results.risk?.risk_label || "Unknown"} ({Math.round(selectedReportDetails.risk_score)}/100)
                          </p>
                        </div>
                        <div className="bg-[var(--bg-card)] border border-[var(--border-strong)] rounded-lg p-3 col-span-2 md:col-span-1">
                          <p className="text-[9px] font-bold text-[var(--text-muted)] uppercase tracking-wider">AI Attribution Confidence</p>
                          <p className="text-xs font-bold text-[var(--primary)] mt-1">
                            {selectedReportDetails.results.ai_summary.confidence || 85}%
                          </p>
                        </div>
                      </div>

                      {/* Executive Summary */}
                      <div className="bg-[var(--bg-page)]/20 border border-[var(--border-soft)] p-4 rounded-xl space-y-2.5 relative group">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
                            <Sparkles className="w-3.5 h-3.5 text-[var(--primary)] animate-pulse" />
                            Executive Risk Summary
                          </h4>
                          <button
                            onClick={() => handleCopySummary(selectedReportDetails.results.ai_summary.executive_summary)}
                            className="p-1 rounded bg-[var(--bg-card)] border border-[var(--border-soft)] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                          >
                            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                        <p className="text-xs text-[var(--text-muted)] leading-relaxed font-normal whitespace-pre-line">
                          {selectedReportDetails.results.ai_summary.executive_summary}
                        </p>
                      </div>

                      {/* Attribution evidence details */}
                      <div className="space-y-3">
                        <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                          Risk Indicators & Evidence
                        </h4>
                        <div className="border border-[var(--border-soft)] bg-[var(--bg-page)]/15 rounded-xl p-4 space-y-2">
                          <p className="text-xs text-[var(--text-muted)] font-normal">
                            {selectedReportDetails.results.ai_summary.why_suspicious}
                          </p>
                        </div>
                      </div>

                      {/* Playbooks & recommendations */}
                      <div className="space-y-3">
                        <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
                          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                          Priority Playbooks & Playlists
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {selectedReportDetails.results.ai_summary.recommended_actions?.map((act: string, idx: number) => (
                            <div key={idx} className="bg-[var(--bg-page)]/20 border border-[var(--border-soft)] rounded-lg p-3 flex items-start gap-2.5">
                              <span className="flex-shrink-0 w-5 h-5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center text-[10px] font-black">
                                {idx + 1}
                              </span>
                              <p className="text-[11px] text-[var(--text-muted)] font-semibold leading-normal">{act}</p>
                            </div>
                          ))}
                        </div>
                      </div>

                    </div>
                  ) : (
                    <div className="py-20 text-center text-[var(--text-muted)]">
                      <AlertTriangle className="w-10 h-10 mx-auto mb-2 text-amber-500/60" />
                      <p className="text-sm font-semibold">No AI report summary generated.</p>
                      <p className="text-xs text-[var(--text-muted)] mt-1">This investigation may have been run without enabling the AI Synthesis block.</p>
                    </div>
                  )}

                </div>
              ) : null}
            </Card>
          ) : (
            <div className="border border-dashed border-[var(--border-strong)] rounded-2xl flex flex-col items-center justify-center p-20 text-center min-h-[450px]">
              <Sparkles className="w-10 h-10 text-[var(--primary)]/30 animate-pulse mb-3" />
              <h3 className="text-[var(--text-secondary)] font-semibold">Executive Threat Briefing</h3>
              <p className="text-xs text-[var(--text-muted)] max-w-sm mt-1">Select an intelligence scan report on the left panel to load and analyze detailed attribution breakdowns.</p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
