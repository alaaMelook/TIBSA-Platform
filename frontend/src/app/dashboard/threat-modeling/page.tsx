"use client";

import { useState, useCallback } from "react";
import { Card, Button, Input } from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { ScanHistory } from "./scan-history";
import { notifySuccess, notifyError, notifyWarning } from "@/lib/notify";

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

type AppType = "Web" | "Mobile" | "API" | "Cloud";
type RiskLevel = "High" | "Medium" | "Low";
type DeployEnv = "On-Premise" | "Cloud (AWS / GCP / Azure)" | "Hybrid" | "Serverless" | "Containerized (Docker / K8s)" | "Edge";
type DeployType = "SaaS" | "Internal Tool" | "Open Source" | "Enterprise" | "B2C Product" | "IoT / Embedded";
type DatabaseType = "PostgreSQL" | "MySQL / MariaDB" | "MongoDB" | "Redis" | "SQLite" | "Elasticsearch" | "Firebase / Firestore" | "DynamoDB" | "MSSQL" | "Oracle";
type ProtocolType = "HTTPS" | "HTTP (plain)" | "WebSocket / WSS" | "gRPC" | "GraphQL" | "REST" | "MQTT" | "AMQP" | "FTP / SFTP" | "SSH";
type FrameworkType = "React" | "Next.js" | "Vue" | "Angular" | "Svelte" | "Django" | "FastAPI" | "Flask" | "Express" | "NestJS" | "Spring Boot" | "Laravel" | "Rails" | "ASP.NET";
type LanguageType = "TypeScript" | "JavaScript" | "Python" | "Java" | "Go" | "PHP" | "Ruby" | "C#" | "Rust" | "C / C++";

interface FormState {
    // Section 1 – Basic
    projectName: string;
    appType: AppType;
    usesAuth: boolean;
    usesDatabase: boolean;
    hasAdminPanel: boolean;
    usesExternalAPIs: boolean;
    storesSensitiveData: boolean;
    // Section 2 – Stack
    frameworks: FrameworkType[];
    languages: LanguageType[];
    // Section 3 – Environment
    deployEnvs: DeployEnv[];
    deployTypes: DeployType[];
    // Section 4 – Data & Protocols
    databases: DatabaseType[];
    protocols: ProtocolType[];
}

interface ThreatItem {
    id: string;
    title: string;
    risk: RiskLevel;
    category: string;
    description: string;
    mitigation: string;
    priority?: number;
    stride_category?: string;
}

interface AnalysisResult {
    threats: ThreatItem[];
    riskScore: number | null;
    genericWarning?: boolean;
    blocked?: boolean;
    riskLabel?: string | null;
}

// ─────────────────────────────────────────────────────────────────────
// Static option sets
// ─────────────────────────────────────────────────────────────────────

const APP_TYPES: AppType[] = ["Web", "Mobile", "API", "Cloud"];
const DEPLOY_ENVS: DeployEnv[] = ["On-Premise", "Cloud (AWS / GCP / Azure)", "Hybrid", "Serverless", "Containerized (Docker / K8s)", "Edge"];
const DEPLOY_TYPES: DeployType[] = ["SaaS", "Internal Tool", "Open Source", "Enterprise", "B2C Product", "IoT / Embedded"];
const DATABASE_OPTS: DatabaseType[] = ["PostgreSQL", "MySQL / MariaDB", "MongoDB", "Redis", "SQLite", "Elasticsearch", "Firebase / Firestore", "DynamoDB", "MSSQL", "Oracle"];
const PROTOCOL_OPTS: ProtocolType[] = ["HTTPS", "HTTP (plain)", "WebSocket / WSS", "gRPC", "GraphQL", "REST", "MQTT", "AMQP", "FTP / SFTP", "SSH"];
const FRAMEWORK_OPTS: FrameworkType[] = ["React", "Next.js", "Vue", "Angular", "Svelte", "Django", "FastAPI", "Flask", "Express", "NestJS", "Spring Boot", "Laravel", "Rails", "ASP.NET"];
const LANGUAGE_OPTS: LanguageType[] = ["TypeScript", "JavaScript", "Python", "Java", "Go", "PHP", "Ruby", "C#", "Rust", "C / C++"];

const CHECKBOXES: { key: keyof FormState; label: string }[] = [
    { key: "usesAuth", label: "Uses Authentication" },
    { key: "usesDatabase", label: "Uses Database" },
    { key: "hasAdminPanel", label: "Has Admin Panel" },
    { key: "usesExternalAPIs", label: "Uses External APIs" },
    { key: "storesSensitiveData", label: "Stores Sensitive Data" },
];

const initialForm: FormState = {
    projectName: "", appType: "Web",
    usesAuth: false, usesDatabase: false, hasAdminPanel: false,
    usesExternalAPIs: false, storesSensitiveData: false,
    frameworks: [], languages: [],
    deployEnvs: [], deployTypes: [],
    databases: [], protocols: [],
};

// ─────────────────────────────────────────────────────────────────────
// Risk helpers
// ─────────────────────────────────────────────────────────────────────

const RISK_BADGE: Record<RiskLevel, string> = {
    High: "bg-red-500/15 text-red-400 border border-red-500/20",
    Medium: "bg-orange-500/15 text-orange-400 border border-orange-500/20",
    Low: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/20",
};

const RISK_DOT: Record<RiskLevel, string> = {
    High: "bg-red-500", Medium: "bg-orange-400", Low: "bg-yellow-400",
};

const SCORE_COLOR: Record<string, string> = {
    Critical: "bg-red-600", High: "bg-red-500", Medium: "bg-orange-400", Low: "bg-green-500",
};

const SCORE_LABEL_STYLE: Record<string, string> = {
    Critical: "bg-red-500/15 text-red-400",
    High: "bg-red-500/15 text-red-400",
    Medium: "bg-orange-500/15 text-orange-400",
    Low: "bg-green-500/15 text-green-400",
};

function getRiskLabel(score: number | null): string {
    if (score === null) return "Insufficient Data";
    if (score >= 80) return "Critical";
    if (score >= 60) return "High";
    if (score >= 35) return "Medium";
    return "Low";
}

// ─────────────────────────────────────────────────────────────────────
// Threat generation engine
// ─────────────────────────────────────────────────────────────────────


// ─────────────────────────────────────────────────────────────────────
// Reusable sub-components
// ─────────────────────────────────────────────────────────────────────

type PillColor = "blue" | "indigo" | "violet" | "teal" | "emerald" | "rose";

const PILL_ACTIVE: Record<PillColor, string> = {
    blue: "bg-[var(--primary)] !text-white border-[var(--primary)]",
    indigo: "bg-[var(--primary)] !text-white border-[var(--primary)]",
    violet: "bg-[var(--primary)] !text-white border-[var(--primary)]",
    teal: "bg-[var(--primary)] !text-white border-[var(--primary)]",
    emerald: "bg-[var(--primary)] !text-white border-[var(--primary)]",
    rose: "bg-[var(--primary)] !text-white border-[var(--primary)]",
};

const PILL_HOVER: Record<PillColor, string> = {
    blue: "hover:border-[var(--primary)] hover:text-[var(--primary)]",
    indigo: "hover:border-[var(--primary)] hover:text-[var(--primary)]",
    violet: "hover:border-[var(--primary)] hover:text-[var(--primary)]",
    teal: "hover:border-[var(--primary)] hover:text-[var(--primary)]",
    emerald: "hover:border-[var(--primary)] hover:text-[var(--primary)]",
    rose: "hover:border-[var(--primary)] hover:text-[var(--primary)]",
};

function MultiPillSelect<T extends string>({
    label, hint, options, selected, onToggle, color = "blue",
}: {
    label: string; hint?: string; options: T[];
    selected: T[]; onToggle: (v: T) => void; color?: PillColor;
}) {
    return (
        <div>
            <div className="mb-3">
                <span className="block text-sm font-semibold text-[var(--text-primary)]">{label}</span>
                {hint && <span className="block text-[11px] font-medium text-[var(--text-muted)] mt-1 uppercase tracking-wider">{hint}</span>}
            </div>
            <div className="flex flex-wrap gap-2">
                {options.map((opt) => {
                    const active = selected.includes(opt);
                    return (
                        <button
                            key={opt}
                            type="button"
                            onClick={() => onToggle(opt)}
                            className={`px-3 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 motion-reduce:transition-colors motion-reduce:hover:transform-none ${
                                active
                                    ? 'bg-[#edf8f3] border border-[#0f9d76] text-[#0f9d76]'
                                    : 'bg-[#ffffff] border border-[#e7ddd1] text-[#1d1d1d] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76]'
                            }`}
                        >
                            {opt}
                        </button>
                    );
                })}
            </div>
            {selected.length > 0 && (
                <p className="mt-3 text-[11px] font-medium text-[var(--text-muted)] bg-[var(--bg-elevated)] inline-block px-3 py-1.5 rounded-md border border-[var(--border-soft)]">
                    <span className="text-emerald-400 mr-1.5">✓</span>
                    {selected.join(" • ")}
                </p>
            )}
        </div>
    );
}

function SectionDivider({ label }: { label: string }) {
    return (
        <div className="flex items-center gap-4 py-2">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/[0.1] to-transparent" />
            <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-widest whitespace-nowrap">
                {label}
            </span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/[0.1] to-transparent" />
        </div>
    );
}

function CollapsibleSection({ 
    title, 
    description, 
    icon, 
    children, 
    defaultOpen = true 
}: { 
    title: string; 
    description: string; 
    icon: React.ReactNode; 
    children: React.ReactNode; 
    defaultOpen?: boolean;
}) {
    const [isOpen, setIsOpen] = useState(defaultOpen);
    return (
        <div className="bg-[var(--bg-card)] backdrop-blur-md rounded-2xl border border-[var(--border-soft)] shadow-sm overflow-hidden transition-all duration-300 hover:border-[var(--primary)] group">
            <button 
                type="button" 
                onClick={() => setIsOpen(!isOpen)} 
                className="w-full flex items-center justify-between p-5 text-left transition-all duration-180 active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 rounded-2xl motion-reduce:transition-colors motion-reduce:hover:transform-none"
            >
                <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-xl bg-[#edf8f3] flex items-center justify-center border border-[#0f9d76] text-[#0f9d76] group-hover:bg-[#0f9d76] group-hover:text-[#ffffff] transition-all duration-180">
                        {icon}
                    </div>
                    <div>
                        <h3 className="text-base font-bold text-[#1d1d1d] tracking-wide group-hover:text-[#0f9d76] transition-colors">{title}</h3>
                        <p className="text-[11px] font-medium text-[#8a8178] mt-1 uppercase tracking-wider">{description}</p>
                    </div>
                </div>
                <div className={`w-8 h-8 rounded-full bg-[#f8f3eb] flex items-center justify-center transition-transform duration-180 ${isOpen ? 'rotate-180' : ''}`}>
                    <svg className="w-4 h-4 text-[#4f4a45] group-hover:text-[#0f9d76] transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                    </svg>
                </div>
            </button>
            <div className={`transition-all duration-500 ease-in-out origin-top ${isOpen ? 'max-h-[2000px] opacity-100 scale-y-100' : 'max-h-0 opacity-0 scale-y-95 pointer-events-none'}`}>
                <div className="p-6 pt-2 border-t border-[var(--border-soft)]">
                    {children}
                </div>
            </div>
        </div>
    );
}

function formatBytes(b: number): string {
    if (b === 0) return "0 B";
    if (b < 1024) return `${b} B`;
    if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
    return `${(b / 1048576).toFixed(1)} MB`;
}

// ─────────────────────────────────────────────────────────────────────
// Main Page Component
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────
// PDF generation (pure client-side, no external lib needed)
// ─────────────────────────────────────────────────────────────────────

function buildPdfHtml(form: FormState, result: AnalysisResult): string {
    const riskColor: Record<string, string> = {
        High: "#ef4444", Medium: "#f97316", Low: "#eab308", Critical: "#dc2626",
    };
    const label = getRiskLabel(result.riskScore);
    const now = new Date().toLocaleString();
    const stackTags = [...form.frameworks, ...form.languages, ...form.deployEnvs, ...form.deployTypes, ...form.databases, ...form.protocols];

    const threatsHtml = result.threats.map(t => `
        <div style="margin-bottom:16px;padding:14px;border:1px solid #e2e8f0;border-radius:8px;border-left:4px solid ${riskColor[t.risk] || "#94a3b8"}">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                <span style="font-weight:700;font-size:15px;color:#1e293b">${t.title}</span>
                <span style="font-size:12px;font-weight:600;color:${riskColor[t.risk]};background:${riskColor[t.risk]}22;padding:2px 10px;border-radius:999px;border:1px solid ${riskColor[t.risk]}44">${t.risk}</span>
            </div>
            <div style="font-size:11px;color:#64748b;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em">${t.category}</div>
            <p style="font-size:13px;color:#475569;margin:0 0 8px 0;line-height:1.6"><strong>Risk:</strong> ${t.description}</p>
            <p style="font-size:13px;color:#0f766e;margin:0;line-height:1.6;background:#f0fdf4;padding:8px;border-radius:6px"><strong>✅ Mitigation:</strong> ${t.mitigation}</p>
        </div>`).join("");

    const tagsHtml = stackTags.length > 0
        ? stackTags.map(t => `<span style="display:inline-block;padding:3px 10px;margin:3px;background:#eff6ff;color:#1d4ed8;border-radius:999px;font-size:12px;border:1px solid #bfdbfe">${t}</span>`).join("")
        : "<span style='color:#94a3b8;font-size:13px'>None selected</span>";

    const highCount = result.threats.filter(t => t.risk === "High").length;
    const medCount = result.threats.filter(t => t.risk === "Medium").length;
    const lowCount = result.threats.filter(t => t.risk === "Low").length;

    return `<!DOCTYPE html><html><head><meta charset="utf-8">
    <title>Threat Report — ${form.projectName}</title>
    <style>
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:32px;color:#1e293b;background:#fff}
        @media print{body{padding:0}}
        h1{margin:0;font-size:26px} h2{font-size:17px;margin:24px 0 12px;color:#1e293b;border-bottom:2px solid #e2e8f0;padding-bottom:6px}
        .badge{display:inline-block;padding:4px 14px;border-radius:999px;font-weight:700;font-size:13px}
        table{width:100%;border-collapse:collapse;font-size:13px} td{padding:6px 10px;border-bottom:1px solid #f1f5f9} td:first-child{color:#64748b;width:160px}
    </style></head><body>
    <div style="background:linear-gradient(135deg,#1d4ed8,#1e40af);color:white;padding:28px 32px;border-radius:12px;margin-bottom:28px">
        <div style="font-size:12px;text-transform:uppercase;letter-spacing:0.1em;opacity:0.7;margin-bottom:6px">TIBSA · Security Analysis · TMaaS</div>
        <h1>Threat Report — ${form.projectName}</h1>
        <div style="opacity:0.8;margin-top:6px;font-size:14px">${form.appType} Application · Generated ${now}</div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px;margin-bottom:24px">
        <div style="padding:16px;background:#fef2f2;border-radius:10px;text-align:center;border:1px solid #fecaca">
            <div style="font-size:28px;font-weight:800;color:#ef4444">${highCount}</div>
            <div style="font-size:12px;color:#b91c1c;font-weight:600">HIGH RISK</div>
        </div>
        <div style="padding:16px;background:#fff7ed;border-radius:10px;text-align:center;border:1px solid #fed7aa">
            <div style="font-size:28px;font-weight:800;color:#f97316">${medCount}</div>
            <div style="font-size:12px;color:#c2410c;font-weight:600">MEDIUM RISK</div>
        </div>
        <div style="padding:16px;background:#fefce8;border-radius:10px;text-align:center;border:1px solid #fde68a">
            <div style="font-size:28px;font-weight:800;color:#eab308">${lowCount}</div>
            <div style="font-size:12px;color:#a16207;font-weight:600">LOW RISK</div>
        </div>
        <div style="padding:16px;background:#f0f9ff;border-radius:10px;text-align:center;border:1px solid #bae6fd">
            <div style="font-size:28px;font-weight:800;color:${riskColor[label] || "#0ea5e9"}">${result.riskScore}</div>
            <div style="font-size:12px;color:#0369a1;font-weight:600">RISK SCORE</div>
        </div>
    </div>

    <h2>Project Information</h2>
    <table>
        <tr><td>Project Name</td><td><strong>${form.projectName}</strong></td></tr>
        <tr><td>App Type</td><td>${form.appType}</td></tr>
        <tr><td>Risk Label</td><td><span class="badge" style="background:${riskColor[label]}22;color:${riskColor[label]};border:1px solid ${riskColor[label]}44">${label}</span></td></tr>
        <tr><td>Uses Auth</td><td>${form.usesAuth ? "✅ Yes" : "❌ No"}</td></tr>
        <tr><td>Uses Database</td><td>${form.usesDatabase ? "✅ Yes" : "❌ No"}</td></tr>
        <tr><td>Admin Panel</td><td>${form.hasAdminPanel ? "✅ Yes" : "❌ No"}</td></tr>
        <tr><td>External APIs</td><td>${form.usesExternalAPIs ? "✅ Yes" : "❌ No"}</td></tr>
        <tr><td>Sensitive Data</td><td>${form.storesSensitiveData ? "✅ Yes" : "❌ No"}</td></tr>
    </table>

    <h2>Technology Stack</h2>
    <div style="margin-bottom:8px">${tagsHtml}</div>

    <h2>Identified Threats (${result.threats.length})</h2>
    ${threatsHtml}

    <div style="margin-top:32px;padding:14px;background:#f8fafc;border-radius:8px;font-size:12px;color:#94a3b8;text-align:center;border:1px solid #e2e8f0">
        Generated by TIBSA Platform · Threat Modeling as a Service · ${now}
    </div>
    </body></html>`;
}

function downloadAsPDF(form: FormState, result: AnalysisResult) {
    const html = buildPdfHtml(form, result);
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const win = window.open(url, "_blank");
    if (win) {
        win.addEventListener("load", () => {
            setTimeout(() => {
                win.print();
                URL.revokeObjectURL(url);
            }, 400);
        });
    }
}

function downloadAsJSON(form: FormState, result: AnalysisResult) {
    const now = new Date().toISOString();
    const jsonData = {
        metadata: {
            generated_at: now,
            generator: "TIBSA Platform - Threat Modeling as a Service",
            version: "1.0",
            framework: "STRIDE"
        },
        project: {
            name: form.projectName,
            app_type: form.appType,
            uses_auth: form.usesAuth,
            uses_database: form.usesDatabase,
            has_admin_panel: form.hasAdminPanel,
            uses_external_apis: form.usesExternalAPIs,
            stores_sensitive_data: form.storesSensitiveData
        },
        technology_stack: {
            frameworks: form.frameworks,
            languages: form.languages,
            databases: form.databases,
            protocols: form.protocols
        },
        deployment: {
            environments: form.deployEnvs,
            types: form.deployTypes
        },
        analysis: {
            risk_score: result.riskScore,
            risk_label: getRiskLabel(result.riskScore),
            total_threats: result.threats.length,
            threats: result.threats.map(t => ({
                id: t.id,
                title: t.title,
                risk: t.risk,
                category: t.category,
                description: t.description,
                mitigation: t.mitigation
            }))
        }
    };

    const jsonString = JSON.stringify(jsonData, null, 2);
    const blob = new Blob([jsonString], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `threat-model-${form.projectName.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase()}-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

export default function ThreatModelingPage() {
    const { token, isLoading, isAuthenticated } = useAuth();
    const [form, setForm] = useState<FormState>(initialForm);
    const [result, setResult] = useState<AnalysisResult | null>(null);
    const [isSaving, setIsSaving] = useState(false);
    const [autoSaved, setAutoSaved] = useState(false);
    const [nameError, setNameErr] = useState("");
    const [showWarning, setShowWarning] = useState(false);

    const canSubmit = !!token && !isLoading;
    const canSave = !!token && !isSaving;

    // Generic array toggle
    const toggleArr = useCallback(<T extends string>(key: keyof FormState, val: T) => {
        setForm(prev => {
            const arr = prev[key] as T[];
            const next = arr.includes(val) ? arr.filter(v => v !== val) : [...arr, val];
            return { ...prev, [key]: next };
        });
    }, []);

    const toggleBool = (key: keyof FormState) =>
        setForm(prev => ({ ...prev, [key]: !prev[key] }));

    // Form submit
    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!form.projectName.trim()) { setNameErr("Project name is required."); return; }
        setNameErr("");

        if (!token) {
            setResult({
                threats: [{
                    id: "auth-required",
                    title: "Authentication Required",
                    risk: "High",
                    category: "Authorization",
                    description: "Please sign in and reload the page before generating a threat model.",
                    mitigation: "Log in and try again.",
                }],
                riskScore: 0,
            });
            return;
        }

        // Set loading state with analysis info
        const loadingResult: AnalysisResult = {
            threats: [{
                id: "analysis-loading",
                title: "Analyzing your system…",
                risk: "Low",
                category: "Analysis",
                description: `Scanning threat landscape based on your inputs: ${form.appType} application using ${form.frameworks.length > 0 ? form.frameworks.join(", ") : "selected frameworks"} with ${form.databases.length > 0 ? form.databases.join(", ") : "selected databases"}. This analysis evaluates all STRIDE threat categories.`,
                mitigation: "Please wait while the threat modeling engine generates detailed vulnerability assessments...",
            }],
            riskScore: 0
        };
        setResult(loadingResult);

        try {
            // Transform form data to match backend API
            const requestData = {
                project_name: form.projectName,
                app_type: form.appType,
                uses_auth: form.usesAuth,
                uses_database: form.usesDatabase,
                has_admin_panel: form.hasAdminPanel,
                uses_external_apis: form.usesExternalAPIs,
                stores_sensitive_data: form.storesSensitiveData,
                frameworks: form.frameworks,
                languages: form.languages,
                deploy_envs: form.deployEnvs,
                deploy_types: form.deployTypes,
                databases: form.databases,
                protocols: form.protocols,
            };

            // Call STRIDE analysis endpoint
            const response = await api.post<{
                threats?: Array<{
                    id?: string;
                    title: string;
                    risk: string;
                    category: string;
                    description: string;
                    mitigation: string;
                    priority_score?: number;
                    stride_category?: string;
                }>;
                risk_score: number | null;
                generic_warning?: boolean;
                blocked?: boolean;
            }>("/api/v1/threat-modeling/analyze/stride", requestData, token);

            // Transform backend response to frontend format
            const transformedResponse: AnalysisResult = {
                threats: (response.threats || []).map((threat) => ({
                    id: threat.id || threat.title.toLowerCase().replace(/\s+/g, "-"),
                    title: threat.title,
                    risk: threat.risk as RiskLevel,
                    category: threat.category,
                    description: threat.description,
                    mitigation: threat.mitigation,
                    priority: threat.priority_score,
                    stride_category: threat.stride_category,
                })),
                riskScore: response.risk_score,
                genericWarning: response.generic_warning,
                blocked: response.blocked,
            };

            setResult(transformedResponse);

            if (
                transformedResponse.blocked === true ||
                !transformedResponse.threats ||
                transformedResponse.threats.length === 0
            ) {
                setResult({
                    threats: [],
                    riskScore: null,
                    riskLabel: null,
                    blocked: true
                });
                return;
            }
            setShowWarning(!!response.generic_warning);

            // ── Auto-save to database ──
            if (token) {
                setIsSaving(true);
                setAutoSaved(false);
                try {
                    await api.post(
                        "/api/v1/threat-modeling/analyses",
                        {
                            project_name: form.projectName,
                            app_type: form.appType,
                            uses_auth: form.usesAuth,
                            uses_database: form.usesDatabase,
                            has_admin_panel: form.hasAdminPanel,
                            uses_external_apis: form.usesExternalAPIs,
                            stores_sensitive_data: form.storesSensitiveData,
                            frameworks: form.frameworks,
                            languages: form.languages,
                            deploy_envs: form.deployEnvs,
                            deploy_types: form.deployTypes,
                            databases: form.databases,
                            protocols: form.protocols,
                        },
                        token,
                    );
                    setAutoSaved(true);
                    notifySuccess("Report auto-saved", "Threat model report was auto-saved to your history.");
                } catch {
                    notifyWarning("Auto-save failed", "You can save manually if needed.");
                } finally {
                    setIsSaving(false);
                }
            }
        } catch (error) {
            console.error("STRIDE analysis failed:", error);
            // Fallback to a basic error result
            const errorResult: AnalysisResult = {
                threats: [{
                    id: "analysis-error",
                    title: "Analysis Error",
                    risk: "High",
                    category: "System Error",
                    description: "Failed to perform STRIDE threat analysis. Please check your connection and try again.",
                    mitigation: "Ensure the backend service is running and accessible.",
                }],
                riskScore: 50,
            };
            setResult(errorResult);
        }

        setTimeout(() => window.scrollTo({ top: 0, behavior: "smooth" }), 50);
    };

    const handleReset = () => { setForm(initialForm); setResult(null); setNameErr(""); setShowWarning(false); setAutoSaved(false); };

    const handleSave = async () => {
        if (!result || !token) return;
        setIsSaving(true);
        try {
            await api.post(
                "/api/v1/threat-modeling/analyses",
                {
                    project_name: form.projectName,
                    app_type: form.appType,
                    uses_auth: form.usesAuth,
                    uses_database: form.usesDatabase,
                    has_admin_panel: form.hasAdminPanel,
                    uses_external_apis: form.usesExternalAPIs,
                    stores_sensitive_data: form.storesSensitiveData,
                    frameworks: form.frameworks,
                    languages: form.languages,
                    deploy_envs: form.deployEnvs,
                    deploy_types: form.deployTypes,
                    databases: form.databases,
                    protocols: form.protocols,
                },
                token,
            );
            notifySuccess("Report saved", "You can view it in the Reports page.");
        } catch (err) {
            notifyError("Failed to save", err instanceof Error ? err.message : "Unknown error");
        } finally {
            setIsSaving(false);
        }
    };

    const handleDownloadPDF = () => {
        if (!result) return;
        downloadAsPDF(form, result);
    };

    const handleDownloadJSON = () => {
        if (!result) return;
        downloadAsJSON(form, result);
    };

    const riskLabel = result ? getRiskLabel(result.riskScore) : "";
    const barColor = SCORE_COLOR[riskLabel] ?? "bg-[var(--bg-elevated)]";
    const labelStyle = SCORE_LABEL_STYLE[riskLabel] ?? "";

    // Compact summary of selected options for the report header
    const stackTags = [...form.frameworks, ...form.languages, ...form.deployEnvs, ...form.deployTypes, ...form.databases, ...form.protocols];

    // ── Render ────────────────────────────────────────────────
    return (
        <div className="space-y-8 print:p-8 w-full max-w-none pb-16">

            {/* ════════════════════ HERO ════════════════════ */}
            <div 
                className="relative rounded-2xl overflow-hidden print:hidden border shadow-xl metric-card-animated"
                style={{
                    background: "radial-gradient(circle at center, rgba(15, 157, 118, 0.16), transparent 45%), linear-gradient(135deg, #edf8f3 0%, #fffaf4 55%, #dff5ec 100%)",
                    borderColor: "rgba(15, 157, 118, 0.25)",
                    boxShadow: "0 18px 40px rgba(15, 157, 118, 0.10)"
                }}
            >
                <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-[#0f9d76]/40 to-transparent opacity-50" />
                
                <div className="relative px-8 py-14 flex flex-col items-center text-center">
                    <div className="relative w-16 h-16 mb-6">
                        <div className="absolute inset-0 bg-[var(--primary)]/20 rounded-full blur-xl animate-pulse" />
                        <div className="relative w-full h-full rounded-2xl bg-[var(--primary-soft)] border border-[var(--primary)] flex items-center justify-center shadow-sm">
                            <svg className="w-8 h-8 text-[var(--primary)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                        </div>
                    </div>
                    
                    <h1 className="text-4xl sm:text-5xl font-extrabold mb-4 tracking-tight text-[var(--text-primary)]">
                        Threat Modeling
                        <span className="text-[var(--primary)] ml-2">
                            as a Service
                        </span>
                    </h1>
                    
                    <p className="text-[var(--text-muted)] text-lg max-w-2xl mb-10 font-medium leading-relaxed">
                        Proactively discover architectural vulnerabilities and continuously adapt your defenses with AI-driven threat intelligence.
                    </p>
                    
                    {!result && (
                        <button
                            onClick={() => document.getElementById("tm-form")?.scrollIntoView({ behavior: "smooth" })}
                            className="btn-animated btn-primary-emerald inline-flex items-center justify-center gap-3 font-bold text-sm tracking-wider uppercase px-8 py-4 rounded-xl shadow-sm focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35"
                        >
                            <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                            </svg>
                            Start Analysis
                        </button>
                    )}
                </div>
            </div>

            {/* ════════════════════ FORM ════════════════════ */}
            {!result && (
                <form id="tm-form" onSubmit={handleSubmit} className="space-y-6">

                    {/* ── Card 1: System Information ── */}
                    <CollapsibleSection 
                        title="System Information" 
                        description="Define the core properties and architecture of your application"
                        icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" /></svg>}
                    >
                        <div className="space-y-8 mt-2">
                            {/* Project name */}
                            <div>
                                <label className="block text-sm font-semibold text-[var(--text-primary)] mb-2">Project Name <span className="text-red-400">*</span></label>
                                <input
                                    type="text"
                                    placeholder="e.g. Project Phoenix"
                                    value={form.projectName}
                                    onChange={e => setForm(p => ({ ...p, projectName: e.target.value }))}
                                    className={`w-full bg-[var(--bg-elevated)] text-[var(--text-primary)] border ${nameError ? 'border-red-500/50 focus:border-red-500' : 'border-[var(--border-strong)] focus:border-[var(--primary)]'} rounded-xl px-4 py-3 focus:outline-none focus:ring-1 focus:ring-[var(--primary)] transition-colors shadow-inner`}
                                />
                                {nameError && <p className="mt-2 text-xs font-medium text-red-400">{nameError}</p>}
                            </div>

                            {/* App type - 2x2 Grid */}
                            <div>
                                <label className="block text-sm font-semibold text-[var(--text-primary)] mb-3">Application Architecture</label>
                                <div className="grid grid-cols-2 gap-3">
                                    {[
                                        { type: 'Web', icon: <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /> },
                                        { type: 'Mobile', icon: <path strokeLinecap="round" strokeLinejoin="round" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" /> },
                                        { type: 'API', icon: <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /> },
                                        { type: 'Cloud', icon: <path strokeLinecap="round" strokeLinejoin="round" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" /> },
                                    ].map(({ type, icon }) => {
                                        const isActive = form.appType === type;
                                        return (
                                            <button 
                                                key={type} 
                                                type="button"
                                                onClick={() => setForm(p => ({ ...p, appType: type as AppType }))}
                                                className={`flex items-center gap-3 p-4 rounded-xl border text-left transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 group motion-reduce:transition-colors motion-reduce:hover:transform-none shadow-sm ${
                                                    isActive 
                                                        ? 'bg-[#edf8f3] border-[#0f9d76]' 
                                                        : 'bg-[#ffffff] border-[#e7ddd1] hover:border-[#0f9d76] hover:bg-[#edf8f3]'
                                                }`}
                                            >
                                                <div className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${isActive ? 'bg-[#0f9d76] text-white shadow-md shadow-[#0f9d76]/20' : 'bg-[#f8f3eb] text-[#4f4a45] group-hover:text-[#0f9d76]'}`}>
                                                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                        {icon}
                                                    </svg>
                                                </div>
                                                <span className={`font-semibold ${isActive ? 'text-[#0f9d76]' : 'text-[#4f4a45] group-hover:text-[#0f9d76]'}`}>{type} Application</span>
                                            </button>
                                        );
                                    })}
                                </div>
                            </div>

                            {/* System characteristics - Modern Toggle Chips */}
                            <div>
                                <label className="block text-sm font-semibold text-[var(--text-primary)] mb-3">System Characteristics</label>
                                <div className="flex flex-wrap gap-2.5">
                                    {CHECKBOXES.map(({ key, label }) => {
                                        const isChecked = form[key] as boolean;
                                        return (
                                            <button 
                                                key={key}
                                                type="button"
                                                onClick={() => toggleBool(key)}
                                                className={`flex items-center gap-2 px-4 py-2.5 rounded-full text-sm font-semibold transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 border shadow-sm motion-reduce:transition-colors motion-reduce:hover:transform-none ${
                                                    isChecked 
                                                        ? 'bg-[#edf8f3] text-[#0f9d76] border-[#0f9d76]' 
                                                        : 'bg-[#ffffff] text-[#1d1d1d] border-[#e7ddd1] hover:border-[#0f9d76] hover:text-[#0f9d76] hover:bg-[#edf8f3]'
                                                }`}
                                            >
                                                <div className={`w-4 h-4 rounded-full flex items-center justify-center border transition-colors ${isChecked ? 'bg-[#0f9d76] border-[#0f9d76]' : 'bg-transparent border-[#d9cdbf]'}`}>
                                                    {isChecked && (
                                                        <svg className="w-3 h-3 text-white" viewBox="0 0 20 20" fill="currentColor">
                                                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                                                        </svg>
                                                    )}
                                                </div>
                                                {label}
                                            </button>
                                        );
                                    })}
                                </div>
                            </div>
                        </div>
                    </CollapsibleSection>

                    {/* ── Card 2: Technology Stack ── */}
                    <CollapsibleSection 
                        title="Technology Stack" 
                        description="Frameworks and languages defining your system's attack surface"
                        icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>}
                    >
                        <div className="space-y-6 mt-2">
                            <MultiPillSelect
                                label="Frameworks & Libraries"
                                hint="Select all that apply across the full stack"
                                options={FRAMEWORK_OPTS}
                                selected={form.frameworks}
                                onToggle={v => toggleArr("frameworks", v)}
                                color="indigo"
                            />
                            <SectionDivider label="Languages" />
                            <MultiPillSelect
                                label="Programming Languages"
                                hint="Core languages used in development"
                                options={LANGUAGE_OPTS}
                                selected={form.languages}
                                onToggle={v => toggleArr("languages", v)}
                                color="violet"
                            />
                        </div>
                    </CollapsibleSection>

                    {/* ── Card 3: Deployment ── */}
                    <CollapsibleSection 
                        title="Deployment & Environment" 
                        description="Infrastructure architecture and delivery models"
                        icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 002-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>}
                    >
                        <div className="space-y-6 mt-2">
                            <MultiPillSelect
                                label="Deployment Environment"
                                hint="Where your application is physically or virtually hosted"
                                options={DEPLOY_ENVS}
                                selected={form.deployEnvs}
                                onToggle={v => toggleArr("deployEnvs", v)}
                                color="teal"
                            />
                            <SectionDivider label="Delivery Model" />
                            <MultiPillSelect
                                label="Deployment Type"
                                hint="How your application is packaged and accessed"
                                options={DEPLOY_TYPES}
                                selected={form.deployTypes}
                                onToggle={v => toggleArr("deployTypes", v)}
                                color="emerald"
                            />
                        </div>
                    </CollapsibleSection>

                    {/* ── Card 4: Data & Protocols ── */}
                    <CollapsibleSection 
                        title="Data & Network Protocols" 
                        description="Data persistence layers and communication channels"
                        icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>}
                    >
                        <div className="space-y-6 mt-2">
                            <MultiPillSelect
                                label="Storage & Databases"
                                hint="Relational, NoSQL, caches, and search engines"
                                options={DATABASE_OPTS}
                                selected={form.databases}
                                onToggle={v => toggleArr("databases", v)}
                                color="blue"
                            />
                            <SectionDivider label="Protocols" />
                            <MultiPillSelect
                                label="Network Protocols"
                                hint="Communication standards used internally and externally"
                                options={PROTOCOL_OPTS}
                                selected={form.protocols}
                                onToggle={v => toggleArr("protocols", v)}
                                color="rose"
                            />
                        </div>
                    </CollapsibleSection>

                    {!isAuthenticated && !isLoading && (
                        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-200 px-5 py-4 mb-4 flex items-center gap-3 backdrop-blur-sm">
                            <svg className="w-6 h-6 text-amber-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                            <span className="font-medium text-sm">Authentication Required. You must be signed in to generate and save threat models.</span>
                        </div>
                    )}
                    {isLoading && (
                        <div className="rounded-xl border border-[var(--primary)] bg-[var(--primary-soft)] text-[var(--primary)] px-5 py-4 mb-4 flex items-center gap-3">
                            <svg className="w-5 h-5 text-[var(--primary)] animate-spin flex-shrink-0" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                            </svg>
                            <span className="font-medium text-sm">Verifying security context...</span>
                        </div>
                    )}

                    {/* ── Submit ── */}
                    <div className="pt-6 pb-4">
                        <button 
                            type="submit" 
                            disabled={!canSubmit}
                            className={`w-full relative overflow-hidden rounded-xl font-bold text-lg tracking-widest uppercase py-5 transition-all duration-180 focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 ${
                                canSubmit 
                                    ? 'btn-animated btn-primary-emerald shadow-sm hover:shadow-md border border-[#0f9d76]' 
                                    : 'bg-[#f6f0e7] text-[#8a8178] cursor-not-allowed border border-[#d9cdbf]'
                            }`}
                        >
                            {canSubmit && (
                                <>
                                    <div className="absolute inset-0 bg-[linear-gradient(90deg,transparent,rgba(255,255,255,0.2),transparent)] -translate-x-[150%] animate-[shimmer_2.5s_infinite]" />
                                    <div className="absolute inset-0 opacity-0 hover:opacity-100 bg-[#0f9d76]/20 mix-blend-overlay transition-opacity duration-500 pointer-events-none" />
                                </>
                            )}
                            <div className="relative flex items-center justify-center gap-3">
                                <svg className={`w-6 h-6 ${canSubmit ? 'animate-pulse text-white' : 'text-[#8a8178]'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                                Generate Threat Model
                            </div>
                        </button>
                    </div>
                </form>
            )}

            {/* ════════════════════ RESULTS ════════════════════ */}
            {result && (
                <div className="space-y-5">

                    {/* No-stack Warning Banner */}
                    {result.blocked === true ? (
                        <div className="bg-amber-500/10 border border-amber-500/20 text-amber-500 text-sm px-5 py-4 rounded-lg print:hidden relative mb-2 space-y-3">
                            <div className="pr-6">
                                <strong>⚠️ No technology stack selected.</strong><br />
                                Select your stack for accurate threat modeling. Generic results may not apply to your system.
                            </div>
                            <div>
                                <Button variant="secondary" size="sm" onClick={handleReset} className="bg-amber-500/20 text-amber-300 border-amber-500/30 hover:bg-amber-500/30">
                                    <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                                    </svg>
                                    Go Back & Select Stack
                                </Button>
                            </div>
                        </div>
                    ) : (
                        result.genericWarning && showWarning && (
                            <div className="bg-amber-500/10 border border-amber-500/20 text-amber-500 text-sm px-4 py-3 rounded-lg print:hidden relative mb-2">
                                <div className="pr-6">
                                    <strong>⚠️ No technology stack selected.</strong><br />
                                    Select your stack for accurate threat modeling. Generic results may not apply to your system.
                                </div>
                                <button onClick={() => setShowWarning(false)} className="absolute top-3 right-3 text-amber-500 hover:text-amber-400">
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>
                        )
                    )}

                    {result.blocked ? (
                        // show nothing — warning banner already handles this
                        null
                    ) : (
                        <>
                            {/* ── Report header + action buttons ── */}
                            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 print:hidden">
                                    <div>
                                        <h2 className="text-xl font-bold text-[var(--text-primary)]">
                                            Threat Report —{" "}
                                            <span className="text-[var(--primary)]">{form.projectName}</span>
                                        </h2>
                                        <p className="text-sm text-[var(--text-muted)] mt-0.5">
                                            {form.appType} · {result.threats.length} threat{result.threats.length !== 1 ? "s" : ""} identified
                                        </p>
                                    </div>
                                    <div className="flex flex-wrap items-center gap-2.5 flex-shrink-0">
                                        {isSaving && (
                                            <span className="inline-flex items-center gap-1.5 text-xs text-[var(--text-muted)] px-2 mr-1">
                                                <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                                </svg>
                                                Saving…
                                            </span>
                                        )}
                                        <button onClick={handleDownloadPDF} className="btn-animated btn-primary-emerald flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold shadow-sm focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35">
                                            <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2v-5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                            </svg>
                                            Download PDF
                                        </button>
                                        <button onClick={handleDownloadJSON} className="btn-animated flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold bg-[#ffffff] border border-[#e7ddd1] text-[#1d1d1d] hover:bg-[#edf8f3] hover:border-[#0f9d76] hover:text-[#0f9d76] shadow-sm focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35">
                                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                                            </svg>
                                            Download JSON
                                        </button>
                                        <button onClick={handleReset} className="btn-animated flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold bg-[#ffffff] border border-[#e7ddd1] text-[#1d1d1d] hover:bg-[#edf8f3] hover:text-[#0f9d76] hover:border-[#0f9d76] shadow-sm focus:outline-none focus:ring-2 focus:ring-[#0f9d76]/35 transition-colors">
                                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                            </svg>
                                            Run Another Analysis
                                        </button>
                                    </div>
                                </div>

                            {/* ── Stack summary tags ── */}
                            {stackTags.length > 0 && (
                                <div className="flex flex-wrap gap-1.5 print:hidden">
                                    <span className="text-xs font-medium text-[var(--text-muted)] self-center mr-1">Stack:</span>
                                    {stackTags.map(tag => (
                                        <span key={tag} className="text-xs bg-[var(--bg-elevated)] text-[var(--text-muted)] border border-[var(--border-soft)] px-2.5 py-1 rounded-full font-medium">
                                            {tag}
                                        </span>
                                    ))}
                                </div>
                            )}

                            {/* ── Risk Score Card ── */}
                            <div className="metric-card-animated bg-[#ffffff] border border-[#e7ddd1] rounded-[18px] shadow-sm overflow-hidden mt-6 mb-8 print:hidden">
                                    <div className="px-6 py-5 border-b border-[#f6f0e7] flex items-center justify-between bg-[#fffaf4]">
                                        <div>
                                            <h3 className="text-lg font-bold text-[#1d1d1d] tracking-wide">Overall Risk Score</h3>
                                            <p className="text-xs font-medium text-[#8a8178] mt-0.5 uppercase tracking-wider">Composite score based on all selected system properties</p>
                                        </div>
                                    </div>
                                    <div className="px-6 py-8">
                                        <div className="flex items-center gap-8">
                                            <div className="flex-shrink-0 text-center w-24">
                                                <div className="text-6xl font-black text-[#1d1d1d] leading-none tracking-tighter">{result.riskScore ?? 0}</div>
                                                <div className="text-xs font-bold text-[#8a8178] mt-2 uppercase tracking-wider">/ 100</div>
                                            </div>
                                            <div className="flex-1">
                                                <div className="flex justify-between items-center mb-3">
                                                    <span className="text-sm font-bold text-[#4f4a45]">Risk Level</span>
                                                    <span className={`text-xs font-bold px-3 py-1 rounded-full ${labelStyle}`}>
                                                        {riskLabel}
                                                    </span>
                                                </div>
                                                <div className="w-full bg-[#f6f0e7] rounded-full h-4 overflow-hidden shadow-inner">
                                                    <div
                                                        className={`h-full rounded-full transition-all duration-1000 ease-out ${barColor}`}
                                                        style={{ width: `${result.riskScore ?? 0}%` }}
                                                    />
                                                </div>
                                                <div className="flex justify-between text-xs font-medium text-[#8a8178] mt-2">
                                                    <span>0 — Safe</span>
                                                    <span>100 — Critical</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            {/* ── Uploaded files in report ── */}

                            {/* ── Threats list ── */}
                            {result.threats.length > 0 && (
                                <div>
                                    <div className="flex items-center justify-between mb-3">
                                        <h3 className="text-base font-semibold text-[var(--text-primary)]">
                                            Identified Threats
                                        </h3>
                                        <div className="flex items-center gap-3 text-xs text-[var(--text-muted)]">
                                            <span className="flex items-center gap-1.5">
                                                <span className="w-2 h-2 rounded-full bg-red-500 inline-block" /> High
                                            </span>
                                            <span className="flex items-center gap-1.5">
                                                <span className="w-2 h-2 rounded-full bg-orange-400 inline-block" /> Medium
                                            </span>
                                            <span className="flex items-center gap-1.5">
                                                <span className="w-2 h-2 rounded-full bg-yellow-400 inline-block" /> Low
                                            </span>
                                        </div>
                                    </div>

                                    <div className="space-y-3">
                                        {result.threats.map(threat => {
                                            const borderLeft = threat.risk === "High" ? "border-l-4 border-l-[#dc2626]" : threat.risk === "Medium" ? "border-l-4 border-l-[#d97706]" : "border-l-4 border-l-[#2563eb]";
                                            const riskBadgeClass = threat.risk === "High" ? "bg-[#fee2e2] text-[#dc2626] border-[#dc2626]" : threat.risk === "Medium" ? "bg-[#fff7ed] text-[#d97706] border-[#d97706]" : "bg-[#eff6ff] text-[#2563eb] border-[#2563eb]";
                                            return (
                                            <div key={threat.id}
                                                className={`threat-card-animated bg-[#ffffff] border border-[#e7ddd1] rounded-2xl overflow-hidden shadow-sm ${borderLeft}`}>
                                                {/* Threat header */}
                                                <div className="px-6 py-4 border-b border-[#f6f0e7] flex items-center justify-between gap-4 bg-[#fffaf4]">
                                                    <div className="flex items-center gap-3 min-w-0">
                                                        <div className={`w-2 h-2 rounded-full flex-shrink-0 ${RISK_DOT[threat.risk]}`} />
                                                        <div className="min-w-0">
                                                            <h4 className="font-bold text-[#1d1d1d] text-base leading-tight truncate">
                                                                {threat.title}
                                                            </h4>
                                                            <span className="text-xs font-medium text-[#8a8178] uppercase tracking-wider">{threat.category}</span>
                                                        </div>
                                                    </div>
                                                    <div className="flex items-center gap-2 flex-shrink-0">
                                                        {threat.stride_category && (
                                                            <span className="text-xs font-bold px-2.5 py-1 rounded-full bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]">
                                                                {threat.stride_category}
                                                            </span>
                                                        )}
                                                        <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${riskBadgeClass}`}>
                                                            {threat.risk} Risk
                                                        </span>
                                                    </div>
                                                </div>
                                                {/* Threat body */}
                                                <div className="px-6 py-5 space-y-5">
                                                    <div>
                                                        <p className="text-xs font-bold text-[#8a8178] uppercase tracking-wider mb-2">
                                                            Description
                                                        </p>
                                                        <p className="text-sm text-[#4f4a45] leading-relaxed">
                                                            {threat.description}
                                                        </p>
                                                    </div>
                                                    <div className="border-t border-[#f6f0e7] pt-5">
                                                        <p className="text-xs font-bold text-[#0f9d76] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                                                                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                                                            </svg>
                                                            Mitigation
                                                        </p>
                                                        <p className="text-sm text-[#4f4a45] leading-relaxed">
                                                            {threat.mitigation}
                                                        </p>
                                                    </div>
                                                    {threat.priority && (
                                                        <div className="flex items-center gap-3 text-xs bg-[#fffaf4] p-3 rounded-xl border border-[#e7ddd1]">
                                                            <span className="font-bold text-[#8a8178] uppercase tracking-wider">Priority Score:</span>
                                                            <div className="flex-1 bg-[#e7ddd1] rounded-full h-2 overflow-hidden shadow-inner">
                                                                <div
                                                                    className="h-full rounded-full bg-gradient-to-r from-yellow-500 to-red-500"
                                                                    style={{ width: `${Math.min(threat.priority, 100)}%` }}
                                                                />
                                                            </div>
                                                            <span className="font-black text-[#1d1d1d]">{threat.priority}</span>
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        )})}
                                    </div>
                                </div>
                            )}

                            {/* ── Print-only header/footer ── */}
                            <div className="hidden print:block border-t pt-4 mt-8">
                                    <p className="text-xs text-[var(--text-muted)]">
                                        TIBSA Platform · Threat Modeling as a Service · Generated {new Date().toLocaleString()}
                                    </p>
                                    <p className="text-xs text-[var(--text-muted)] mt-1">
                                        Project: {form.projectName} · Type: {form.appType} · Risk Score: {result.riskScore ?? 0}/100 ({riskLabel})
                                    </p>
                                </div>
                        </>
                    )}
                </div>
            )}

            {/* ════════════════════ SCAN HISTORY ════════════════════ */}
            {!result && (
                <div className="print:hidden">
                    <h2 className="text-xl font-bold text-[var(--text-primary)] mb-4">Scan History</h2>
                    <ScanHistory />
                </div>
            )}
        </div>
    );
}
