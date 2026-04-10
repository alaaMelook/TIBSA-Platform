"use client";

import { useState, useRef, useCallback } from "react";
import { Card, Button, Input } from "@/components/ui";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

type AppType        = "Web" | "Mobile" | "API" | "Cloud";
type RiskLevel      = "High" | "Medium" | "Low";
type DeployEnv      = "On-Premise" | "Cloud (AWS / GCP / Azure)" | "Hybrid" | "Serverless" | "Containerized (Docker / K8s)" | "Edge";
type DeployType     = "SaaS" | "Internal Tool" | "Open Source" | "Enterprise" | "B2C Product" | "IoT / Embedded";
type DatabaseType   = "PostgreSQL" | "MySQL / MariaDB" | "MongoDB" | "Redis" | "SQLite" | "Elasticsearch" | "Firebase / Firestore" | "DynamoDB" | "MSSQL" | "Oracle";
type ProtocolType   = "HTTPS" | "HTTP (plain)" | "WebSocket / WSS" | "gRPC" | "GraphQL" | "REST" | "MQTT" | "AMQP" | "FTP / SFTP" | "SSH";
type FrameworkType  = "React" | "Next.js" | "Vue" | "Angular" | "Svelte" | "Django" | "FastAPI" | "Flask" | "Express" | "NestJS" | "Spring Boot" | "Laravel" | "Rails" | "ASP.NET";
type LanguageType   = "TypeScript" | "JavaScript" | "Python" | "Java" | "Go" | "PHP" | "Ruby" | "C#" | "Rust" | "C / C++";

interface UploadedEntry {
    name:  string;
    size:  number;
    kind:  "file" | "folder";
    path:  string;
}

interface FormState {
    // Section 1 – Basic
    projectName:         string;
    appType:             AppType;
    usesAuth:            boolean;
    usesDatabase:        boolean;
    hasAdminPanel:       boolean;
    usesExternalAPIs:    boolean;
    storesSensitiveData: boolean;
    // Section 2 – Stack
    frameworks: FrameworkType[];
    languages:  LanguageType[];
    // Section 3 – Environment
    deployEnvs:   DeployEnv[];
    deployTypes:  DeployType[];
    // Section 4 – Data & Protocols
    databases:  DatabaseType[];
    protocols:  ProtocolType[];
    // Section 5 – Files
    uploads: UploadedEntry[];
}

interface ThreatItem {
    id:          string;
    title:       string;
    risk:        RiskLevel;
    category:    string;
    description: string;
    mitigation:  string;
}

interface AnalysisResult {
    threats:   ThreatItem[];
    riskScore: number;
}

// ─────────────────────────────────────────────────────────────────────
// Static option sets
// ─────────────────────────────────────────────────────────────────────

const APP_TYPES:     AppType[]       = ["Web", "Mobile", "API", "Cloud"];
const DEPLOY_ENVS:   DeployEnv[]     = ["On-Premise", "Cloud (AWS / GCP / Azure)", "Hybrid", "Serverless", "Containerized (Docker / K8s)", "Edge"];
const DEPLOY_TYPES:  DeployType[]    = ["SaaS", "Internal Tool", "Open Source", "Enterprise", "B2C Product", "IoT / Embedded"];
const DATABASE_OPTS: DatabaseType[]  = ["PostgreSQL", "MySQL / MariaDB", "MongoDB", "Redis", "SQLite", "Elasticsearch", "Firebase / Firestore", "DynamoDB", "MSSQL", "Oracle"];
const PROTOCOL_OPTS: ProtocolType[]  = ["HTTPS", "HTTP (plain)", "WebSocket / WSS", "gRPC", "GraphQL", "REST", "MQTT", "AMQP", "FTP / SFTP", "SSH"];
const FRAMEWORK_OPTS: FrameworkType[] = ["React", "Next.js", "Vue", "Angular", "Svelte", "Django", "FastAPI", "Flask", "Express", "NestJS", "Spring Boot", "Laravel", "Rails", "ASP.NET"];
const LANGUAGE_OPTS:  LanguageType[]  = ["TypeScript", "JavaScript", "Python", "Java", "Go", "PHP", "Ruby", "C#", "Rust", "C / C++"];

const CHECKBOXES: { key: keyof FormState; label: string }[] = [
    { key: "usesAuth",            label: "Uses Authentication"   },
    { key: "usesDatabase",        label: "Uses Database"          },
    { key: "hasAdminPanel",       label: "Has Admin Panel"        },
    { key: "usesExternalAPIs",    label: "Uses External APIs"     },
    { key: "storesSensitiveData", label: "Stores Sensitive Data"  },
];

const initialForm: FormState = {
    projectName: "", appType: "Web",
    usesAuth: false, usesDatabase: false, hasAdminPanel: false,
    usesExternalAPIs: false, storesSensitiveData: false,
    frameworks: [], languages: [],
    deployEnvs: [], deployTypes: [],
    databases: [], protocols: [],
    uploads: [],
};

// ─────────────────────────────────────────────────────────────────────
// Risk helpers
// ─────────────────────────────────────────────────────────────────────

const RISK_BADGE: Record<RiskLevel, string> = {
    High:   "bg-red-500/15 text-red-400 border border-red-500/20",
    Medium: "bg-orange-500/15 text-orange-400 border border-orange-500/20",
    Low:    "bg-yellow-500/15 text-yellow-400 border border-yellow-500/20",
};

const RISK_DOT: Record<RiskLevel, string> = {
    High: "bg-red-500", Medium: "bg-orange-400", Low: "bg-yellow-400",
};

const SCORE_COLOR: Record<string, string> = {
    Critical: "bg-red-600", High: "bg-red-500", Medium: "bg-orange-400", Low: "bg-green-500",
};

const SCORE_LABEL_STYLE: Record<string, string> = {
    Critical: "bg-red-500/15 text-red-400",
    High:     "bg-red-500/15 text-red-400",
    Medium:   "bg-orange-500/15 text-orange-400",
    Low:      "bg-green-500/15 text-green-400",
};

function getRiskLabel(score: number): string {
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
    blue:    "bg-blue-600 text-white border-blue-600",
    indigo:  "bg-indigo-600 text-white border-indigo-600",
    violet:  "bg-violet-600 text-white border-violet-600",
    teal:    "bg-teal-600 text-white border-teal-600",
    emerald: "bg-emerald-600 text-white border-emerald-600",
    rose:    "bg-rose-600 text-white border-rose-600",
};

const PILL_HOVER: Record<PillColor, string> = {
    blue:    "hover:border-blue-400/50 hover:text-blue-400",
    indigo:  "hover:border-indigo-400/50 hover:text-indigo-400",
    violet:  "hover:border-violet-400/50 hover:text-violet-400",
    teal:    "hover:border-teal-400/50 hover:text-teal-400",
    emerald: "hover:border-emerald-400/50 hover:text-emerald-400",
    rose:    "hover:border-rose-400/50 hover:text-rose-400",
};

function MultiPillSelect<T extends string>({
    label, hint, options, selected, onToggle, color = "blue",
}: {
    label: string; hint?: string; options: T[];
    selected: T[]; onToggle: (v: T) => void; color?: PillColor;
}) {
    return (
        <div>
            <div className="mb-2">
                <span className="block text-sm font-medium text-slate-300">{label}</span>
                {hint && <span className="block text-xs text-slate-500 mt-0.5">{hint}</span>}
            </div>
            <div className="flex flex-wrap gap-2">
                {options.map((opt) => {
                    const active = selected.includes(opt);
                    return (
                        <button
                            key={opt}
                            type="button"
                            onClick={() => onToggle(opt)}
                            className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-all duration-150 ${
                                active
                                    ? PILL_ACTIVE[color]
                                    : `bg-white/[0.04] text-slate-400 border-white/[0.08] ${PILL_HOVER[color]}`
                            }`}
                        >
                            {opt}
                        </button>
                    );
                })}
            </div>
            {selected.length > 0 && (
                <p className="mt-2 text-xs text-slate-500 leading-relaxed">
                    ✓ {selected.join(" · ")}
                </p>
            )}
        </div>
    );
}

function SectionDivider({ label }: { label: string }) {
    return (
        <div className="flex items-center gap-3 py-1">
            <div className="flex-1 h-px bg-white/[0.06]" />
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-widest whitespace-nowrap">
                {label}
            </span>
            <div className="flex-1 h-px bg-white/[0.06]" />
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

    const highCount   = result.threats.filter(t => t.risk === "High").length;
    const medCount    = result.threats.filter(t => t.risk === "Medium").length;
    const lowCount    = result.threats.filter(t => t.risk === "Low").length;

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
    const url  = URL.createObjectURL(blob);
    const win  = window.open(url, "_blank");
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
        uploaded_files: form.uploads.map(u => ({
            name: u.name,
            path: u.path,
            size: u.size,
            kind: u.kind
        })),
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
    const { token } = useAuth();
    const [form, setForm]         = useState<FormState>(initialForm);
    const [result, setResult]     = useState<AnalysisResult | null>(null);
    const [saveMsg, setSaveMsg]   = useState("");
    const [saveErr, setSaveErr]   = useState("");
    const [isSaving, setIsSaving] = useState(false);
    const [nameError, setNameErr] = useState("");
    const [dragOver, setDragOver] = useState(false);

    const fileInputRef   = useRef<HTMLInputElement>(null);
    const folderInputRef = useRef<HTMLInputElement>(null);

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

    // File / folder ingestion
    const ingestFiles = useCallback((fileList: FileList | null, kind: "file" | "folder" = "file") => {
        if (!fileList || fileList.length === 0) return;
        const entries: UploadedEntry[] = [];
        for (let i = 0; i < fileList.length; i++) {
            const f = fileList[i];
            // When coming from a folder input, webkitRelativePath contains the folder structure
            const path = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
            entries.push({ name: f.name, size: f.size, kind, path });
        }
        setForm(prev => ({ ...prev, uploads: [...prev.uploads, ...entries] }));
    }, []);

    const removeUpload = (path: string) =>
        setForm(prev => ({ ...prev, uploads: prev.uploads.filter(u => u.path !== path) }));

    const clearUploads = () => setForm(prev => ({ ...prev, uploads: [] }));

    // Drop zone
    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault();
        setDragOver(false);
        ingestFiles(e.dataTransfer.files, "file");
    };

    // Form submit
    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!form.projectName.trim()) { setNameErr("Project name is required."); return; }
        setNameErr("");

        // Set loading state
        const loadingResult: AnalysisResult = {
            threats: [],
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
            const response = await api.post("/api/v1/threat-modeling/analyze/stride", requestData);

            // Transform backend response to frontend format
            const analysisResult: AnalysisResult = {
                threats: response.threats.map((threat: any) => ({
                    id: threat.title.toLowerCase().replace(/\s+/g, "-"),
                    title: threat.title,
                    risk: threat.risk,
                    category: threat.category,
                    description: threat.description,
                    mitigation: threat.mitigation,
                })),
                riskScore: response.risk_score,
            };

            setResult(analysisResult);
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

    const handleReset = () => { setForm(initialForm); setResult(null); setSaveMsg(""); setSaveErr(""); setNameErr(""); };

    const handleSave = async () => {
        if (!result || !token) return;
        setIsSaving(true);
        setSaveMsg("");
        setSaveErr("");
        try {
            await api.post(
                "/api/v1/threat-modeling/analyses",
                {
                    project_name:          form.projectName,
                    app_type:              form.appType,
                    uses_auth:             form.usesAuth,
                    uses_database:         form.usesDatabase,
                    has_admin_panel:       form.hasAdminPanel,
                    uses_external_apis:    form.usesExternalAPIs,
                    stores_sensitive_data: form.storesSensitiveData,
                    frameworks:            form.frameworks,
                    languages:             form.languages,
                    deploy_envs:           form.deployEnvs,
                    deploy_types:          form.deployTypes,
                    databases:             form.databases,
                    protocols:             form.protocols,
                },
                token,
            );
            setSaveMsg("✅ Report saved! You can view it in the Reports page.");
            setTimeout(() => setSaveMsg(""), 5000);
        } catch (err) {
            setSaveErr(`❌ Failed to save: ${err instanceof Error ? err.message : "Unknown error"}`);
            setTimeout(() => setSaveErr(""), 5000);
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

    const riskLabel  = result ? getRiskLabel(result.riskScore) : "";
    const barColor   = SCORE_COLOR[riskLabel]       ?? "bg-slate-600";
    const labelStyle = SCORE_LABEL_STYLE[riskLabel] ?? "";

    // Compact summary of selected options for the report header
    const stackTags = [...form.frameworks, ...form.languages, ...form.deployEnvs, ...form.deployTypes, ...form.databases, ...form.protocols];

    // ── Render ────────────────────────────────────────────────
    return (
        <div className="space-y-6 print:p-8 max-w-4xl">

            {/* ════════════════════ HERO ════════════════════ */}
            <div className="rounded-xl bg-gradient-to-r from-blue-600 to-blue-800 px-8 py-10 text-white shadow-lg print:hidden">
                <div className="flex items-center gap-3 mb-3">
                    <div className="w-10 h-10 rounded-lg bg-white/20 flex items-center justify-center flex-shrink-0">
                        <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    </div>
                    <span className="text-blue-200 text-sm font-medium uppercase tracking-wider">
                        Security Analysis · TMaaS
                    </span>
                </div>
                <h1 className="text-3xl font-bold mb-2">Threat Modeling as a Service</h1>
                <p className="text-blue-100 text-lg mb-6">Identify vulnerabilities before attackers do.</p>
                {!result && (
                    <button
                        onClick={() => document.getElementById("tm-form")?.scrollIntoView({ behavior: "smooth" })}
                        className="inline-flex items-center gap-2 bg-white text-blue-700 font-semibold px-5 py-2.5 rounded-lg hover:bg-blue-50 transition-colors text-sm shadow-sm"
                    >
                        Start Analysis
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                        </svg>
                    </button>
                )}
            </div>

            {/* ════════════════════ FORM ════════════════════ */}
            {!result && (
                <form id="tm-form" onSubmit={handleSubmit} className="space-y-4">

                    {/* ── Card 1: System Information ── */}
                    <Card title="System Information" description="Describe your project so the engine can tailor threats to your context.">
                        <div className="space-y-5 mt-1">
                            {/* Project name */}
                            <Input
                                label="Project Name *"
                                placeholder="e.g. Customer Portal v2"
                                value={form.projectName}
                                onChange={e => setForm(p => ({ ...p, projectName: e.target.value }))}
                                error={nameError}
                            />

                            {/* App type */}
                            <div>
                                <label className="block text-sm font-medium text-slate-300 mb-2">Application Type</label>
                                <div className="flex flex-wrap gap-2">
                                    {APP_TYPES.map(type => (
                                        <button key={type} type="button"
                                            onClick={() => setForm(p => ({ ...p, appType: type }))}
                                            className={`px-4 py-2 rounded-lg text-sm font-medium border transition-all ${
                                                form.appType === type
                                                    ? "bg-blue-600 text-white border-blue-600 shadow-sm"
                                                    : "bg-white/[0.04] text-slate-400 border-white/[0.08] hover:border-blue-400/50 hover:text-blue-400"
                                            }`}
                                        >{type}</button>
                                    ))}
                                </div>
                            </div>

                            {/* System characteristics */}
                            <div>
                                <label className="block text-sm font-medium text-slate-300 mb-2">System Characteristics</label>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                                    {CHECKBOXES.map(({ key, label }) => (
                                        <label key={key}
                                            className="flex items-center gap-3 px-4 py-3 rounded-lg border border-white/[0.08] hover:border-blue-500/30 hover:bg-blue-500/5 cursor-pointer transition-colors"
                                        >
                                            <input type="checkbox"
                                                checked={form[key] as boolean}
                                                onChange={() => toggleBool(key)}
                                                className="w-4 h-4 rounded accent-blue-600 border-slate-500"
                                            />
                                            <span className="text-sm text-slate-300">{label}</span>
                                        </label>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </Card>

                    {/* ── Card 2: Technology Stack ── */}
                    <Card title="Technology Stack" description="Select all frameworks and languages used in your project.">
                        <div className="space-y-5 mt-1">
                            <MultiPillSelect
                                label="Frameworks / Libraries"
                                hint="Select all that apply — including frontend and backend"
                                options={FRAMEWORK_OPTS}
                                selected={form.frameworks}
                                onToggle={v => toggleArr("frameworks", v)}
                                color="indigo"
                            />
                            <SectionDivider label="Languages" />
                            <MultiPillSelect
                                label="Programming Languages"
                                hint="All languages used across the full stack"
                                options={LANGUAGE_OPTS}
                                selected={form.languages}
                                onToggle={v => toggleArr("languages", v)}
                                color="violet"
                            />
                        </div>
                    </Card>

                    {/* ── Card 3: Deployment ── */}
                    <Card title="Deployment & Environment" description="Where and how is your application deployed and delivered?">
                        <div className="space-y-5 mt-1">
                            <MultiPillSelect
                                label="Deployment Environment"
                                hint="The infrastructure your application runs on"
                                options={DEPLOY_ENVS}
                                selected={form.deployEnvs}
                                onToggle={v => toggleArr("deployEnvs", v)}
                                color="teal"
                            />
                            <SectionDivider label="Delivery Model" />
                            <MultiPillSelect
                                label="Deployment Type"
                                hint="How your application is packaged and delivered to end users"
                                options={DEPLOY_TYPES}
                                selected={form.deployTypes}
                                onToggle={v => toggleArr("deployTypes", v)}
                                color="emerald"
                            />
                        </div>
                    </Card>

                    {/* ── Card 4: Data & Protocols ── */}
                    <Card title="Data & Network Protocols" description="Databases your system stores data in, and protocols it communicates over.">
                        <div className="space-y-5 mt-1">
                            <MultiPillSelect
                                label="Database / Storage Types"
                                hint="Include caches and search engines"
                                options={DATABASE_OPTS}
                                selected={form.databases}
                                onToggle={v => toggleArr("databases", v)}
                                color="blue"
                            />
                            <SectionDivider label="Protocols" />
                            <MultiPillSelect
                                label="Network / Communication Protocols"
                                hint="All protocols your system uses internally and externally"
                                options={PROTOCOL_OPTS}
                                selected={form.protocols}
                                onToggle={v => toggleArr("protocols", v)}
                                color="rose"
                            />
                        </div>
                    </Card>

                    {/* ── Card 5: Project Upload ── */}
                    <Card
                        title="Upload Project Files or Folder"
                        description="Upload individual files or your entire project folder for richer context. Files are analyzed locally — nothing is sent to a server."
                    >
                        <div className="mt-1 space-y-4">

                            {/* Drop zone */}
                            <div
                                onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                                onDragLeave={() => setDragOver(false)}
                                onDrop={handleDrop}
                                className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-colors cursor-pointer ${
                                    dragOver
                                        ? "border-blue-500 bg-blue-500/10"
                                        : "border-white/[0.12] hover:border-blue-400/50 hover:bg-blue-500/5"
                                }`}
                                onClick={() => fileInputRef.current?.click()}
                            >
                                <svg className="w-8 h-8 mx-auto text-slate-500 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                                </svg>
                                <p className="text-sm font-medium text-slate-300 mb-1">
                                    Drag & drop files here, or click to browse
                                </p>
                                <p className="text-xs text-slate-500">
                                    Supports any file type — config files, diagrams, source code, docs
                                </p>

                                {/* Hidden file input */}
                                <input
                                    ref={fileInputRef}
                                    type="file"
                                    multiple
                                    className="hidden"
                                    onChange={e => { ingestFiles(e.target.files, "file"); e.target.value = ""; }}
                                />
                            </div>

                            {/* Folder upload button (separate — uses webkitdirectory) */}
                            <div className="flex items-center gap-3">
                                <button
                                    type="button"
                                    onClick={() => folderInputRef.current?.click()}
                                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border border-white/[0.08] bg-white/[0.04] text-slate-300 hover:border-blue-400/50 hover:text-blue-400 transition-colors"
                                >
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
                                    </svg>
                                    Upload Entire Project Folder
                                </button>
                                <span className="text-xs text-slate-500">
                                    Scans your folder structure for security context
                                </span>
                                {/* Hidden folder input — webkitdirectory is non-standard, so we cast */}
                                <input
                                    ref={folderInputRef}
                                    type="file"
                                    multiple
                                    className="hidden"
                                    {...({ webkitdirectory: "", directory: "" } as React.InputHTMLAttributes<HTMLInputElement>)}
                                    onChange={e => { ingestFiles(e.target.files, "folder"); e.target.value = ""; }}
                                />
                            </div>

                            {/* Uploaded entries list */}
                            {form.uploads.length > 0 && (
                                <div className="rounded-lg border border-white/[0.08] overflow-hidden">
                                    <div className="flex items-center justify-between px-4 py-2.5 bg-white/[0.04] border-b border-white/[0.06]">
                                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">
                                            {form.uploads.length} file{form.uploads.length !== 1 ? "s" : ""} staged
                                        </span>
                                        <button
                                            type="button"
                                            onClick={clearUploads}
                                            className="text-xs text-red-500 hover:text-red-700 font-medium transition-colors"
                                        >
                                            Clear all
                                        </button>
                                    </div>
                                    <ul className="divide-y divide-white/[0.06] max-h-64 overflow-y-auto">
                                        {form.uploads.map(entry => (
                                            <li key={entry.path} className="flex items-center gap-3 px-4 py-2.5">
                                                {/* Icon */}
                                                {entry.kind === "folder"
                                                    ? <svg className="w-4 h-4 text-yellow-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
                                                      </svg>
                                                    : <svg className="w-4 h-4 text-blue-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                                      </svg>
                                                }
                                                {/* Details */}
                                                <div className="flex-1 min-w-0">
                                                    <p className="text-sm font-medium text-slate-200 truncate">{entry.name}</p>
                                                    {entry.path !== entry.name && (
                                                        <p className="text-xs text-slate-500 truncate font-mono">{entry.path}</p>
                                                    )}
                                                </div>
                                                <span className="text-xs text-slate-500 flex-shrink-0">{formatBytes(entry.size)}</span>
                                                <button
                                                    type="button"
                                                    onClick={() => removeUpload(entry.path)}
                                                    className="text-slate-600 hover:text-red-400 transition-colors ml-1 flex-shrink-0"
                                                    aria-label="Remove"
                                                >
                                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                                                    </svg>
                                                </button>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}
                        </div>
                    </Card>

                    {/* ── Submit ── */}
                    <div className="flex justify-end pt-1">
                        <Button type="submit" size="lg">
                            <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                            Generate Threat Model
                        </Button>
                    </div>
                </form>
            )}

            {/* ════════════════════ RESULTS ════════════════════ */}
            {result && (
                <div className="space-y-5">

                    {/* ── Report header + action buttons ── */}
                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 print:hidden">
                        <div>
                            <h2 className="text-xl font-bold text-white">
                                Threat Report —{" "}
                                <span className="text-blue-400">{form.projectName}</span>
                            </h2>
                            <p className="text-sm text-slate-400 mt-0.5">
                                {form.appType} · {result.threats.length} threat{result.threats.length !== 1 ? "s" : ""} identified
                                {form.uploads.length > 0 && ` · ${form.uploads.length} file${form.uploads.length !== 1 ? "s" : ""} uploaded`}
                            </p>
                        </div>
                        <div className="flex flex-wrap gap-2 flex-shrink-0">
                            <Button variant="secondary" size="sm" onClick={handleDownloadPDF}>
                                <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2v-5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                </svg>
                                Download PDF
                            </Button>
                            <Button variant="secondary" size="sm" onClick={handleDownloadJSON}>
                                <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                                </svg>
                                Download JSON
                            </Button>
                            <Button variant="secondary" size="sm" onClick={handleSave} disabled={isSaving}>
                                <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                                </svg>
                                {isSaving ? "Saving…" : "Save Report"}
                            </Button>
                            <Button variant="ghost" size="sm" onClick={handleReset}>
                                <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                </svg>
                                Run Another Analysis
                            </Button>
                        </div>
                    </div>

                    {/* Save confirmation */}
                    {saveMsg && (
                        <div className="bg-green-500/10 border border-green-500/20 text-green-400 text-sm px-4 py-3 rounded-lg print:hidden">
                            {saveMsg}
                        </div>
                    )}
                    {saveErr && (
                        <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-4 py-3 rounded-lg print:hidden">
                            {saveErr}
                        </div>
                    )}

                    {/* ── Stack summary tags ── */}
                    {stackTags.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 print:hidden">
                            <span className="text-xs font-medium text-slate-500 self-center mr-1">Stack:</span>
                            {stackTags.map(tag => (
                                <span key={tag} className="text-xs bg-white/[0.06] text-slate-400 border border-white/[0.08] px-2.5 py-1 rounded-full font-medium">
                                    {tag}
                                </span>
                            ))}
                        </div>
                    )}

                    {/* ── Risk Score Card ── */}
                    <Card title="Overall Risk Score" description="Composite score based on all selected system properties">
                        <div className="flex items-center gap-6 mt-2">
                            <div className="flex-shrink-0 text-center w-20">
                                <div className="text-5xl font-bold text-white leading-none">{result.riskScore}</div>
                                <div className="text-sm text-slate-500 mt-1">/ 100</div>
                            </div>
                            <div className="flex-1">
                                <div className="flex justify-between items-center mb-2">
                                    <span className="text-sm font-medium text-slate-400">Risk Level</span>
                                    <span className={`text-sm font-semibold px-3 py-0.5 rounded-full ${labelStyle}`}>
                                        {riskLabel}
                                    </span>
                                </div>
                                <div className="w-full bg-white/[0.06] rounded-full h-3 overflow-hidden">
                                    <div
                                        className={`h-3 rounded-full transition-all duration-700 ease-out ${barColor}`}
                                        style={{ width: `${result.riskScore}%` }}
                                    />
                                </div>
                                <div className="flex justify-between text-xs text-slate-500 mt-1.5">
                                    <span>0 — Safe</span>
                                    <span>100 — Critical</span>
                                </div>
                            </div>
                        </div>
                    </Card>

                    {/* ── Uploaded files in report ── */}
                    {form.uploads.length > 0 && (
                        <Card title="Project Files Analyzed" description={`${form.uploads.length} file${form.uploads.length !== 1 ? "s" : ""} included in this analysis`}>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-1">
                                {form.uploads.map(u => (
                                    <div key={u.path} className="flex items-center gap-2.5 text-sm text-slate-400">
                                        {u.kind === "folder"
                                            ? <svg className="w-4 h-4 text-yellow-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
                                              </svg>
                                            : <svg className="w-4 h-4 text-blue-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                              </svg>
                                        }
                                        <span className="truncate font-medium">{u.name}</span>
                                        <span className="text-slate-500 text-xs flex-shrink-0">{formatBytes(u.size)}</span>
                                    </div>
                                ))}
                            </div>
                        </Card>
                    )}

                    {/* ── Threats list ── */}
                    <div>
                        <div className="flex items-center justify-between mb-3">
                            <h3 className="text-base font-semibold text-slate-200">
                                Identified Threats
                            </h3>
                            <div className="flex items-center gap-3 text-xs text-slate-500">
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
                            {result.threats.map(threat => (
                                <div key={threat.id}
                                    className="bg-[#263554] border border-white/[0.08] rounded-xl shadow-lg shadow-black/25 overflow-hidden">
                                    {/* Threat header */}
                                    <div className="px-5 py-3.5 border-b border-white/[0.06] flex items-center justify-between gap-4">
                                        <div className="flex items-center gap-3 min-w-0">
                                            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${RISK_DOT[threat.risk]}`} />
                                            <div className="min-w-0">
                                                <h4 className="font-semibold text-white text-sm leading-tight truncate">
                                                    {threat.title}
                                                </h4>
                                                <span className="text-xs text-slate-500">{threat.category}</span>
                                            </div>
                                        </div>
                                        <span className={`flex-shrink-0 text-xs font-semibold px-2.5 py-1 rounded-full ${RISK_BADGE[threat.risk]}`}>
                                            {threat.risk} Risk
                                        </span>
                                    </div>
                                    {/* Threat body */}
                                    <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5">
                                                Description
                                            </p>
                                            <p className="text-sm text-slate-300 leading-relaxed">
                                                {threat.description}
                                            </p>
                                        </div>
                                        <div className="md:border-l md:border-white/[0.06] md:pl-4">
                                            <p className="text-xs font-semibold text-green-400 uppercase tracking-wider mb-1.5">
                                                ✓ Mitigation
                                            </p>
                                            <p className="text-sm text-slate-300 leading-relaxed">
                                                {threat.mitigation}
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* ── Print-only header/footer ── */}
                    <div className="hidden print:block border-t pt-4 mt-8">
                        <p className="text-xs text-slate-500">
                            TIBSA Platform · Threat Modeling as a Service · Generated {new Date().toLocaleString()}
                        </p>
                        <p className="text-xs text-slate-500 mt-1">
                            Project: {form.projectName} · Type: {form.appType} · Risk Score: {result.riskScore}/100 ({riskLabel})
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
}
