"use client";

import { useState } from "react";
import { Card, Button, Input } from "@/components/ui";

type AppType = "Web" | "Mobile" | "API" | "Cloud";
type RiskLevel = "High" | "Medium" | "Low";

interface ThreatItem {
    id: string;
    title: string;
    risk: RiskLevel;
    description: string;
    mitigation: string;
}

interface FormState {
    projectName: string;
    appType: AppType;
    usesAuth: boolean;
    usesDatabase: boolean;
    hasAdminPanel: boolean;
    usesExternalAPIs: boolean;
    storesSensitiveData: boolean;
}

interface AnalysisResult {
    threats: ThreatItem[];
    riskScore: number;
}

const RISK_BADGE: Record<RiskLevel, string> = {
    High: "bg-red-100 text-red-700 border border-red-200",
    Medium: "bg-orange-100 text-orange-700 border border-orange-200",
    Low: "bg-yellow-100 text-yellow-700 border border-yellow-200",
};

const RISK_BAR: Record<string, string> = {
    Critical: "bg-red-600",
    High: "bg-red-500",
    Medium: "bg-orange-400",
    Low: "bg-green-500",
};

function getRiskLabel(score: number): string {
    if (score >= 80) return "Critical";
    if (score >= 60) return "High";
    if (score >= 35) return "Medium";
    return "Low";
}

function generateThreats(form: FormState): AnalysisResult {
    const threats: ThreatItem[] = [];
    let score = 0;

    if (form.usesDatabase) {
        threats.push({
            id: "sql-injection",
            title: "SQL Injection",
            risk: "High",
            description:
                "Malicious SQL queries can be injected through user inputs to manipulate your database, leading to unauthorized data access or deletion.",
            mitigation:
                "Use parameterized queries or prepared statements. Employ an ORM and validate all user inputs server-side. Apply the principle of least privilege on DB accounts.",
        });
        score += 20;
    }

    if (form.usesAuth) {
        threats.push({
            id: "spoofing",
            title: "Identity Spoofing",
            risk: "High",
            description:
                "Attackers may impersonate legitimate users by stealing or forging authentication credentials via phishing, credential stuffing, or session hijacking.",
            mitigation:
                "Enforce multi-factor authentication, use short-lived JWT tokens with refresh rotation, and implement account lockout policies after repeated failed logins.",
        });
        score += 18;
    }

    if (form.hasAdminPanel) {
        threats.push({
            id: "privilege-escalation",
            title: "Privilege Escalation",
            risk: "High",
            description:
                "An attacker who gains low-privilege access may exploit misconfigurations or logic flaws to escalate their permissions and gain admin-level control.",
            mitigation:
                "Implement strict RBAC, audit admin actions, enforce the principle of least privilege, and regularly review access control logic in code.",
        });
        score += 20;
    }

    if (form.storesSensitiveData) {
        threats.push({
            id: "data-exposure",
            title: "Sensitive Data Exposure",
            risk: "High",
            description:
                "Sensitive user data (PII, credentials, financial records) may be exposed through insecure storage, transmission, or misconfigured access controls.",
            mitigation:
                "Encrypt data at rest (AES-256) and in transit (TLS 1.3+). Mask sensitive fields in logs. Apply data minimization principles and conduct regular access audits.",
        });
        score += 18;
    }

    if (form.appType === "Web" || form.appType === "Mobile") {
        threats.push({
            id: "csrf",
            title: "Cross-Site Request Forgery (CSRF)",
            risk: "Medium",
            description:
                "An attacker tricks an authenticated user's browser into making unwanted state-changing requests to your application without the user's knowledge.",
            mitigation:
                "Implement CSRF tokens on all state-changing endpoints. Use the SameSite=Strict cookie attribute and validate the Origin/Referer headers on the server.",
        });
        score += 12;
    }

    if (form.appType === "Web") {
        threats.push({
            id: "xss",
            title: "Cross-Site Scripting (XSS)",
            risk: "Medium",
            description:
                "Malicious scripts injected into your web pages execute in victims' browsers, enabling session theft, credential harvesting, and DOM manipulation.",
            mitigation:
                "Sanitize and encode all user-generated output. Use a strict Content Security Policy (CSP). Prefer frameworks with auto-escaping (e.g., React) and validate inputs on both client and server.",
        });
        score += 12;
    }

    if (form.usesExternalAPIs) {
        threats.push({
            id: "api-abuse",
            title: "Third-Party API Abuse",
            risk: "Medium",
            description:
                "Compromised or misconfigured external API integrations can expose your system to supply-chain attacks, data leakage, or unauthorized actions performed on your behalf.",
            mitigation:
                "Audit all third-party APIs. Store keys in a secrets manager, not in code. Apply the principle of least privilege on API scopes and monitor for anomalous usage patterns.",
        });
        score += 10;
    }

    if (form.appType === "Cloud") {
        threats.push({
            id: "misconfiguration",
            title: "Cloud Misconfiguration",
            risk: "High",
            description:
                "Improperly configured cloud storage buckets, IAM roles, or network security groups can expose sensitive data or allow unauthorized access to cloud resources.",
            mitigation:
                "Enable cloud security posture management (CSPM) tools. Follow the shared responsibility model, enforce MFA on cloud accounts, and use infrastructure-as-code with security linting.",
        });
        score += 20;
    }

    if (form.appType === "API") {
        threats.push({
            id: "broken-object-auth",
            title: "Broken Object Level Authorization",
            risk: "High",
            description:
                "APIs may expose endpoints that accept object IDs without verifying that the requesting user is authorized to access those specific objects.",
            mitigation:
                "Validate object ownership on every API request server-side. Avoid exposing sequential IDs — use UUIDs. Implement comprehensive API authorization tests.",
        });
        score += 18;
    }

    if (!form.usesAuth) {
        threats.push({
            id: "no-auth",
            title: "Missing Authentication Controls",
            risk: "High",
            description:
                "Without authentication, any user can access protected resources, leading to data theft, unauthorized actions, and full system compromise.",
            mitigation:
                "Implement a robust authentication system (e.g., OAuth 2.0, OpenID Connect). Protect all sensitive routes and enforce session management best practices.",
        });
        score += 22;
    }

    const capped = Math.min(score, 100);
    return { threats, riskScore: capped };
}

const APP_TYPES: AppType[] = ["Web", "Mobile", "API", "Cloud"];

const CHECKBOXES: { key: keyof FormState; label: string }[] = [
    { key: "usesAuth", label: "Uses Authentication" },
    { key: "usesDatabase", label: "Uses Database" },
    { key: "hasAdminPanel", label: "Has Admin Panel" },
    { key: "usesExternalAPIs", label: "Uses External APIs" },
    { key: "storesSensitiveData", label: "Stores Sensitive Data" },
];

const initialForm: FormState = {
    projectName: "",
    appType: "Web",
    usesAuth: false,
    usesDatabase: false,
    hasAdminPanel: false,
    usesExternalAPIs: false,
    storesSensitiveData: false,
};

export default function ThreatModelingPage() {
    const [form, setForm] = useState<FormState>(initialForm);
    const [result, setResult] = useState<AnalysisResult | null>(null);
    const [saveMessage, setSaveMessage] = useState("");
    const [nameError, setNameError] = useState("");

    const handleCheckbox = (key: keyof FormState) => {
        setForm((prev) => ({ ...prev, [key]: !prev[key] }));
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!form.projectName.trim()) {
            setNameError("Project name is required.");
            return;
        }
        setNameError("");
        setSaveMessage("");
        setResult(generateThreats(form));
    };

    const handleSave = () => {
        setSaveMessage("✅ Report saved successfully!");
        setTimeout(() => setSaveMessage(""), 3000);
    };

    const handlePrint = () => {
        window.print();
    };

    const handleReset = () => {
        setForm(initialForm);
        setResult(null);
        setSaveMessage("");
        setNameError("");
    };

    const riskLabel = result ? getRiskLabel(result.riskScore) : "";
    const barColor = RISK_BAR[riskLabel] ?? "bg-gray-300";

    return (
        <div className="space-y-6 print:p-8">
            {/* Hero */}
            <div className="rounded-xl bg-gradient-to-r from-blue-600 to-blue-800 px-8 py-10 text-white shadow-lg print:hidden">
                <div className="flex items-center gap-3 mb-3">
                    <div className="w-10 h-10 rounded-lg bg-white/20 flex items-center justify-center">
                        <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    </div>
                    <span className="text-blue-200 text-sm font-medium uppercase tracking-wider">Security Analysis</span>
                </div>
                <h1 className="text-3xl font-bold mb-2">Threat Modeling as a Service</h1>
                <p className="text-blue-100 text-lg mb-6">Identify vulnerabilities before attackers do.</p>
                {!result && (
                    <button
                        onClick={() => document.getElementById("analysis-form")?.scrollIntoView({ behavior: "smooth" })}
                        className="inline-flex items-center gap-2 bg-white text-blue-700 font-semibold px-5 py-2.5 rounded-lg hover:bg-blue-50 transition-colors text-sm shadow"
                    >
                        Start Analysis
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                        </svg>
                    </button>
                )}
            </div>

            {/* Form */}
            {!result && (
                <Card
                    title="System Information"
                    description="Provide details about your project to generate a tailored threat model."
                >
                    <form id="analysis-form" onSubmit={handleSubmit} className="space-y-6 mt-2">
                        <Input
                            label="Project Name"
                            placeholder="e.g. Customer Portal v2"
                            value={form.projectName}
                            onChange={(e) => setForm((p) => ({ ...p, projectName: e.target.value }))}
                            error={nameError}
                        />

                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-2">Application Type</label>
                            <div className="flex flex-wrap gap-2">
                                {APP_TYPES.map((type) => (
                                    <button
                                        key={type}
                                        type="button"
                                        onClick={() => setForm((p) => ({ ...p, appType: type }))}
                                        className={`px-4 py-2 rounded-lg text-sm font-medium border transition-all ${
                                            form.appType === type
                                                ? "bg-blue-600 text-white border-blue-600 shadow-sm"
                                                : "bg-white text-gray-600 border-gray-300 hover:border-blue-400 hover:text-blue-600"
                                        }`}
                                    >
                                        {type}
                                    </button>
                                ))}
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-3">System Characteristics</label>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                {CHECKBOXES.map(({ key, label }) => (
                                    <label
                                        key={key}
                                        className="flex items-center gap-3 p-3 rounded-lg border border-gray-200 hover:border-blue-300 hover:bg-blue-50/40 cursor-pointer transition-colors"
                                    >
                                        <input
                                            type="checkbox"
                                            checked={form[key] as boolean}
                                            onChange={() => handleCheckbox(key)}
                                            className="w-4 h-4 rounded text-blue-600 border-gray-300 focus:ring-blue-500 accent-blue-600"
                                        />
                                        <span className="text-sm text-gray-700">{label}</span>
                                    </label>
                                ))}
                            </div>
                        </div>

                        <div className="pt-2">
                            <Button type="submit" size="lg" className="w-full sm:w-auto">
                                <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                                Generate Threat Model
                            </Button>
                        </div>
                    </form>
                </Card>
            )}

            {/* Results */}
            {result && (
                <div className="space-y-6">
                    {/* Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 print:hidden">
                        <div>
                            <h2 className="text-xl font-bold text-gray-900">
                                Threat Report — <span className="text-blue-600">{form.projectName}</span>
                            </h2>
                            <p className="text-sm text-gray-500 mt-0.5">
                                {form.appType} application · {result.threats.length} threat{result.threats.length !== 1 ? "s" : ""} identified
                            </p>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            <Button variant="secondary" size="sm" onClick={handlePrint}>
                                <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2v-5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                </svg>
                                Download PDF
                            </Button>
                            <Button variant="secondary" size="sm" onClick={handleSave}>
                                <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" />
                                </svg>
                                Save Report
                            </Button>
                            <Button variant="ghost" size="sm" onClick={handleReset}>
                                <svg className="w-4 h-4 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                </svg>
                                Run Another Analysis
                            </Button>
                        </div>
                    </div>

                    {saveMessage && (
                        <div className="bg-green-50 border border-green-200 text-green-700 text-sm px-4 py-3 rounded-lg print:hidden">
                            {saveMessage}
                        </div>
                    )}

                    {/* Risk Score */}
                    <Card title="Overall Risk Score" description="Composite risk based on your system configuration">
                        <div className="flex items-center gap-6 mt-2">
                            <div className="flex-shrink-0 text-center">
                                <div className="text-5xl font-bold text-gray-900">{result.riskScore}</div>
                                <div className="text-sm text-gray-400 mt-1">/ 100</div>
                            </div>
                            <div className="flex-1">
                                <div className="flex justify-between items-center mb-2">
                                    <span className="text-sm font-medium text-gray-600">Risk Level</span>
                                    <span
                                        className={`text-sm font-semibold px-3 py-0.5 rounded-full ${
                                            riskLabel === "Critical"
                                                ? "bg-red-100 text-red-700"
                                                : riskLabel === "High"
                                                ? "bg-red-100 text-red-600"
                                                : riskLabel === "Medium"
                                                ? "bg-orange-100 text-orange-600"
                                                : "bg-green-100 text-green-700"
                                        }`}
                                    >
                                        {riskLabel}
                                    </span>
                                </div>
                                <div className="w-full bg-gray-100 rounded-full h-3 overflow-hidden">
                                    <div
                                        className={`h-3 rounded-full transition-all duration-700 ${barColor}`}
                                        style={{ width: `${result.riskScore}%` }}
                                    />
                                </div>
                                <div className="flex justify-between text-xs text-gray-400 mt-1.5">
                                    <span>0 — Safe</span>
                                    <span>100 — Critical</span>
                                </div>
                            </div>
                        </div>
                    </Card>

                    {/* Threat Cards */}
                    <div>
                        <h3 className="text-base font-semibold text-gray-800 mb-3">
                            Identified Threats ({result.threats.length})
                        </h3>
                        <div className="space-y-4">
                            {result.threats.map((threat) => (
                                <div
                                    key={threat.id}
                                    className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden"
                                >
                                    <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between gap-4">
                                        <div className="flex items-center gap-3">
                                            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                                                threat.risk === "High" ? "bg-red-500" :
                                                threat.risk === "Medium" ? "bg-orange-400" : "bg-yellow-400"
                                            }`} />
                                            <h4 className="font-semibold text-gray-900">{threat.title}</h4>
                                        </div>
                                        <span
                                            className={`flex-shrink-0 text-xs font-semibold px-2.5 py-1 rounded-full ${RISK_BADGE[threat.risk]}`}
                                        >
                                            {threat.risk} Risk
                                        </span>
                                    </div>
                                    <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">Description</p>
                                            <p className="text-sm text-gray-600 leading-relaxed">{threat.description}</p>
                                        </div>
                                        <div className="md:border-l md:border-gray-100 md:pl-4">
                                            <p className="text-xs font-semibold text-green-600 uppercase tracking-wider mb-1.5">
                                                ✓ Mitigation
                                            </p>
                                            <p className="text-sm text-gray-600 leading-relaxed">{threat.mitigation}</p>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Print-only footer */}
                    <div className="hidden print:block text-xs text-gray-400 border-t pt-4 mt-8">
                        Generated by TIBSA Platform · Threat Modeling as a Service · {new Date().toLocaleDateString()}
                    </div>
                </div>
            )}
        </div>
    );
}
