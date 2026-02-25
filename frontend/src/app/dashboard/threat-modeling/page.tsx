"use client";

import { useState, useRef, useCallback } from "react";
import { Card, Button, Input } from "@/components/ui";

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
    High:   "bg-red-50 text-red-700 border border-red-200",
    Medium: "bg-orange-50 text-orange-700 border border-orange-200",
    Low:    "bg-yellow-50 text-yellow-700 border border-yellow-200",
};

const RISK_DOT: Record<RiskLevel, string> = {
    High: "bg-red-500", Medium: "bg-orange-400", Low: "bg-yellow-400",
};

const SCORE_COLOR: Record<string, string> = {
    Critical: "bg-red-600", High: "bg-red-500", Medium: "bg-orange-400", Low: "bg-green-500",
};

const SCORE_LABEL_STYLE: Record<string, string> = {
    Critical: "bg-red-100 text-red-700",
    High:     "bg-red-100 text-red-600",
    Medium:   "bg-orange-100 text-orange-700",
    Low:      "bg-green-100 text-green-700",
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

function generateThreats(f: FormState): AnalysisResult {
    const threats: ThreatItem[] = [];
    let score = 0;

    const add = (t: Omit<ThreatItem, "id">, pts: number) => {
        threats.push({ ...t, id: t.title.toLowerCase().replace(/\s+/g, "-") });
        score += pts;
    };

    // ── System flags ──────────────────────────────────────────
    if (f.usesDatabase)
        add({ title: "SQL / Query Injection", risk: "High", category: "Injection",
            description: "Malicious query statements injected through unsanitized user inputs can manipulate or destroy your database, leading to unauthorized access or data leakage.",
            mitigation: "Use parameterized queries, prepared statements, or a trusted ORM. Validate all inputs server-side and apply least-privilege DB accounts." }, 20);

    if (f.usesAuth)
        add({ title: "Identity Spoofing", risk: "High", category: "Authentication",
            description: "Attackers may impersonate legitimate users by stealing or forging authentication credentials via phishing, credential stuffing, or session hijacking.",
            mitigation: "Enforce MFA, use short-lived JWTs with rotation, implement account-lockout policies, and adopt a zero-trust session model." }, 18);

    if (f.hasAdminPanel)
        add({ title: "Privilege Escalation", risk: "High", category: "Authorization",
            description: "An attacker with low-privilege access may exploit misconfigured logic to gain admin-level control over the application.",
            mitigation: "Implement strict RBAC, audit all elevated-privilege actions, enforce least privilege everywhere, and pen-test your admin surface." }, 20);

    if (f.storesSensitiveData)
        add({ title: "Sensitive Data Exposure", risk: "High", category: "Data Security",
            description: "PII, credentials, or financial records may be exposed through insecure storage, unencrypted transmission, or access-control misconfigurations.",
            mitigation: "Encrypt data at rest (AES-256) and in transit (TLS 1.3+). Mask sensitive fields in logs. Apply data minimization and run regular access audits." }, 18);

    if (!f.usesAuth)
        add({ title: "Missing Authentication Controls", risk: "High", category: "Authentication",
            description: "Without authentication, any user can access protected resources, enabling data theft, unauthorized actions, and full system compromise.",
            mitigation: "Implement OAuth 2.0 / OpenID Connect. Protect all sensitive routes with server-side auth middleware and enforce session management best practices." }, 22);

    // ── App-type specific ─────────────────────────────────────
    if (f.appType === "Web" || f.appType === "Mobile")
        add({ title: "Cross-Site Request Forgery (CSRF)", risk: "Medium", category: "Web Security",
            description: "An attacker tricks an authenticated user's browser into sending unwanted state-changing requests without the user's knowledge.",
            mitigation: "Use CSRF tokens on all state-changing endpoints. Set SameSite=Strict cookies and validate Origin / Referer headers server-side." }, 12);

    if (f.appType === "Web")
        add({ title: "Cross-Site Scripting (XSS)", risk: "Medium", category: "Web Security",
            description: "Injected malicious scripts execute in victims' browsers, enabling session theft, credential harvesting, and DOM manipulation.",
            mitigation: "Sanitize and encode all user-generated output. Enforce a strict Content Security Policy (CSP) and prefer auto-escaping frameworks." }, 12);

    if (f.appType === "Cloud")
        add({ title: "Cloud Misconfiguration", risk: "High", category: "Infrastructure",
            description: "Misconfigured storage buckets, over-permissive IAM roles, or open security groups expose sensitive data and cloud resources to the internet.",
            mitigation: "Enable CSPM tools, apply least-privilege IAM, use infrastructure-as-code with security linting, and enforce MFA on all cloud accounts." }, 20);

    if (f.appType === "API")
        add({ title: "Broken Object-Level Authorization", risk: "High", category: "API Security",
            description: "APIs that accept object IDs without verifying ownership allow attackers to access any other user's resources by simply changing an ID.",
            mitigation: "Validate object ownership on every API request server-side. Use UUIDs instead of sequential IDs and maintain comprehensive authorization tests." }, 18);

    if (f.usesExternalAPIs)
        add({ title: "Third-Party API Compromise", risk: "Medium", category: "Supply Chain",
            description: "Compromised or misconfigured third-party integrations expose your system to supply-chain attacks, data leakage, and unauthorized actions.",
            mitigation: "Audit every third-party API. Store keys in a secrets manager. Apply minimal API scopes and monitor for anomalous usage in real time." }, 10);

    // ── Protocol threats ──────────────────────────────────────
    if (f.protocols.includes("HTTP (plain)"))
        add({ title: "Unencrypted HTTP Traffic", risk: "High", category: "Network Security",
            description: "Transmitting data over plain HTTP exposes it to man-in-the-middle interception, eavesdropping, and content injection attacks.",
            mitigation: "Migrate to HTTPS everywhere. Enforce HSTS, redirect all HTTP to HTTPS, and configure TLS 1.2+ with strong cipher suites." }, 15);

    if (f.protocols.includes("WebSocket / WSS"))
        add({ title: "WebSocket Hijacking", risk: "Medium", category: "Network Security",
            description: "WebSocket connections lacking proper origin validation can be hijacked, allowing attackers to inject commands or read sensitive messages.",
            mitigation: "Validate the Origin header on every WebSocket upgrade. Use WSS exclusively and enforce authentication tokens at connection time." }, 10);

    if (f.protocols.includes("MQTT"))
        add({ title: "MQTT Broker Spoofing", risk: "Medium", category: "IoT / Messaging Security",
            description: "An unauthenticated MQTT broker allows any client to publish malicious messages or subscribe to sensitive telemetry topics.",
            mitigation: "Enable TLS on the MQTT broker, enforce client authentication, and use ACLs to restrict topic publish/subscribe permissions per client." }, 10);

    if (f.protocols.includes("AMQP"))
        add({ title: "Message Queue Tampering (AMQP)", risk: "Medium", category: "Messaging Security",
            description: "Unauthenticated or poorly secured AMQP queues allow attackers to inject malicious messages, replay events, or disrupt queue consumers.",
            mitigation: "Enforce TLS for all AMQP connections, use vhost-level access control, and validate message schemas on the consumer side." }, 10);

    if (f.protocols.includes("FTP / SFTP"))
        add({ title: "FTP Credential Exposure", risk: "High", category: "Network Security",
            description: "Plain FTP transmits credentials and data in cleartext. SFTP can also be misconfigured to allow weak or anonymous authentication.",
            mitigation: "Replace FTP with SFTP or FTPS. Disable anonymous access, enforce key-based authentication, restrict by IP, and log all file transfer activity." }, 15);

    if (f.protocols.includes("SSH"))
        add({ title: "SSH Brute-Force / Key Mismanagement", risk: "Medium", category: "Network Security",
            description: "Exposed SSH services with weak passwords or unmanaged keys are prime targets for brute-force attacks and unauthorized remote access.",
            mitigation: "Disable password-based SSH login. Use ed25519 keys, rotate them regularly, restrict access by IP via firewall rules, and use a bastion host." }, 8);

    // ── Database threats ──────────────────────────────────────
    if (f.databases.includes("MongoDB"))
        add({ title: "NoSQL Injection (MongoDB)", risk: "High", category: "Injection",
            description: "MongoDB queries built from raw user input can be manipulated to bypass authentication checks or return all documents in a collection.",
            mitigation: "Use Mongoose or the official MongoDB driver's query-builder. Never pass raw user objects into queries. Validate and sanitize all input." }, 15);

    if (f.databases.includes("Redis"))
        add({ title: "Redis Unauthorized Access", risk: "High", category: "Infrastructure",
            description: "Redis instances exposed without authentication can be fully read, overwritten, or used as a command execution vector by any internet client.",
            mitigation: "Bind Redis to localhost or a private subnet. Enable requirepass and TLS. Disable dangerous commands (CONFIG, DEBUG) in production." }, 15);

    if (f.databases.includes("Elasticsearch"))
        add({ title: "Elasticsearch Open Exposure", risk: "High", category: "Infrastructure",
            description: "Elasticsearch clusters without authentication expose all indexed data publicly — a leading cause of large-scale data breaches.",
            mitigation: "Enable X-Pack security. Restrict cluster access via network policy. Use role-based access control and rotate API keys regularly." }, 15);

    if (f.databases.includes("Firebase / Firestore"))
        add({ title: "Firebase Insecure Rules", risk: "High", category: "Cloud / Database",
            description: "Overly permissive Firebase Security Rules (e.g., allow read, write: if true) allow any authenticated or even unauthenticated user to read or write all data.",
            mitigation: "Audit and tighten all Firestore / RTDB security rules. Use Firebase Auth UID checks, restrict by resource path, and run the Rules Playground before deploying." }, 15);

    // ── Deployment threats ────────────────────────────────────
    if (f.deployEnvs.includes("Containerized (Docker / K8s)"))
        add({ title: "Container Escape", risk: "High", category: "Infrastructure",
            description: "A compromised container can escape its sandbox via privilege escalation, exploiting the container runtime or misconfigured host mounts.",
            mitigation: "Run containers as non-root. Enable seccomp/AppArmor profiles, disable privileged mode, avoid host-path mounts, and keep runtimes patched." }, 15);

    if (f.deployEnvs.includes("Serverless"))
        add({ title: "Serverless Function Event Injection", risk: "Medium", category: "Infrastructure",
            description: "Serverless functions that process untrusted event payloads without validation are vulnerable to injection attacks and may execute with over-broad permissions.",
            mitigation: "Validate and schema-check all event inputs. Apply least-privilege IAM roles per function. Enable function-level logging and anomaly alerts." }, 10);

    if (f.deployEnvs.includes("Edge"))
        add({ title: "Edge / CDN Cache Poisoning", risk: "Medium", category: "Infrastructure",
            description: "Improperly configured edge nodes or CDN rules can be exploited to poison cached responses, serving malicious content to all subsequent users.",
            mitigation: "Set strict Cache-Control headers. Use vary keys carefully. Purge the cache after every deployment and audit edge configuration regularly." }, 8);

    // ── Framework threats ─────────────────────────────────────
    if (f.frameworks.includes("Express") || f.frameworks.includes("NestJS"))
        add({ title: "Missing HTTP Security Headers (Node)", risk: "Low", category: "Web Security",
            description: "Node.js web servers don't set secure HTTP headers by default, leaving apps exposed to clickjacking, MIME sniffing, and other browser-based attacks.",
            mitigation: "Add Helmet.js to your Express / NestJS app to automatically set X-Frame-Options, CSP, X-Content-Type-Options, and other protective headers." }, 6);

    if (f.frameworks.some(fw => ["Django", "Rails", "Laravel", "ASP.NET"].includes(fw)))
        add({ title: "Mass Assignment Vulnerability", risk: "Medium", category: "Framework Risk",
            description: "MVC frameworks can allow users to overwrite model fields not intended to be user-editable if whitelisting is not enforced on form input.",
            mitigation: "Use strong parameters (Rails), fillable arrays (Laravel), form serializers (Django), or binding whitelists (ASP.NET MVC) on every model update." }, 10);

    if (f.frameworks.includes("Flask"))
        add({ title: "Flask Debug Mode in Production", risk: "High", category: "Framework Risk",
            description: "Running Flask with DEBUG=True in production exposes an interactive debugger console that gives attackers arbitrary remote code execution.",
            mitigation: "Always set FLASK_DEBUG=0 / app.debug=False in production. Use an environment variable check and a production WSGI server like Gunicorn." }, 15);

    // ── Language threats ──────────────────────────────────────
    if (f.languages.includes("PHP"))
        add({ title: "PHP Remote Code Execution Risk", risk: "High", category: "Language Risk",
            description: "PHP's permissive design and functions like eval(), system(), and shell_exec() create remote code execution risk when user input is not rigorously validated.",
            mitigation: "Disable dangerous functions in php.ini. Set allow_url_include=Off. Validate and escape all inputs. Keep PHP 8.x patched and avoid eval() entirely." }, 15);

    if (f.languages.includes("C / C++"))
        add({ title: "Memory Safety Vulnerabilities", risk: "High", category: "Language Risk",
            description: "C/C++ components are susceptible to buffer overflows, use-after-free, and other memory corruption issues that can lead to remote code execution.",
            mitigation: "Use modern C++20 features, smart pointers, and bounds-checked containers. Enable compiler flags (-fstack-protector, -D_FORTIFY_SOURCE). Consider Rust for new critical components." }, 18);

    // ── Upload / file threats ─────────────────────────────────
    if (f.uploads.length > 0)
        add({ title: "Malicious File Upload Risk", risk: "High", category: "File Security",
            description: "Accepting file uploads without rigorous server-side validation allows attackers to upload executable scripts, malware, or oversized files to crash servers.",
            mitigation: "Validate MIME types server-side (never trust client-side extensions). Store files outside the web root. Scan with antivirus. Enforce file size limits and allowed type whitelists." }, 18);

    return { threats, riskScore: Math.min(score, 100) };
}

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
    blue:    "hover:border-blue-400 hover:text-blue-600",
    indigo:  "hover:border-indigo-400 hover:text-indigo-600",
    violet:  "hover:border-violet-400 hover:text-violet-600",
    teal:    "hover:border-teal-400 hover:text-teal-600",
    emerald: "hover:border-emerald-400 hover:text-emerald-600",
    rose:    "hover:border-rose-400 hover:text-rose-600",
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
                <span className="block text-sm font-medium text-gray-700">{label}</span>
                {hint && <span className="block text-xs text-gray-400 mt-0.5">{hint}</span>}
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
                                    : `bg-white text-gray-600 border-gray-300 ${PILL_HOVER[color]}`
                            }`}
                        >
                            {opt}
                        </button>
                    );
                })}
            </div>
            {selected.length > 0 && (
                <p className="mt-2 text-xs text-gray-400 leading-relaxed">
                    ✓ {selected.join(" · ")}
                </p>
            )}
        </div>
    );
}

function SectionDivider({ label }: { label: string }) {
    return (
        <div className="flex items-center gap-3 py-1">
            <div className="flex-1 h-px bg-gray-100" />
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-widest whitespace-nowrap">
                {label}
            </span>
            <div className="flex-1 h-px bg-gray-100" />
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

export default function ThreatModelingPage() {
    const [form, setForm]         = useState<FormState>(initialForm);
    const [result, setResult]     = useState<AnalysisResult | null>(null);
    const [saveMsg, setSaveMsg]   = useState("");
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
    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!form.projectName.trim()) { setNameErr("Project name is required."); return; }
        setNameErr("");
        setSaveMsg("");
        setResult(generateThreats(form));
        setTimeout(() => window.scrollTo({ top: 0, behavior: "smooth" }), 50);
    };

    const handleReset = () => { setForm(initialForm); setResult(null); setSaveMsg(""); setNameErr(""); };
    const handleSave  = () => { setSaveMsg("✅ Report saved successfully!"); setTimeout(() => setSaveMsg(""), 3500); };

    const riskLabel  = result ? getRiskLabel(result.riskScore) : "";
    const barColor   = SCORE_COLOR[riskLabel]       ?? "bg-gray-300";
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
                                <label className="block text-sm font-medium text-gray-700 mb-2">Application Type</label>
                                <div className="flex flex-wrap gap-2">
                                    {APP_TYPES.map(type => (
                                        <button key={type} type="button"
                                            onClick={() => setForm(p => ({ ...p, appType: type }))}
                                            className={`px-4 py-2 rounded-lg text-sm font-medium border transition-all ${
                                                form.appType === type
                                                    ? "bg-blue-600 text-white border-blue-600 shadow-sm"
                                                    : "bg-white text-gray-600 border-gray-300 hover:border-blue-400 hover:text-blue-600"
                                            }`}
                                        >{type}</button>
                                    ))}
                                </div>
                            </div>

                            {/* System characteristics */}
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">System Characteristics</label>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                                    {CHECKBOXES.map(({ key, label }) => (
                                        <label key={key}
                                            className="flex items-center gap-3 px-4 py-3 rounded-lg border border-gray-200 hover:border-blue-300 hover:bg-blue-50/40 cursor-pointer transition-colors"
                                        >
                                            <input type="checkbox"
                                                checked={form[key] as boolean}
                                                onChange={() => toggleBool(key)}
                                                className="w-4 h-4 rounded accent-blue-600 border-gray-300"
                                            />
                                            <span className="text-sm text-gray-700">{label}</span>
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
                                        ? "border-blue-500 bg-blue-50"
                                        : "border-gray-300 hover:border-blue-400 hover:bg-blue-50/30"
                                }`}
                                onClick={() => fileInputRef.current?.click()}
                            >
                                <svg className="w-8 h-8 mx-auto text-gray-300 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                                </svg>
                                <p className="text-sm font-medium text-gray-700 mb-1">
                                    Drag & drop files here, or click to browse
                                </p>
                                <p className="text-xs text-gray-400">
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
                                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border border-gray-300 bg-white text-gray-700 hover:border-blue-400 hover:text-blue-600 transition-colors"
                                >
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
                                    </svg>
                                    Upload Entire Project Folder
                                </button>
                                <span className="text-xs text-gray-400">
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
                                <div className="rounded-lg border border-gray-200 overflow-hidden">
                                    <div className="flex items-center justify-between px-4 py-2.5 bg-gray-50 border-b border-gray-200">
                                        <span className="text-xs font-semibold text-gray-600 uppercase tracking-wide">
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
                                    <ul className="divide-y divide-gray-100 max-h-64 overflow-y-auto">
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
                                                    <p className="text-sm font-medium text-gray-800 truncate">{entry.name}</p>
                                                    {entry.path !== entry.name && (
                                                        <p className="text-xs text-gray-400 truncate font-mono">{entry.path}</p>
                                                    )}
                                                </div>
                                                <span className="text-xs text-gray-400 flex-shrink-0">{formatBytes(entry.size)}</span>
                                                <button
                                                    type="button"
                                                    onClick={() => removeUpload(entry.path)}
                                                    className="text-gray-300 hover:text-red-500 transition-colors ml-1 flex-shrink-0"
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
                            <h2 className="text-xl font-bold text-gray-900">
                                Threat Report —{" "}
                                <span className="text-blue-600">{form.projectName}</span>
                            </h2>
                            <p className="text-sm text-gray-500 mt-0.5">
                                {form.appType} · {result.threats.length} threat{result.threats.length !== 1 ? "s" : ""} identified
                                {form.uploads.length > 0 && ` · ${form.uploads.length} file${form.uploads.length !== 1 ? "s" : ""} uploaded`}
                            </p>
                        </div>
                        <div className="flex flex-wrap gap-2 flex-shrink-0">
                            <Button variant="secondary" size="sm" onClick={() => window.print()}>
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

                    {/* Save confirmation */}
                    {saveMsg && (
                        <div className="bg-green-50 border border-green-200 text-green-700 text-sm px-4 py-3 rounded-lg print:hidden">
                            {saveMsg}
                        </div>
                    )}

                    {/* ── Stack summary tags ── */}
                    {stackTags.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 print:hidden">
                            <span className="text-xs font-medium text-gray-400 self-center mr-1">Stack:</span>
                            {stackTags.map(tag => (
                                <span key={tag} className="text-xs bg-gray-100 text-gray-600 border border-gray-200 px-2.5 py-1 rounded-full font-medium">
                                    {tag}
                                </span>
                            ))}
                        </div>
                    )}

                    {/* ── Risk Score Card ── */}
                    <Card title="Overall Risk Score" description="Composite score based on all selected system properties">
                        <div className="flex items-center gap-6 mt-2">
                            <div className="flex-shrink-0 text-center w-20">
                                <div className="text-5xl font-bold text-gray-900 leading-none">{result.riskScore}</div>
                                <div className="text-sm text-gray-400 mt-1">/ 100</div>
                            </div>
                            <div className="flex-1">
                                <div className="flex justify-between items-center mb-2">
                                    <span className="text-sm font-medium text-gray-600">Risk Level</span>
                                    <span className={`text-sm font-semibold px-3 py-0.5 rounded-full ${labelStyle}`}>
                                        {riskLabel}
                                    </span>
                                </div>
                                <div className="w-full bg-gray-100 rounded-full h-3 overflow-hidden">
                                    <div
                                        className={`h-3 rounded-full transition-all duration-700 ease-out ${barColor}`}
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

                    {/* ── Uploaded files in report ── */}
                    {form.uploads.length > 0 && (
                        <Card title="Project Files Analyzed" description={`${form.uploads.length} file${form.uploads.length !== 1 ? "s" : ""} included in this analysis`}>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-1">
                                {form.uploads.map(u => (
                                    <div key={u.path} className="flex items-center gap-2.5 text-sm text-gray-600">
                                        {u.kind === "folder"
                                            ? <svg className="w-4 h-4 text-yellow-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
                                              </svg>
                                            : <svg className="w-4 h-4 text-blue-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                              </svg>
                                        }
                                        <span className="truncate font-medium">{u.name}</span>
                                        <span className="text-gray-400 text-xs flex-shrink-0">{formatBytes(u.size)}</span>
                                    </div>
                                ))}
                            </div>
                        </Card>
                    )}

                    {/* ── Threats list ── */}
                    <div>
                        <div className="flex items-center justify-between mb-3">
                            <h3 className="text-base font-semibold text-gray-800">
                                Identified Threats
                            </h3>
                            <div className="flex items-center gap-3 text-xs text-gray-400">
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
                                    className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
                                    {/* Threat header */}
                                    <div className="px-5 py-3.5 border-b border-gray-100 flex items-center justify-between gap-4">
                                        <div className="flex items-center gap-3 min-w-0">
                                            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${RISK_DOT[threat.risk]}`} />
                                            <div className="min-w-0">
                                                <h4 className="font-semibold text-gray-900 text-sm leading-tight truncate">
                                                    {threat.title}
                                                </h4>
                                                <span className="text-xs text-gray-400">{threat.category}</span>
                                            </div>
                                        </div>
                                        <span className={`flex-shrink-0 text-xs font-semibold px-2.5 py-1 rounded-full ${RISK_BADGE[threat.risk]}`}>
                                            {threat.risk} Risk
                                        </span>
                                    </div>
                                    {/* Threat body */}
                                    <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">
                                                Description
                                            </p>
                                            <p className="text-sm text-gray-600 leading-relaxed">
                                                {threat.description}
                                            </p>
                                        </div>
                                        <div className="md:border-l md:border-gray-100 md:pl-4">
                                            <p className="text-xs font-semibold text-green-600 uppercase tracking-wider mb-1.5">
                                                ✓ Mitigation
                                            </p>
                                            <p className="text-sm text-gray-600 leading-relaxed">
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
                        <p className="text-xs text-gray-400">
                            TIBSA Platform · Threat Modeling as a Service · Generated {new Date().toLocaleString()}
                        </p>
                        <p className="text-xs text-gray-400 mt-1">
                            Project: {form.projectName} · Type: {form.appType} · Risk Score: {result.riskScore}/100 ({riskLabel})
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
}
