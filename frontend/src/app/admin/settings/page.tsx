"use client";

import { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AdminSectionCard, ConfirmationModal } from "../components";

interface SettingToggle {
    key: string;
    label: string;
    description: string;
    enabled: boolean;
}

interface SettingInput {
    key: string;
    label: string;
    description: string;
    value: string;
    type: "text" | "number";
    placeholder?: string;
    min?: number;
    max?: number;
}

const DEFAULT_TOGGLES: SettingToggle[] = [
    { key: "2fa", label: "Enforce 2FA", description: "Require all users to enable two-factor authentication", enabled: true },
    { key: "audit", label: "Audit Logging", description: "Log all admin and security-relevant actions", enabled: true },
    { key: "auto_block", label: "Auto-Block Threats", description: "Automatically block IPs that exceed threat threshold", enabled: true },
    { key: "email_alerts", label: "Email Alerts", description: "Send email notifications for critical security events", enabled: false },
    { key: "api_access", label: "Public API Access", description: "Allow external API access with API keys", enabled: true },
    { key: "dark_mode", label: "Force Dark Mode", description: "Enforce dark mode for all users", enabled: true },
];

const DEFAULT_INPUTS: SettingInput[] = [
    { key: "rate_limit", label: "Rate Limit", description: "Maximum API requests per minute per user (1-10000)", value: "150", type: "number", placeholder: "100", min: 1, max: 10000 },
    { key: "session_timeout", label: "Session Timeout", description: "Minutes of inactivity before session expires (5-1440)", value: "30", type: "number", placeholder: "30", min: 5, max: 1440 },
    { key: "max_file_size", label: "Max Upload Size", description: "Maximum file upload size in MB (1-500)", value: "50", type: "number", placeholder: "50", min: 1, max: 500 },
    { key: "webhook_url", label: "Webhook URL", description: "URL for security event webhooks (must be valid HTTPS URL)", value: "", type: "text", placeholder: "https://hooks.example.com/alerts" },
];

export default function SettingsPage() {
    const [toggles, setToggles] = useState<SettingToggle[]>(DEFAULT_TOGGLES);
    const [inputs, setInputs] = useState<SettingInput[]>(DEFAULT_INPUTS);
    
    // Keep track of original state for dirty checking
    const [originalToggles, setOriginalToggles] = useState<SettingToggle[]>(DEFAULT_TOGGLES);
    const [originalInputs, setOriginalInputs] = useState<SettingInput[]>(DEFAULT_INPUTS);

    const [isLoaded, setIsLoaded] = useState(false);
    const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved">("idle");
    const [webhookStatus, setWebhookStatus] = useState<"idle" | "testing" | "success" | "error">("idle");

    // Danger Zone Modals
    const [activeModal, setActiveModal] = useState<"reset_feeds" | "purge_data" | null>(null);
    const [isConfirmingDanger, setIsConfirmingDanger] = useState(false);

    // Toast Notifications
    const [toast, setToast] = useState<{ message: string; type: "success" | "error" | "info" } | null>(null);

    const showToast = (message: string, type: "success" | "error" | "info") => {
        setToast({ message, type });
        setTimeout(() => setToast(null), 3000);
    };

    // Hydrate from localStorage
    useEffect(() => {
        try {
            const savedToggles = localStorage.getItem("tibsa_admin_toggles");
            const savedInputs = localStorage.getItem("tibsa_admin_inputs");
            
            if (savedToggles) {
                const parsed = JSON.parse(savedToggles);
                setToggles(parsed);
                setOriginalToggles(parsed);
            }
            if (savedInputs) {
                const parsed = JSON.parse(savedInputs);
                setInputs(parsed);
                setOriginalInputs(parsed);
            }
        } catch (e) {
            console.error("Failed to load settings from localStorage", e);
        }
        setIsLoaded(true);
    }, []);

    // ── Validation Logic ──
    const getValidationErrors = useMemo(() => {
        const errors: Record<string, string> = {};
        
        inputs.forEach(input => {
            if (input.type === "number") {
                const num = Number(input.value);
                if (isNaN(num)) {
                    errors[input.key] = "Must be a valid number";
                } else if (input.min !== undefined && num < input.min) {
                    errors[input.key] = `Minimum value is ${input.min}`;
                } else if (input.max !== undefined && num > input.max) {
                    errors[input.key] = `Maximum value is ${input.max}`;
                }
            } else if (input.key === "webhook_url" && input.value.trim() !== "") {
                try {
                    const url = new URL(input.value);
                    if (url.protocol !== "https:" && url.protocol !== "http:") {
                        errors[input.key] = "URL must start with http:// or https://";
                    }
                } catch {
                    errors[input.key] = "Must be a valid URL";
                }
            }
        });
        
        return errors;
    }, [inputs]);

    const hasErrors = Object.keys(getValidationErrors).length > 0;

    // ── Dirty State Logic ──
    const isDirty = useMemo(() => {
        const togglesChanged = JSON.stringify(toggles) !== JSON.stringify(originalToggles);
        const inputsChanged = JSON.stringify(inputs) !== JSON.stringify(originalInputs);
        return togglesChanged || inputsChanged;
    }, [toggles, originalToggles, inputs, originalInputs]);

    // ── Handlers ──
    const handleToggle = (key: string) => {
        setToggles((prev) => prev.map((t) => (t.key === key ? { ...t, enabled: !t.enabled } : t)));
    };

    const handleInputChange = (key: string, value: string) => {
        setInputs((prev) => prev.map((i) => (i.key === key ? { ...i, value } : i)));
    };

    const handleSave = () => {
        if (hasErrors || !isDirty) return;
        
        setSaveStatus("saving");
        
        // Simulate API and localStorage save
        setTimeout(() => {
            localStorage.setItem("tibsa_admin_toggles", JSON.stringify(toggles));
            localStorage.setItem("tibsa_admin_inputs", JSON.stringify(inputs));
            setOriginalToggles(toggles);
            setOriginalInputs(inputs);
            
            setSaveStatus("saved");
            showToast("Settings saved successfully", "success");
            
            setTimeout(() => setSaveStatus("idle"), 2000);
        }, 800);
    };

    const handleWebhookTest = () => {
        const webhookUrl = inputs.find(i => i.key === "webhook_url")?.value;
        if (!webhookUrl || getValidationErrors["webhook_url"]) return;

        setWebhookStatus("testing");
        setTimeout(() => {
            // Mock success based on random chance or just success
            const success = Math.random() > 0.2;
            if (success) {
                setWebhookStatus("success");
                showToast("Webhook test payload delivered successfully", "success");
            } else {
                setWebhookStatus("error");
                showToast("Webhook test failed (simulated timeout)", "error");
            }
            setTimeout(() => setWebhookStatus("idle"), 3000);
        }, 1500);
    };

    const executeDangerAction = (action: "reset_feeds" | "purge_data") => {
        setIsConfirmingDanger(true);
        setTimeout(() => {
            setIsConfirmingDanger(false);
            setActiveModal(null);
            showToast(action === "reset_feeds" ? "Threat feeds reset to defaults" : "Scan history purged successfully", "success");
        }, 1500);
    };

    if (!isLoaded) return null; // Avoid hydration mismatch

    return (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }} className="space-y-6 max-w-[900px]">
            {/* ── Toast Notifications ── */}
            <AnimatePresence>
                {toast && (
                    <motion.div
                        initial={{ opacity: 0, y: -20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        className="fixed top-6 right-6 z-50 pointer-events-none"
                    >
                        <div className={`flex items-center gap-3 px-4 py-3 rounded-lg shadow-2xl border backdrop-blur-md ${
                            toast.type === "success" ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" :
                            toast.type === "error" ? "bg-red-500/10 border-red-500/20 text-red-400" :
                            "bg-blue-500/10 border-blue-500/20 text-blue-400"
                        }`}>
                            {toast.type === "success" && (
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                                </svg>
                            )}
                            {toast.type === "error" && (
                                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                </svg>
                            )}
                            <p className="text-sm font-medium">{toast.message}</p>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* ── Header ── */}
            <div className="flex items-center justify-between">
                <div>
                    <div className="flex items-center gap-3 mb-1">
                        <h1 className="text-2xl font-bold text-white">System Settings</h1>
                        <span className="px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-widest bg-gradient-to-r from-slate-500/20 to-blue-500/20 border border-slate-500/20 text-slate-400 rounded-full">
                            Config
                        </span>
                    </div>
                    <p className="text-sm text-slate-400">Configure platform security, rate limits, and integrations</p>
                </div>
                <div className="flex items-center gap-4">
                    {isDirty && !hasErrors && (
                        <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-xs text-amber-400 flex items-center gap-1.5">
                            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                            Unsaved changes
                        </motion.span>
                    )}
                    <button
                        onClick={handleSave}
                        disabled={saveStatus === "saving" || !isDirty || hasErrors}
                        className={`flex items-center gap-2 px-5 py-2.5 text-sm font-medium rounded-lg transition-all ${
                            saveStatus === "saved"
                                ? "bg-emerald-500/20 border border-emerald-500/30 text-emerald-400"
                                : !isDirty || hasErrors
                                ? "bg-white/[0.04] text-slate-500 cursor-not-allowed border border-transparent"
                                : "bg-blue-500 text-white hover:bg-blue-400 shadow-lg shadow-blue-500/20"
                        }`}
                    >
                        {saveStatus === "saving" && (
                            <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                            </svg>
                        )}
                        {saveStatus === "saved" && (
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                            </svg>
                        )}
                        {saveStatus === "saving" ? "Saving..." : saveStatus === "saved" ? "Saved!" : "Save Changes"}
                    </button>
                </div>
            </div>

            {/* ── Security Toggles ── */}
            <AdminSectionCard
                title="Security & Access"
                description="Configure security policies and access controls"
            >
                <div className="space-y-1">
                    {toggles.map((toggle) => (
                        <div
                            key={toggle.key}
                            className="flex items-center justify-between px-3 py-3 rounded-lg hover:bg-white/[0.02] transition-colors"
                        >
                            <div>
                                <p className="text-sm font-medium text-slate-200">{toggle.label}</p>
                                <p className="text-xs text-slate-500 mt-0.5">{toggle.description}</p>
                            </div>
                            <button
                                onClick={() => handleToggle(toggle.key)}
                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500/30 ${
                                    toggle.enabled ? "bg-blue-500" : "bg-white/[0.1]"
                                }`}
                            >
                                <span
                                    className={`inline-block h-4 w-4 rounded-full bg-white shadow-md transition-transform duration-200 ${
                                        toggle.enabled ? "translate-x-6" : "translate-x-1"
                                    }`}
                                />
                            </button>
                        </div>
                    ))}
                </div>
            </AdminSectionCard>

            {/* ── Configuration Inputs ── */}
            <AdminSectionCard
                title="Platform Configuration"
                description="Set rate limits, timeouts, and integration endpoints"
            >
                <div className="space-y-6">
                    {inputs.map((input) => {
                        const error = getValidationErrors[input.key];
                        return (
                            <div key={input.key} className="space-y-1.5">
                                <label className="block text-sm font-medium text-slate-200 flex items-center justify-between">
                                    {input.label}
                                    {error && <span className="text-xs text-red-400">{error}</span>}
                                </label>
                                <p className="text-xs text-slate-500">{input.description}</p>
                                <div className="relative">
                                    <input
                                        type={input.type}
                                        value={input.value}
                                        onChange={(e) => handleInputChange(input.key, e.target.value)}
                                        placeholder={input.placeholder}
                                        className={`w-full px-4 py-2.5 bg-white/[0.02] border rounded-lg text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 transition-colors ${
                                            error
                                                ? "border-red-500/50 focus:border-red-500 focus:ring-red-500/50"
                                                : "border-white/[0.08] focus:border-blue-500/40 focus:ring-blue-500/20"
                                        }`}
                                    />
                                    {input.key === "webhook_url" && input.value.trim() !== "" && !error && (
                                        <div className="absolute right-2 top-1/2 -translate-y-1/2">
                                            <button
                                                onClick={handleWebhookTest}
                                                disabled={webhookStatus === "testing"}
                                                className={`px-3 py-1 text-xs font-medium rounded-md transition-colors ${
                                                    webhookStatus === "testing" ? "bg-white/[0.04] text-slate-400" :
                                                    webhookStatus === "success" ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/20" :
                                                    webhookStatus === "error" ? "bg-red-500/20 text-red-400 border border-red-500/20" :
                                                    "bg-blue-500/10 text-blue-400 hover:bg-blue-500/20"
                                                }`}
                                            >
                                                {webhookStatus === "testing" ? "Testing..." : webhookStatus === "success" ? "Success" : webhookStatus === "error" ? "Failed" : "Test Connection"}
                                            </button>
                                        </div>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                </div>
            </AdminSectionCard>

            {/* ── Danger Zone ── */}
            <AdminSectionCard
                title={<span className="text-red-400 flex items-center gap-2"><svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>Danger Zone</span>}
                description="Irreversible actions — proceed with caution"
                className="border-red-500/20 bg-red-500/[0.01]"
            >
                <div className="space-y-4">
                    <div className="flex items-center justify-between px-4 py-4 rounded-lg bg-red-500/[0.03] border border-red-500/10">
                        <div>
                            <p className="text-sm font-medium text-red-400">Reset All Threat Feeds</p>
                            <p className="text-xs text-slate-500 mt-0.5 max-w-sm">Remove all custom threat feed configurations and reset the platform to default sources.</p>
                        </div>
                        <button
                            onClick={() => setActiveModal("reset_feeds")}
                            className="px-4 py-2 text-xs font-medium rounded-lg border border-red-500/30 text-red-400 hover:bg-red-500/10 hover:border-red-500/50 transition-colors"
                        >
                            Reset Feeds
                        </button>
                    </div>
                    <div className="flex items-center justify-between px-4 py-4 rounded-lg bg-red-500/[0.03] border border-red-500/10">
                        <div>
                            <p className="text-sm font-medium text-red-400">Purge Scan History</p>
                            <p className="text-xs text-slate-500 mt-0.5 max-w-sm">Permanently delete all historical scan data older than 90 days. This action cannot be undone.</p>
                        </div>
                        <button
                            onClick={() => setActiveModal("purge_data")}
                            className="px-4 py-2 text-xs font-medium rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 hover:border-red-500/50 transition-colors"
                        >
                            Purge Data
                        </button>
                    </div>
                </div>
            </AdminSectionCard>

            {/* Modals */}
            <ConfirmationModal
                isOpen={activeModal === "reset_feeds"}
                onClose={() => setActiveModal(null)}
                onConfirm={() => executeDangerAction("reset_feeds")}
                title="Reset Threat Feeds"
                description="You are about to reset all threat intelligence configurations."
                consequences="This will immediately detach all custom indicator feeds, API keys for external intelligence, and revert the platform to factory defaults. Active alerts may be disrupted."
                confirmationString="RESET"
                isConfirming={isConfirmingDanger}
            />

            <ConfirmationModal
                isOpen={activeModal === "purge_data"}
                onClose={() => setActiveModal(null)}
                onConfirm={() => executeDangerAction("purge_data")}
                title="Purge Historical Scan Data"
                description="You are about to irreversibly delete system data."
                consequences="All security scan history, detected vulnerabilities, and linked IP intelligence logs older than 90 days will be permanently wiped from the primary database."
                confirmationString="PURGE"
                isConfirming={isConfirmingDanger}
            />
        </motion.div>
    );
}
