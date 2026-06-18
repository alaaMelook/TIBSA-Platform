"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

interface ConfirmationModalProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    title: string;
    description: string;
    consequences: string;
    confirmationString: string;
    isConfirming?: boolean;
}

export function ConfirmationModal({
    isOpen,
    onClose,
    onConfirm,
    title,
    description,
    consequences,
    confirmationString,
    isConfirming = false,
}: ConfirmationModalProps) {
    const [input, setInput] = useState("");

    const isValid = input === confirmationString;

    const handleConfirm = () => {
        if (isValid && !isConfirming) {
            onConfirm();
        }
    };

    // Reset input when modal closes
    if (!isOpen && input) {
        setInput("");
    }

    return (
        <AnimatePresence>
            {isOpen && (
                <>
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={!isConfirming ? onClose : undefined}
                        className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
                    />
                    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95, y: 20 }}
                            animate={{ opacity: 1, scale: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 0.95, y: 20 }}
                            className="w-full max-w-md bg-[var(--bg-card)] border border-red-500/30 rounded-xl shadow-2xl shadow-red-500/10 pointer-events-auto overflow-hidden"
                        >
                            {/* Header */}
                            <div className="flex items-center gap-3 p-5 border-b border-[var(--border-strong)] bg-red-500/[0.03]">
                                <div className="w-10 h-10 rounded-full bg-red-500/10 flex items-center justify-center shrink-0">
                                    <svg className="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                    </svg>
                                </div>
                                <div>
                                    <h3 className="text-lg font-bold text-[var(--text-primary)]">{title}</h3>
                                    <p className="text-sm text-red-400">{description}</p>
                                </div>
                            </div>

                            {/* Body */}
                            <div className="p-5 space-y-4">
                                <p className="text-sm text-[var(--text-secondary)]">
                                    {consequences}
                                </p>
                                <div className="space-y-2">
                                    <label className="block text-xs font-medium text-[var(--text-muted)]">
                                        Please type <span className="font-mono text-red-400 select-all">{confirmationString}</span> to confirm.
                                    </label>
                                    <input
                                        type="text"
                                        value={input}
                                        onChange={(e) => setInput(e.target.value)}
                                        placeholder={confirmationString}
                                        disabled={isConfirming}
                                        className="w-full px-3 py-2 bg-black/20 border border-[var(--border-soft)] rounded-md text-sm text-[var(--text-primary)] placeholder-slate-600 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/50 transition-colors"
                                    />
                                </div>
                            </div>

                            {/* Footer */}
                            <div className="flex items-center justify-end gap-3 p-5 border-t border-[var(--border-strong)] bg-black/20">
                                <button
                                    onClick={onClose}
                                    disabled={isConfirming}
                                    className="px-4 py-2 text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-50"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleConfirm}
                                    disabled={!isValid || isConfirming}
                                    className={`flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium rounded-md transition-all ${
                                        isValid
                                            ? "bg-red-500 text-[var(--text-primary)] hover:bg-red-600 shadow-lg shadow-red-500/20"
                                            : "bg-[var(--bg-elevated)] text-[var(--text-muted)] cursor-not-allowed"
                                    }`}
                                >
                                    {isConfirming ? (
                                        <>
                                            <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                            </svg>
                                            Confirming...
                                        </>
                                    ) : (
                                        "Confirm Action"
                                    )}
                                </button>
                            </div>
                        </motion.div>
                    </div>
                </>
            )}
        </AnimatePresence>
    );
}
