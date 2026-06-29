"use client";

import React, { useState, useRef, useEffect, useCallback } from "react";
import { useAuthContext } from "@/contexts/AuthContext";
import ReactMarkdown from "react-markdown";
import { MessageCircle } from "lucide-react";

/* ── Types ─────────────────────────────────────────────────── */
interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
  category?: string;
  safe?: boolean;
}

interface ChatAPIResponse {
  answer: string;
  language: string;
  category: string;
  safe: boolean;
  provider: string;
  model: string;
}

/* ── Suggested Questions ───────────────────────────────────── */
const SUGGESTED_QUESTIONS = [
  "What is Threat Modeling?",
  "What is STRIDE?",
  "What is Threat Intelligence?",
  "What is XSS?",
  "What is SQL Injection?",
  "What is CSRF?",
  "What does Missing CSP mean?",
  "How do I secure authentication?",
  "How do I secure APIs?",
  "What should I do after a scan?",
  "How does TIBSA work?",
];

/* ── Inline SVG Icons ──────────────────────────────────────── */
const BotIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 8V4H8" /><rect width="16" height="12" x="4" y="8" rx="2" />
    <path d="M2 14h2" /><path d="M20 14h2" /><path d="M15 13v2" /><path d="M9 13v2" />
  </svg>
);
const SendIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="m22 2-7 20-4-9-9-4Z" /><path d="M22 2 11 13" />
  </svg>
);
const CloseIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 6 6 18" /><path d="m6 6 12 12" />
  </svg>
);
const CopyIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect width="14" height="14" x="8" y="8" rx="2" /><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
  </svg>
);
const TrashIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 6h18" /><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" /><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" />
  </svg>
);
const StopIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2" /></svg>
);
const CheckIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#4ade80" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 6 9 17l-5-5" />
  </svg>
);
const RetryIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
    <path d="M3 3v5h5" />
  </svg>
);

/* ── Component ─────────────────────────────────────────────── */
export default function FloatingChatbot() {
  const { token } = useAuthContext();
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<{ message: string; isRateLimit: boolean } | null>(null);
  const [cooldown, setCooldown] = useState(0);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  
  const bodyRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const scroll = useCallback(() => {
    setTimeout(() => bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight, behavior: "smooth" }), 50);
  }, [messages, error, loading]);

  useEffect(scroll, [scroll]);

  useEffect(() => {
    if (cooldown > 0) {
      const timer = setTimeout(() => setCooldown(c => c - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [cooldown]);

  /* ── Copy answer ──────────────────────────────────────────── */
  const copyText = (id: string, text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1500);
    });
  };

  /* ── Clear chat ───────────────────────────────────────────── */
  const clearChat = () => { 
    setMessages([]); 
    setError(null); 
    setCooldown(0);
  };

  /* ── Stop generating ──────────────────────────────────────── */
  const stopGenerating = () => { abortRef.current?.abort(); };

  /* ── API Call ─────────────────────────────────────────────── */
  const sendToAPI = async (text: string) => {
    setError(null);
    setLoading(true);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
      const res = await fetch(`${API_BASE}/api/v1/ai-chatbot/chat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ message: text, language: "auto", context: { page: "dashboard", module: "general" } }),
        signal: controller.signal,
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        const detail = errData.detail || `HTTP ${res.status}`;
        if (res.status === 429 || detail.toLowerCase().includes("rate limit")) {
          throw new Error("RATE_LIMIT");
        } else if (res.status === 503) {
          throw new Error("AI chatbot is not configured. Please set your OpenRouter API key.");
        }
        throw new Error(detail);
      }

      const data: ChatAPIResponse = await res.json();
      const botMsg: ChatMessage = {
        id: (Date.now() + 1).toString(), role: "assistant",
        content: data.answer, timestamp: new Date(),
        category: data.category, safe: data.safe,
      };
      setMessages(p => [...p, botMsg]);
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setMessages(p => [...p, {
          id: (Date.now() + 1).toString(), role: "assistant",
          content: "⏹ Response generation was stopped.", timestamp: new Date(),
        }]);
      } else {
        const msg = err instanceof Error ? err.message : "Something went wrong.";
        if (msg === "RATE_LIMIT") {
          setError({ message: "Free AI model limit reached. Please try again in a few minutes.", isRateLimit: true });
          setCooldown(30);
        } else {
          setError({ message: msg, isRateLimit: false });
        }
      }
    } finally {
      setLoading(false);
      abortRef.current = null;
    }
  };

  /* ── Send message ─────────────────────────────────────────── */
  const sendMessage = async (text: string) => {
    if (!text.trim() || loading || cooldown > 0) return;
    const userMsg: ChatMessage = { id: Date.now().toString(), role: "user", content: text.trim(), timestamp: new Date() };
    setMessages(p => [...p, userMsg]);
    setInput("");
    await sendToAPI(text.trim());
  };

  /* ── Retry Last Message ───────────────────────────────────── */
  const retryLastMessage = () => {
    if (loading || cooldown > 0) return;
    const lastMsg = messages[messages.length - 1];
    if (lastMsg && lastMsg.role === "user") {
      sendToAPI(lastMsg.content);
    }
  };

  const handleKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) { 
      e.preventDefault(); 
      if (input.trim() && !loading && cooldown === 0) {
        sendMessage(input); 
      }
    }
  };

  return (
    <>
      {/* FAB — Cybersecurity Mascot */}
      <button 
        id="ai-chatbot-fab" 
        onClick={() => setOpen(o => !o)}
        aria-label="Open AI Security Chatbot"
        className={`fixed bottom-6 right-6 z-[9999] flex h-[60px] w-[60px] items-center justify-center rounded-full bg-gradient-to-br from-[#0f9d76] to-[#0b7d5d] shadow-[0_4px_20px_rgba(15,157,118,0.35)] transition-all duration-300 hover:scale-110 hover:shadow-[0_6px_28px_rgba(15,157,118,0.45)] focus:outline-none focus:ring-4 focus:ring-[#0f9d76]/30 ${open ? 'scale-0 opacity-0 pointer-events-none' : 'scale-100 opacity-100 chatbot-fab-pulse'}`}
      >
        {/* Custom mascot SVG */}
        <svg width="34" height="34" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
          {/* Chat bubble body */}
          <rect x="6" y="7" width="28" height="22" rx="8" fill="white" fillOpacity="0.95" />
          <rect x="6" y="7" width="28" height="22" rx="8" stroke="white" strokeWidth="0.5" strokeOpacity="0.3" />
          {/* Bubble tail */}
          <path d="M12 29 L9 35 L17 29" fill="white" fillOpacity="0.95" />
          {/* Left eye */}
          <circle cx="16" cy="17" r="2.2" fill="#0f9d76" />
          <circle cx="16.6" cy="16.4" r="0.7" fill="white" />
          {/* Right eye */}
          <circle cx="24" cy="17" r="2.2" fill="#0f9d76" />
          <circle cx="24.6" cy="16.4" r="0.7" fill="white" />
          {/* Smile */}
          <path d="M16.5 22.5 Q20 25.5 23.5 22.5" stroke="#0f9d76" strokeWidth="1.5" strokeLinecap="round" fill="none" />
          {/* Shield badge (bottom-right of bubble) */}
          <g transform="translate(28, 22)">
            <path d="M0-1.5 L4-1.5 L4 2 Q4 5 2 6.5 Q0 5 0 2 Z" fill="#0f9d76" stroke="white" strokeWidth="1" />
            <path d="M1.3 1.5 L1.8 2.2 L3 0.8" stroke="white" strokeWidth="0.8" strokeLinecap="round" strokeLinejoin="round" fill="none" />
          </g>
          {/* Sparkle accent (top-right) */}
          <g transform="translate(31, 6)" className="chatbot-sparkle">
            <line x1="2" y1="0" x2="2" y2="4" stroke="white" strokeWidth="1" strokeLinecap="round" opacity="0.9" />
            <line x1="0" y1="2" x2="4" y2="2" stroke="white" strokeWidth="1" strokeLinecap="round" opacity="0.9" />
          </g>
        </svg>
      </button>

      {/* Window */}
      <div 
        id="ai-chatbot-window" 
        className={`fixed bottom-6 right-6 z-[9998] flex flex-col overflow-hidden rounded-2xl border border-[var(--border-strong)] bg-[var(--bg-card)] shadow-md transition-all duration-300 ease-in-out ${
          open ? 'scale-100 opacity-100 translate-y-0' : 'pointer-events-none scale-95 opacity-0 translate-y-4'
        } w-[calc(100vw-24px)] h-[calc(100vh-120px)] sm:w-[520px] sm:h-[680px] max-w-[calc(100vw-32px)] max-h-[calc(100vh-32px)] transform origin-bottom-right`}
      >
        {/* Header */}
        <div className="flex items-center gap-4 border-b border-[var(--border-strong)] bg-[var(--bg-card)] p-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-[var(--primary-soft)] border border-[var(--primary)] text-[var(--primary)] shadow-sm">
            <BotIcon />
          </div>
          <div>
            <h2 className="m-0 text-lg font-semibold tracking-tight text-[var(--text-primary)]">TIBSA AI Assistant</h2>
            <p className="m-0 text-xs font-medium text-[var(--text-secondary)]">Cybersecurity & Platform Help</p>
          </div>
          <div className="ml-auto flex gap-2">
            {messages.length > 0 && (
              <button 
                onClick={clearChat} 
                title="Clear chat"
                className="flex h-9 w-9 items-center justify-center rounded-lg text-[var(--text-muted)] transition-colors hover:bg-red-100 hover:text-red-600 focus:outline-none"
              >
                <TrashIcon />
              </button>
            )}
            <button 
              onClick={() => setOpen(false)} 
              aria-label="Close chat"
              className="flex h-9 w-9 items-center justify-center rounded-lg text-[var(--text-muted)] transition-colors hover:bg-[var(--bg-page)] hover:text-[var(--text-primary)] focus:outline-none"
            >
              <CloseIcon />
            </button>
          </div>
        </div>

        {/* Body */}
        <div 
          ref={bodyRef} 
          className="flex flex-1 flex-col gap-6 overflow-y-auto p-5 pb-6 bg-[var(--bg-page)] scroll-smooth"
        >
          {messages.length === 0 && !loading && (
            <div className="mt-2">
              <p className="mb-4 text-sm leading-relaxed text-[var(--text-secondary)]">
                👋 Hi! Ask me anything about cybersecurity or the TIBSA platform.
              </p>
              <div className="flex flex-wrap gap-2.5">
                {SUGGESTED_QUESTIONS.map(q => (
                  <button 
                    key={q} 
                    onClick={() => sendMessage(q)}
                    className="rounded-lg border border-[var(--primary)] bg-[var(--bg-card)] px-3.5 py-2 text-sm font-medium text-[var(--primary)] transition-all hover:bg-[var(--primary-soft)] hover:border-[var(--primary-hover)] hover:text-[var(--primary-hover)] focus:outline-none active:scale-95"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map(m => m.role === "user" ? (
            <div key={m.id} className="self-end max-w-[80%] rounded-2xl rounded-tr-sm bg-[var(--primary)] p-3.5 text-sm leading-relaxed !text-white shadow-sm">
              <span className="whitespace-pre-wrap">{m.content}</span>
            </div>
          ) : (
            <div key={m.id} className="group flex w-full max-w-[85%] items-start gap-3 self-start">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--primary-soft)] border border-[var(--primary)] text-[var(--primary)] shadow-sm mt-1">
                <BotIcon />
              </div>
              <div className="flex flex-col items-start gap-1 w-full overflow-hidden">
                <div className="w-full overflow-hidden rounded-2xl rounded-tl-sm border border-[var(--border-strong)] bg-[var(--bg-elevated)] p-4 text-sm leading-relaxed text-[var(--text-primary)] shadow-sm">
                  <ReactMarkdown
                    components={{
                      p: ({ node, ...props }) => <p className="mb-3 last:mb-0" {...props} />,
                      ul: ({ node, ...props }) => <ul className="mb-3 list-disc pl-5 last:mb-0 space-y-1" {...props} />,
                      ol: ({ node, ...props }) => <ol className="mb-3 list-decimal pl-5 last:mb-0 space-y-1" {...props} />,
                      li: ({ node, ...props }) => <li className="mb-1" {...props} />,
                      h1: ({ node, ...props }) => <h3 className="mb-2 mt-4 text-base font-semibold text-[var(--text-primary)] first:mt-0" {...props} />,
                      h2: ({ node, ...props }) => <h3 className="mb-2 mt-4 text-base font-semibold text-[var(--text-primary)] first:mt-0" {...props} />,
                      h3: ({ node, ...props }) => <h3 className="mb-2 mt-4 text-base font-semibold text-[var(--text-primary)] first:mt-0" {...props} />,
                      code: ({ node, className, children, ...props }) => {
                        const match = /language-(\w+)/.exec(className || "");
                        const isInline = !match && !className;
                        return isInline ? (
                          <code className="rounded bg-[var(--bg-page)] border border-[var(--border-soft)] px-1.5 py-0.5 text-[13px] font-mono text-[var(--text-primary)]" {...props}>
                            {children}
                          </code>
                        ) : (
                          <code className={className} {...props}>
                            {children}
                          </code>
                        );
                      },
                      pre: ({ node, ...props }) => <pre className="my-3 overflow-x-auto rounded-lg bg-[var(--bg-page)] p-3 text-[13px] font-mono text-[var(--text-primary)] border border-[var(--border-soft)]" {...props} />,
                    }}
                  >
                    {m.content}
                  </ReactMarkdown>
                </div>
                <button 
                  onClick={() => copyText(m.id, m.content)} 
                  title="Copy answer"
                  className="flex items-center gap-1.5 px-2 py-1 text-xs font-medium text-[var(--text-muted)] opacity-0 transition-all group-hover:opacity-100 hover:text-[var(--text-secondary)] focus:opacity-100"
                >
                  {copiedId === m.id ? <><CheckIcon /><span>Copied</span></> : <><CopyIcon /><span>Copy</span></>}
                </button>
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex w-full max-w-[85%] items-start gap-3 self-start">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--primary-soft)] border border-[var(--primary)] text-[var(--primary)] shadow-sm mt-1">
                <BotIcon />
              </div>
              <div className="flex flex-col items-start gap-2 mt-2">
                <div className="flex items-center gap-1.5 rounded-2xl rounded-tl-sm border border-[var(--border-strong)] bg-[var(--bg-elevated)] px-4 py-3 shadow-sm">
                  {[0, 1, 2].map(i => (
                    <span key={i} className="h-2 w-2 rounded-full bg-[var(--primary)]" style={{ animation: `chatDotPulse 1.2s ${i * 0.2}s infinite ease-in-out` }} />
                  ))}
                </div>
                <span className="pl-1 text-xs font-medium text-[var(--text-muted)]">Generating response…</span>
              </div>
            </div>
          )}

          {error && (
            <div className="flex w-full max-w-[85%] items-start gap-3 self-start">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--bg-elevated)] text-[var(--text-muted)] shadow-sm mt-1 border border-[var(--border-soft)]">
                <BotIcon />
              </div>
              <div className="flex flex-col items-start gap-2 w-full mt-1">
                <div className={`w-fit rounded-2xl rounded-tl-sm border px-4 py-3 text-[13px] leading-relaxed shadow-sm backdrop-blur-sm ${
                  error.isRateLimit 
                    ? 'border-amber-500/20 bg-amber-500/10 text-amber-700' 
                    : 'border-red-500/20 bg-red-500/10 text-red-700'
                }`}>
                  {error.message}
                </div>
                <button
                  onClick={retryLastMessage}
                  disabled={cooldown > 0}
                  className="ml-1 flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium text-[var(--text-muted)] transition-colors hover:bg-[var(--bg-elevated)] hover:text-[var(--text-primary)] disabled:pointer-events-none disabled:opacity-50"
                >
                  <RetryIcon />
                  {cooldown > 0 ? `Retry in ${cooldown}s` : "Retry"}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Input */}
        <div className="border-t border-[var(--border-strong)] bg-[var(--bg-card)] p-4">
          <div className="relative flex items-end gap-3">
            <textarea 
              rows={1} 
              placeholder="Ask a security question…"
              value={input} 
              onChange={e => {
                setInput(e.target.value);
                e.target.style.height = 'auto';
                e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
              }} 
              onKeyDown={handleKey} 
              disabled={loading}
              className="max-h-[120px] min-h-[52px] w-full resize-none rounded-2xl border border-[var(--border-strong)] bg-[var(--bg-elevated)] py-3.5 pl-5 pr-14 text-sm leading-relaxed text-[var(--text-primary)] placeholder-[var(--text-muted)] transition-all focus:border-[var(--primary)] focus:bg-[var(--bg-elevated)] focus:outline-none focus:ring-4 focus:ring-[var(--primary)]/20 disabled:opacity-50"
            />
            <div className="absolute right-1.5 bottom-1.5 flex">
              {loading ? (
                <button 
                  onClick={stopGenerating} 
                  title="Stop generating"
                  className="flex h-10 w-10 items-center justify-center rounded-full bg-red-100 text-red-600 transition-colors hover:bg-red-200 focus:outline-none"
                >
                  <StopIcon />
                </button>
              ) : (
                <button 
                  onClick={() => sendMessage(input)} 
                  disabled={!input.trim() || cooldown > 0} 
                  aria-label="Send"
                  className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] !text-white shadow-sm transition-all hover:scale-105 hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-[var(--primary)]/50 disabled:pointer-events-none disabled:opacity-50"
                >
                  <SendIcon />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes chatDotPulse {
          0%, 80%, 100% { opacity: 0.3; transform: scale(0.8); }
          40% { opacity: 1; transform: scale(1.1); }
        }
        /* Soft breathing pulse for the FAB */
        @keyframes fabPulse {
          0%, 100% { box-shadow: 0 4px 20px rgba(15, 157, 118, 0.35); }
          50% { box-shadow: 0 4px 28px rgba(15, 157, 118, 0.5), 0 0 0 8px rgba(15, 157, 118, 0.08); }
        }
        .chatbot-fab-pulse {
          animation: fabPulse 3s ease-in-out infinite;
        }
        /* Sparkle twinkle */
        @keyframes sparkleTwinkle {
          0%, 100% { opacity: 0.5; transform: scale(0.8) rotate(0deg); }
          50% { opacity: 1; transform: scale(1.15) rotate(15deg); }
        }
        .chatbot-sparkle {
          animation: sparkleTwinkle 2.5s ease-in-out infinite;
          transform-origin: center;
        }
        /* Custom scrollbar for chatbot body */
        #ai-chatbot-window ::-webkit-scrollbar {
          width: 6px;
        }
        #ai-chatbot-window ::-webkit-scrollbar-track {
          background: transparent;
        }
        #ai-chatbot-window ::-webkit-scrollbar-thumb {
          background: rgba(148, 163, 184, 0.2);
          border-radius: 10px;
        }
        #ai-chatbot-window ::-webkit-scrollbar-thumb:hover {
          background: rgba(148, 163, 184, 0.4);
        }
      `}</style>
    </>
  );
}
