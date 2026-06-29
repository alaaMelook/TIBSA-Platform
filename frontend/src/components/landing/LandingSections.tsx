"use client";
import Link from "next/link";
import { useEffect } from "react";
import {
  ArrowRight, CheckCircle, AlertTriangle, Globe, FileSearch,
  Shield, BarChart3, FileText, Zap, Database, Brain, Lock,
} from "lucide-react";

export default function LandingSections() {
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) entry.target.classList.add("is-visible");
        });
      },
      { threshold: 0.07, rootMargin: "0px 0px -30px 0px" }
    );
    document.querySelectorAll(".reveal").forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, []);

  return (
    <>
      <style>{`
        .reveal {
          opacity: 0;
          transform: translateY(20px);
          transition: opacity 0.55s ease, transform 0.55s ease;
        }
        .reveal.is-visible { opacity: 1; transform: translateY(0); }
        .d1 { transition-delay: 0.08s; }
        .d2 { transition-delay: 0.16s; }
        .d3 { transition-delay: 0.24s; }
        .d4 { transition-delay: 0.32s; }
        .d5 { transition-delay: 0.40s; }
        .lift {
          transition: transform 0.28s ease, box-shadow 0.28s ease;
        }
        .lift:hover {
          transform: translateY(-5px);
          box-shadow: 0 18px 48px rgba(15,157,118,0.11);
        }
        /* Workflow connector line between steps */
        @media (min-width: 1024px) {
          .step-wrap:not(:last-child)::after {
            content: '';
            position: absolute;
            top: 22px;
            right: -24px;
            width: 48px;
            height: 1px;
            background: linear-gradient(90deg, #0f9d76 0%, #d9cdbf 100%);
            opacity: 0.45;
          }
        }
      `}</style>

      {/* ────────────────────────────────────────────
          ABOUT
      ──────────────────────────────────────────── */}
      <section
        id="about"
        className="scroll-mt-28 relative z-10 py-28 px-6 lg:px-10 xl:px-12"
        style={{ background: "rgba(248,243,235,0.55)" }}
      >
        {/* Soft band separator top */}
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#d9cdbf]/60 to-transparent" />

        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-14 lg:gap-20 items-start">

            {/* Left: text */}
            <div>
              <div className="reveal inline-flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.18em] text-[#0f9d76] bg-[#edf8f3] border border-[#0f9d76]/25 px-4 py-1.5 rounded-full mb-6">
                <span className="w-1.5 h-1.5 rounded-full bg-[#0f9d76] inline-block" />
                About TIBSA
              </div>
              <h2 className="reveal d1 text-3xl sm:text-4xl xl:text-5xl font-black text-[#1d1d1d] tracking-tight leading-[1.1] mb-6">
                Security Intelligence,<br />Not Just Raw Data
              </h2>
              <p className="reveal d2 text-[#4f4a45] text-[16px] font-medium leading-[1.75] max-w-lg">
                TIBSA is a security intelligence platform designed to turn raw scanner
                findings into meaningful risk insights. It combines website scanning,
                threat intelligence enrichment, contextual risk analysis, STRIDE threat
                modeling, and AI-powered reporting in one unified workflow.
              </p>
            </div>

            {/* Right: highlight cards */}
            <div className="flex flex-col gap-4">
              {[
                {
                  icon: <CheckCircle className="w-5 h-5" />,
                  title: "Reduces False Positives",
                  desc: "Context-aware analysis distinguishes real threats from noise automatically.",
                },
                {
                  icon: <Shield className="w-5 h-5" />,
                  title: "Confirmed vs Potential",
                  desc: "Separates verified vulnerabilities from advisory hardening findings.",
                },
                {
                  icon: <BarChart3 className="w-5 h-5" />,
                  title: "Clear Risk Impact",
                  desc: "Helps teams understand business impact and prioritise remediation.",
                },
              ].map(({ icon, title, desc }, i) => (
                <div
                  key={i}
                  className={`reveal d${i + 1} lift bg-white/80 border border-[#e7ddd1] rounded-2xl p-5 flex gap-4 items-start`}
                >
                  <div className="w-10 h-10 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center flex-shrink-0">
                    {icon}
                  </div>
                  <div>
                    <p className="font-black text-[#1d1d1d] text-[14px] mb-1">{title}</p>
                    <p className="text-[#8a8178] text-[13px] font-medium leading-relaxed">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-[#d9cdbf]/60 to-transparent" />
      </section>

      {/* ────────────────────────────────────────────
          HOW IT WORKS
      ──────────────────────────────────────────── */}
      <section
        id="workflow"
        className="scroll-mt-28 relative z-10 py-28 px-6 lg:px-10 xl:px-12"
      >
        <div className="max-w-6xl mx-auto">

          <div className="reveal text-center mb-16">
            <div className="inline-flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.18em] text-[#0f9d76] bg-[#edf8f3] border border-[#0f9d76]/25 px-4 py-1.5 rounded-full mb-5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#0f9d76] inline-block" />
              How It Works
            </div>
            <h2 className="text-3xl sm:text-4xl xl:text-5xl font-black text-[#1d1d1d] tracking-tight leading-[1.1]">
              How TIBSA Works
            </h2>
          </div>

          {/* Steps */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-6 lg:gap-0">
            {[
              { n: "01", icon: <Globe className="w-5 h-5" />, title: "Enter Target URL", desc: "Provide the URL of the website to analyse." },
              { n: "02", icon: <FileSearch className="w-5 h-5" />, title: "Run Security Scan", desc: "Probe headers, forms, cookies, paths, and injection vectors." },
              { n: "03", icon: <Database className="w-5 h-5" />, title: "Enrich with Threat Intel", desc: "Cross-reference findings with IOC reputation data." },
              { n: "04", icon: <Shield className="w-5 h-5" />, title: "Map Risks with STRIDE", desc: "Categorise confirmed and potential risks across STRIDE." },
              { n: "05", icon: <Brain className="w-5 h-5" />, title: "Generate AI Report", desc: "Receive an executive report with scores and mitigations." },
            ].map(({ n, icon, title, desc }, i) => (
              <div
                key={i}
                className={`reveal d${i + 1} step-wrap relative flex flex-col items-center text-center lg:px-4`}
              >
                <div className="w-11 h-11 rounded-2xl bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] text-white flex items-center justify-center mb-4 shadow-md shadow-[#0f9d76]/20 flex-shrink-0">
                  {icon}
                </div>
                <div className="text-[10px] font-black text-[#0f9d76] tracking-[0.2em] mb-2 uppercase">{n}</div>
                <h3 className="text-[13px] font-black text-[#1d1d1d] mb-2 leading-snug">{title}</h3>
                <p className="text-[12px] text-[#8a8178] font-medium leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ────────────────────────────────────────────
          CONFIRMED vs POTENTIAL
      ──────────────────────────────────────────── */}
      <section
        id="threat-modeling"
        className="scroll-mt-28 relative z-10 py-28 px-6 lg:px-10 xl:px-12"
        style={{ background: "rgba(248,243,235,0.55)" }}
      >
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#d9cdbf]/60 to-transparent" />

        <div className="max-w-6xl mx-auto">
          <div className="reveal text-center mb-14">
            <div className="inline-flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.18em] text-[#0f9d76] bg-[#edf8f3] border border-[#0f9d76]/25 px-4 py-1.5 rounded-full mb-5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#0f9d76] inline-block" />
              Threat Modeling
            </div>
            <h2 className="text-2xl sm:text-3xl xl:text-4xl font-black tracking-tight leading-[1.1] mb-4">
              <span className="text-transparent bg-clip-text bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)]">Confirmed Threats</span>
              <span className="text-[#4f4a45] font-bold mx-3">vs</span>
              <span className="text-[#1d1d1d]">Potential Scenarios</span>
            </h2>
            <p className="text-[#4f4a45] text-[16px] font-medium max-w-2xl mx-auto leading-relaxed">
              TIBSA separates verified vulnerabilities from advisory hardening scenarios, helping
              security teams avoid false positives and focus on what truly matters.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

            {/* Confirmed */}
            <div className="reveal d1 lift bg-white border border-[#e7ddd1] rounded-2xl p-8 lg:p-10">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-11 h-11 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <span className="text-[11px] font-black px-3 py-1 rounded-full bg-[#0f9d76] text-white tracking-wide">
                  CONFIRMED
                </span>
              </div>
              <h3 className="text-2xl font-black text-[#1d1d1d] mb-3">Confirmed Threats</h3>
              <p className="text-[#4f4a45] font-medium text-[14px] leading-[1.75] mb-7">
                Verified vulnerabilities such as SQL Injection, confirmed XSS, or exploitable
                misconfigurations detected with active exploitation evidence. Require immediate remediation.
              </p>
              <div className="flex flex-wrap gap-2">
                {["SQL Injection", "Confirmed XSS", "Auth Bypass", "SSRF"].map((t) => (
                  <span key={t} className="text-[11px] font-bold px-3 py-1 rounded-full bg-[#0f9d76]/10 text-[#0f9d76] border border-[#0f9d76]/20">
                    {t}
                  </span>
                ))}
              </div>
            </div>

            {/* Potential */}
            <div className="reveal d2 lift bg-white border border-[#e7ddd1] rounded-2xl p-8 lg:p-10">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-11 h-11 rounded-xl bg-[#f0ebe3] text-[#4f4a45] flex items-center justify-center">
                  <Zap className="w-5 h-5" />
                </div>
                <span className="text-[11px] font-black px-3 py-1 rounded-full bg-[#e7ddd1] text-[#4f4a45] tracking-wide">
                  POTENTIAL
                </span>
              </div>
              <h3 className="text-2xl font-black text-[#1d1d1d] mb-3">Potential Scenarios</h3>
              <p className="text-[#4f4a45] font-medium text-[14px] leading-[1.75] mb-7">
                Hardening recommendations such as missing CSP, weak cookie flags, and security
                header gaps. Advisory findings that reduce attack surface without active exploits.
              </p>
              <div className="flex flex-wrap gap-2">
                {["Missing CSP", "Cookie Flags", "Header Config", "HSTS"].map((t) => (
                  <span key={t} className="text-[11px] font-bold px-3 py-1 rounded-full bg-[#f0ebe3] text-[#4f4a45] border border-[#e7ddd1]">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-[#d9cdbf]/60 to-transparent" />
      </section>

      {/* ────────────────────────────────────────────
          AI REPORT PREVIEW
      ──────────────────────────────────────────── */}
      <section
        id="report-preview"
        className="scroll-mt-28 relative z-10 py-28 px-6 lg:px-10 xl:px-12"
      >
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-14 lg:gap-20 items-center">

            {/* Left: text */}
            <div>
              <div className="reveal inline-flex items-center gap-2 text-[11px] font-black uppercase tracking-[0.18em] text-[#0f9d76] bg-[#edf8f3] border border-[#0f9d76]/25 px-4 py-1.5 rounded-full mb-6">
                <span className="w-1.5 h-1.5 rounded-full bg-[#0f9d76] inline-block" />
                Report Preview
              </div>
              <h2 className="reveal d1 text-3xl sm:text-4xl xl:text-5xl font-black text-[#1d1d1d] tracking-tight leading-[1.1] mb-5">
                Executive-Ready<br />AI Reports
              </h2>
              <p className="reveal d2 text-[#4f4a45] text-[16px] font-medium leading-[1.75] mb-8 max-w-md">
                Generate clear reports with risk scores, confirmed findings, STRIDE mapping,
                potential scenarios, and practical mitigation steps — ready to share with any team.
              </p>
              <div className="reveal d3 flex flex-col gap-3">
                {[
                  "Confirmed findings with exploitation evidence",
                  "STRIDE category mapping per finding",
                  "Risk score and business impact summary",
                  "Prioritised mitigation roadmap",
                ].map((item) => (
                  <div key={item} className="flex items-start gap-3">
                    <CheckCircle className="w-4 h-4 text-[#0f9d76] mt-0.5 flex-shrink-0" />
                    <span className="text-[14px] font-medium text-[#4f4a45]">{item}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: mock report card */}
            <div className="reveal d2 lift">
              <div className="bg-white border border-[#e7ddd1] rounded-2xl overflow-hidden shadow-lg">
                {/* Report header */}
                <div className="bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] px-7 py-6 flex items-center justify-between">
                  <div>
                    <div className="text-white/65 text-[11px] font-bold uppercase tracking-widest mb-1">
                      Security Intelligence Report
                    </div>
                    <div className="text-white font-black text-[17px]">example-target.com</div>
                  </div>
                  <div className="text-right">
                    <div className="text-white/65 text-[11px] font-bold uppercase tracking-widest mb-1">
                      Risk Score
                    </div>
                    <div className="text-white font-black text-[32px] leading-none">
                      57<span className="text-white/55 text-[18px] font-bold">/100</span>
                    </div>
                  </div>
                </div>

                {/* Risk bar */}
                <div className="px-7 pt-5 pb-2">
                  <div className="w-full h-2 bg-[#f0ebe3] rounded-full overflow-hidden">
                    <div className="h-full w-[57%] bg-[linear-gradient(90deg,#0f9d76,#e6a817)] rounded-full" />
                  </div>
                  <div className="flex justify-between text-[11px] font-bold text-[#8a8178] mt-1.5">
                    <span>Low</span><span>Medium</span><span>High</span><span>Critical</span>
                  </div>
                </div>

                {/* Metric rows */}
                <div className="px-7 pb-6 pt-3 flex flex-col divide-y divide-[#f0ebe3]">
                  {[
                    { label: "Confirmed Threat", value: "SQL Injection (Error-Based)", badge: "HIGH", bc: "bg-red-50 text-red-600 border border-red-100" },
                    { label: "STRIDE", value: "Tampering · Information Disclosure", badge: "STRIDE", bc: "bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20" },
                    { label: "Potential Scenario", value: "Missing Content-Security-Policy", badge: "MEDIUM", bc: "bg-amber-50 text-amber-600 border border-amber-100" },
                    { label: "Recommended Mitigation", value: "Use parameterized queries", badge: "ACTION", bc: "bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20" },
                  ].map(({ label, value, badge, bc }) => (
                    <div key={label} className="flex items-center justify-between gap-3 py-3">
                      <div>
                        <div className="text-[10px] font-bold text-[#8a8178] uppercase tracking-wider mb-0.5">{label}</div>
                        <div className="text-[13px] font-bold text-[#1d1d1d]">{value}</div>
                      </div>
                      <span className={`text-[10px] font-black px-2.5 py-1 rounded-full whitespace-nowrap flex-shrink-0 ${bc}`}>
                        {badge}
                      </span>
                    </div>
                  ))}
                </div>

                <div className="px-7 pb-5">
                  <div className="flex items-center gap-2 text-[11px] text-[#8a8178] font-medium bg-[#f8f3eb] rounded-xl px-4 py-3">
                    <FileText className="w-3.5 h-3.5 text-[#0f9d76] flex-shrink-0" />
                    Generated by TIBSA AI Reporter · STRIDE mapping included
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

    </>
  );
}
