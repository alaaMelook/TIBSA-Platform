"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, Shield, Globe, FileSearch, BarChart3, ShieldCheck, Microscope } from "lucide-react";
import LandingSections from "@/components/landing/LandingSections";

export default function Home() {
  const [activeSection, setActiveSection] = useState("home");
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    document.documentElement.style.scrollBehavior = "smooth";

    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);

      const sections = [
        "home",
        "features",
        "about",
        "workflow",
        "threat-modeling",
        "report-preview",
      ];
      
      const scrollPosition = window.scrollY + 160;

      for (const section of sections) {
        const el = document.getElementById(section);
        if (el) {
          const top = el.offsetTop;
          const height = el.offsetHeight;
          if (scrollPosition >= top && scrollPosition < top + height) {
            setActiveSection(section);
            break;
          }
        }
      }
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <div className="relative min-h-screen bg-[#f8f3eb] text-[#1d1d1d] font-sans overflow-x-hidden selection:bg-[#0f9d76]/20">


      {/* ── Global Background Image ── */}
      <div className="fixed inset-0 z-0 pointer-events-none opacity-0 animate-[fadeIn_1.5s_ease-in-out_forwards]">
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat"
          style={{ backgroundImage: "url('/images/landing-bg.png')" }}
        />
        {/* Soft light overlay */}
        <div className="absolute inset-0" style={{ backgroundColor: "rgba(250, 247, 241, 0.72)" }} />
      </div>

      <style dangerouslySetInnerHTML={{
        __html: `
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
      `}} />

      {/* ── Background Decorative Layers ── */}
      <div className="fixed inset-0 pointer-events-none z-0">
        {/* Soft radial glow centered */}
        <div className="absolute top-[30%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-[#0f9d76] rounded-full blur-[140px] opacity-[0.08]"></div>

        {/* Faint circuit lines / digital nodes (CSS pattern) */}
        <div className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: 'radial-gradient(#0f9d76 1.5px, transparent 1.5px)',
            backgroundSize: '36px 36px',
            backgroundPosition: '0 0'
          }}>
        </div>

        {/* Faint vertical binary texture effect */}
        <div className="absolute inset-0 opacity-[0.01]"
          style={{
            backgroundImage: 'linear-gradient(0deg, transparent 24%, rgba(15, 157, 118, .3) 25%, rgba(15, 157, 118, .3) 26%, transparent 27%, transparent 74%, rgba(15, 157, 118, .3) 75%, rgba(15, 157, 118, .3) 76%, transparent 77%, transparent), linear-gradient(90deg, transparent 24%, rgba(15, 157, 118, .3) 25%, rgba(15, 157, 118, .3) 26%, transparent 27%, transparent 74%, rgba(15, 157, 118, .3) 75%, rgba(15, 157, 118, .3) 76%, transparent 77%, transparent)',
            backgroundSize: '50px 50px'
          }}>
        </div>
      </div>

      {/* ── Navbar ── */}
      <header className={`fixed top-0 left-0 right-0 z-50 w-full transition-all duration-300 ${isScrolled ? 'bg-[#f8f3eb]/80 backdrop-blur-md border-b border-[#e7ddd1]/60 shadow-sm' : 'bg-transparent'}`}>
        <div className="container mx-auto flex items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] flex items-center justify-center shadow-sm shadow-[#0f9d76]/20">
              <span className="text-white font-black text-xl tracking-tighter">T</span>
            </div>
            <span className="text-2xl font-black text-[#1d1d1d] tracking-tight">TIBSA</span>
          </div>
          <nav className="hidden lg:flex items-center gap-2">
            {[
              { label: "Home", href: "#home", id: "home" },
              { label: "Features", href: "#features", id: "features" },
              { label: "About", href: "#about", id: "about" },
              { label: "Workflow", href: "#workflow", id: "workflow" },
              { label: "Threat Modeling", href: "#threat-modeling", id: "threat-modeling" },
              { label: "Report Preview", href: "#report-preview", id: "report-preview" },
            ].map(({ label, href, id }) => {
              const isActive = activeSection === id;
              return (
                <a
                  key={label}
                  href={href}
                  className={`text-[13px] font-bold px-3.5 py-1.5 rounded-full transition-all duration-200 ${
                    isActive
                      ? "bg-[#0f9d76] text-white shadow-sm shadow-[#0f9d76]/20"
                      : "text-[#4f4a45] hover:bg-[#edf8f3] hover:text-[#0f9d76]"
                  }`}
                >
                  {label}
                </a>
              );
            })}
          </nav>
          <div className="flex items-center gap-4">
            <Link href="/login" className="hidden sm:block text-sm font-bold text-[#4f4a45] hover:text-[#0f9d76] transition-colors">
              Login
            </Link>
            <Link href="/register" className="text-sm px-5 py-2.5 rounded-full font-bold btn-animated btn-primary-emerald">
              Get Started
            </Link>
          </div>
        </div>
      </header>

      {/* ── Main Hero Section ── */}
      <main className="relative z-10 container mx-auto px-6 pt-24 pb-32">

        <div id="home" className="scroll-mt-28 relative w-full flex flex-col items-center justify-center min-h-[60vh]">

          {/* Left Decorative Visual: Translucent 3D Shield */}
          <div className="hidden xl:flex absolute left-0 top-1/2 -translate-y-1/2 -translate-x-8 w-72 h-[340px] items-center justify-center z-10">
            <div className="relative w-full h-full rounded-[2.5rem] bg-white/30 backdrop-blur-xl border border-white/60 shadow-[0_8px_32px_rgba(15,157,118,0.12)] p-6 flex flex-col justify-between transform -rotate-12 hover:rotate-0 transition-transform duration-700 ease-out group">
              {/* Internal glow */}
              <div className="absolute inset-0 bg-gradient-to-br from-white/50 to-transparent rounded-[2.5rem] pointer-events-none"></div>
              <div className="absolute w-32 h-40 bg-[#0f9d76] blur-3xl opacity-15 rounded-full group-hover:opacity-25 transition-opacity duration-700 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"></div>

              {/* Card Header */}
              <div className="relative z-10 flex items-center justify-between pb-3 border-b border-white/40">
                <div className="flex items-center gap-2">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#0f9d76] opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-[#0f9d76]"></span>
                  </span>
                  <span className="text-[10px] font-black uppercase tracking-wider text-[#4f4a45]">Secure Scan</span>
                </div>
                <span className="text-[9px] font-bold px-2 py-0.5 rounded bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20">ACTIVE</span>
              </div>

              {/* Center: Shield with layered rings */}
              <div className="relative z-10 flex-1 flex items-center justify-center py-4">
                {/* Outer dashed spinning ring */}
                <div className="absolute w-32 h-32 rounded-full border border-dashed border-[#0f9d76]/30 animate-[spin_30s_linear_infinite]" />
                {/* Inner solid ring */}
                <div className="absolute w-24 h-24 rounded-full border border-[#e7ddd1] bg-white/30 backdrop-blur-sm flex items-center justify-center shadow-inner" />
                {/* Glowing center */}
                <div className="absolute w-16 h-16 rounded-full bg-[#0f9d76]/10 blur-md" />
                
                {/* Shield icon */}
                <ShieldCheck className="w-12 h-12 text-[#0f9d76] drop-shadow-sm relative z-10 stroke-[1.8]" />
              </div>

              {/* Card Footer: Status List */}
              <div className="relative z-10 flex flex-col gap-2 bg-white/50 backdrop-blur-sm border border-white/50 rounded-2xl p-3">
                <div className="flex items-center justify-between text-[10px]">
                  <span className="text-[#8a8178] font-bold">Threat Level</span>
                  <span className="text-[#0f9d76] font-extrabold uppercase">Safe</span>
                </div>
                <div className="h-1.5 w-full bg-[#f0ebe3] rounded-full overflow-hidden">
                  <div className="h-full w-1/4 bg-[#0f9d76] rounded-full" />
                </div>
                <div className="flex items-center justify-between text-[9px] text-[#4f4a45] font-bold mt-1">
                  <span className="flex items-center gap-1">
                    <span className="w-1 h-1 rounded-full bg-[#0f9d76]" />
                    Headers Ok
                  </span>
                  <span className="flex items-center gap-1">
                    <span className="w-1 h-1 rounded-full bg-[#0f9d76]" />
                    Cookies Sec
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Decorative Visual: Translucent Dashboard Analytics */}
          <div className="hidden xl:flex absolute right-0 top-1/2 -translate-y-1/2 translate-x-8 w-72 h-[340px] items-center justify-center z-10">
            <div className="relative w-full h-full rounded-[2.5rem] bg-white/40 backdrop-blur-xl border border-white/60 shadow-[0_8px_32px_rgba(15,157,118,0.12)] p-6 flex flex-col justify-between transform rotate-6 hover:rotate-0 transition-transform duration-700 ease-out group">
              <div className="absolute inset-0 bg-gradient-to-tl from-white/50 to-transparent rounded-[2.5rem] pointer-events-none"></div>
              <div className="absolute w-32 h-40 bg-[#0f9d76] blur-3xl opacity-15 rounded-full group-hover:opacity-25 transition-opacity duration-700 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2"></div>

              {/* Card Header */}
              <div className="relative z-10 flex items-center justify-between pb-3 border-b border-white/40">
                <span className="text-[10px] font-black uppercase tracking-wider text-[#4f4a45]">Security Intelligence</span>
                <span className="text-[9px] font-black px-2 py-0.5 rounded bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20">READY</span>
              </div>

              {/* Center: Circular Risk Score + Mini Bar Chart */}
              <div className="relative z-10 flex-1 flex flex-col justify-center gap-4 py-3">
                <div className="flex items-center justify-between gap-4">
                  {/* Circular Risk Indicator */}
                  <div className="relative w-16 h-16 rounded-full border-4 border-[#0f9d76]/10 border-t-[#0f9d76] border-r-[#0f9d76]/50 flex items-center justify-center">
                    <span className="text-xs font-black text-[#1d1d1d]">57%</span>
                    <span className="absolute text-[8px] font-bold text-[#8a8178] -bottom-3">Risk</span>
                  </div>

                  {/* Severities mini chart */}
                  <div className="flex-1 flex flex-col gap-1.5">
                    <div className="flex justify-between text-[8px] font-bold text-[#8a8178]">
                      <span>Findings</span>
                      <span className="text-[#0f9d76]">4 Total</span>
                    </div>
                    {/* High (Red), Med (Amber), Low (Green) bars */}
                    <div className="flex gap-1 items-end h-7 justify-center bg-white/30 backdrop-blur-sm rounded-lg p-1.5 border border-white/40">
                      <div className="w-2.5 bg-red-400 rounded-sm h-[80%]" title="High" />
                      <div className="w-2.5 bg-amber-400 rounded-sm h-[50%]" title="Medium" />
                      <div className="w-2.5 bg-[#0f9d76] rounded-sm h-[30%]" title="Low" />
                    </div>
                  </div>
                </div>
              </div>

              {/* Card Footer: Metrics & Details */}
              <div className="relative z-10 flex flex-col gap-2 bg-white/50 backdrop-blur-sm border border-white/50 rounded-2xl p-3">
                <div className="flex flex-col gap-1 text-[9px] text-[#4f4a45] font-bold">
                  <div className="flex justify-between">
                    <span>Threat Category</span>
                    <span className="text-red-500 font-extrabold">STRIDE</span>
                  </div>
                  <div className="h-px bg-white/40 my-0.5" />
                  <div className="flex justify-between text-[#8a8178] font-semibold">
                    <span>Tampering Risks</span>
                    <span>Detected</span>
                  </div>
                  <div className="flex justify-between text-[#8a8178] font-semibold">
                    <span>Mitigation Plan</span>
                    <span>Generated</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Centered Hero Content */}
          <div className="relative z-20 flex flex-col items-center text-center max-w-4xl mx-auto">

            {/* Emerald Eyebrow Badge */}
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#edf8f3] border border-[#0f9d76]/30 text-[#0f9d76] font-bold text-xs uppercase tracking-widest mb-10 shadow-sm">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#0f9d76] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#0f9d76]"></span>
              </span>
              Threat Intelligence Platform
            </div>

            {/* Main Headline */}
            <h1 className="text-5xl sm:text-6xl lg:text-6xl font-black leading-[1.15] tracking-tight mb-8 text-[#1d1d1d] max-w-5xl w-full">
              <span className="block whitespace-nowrap">Turn Security Findings into</span>
              <span className="block whitespace-nowrap">
                <span className="text-transparent bg-clip-text bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] relative inline-block">
                  Actionable
                  {/* Tiny glowing dot accent for flair */}
                  <div className="absolute -top-1 -right-4 w-2 h-2 bg-[#0f9d76] rounded-full blur-[2px]"></div>
                </span>
                {" "}Intelligence
              </span>
            </h1>

            {/* Subtitle */}
            <p className="text-lg md:text-xl text-[#4f4a45] font-medium max-w-2xl mx-auto mb-12 leading-relaxed">
              TIBSA scans websites, detects vulnerabilities, enriches findings with threat intelligence, maps STRIDE risks, and generates AI-powered security reports.
            </p>

            {/* CTAs */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 w-full">
              <Link
                href="/register"
                className="w-full sm:w-auto flex items-center justify-center gap-2 px-9 py-4 rounded-xl text-[15px] font-bold btn-animated btn-primary-emerald"
              >
                Start Scanning <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/login"
                className="w-full sm:w-auto flex items-center justify-center px-9 py-4 rounded-xl text-[15px] font-bold btn-animated btn-secondary-soft"
              >
                Sign In
              </Link>
            </div>
          </div>
        </div>

        {/* ── Feature Cards ── */}
        <div id="features" className="scroll-mt-28 relative z-20 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 lg:gap-5 mt-16 lg:mt-20 max-w-5xl mx-auto">

          <div className="bg-[rgba(255,250,244,0.85)] backdrop-blur-sm border border-[#e7ddd1] rounded-2xl p-6 hover:bg-[#ffffff] hover:border-[#d9cdbf] transition-all shadow-sm hover:shadow-md flex flex-col items-start group">
            <div className="w-10 h-10 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center mb-4 group-hover:scale-110 transition-transform flex-shrink-0">
              <Globe className="w-5 h-5" />
            </div>
            <h3 className="text-[15px] font-bold mb-2 text-[#1d1d1d]">Website Scanner</h3>
            <p className="text-[#8a8178] leading-relaxed font-medium text-[13px] mb-4">
              Detect headers, cookies, exposed paths, misconfigurations, XSS, and SQL injection risks with safe automated scanning.
            </p>
            <div className="flex flex-wrap gap-1.5 mt-auto">
              {["Headers", "Cookies", "SQLi", "XSS"].map((tag) => (
                <span key={tag} className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20 tracking-wide">
                  {tag}
                </span>
              ))}
            </div>
          </div>

          <div className="bg-[rgba(255,250,244,0.85)] backdrop-blur-sm border border-[#e7ddd1] rounded-2xl p-6 hover:bg-[#ffffff] hover:border-[#d9cdbf] transition-all shadow-sm hover:shadow-md flex flex-col items-start group">
            <div className="w-10 h-10 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center mb-4 group-hover:scale-110 transition-transform flex-shrink-0">
              <FileSearch className="w-5 h-5" />
            </div>
            <h3 className="text-[15px] font-bold mb-2 text-[#1d1d1d]">Threat Intelligence</h3>
            <p className="text-[#8a8178] leading-relaxed font-medium text-[13px] mb-4">
              Enrich scan results with IOC reputation, detected technologies, and external threat context.
            </p>
            <div className="flex flex-wrap gap-1.5 mt-auto">
              {["IOC Reputation", "Technologies", "Risk Context"].map((tag) => (
                <span key={tag} className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20 tracking-wide">
                  {tag}
                </span>
              ))}
            </div>
          </div>

          <div className="bg-[rgba(255,250,244,0.85)] backdrop-blur-sm border border-[#e7ddd1] rounded-2xl p-6 hover:bg-[#ffffff] hover:border-[#d9cdbf] transition-all shadow-sm hover:shadow-md flex flex-col items-start group">
            <div className="w-10 h-10 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center mb-4 group-hover:scale-110 transition-transform flex-shrink-0">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h3 className="text-[15px] font-bold mb-2 text-[#1d1d1d]">AI Security Reports</h3>
            <p className="text-[#8a8178] leading-relaxed font-medium text-[13px] mb-4">
              Generate executive-ready reports with findings, risk summaries, STRIDE mapping, and mitigation steps.
            </p>
            <div className="flex flex-wrap gap-1.5 mt-auto">
              {["STRIDE", "AI Summary", "Mitigations"].map((tag) => (
                <span key={tag} className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20 tracking-wide">
                  {tag}
                </span>
              ))}
            </div>
          </div>

          <div className="bg-[rgba(255,250,244,0.85)] backdrop-blur-sm border border-[#e7ddd1] rounded-2xl p-6 hover:bg-[#ffffff] hover:border-[#d9cdbf] transition-all shadow-sm hover:shadow-md flex flex-col items-start group">
            <div className="w-10 h-10 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center mb-4 group-hover:scale-110 transition-transform flex-shrink-0">
              <BarChart3 className="w-5 h-5" />
            </div>
            <h3 className="text-[15px] font-bold mb-2 text-[#1d1d1d]">Contextual Risk Intelligence</h3>
            <p className="text-[#8a8178] leading-relaxed font-medium text-[13px] mb-4">
              Connect findings together, reduce false positives, and separate confirmed issues from hardening advice.
            </p>
            <div className="flex flex-wrap gap-1.5 mt-auto">
              {["Risk Scoring", "False Positive Control", "Context Analysis"].map((tag) => (
                <span key={tag} className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20 tracking-wide">
                  {tag}
                </span>
              ))}
            </div>
          </div>

          <div className="bg-[rgba(255,250,244,0.85)] backdrop-blur-sm border border-[#e7ddd1] rounded-2xl p-6 hover:bg-[#ffffff] hover:border-[#d9cdbf] transition-all shadow-sm hover:shadow-md flex flex-col items-start group">
            <div className="w-10 h-10 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center mb-4 group-hover:scale-110 transition-transform flex-shrink-0">
              <Shield className="w-5 h-5" />
            </div>
            <h3 className="text-[15px] font-bold mb-2 text-[#1d1d1d]">STRIDE Threat Modeling</h3>
            <p className="text-[#8a8178] leading-relaxed font-medium text-[13px] mb-4">
              Map confirmed and potential risks into STRIDE categories for clearer security impact analysis.
            </p>
            <div className="flex flex-wrap gap-1.5 mt-auto">
              {["STRIDE", "Confirmed Threats", "Potential Scenarios"].map((tag) => (
                <span key={tag} className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20 tracking-wide">
                  {tag}
                </span>
              ))}
            </div>
          </div>

          <div className="bg-[rgba(255,250,244,0.85)] backdrop-blur-sm border border-[#e7ddd1] rounded-2xl p-6 hover:bg-[#ffffff] hover:border-[#d9cdbf] transition-all shadow-sm hover:shadow-md flex flex-col items-start group">
            <div className="w-10 h-10 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center mb-4 group-hover:scale-110 transition-transform flex-shrink-0">
              <Microscope className="w-5 h-5" />
            </div>
            <h3 className="text-[15px] font-bold mb-2 text-[#1d1d1d]">Static Malware Analysis</h3>
            <p className="text-[#8a8178] leading-relaxed font-medium text-[13px] mb-4">
              Analyze suspicious files using static feature extraction and AI-based malware classification to identify potential threats without executing the file.
            </p>
            <div className="flex flex-wrap gap-1.5 mt-auto">
              {["Static Analysis", "Feature Extraction", "Malware Classification"].map((tag) => (
                <span key={tag} className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#edf8f3] text-[#0f9d76] border border-[#0f9d76]/20 tracking-wide">
                  {tag}
                </span>
              ))}
            </div>
          </div>

        </div>

      </main>

      {/* ── Additional Landing Sections ── */}
      <LandingSections />

      {/* ── Footer ── */}
      <footer className="relative z-20 border-t border-[#e7ddd1] py-10 bg-[#fffaf4]">
        <div className="container mx-auto px-6 text-center">
          <p className="text-sm font-medium text-[#8a8178]">
            &copy; {new Date().getFullYear()} TIBSA — Threat Intelligence Platform. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}
