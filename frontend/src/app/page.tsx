import Link from "next/link";
import { ArrowRight, Shield, Globe, FileSearch, BarChart3, ShieldCheck, Activity } from "lucide-react";

export default function Home() {
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
      <header className="relative z-50 container mx-auto flex items-center justify-between px-6 py-8">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] flex items-center justify-center shadow-sm shadow-[#0f9d76]/20">
            <span className="text-white font-black text-xl tracking-tighter">T</span>
          </div>
          <span className="text-2xl font-black text-[#1d1d1d] tracking-tight">TIBSA</span>
        </div>

        <div className="flex items-center gap-5">
          <Link
            href="/login"
            className="text-sm font-bold text-[#4f4a45] hover:text-[#0f9d76] transition-colors"
          >
            Login
          </Link>
          <Link
            href="/register"
            className="text-sm px-6 py-2.5 rounded-full font-bold btn-animated btn-primary-emerald"
          >
            Get Started
          </Link>
        </div>
      </header>

      {/* ── Main Hero Section ── */}
      <main className="relative z-10 container mx-auto px-6 pt-12 pb-32">

        <div className="relative w-full flex flex-col items-center justify-center min-h-[60vh]">

          {/* Left Decorative Visual: Translucent 3D Shield */}
          <div className="hidden xl:flex absolute left-0 top-1/2 -translate-y-1/2 -translate-x-8 w-72 h-[340px] items-center justify-center z-10">
            <div className="relative w-full h-full rounded-[2.5rem] bg-white/30 backdrop-blur-xl border border-white/60 shadow-[0_8px_32px_rgba(15,157,118,0.12)] flex items-center justify-center transform -rotate-12 hover:rotate-0 transition-transform duration-700 ease-out group">
              {/* Internal glow */}
              <div className="absolute inset-0 bg-gradient-to-br from-white/50 to-transparent rounded-[2.5rem] pointer-events-none"></div>
              <div className="absolute w-32 h-40 bg-[#0f9d76] blur-3xl opacity-20 rounded-full group-hover:opacity-30 transition-opacity duration-700"></div>

              {/* Shield Icon */}
              <Shield className="w-28 h-28 text-[#0f9d76]/70 drop-shadow-md relative z-10 stroke-[1.5]" />

              {/* Tech accents */}
              <div className="absolute top-8 right-8 w-2 h-2 rounded-full bg-[#0f9d76] animate-pulse"></div>
              <div className="absolute bottom-8 left-8 flex gap-1.5 items-end">
                <div className="w-1.5 h-4 bg-[#0f9d76]/30 rounded-full"></div>
                <div className="w-1.5 h-7 bg-[#0f9d76]/60 rounded-full"></div>
                <div className="w-1.5 h-3 bg-[#0f9d76]/40 rounded-full"></div>
              </div>
            </div>
          </div>

          {/* Right Decorative Visual: Translucent Dashboard Analytics */}
          <div className="hidden xl:flex absolute right-0 top-1/2 -translate-y-1/2 translate-x-8 w-72 h-[340px] items-center justify-center z-10">
            <div className="relative w-full h-full rounded-[2.5rem] bg-white/40 backdrop-blur-xl border border-white/60 shadow-[0_8px_32px_rgba(15,157,118,0.12)] p-6 flex flex-col gap-4 transform rotate-6 hover:rotate-0 transition-transform duration-700 ease-out group">
              <div className="absolute inset-0 bg-gradient-to-tl from-white/50 to-transparent rounded-[2.5rem] pointer-events-none"></div>

              {/* Mock Header */}
              <div className="flex justify-between items-center pb-3 border-b border-white/40 relative z-10">
                <div className="h-3.5 w-20 bg-[#0f9d76]/20 rounded-full"></div>
                <div className="h-2.5 w-2.5 rounded-full bg-[#0f9d76] animate-pulse"></div>
              </div>

              {/* Bar Chart Mockup */}
              <div className="flex-1 bg-white/40 rounded-2xl p-4 border border-white/50 flex flex-col justify-end relative overflow-hidden z-10">
                {/* Micro grid */}
                <div className="absolute inset-0 bg-[linear-gradient(rgba(15,157,118,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(15,157,118,0.05)_1px,transparent_1px)] bg-[size:14px_14px]"></div>

                <div className="relative z-10 flex items-end gap-2.5 h-full pb-1 justify-center w-full">
                  <div className="w-full max-w-[12px] bg-[#0f9d76]/30 rounded-t-sm h-[30%]"></div>
                  <div className="w-full max-w-[12px] bg-[#0f9d76]/50 rounded-t-sm h-[50%]"></div>
                  <div className="w-full max-w-[12px] bg-[linear-gradient(180deg,#0f9d76,rgba(15,157,118,0.4))] rounded-t-sm h-[90%] shadow-[0_0_10px_rgba(15,157,118,0.4)]"></div>
                  <div className="w-full max-w-[12px] bg-[#0f9d76]/40 rounded-t-sm h-[60%]"></div>
                  <div className="w-full max-w-[12px] bg-[#0f9d76]/20 rounded-t-sm h-[25%]"></div>
                </div>
              </div>

              {/* Status Indicator Mockup */}
              <div className="h-24 bg-white/40 rounded-2xl p-4 border border-white/50 flex items-center justify-between relative z-10">
                <div className="w-14 h-14 rounded-full border-4 border-[#0f9d76]/10 border-t-[#0f9d76] border-r-[#0f9d76]/50 flex items-center justify-center animate-[spin_8s_linear_infinite]">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#0f9d76]"></div>
                </div>
                <div className="flex flex-col gap-2.5 w-1/2">
                  <div className="h-2 w-full bg-[#0f9d76]/20 rounded-full"></div>
                  <div className="h-2 w-3/4 bg-[#0f9d76]/10 rounded-full"></div>
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
            <h1 className="text-5xl sm:text-6xl lg:text-7xl font-black leading-[1.1] tracking-tight mb-8 text-[#1d1d1d] max-w-3xl">
              Protect Your Digital <br className="hidden sm:block" />
              <span className="text-transparent bg-clip-text bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] relative inline-block">
                Assets
                {/* Tiny glowing dot accent for flair */}
                <div className="absolute -top-1 -right-4 w-2 h-2 bg-[#0f9d76] rounded-full blur-[2px]"></div>
              </span>
              {" "}with Intelligence
            </h1>

            {/* Subtitle */}
            <p className="text-lg md:text-xl text-[#4f4a45] font-medium max-w-2xl mx-auto mb-12 leading-relaxed">
              TIBSA is a comprehensive threat intelligence platform that helps you scan URLs, analyze files, and detect threats using advanced security analysis.
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
        <div className="relative z-20 grid grid-cols-1 md:grid-cols-3 gap-6 lg:gap-8 mt-24 lg:mt-32 max-w-5xl mx-auto">

          <div className="bg-[rgba(255,250,244,0.85)] backdrop-blur-sm border border-[#e7ddd1] rounded-2xl p-8 hover:bg-[#ffffff] hover:border-[#d9cdbf] transition-all shadow-sm hover:shadow-md flex flex-col items-start group">
            <div className="w-12 h-12 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
              <Globe className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-bold mb-3 text-[#1d1d1d]">URL Scanning</h3>
            <p className="text-[#8a8178] leading-relaxed font-medium text-sm">
              Scan suspicious domains and URLs instantly with deep infrastructure profiling and AI-driven phishing detection.
            </p>
          </div>

          <div className="bg-[rgba(255,250,244,0.85)] backdrop-blur-sm border border-[#e7ddd1] rounded-2xl p-8 hover:bg-[#ffffff] hover:border-[#d9cdbf] transition-all shadow-sm hover:shadow-md flex flex-col items-start group">
            <div className="w-12 h-12 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
              <FileSearch className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-bold mb-3 text-[#1d1d1d]">Threat Intelligence</h3>
            <p className="text-[#8a8178] leading-relaxed font-medium text-sm">
              Cross-reference file hashes and indicators of compromise against global threat feeds and historical databases.
            </p>
          </div>

          <div className="bg-[rgba(255,250,244,0.85)] backdrop-blur-sm border border-[#e7ddd1] rounded-2xl p-8 hover:bg-[#ffffff] hover:border-[#d9cdbf] transition-all shadow-sm hover:shadow-md flex flex-col items-start group">
            <div className="w-12 h-12 rounded-xl bg-[#edf8f3] text-[#0f9d76] flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-bold mb-3 text-[#1d1d1d]">Security Reports</h3>
            <p className="text-[#8a8178] leading-relaxed font-medium text-sm">
              Export clean, executive-ready threat reports summarizing risk scores, malicious behavior, and mitigation steps.
            </p>
          </div>

        </div>
      </main>

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
