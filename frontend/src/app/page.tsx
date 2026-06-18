import Link from "next/link";

export default function Home() {
  return (
    <div className="min-h-screen bg-[linear-gradient(135deg,#f8f3eb_0%,#f6f0e7_55%,#edf8f3_100%)] text-[#1d1d1d]">
      {/* Header */}
      <header className="container mx-auto flex items-center justify-between px-6 py-6">
        <div className="flex items-center gap-2">
          <div className="h-10 w-10 rounded-xl bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] flex items-center justify-center shadow-sm">
            <span className="text-white font-bold text-lg">T</span>
          </div>
          <span className="text-2xl font-black text-[#1d1d1d]">TIBSA</span>
        </div>
        <nav className="flex items-center gap-4">
          <Link
            href="/login"
            className="text-sm font-bold text-[#4f4a45] hover:text-[#0f9d76] transition-colors"
          >
            Login
          </Link>
          <Link
            href="/register"
            className="text-sm bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] !text-white px-5 py-2.5 rounded-lg transition-colors font-bold shadow-sm hover:shadow-md"
          >
            Get Started
          </Link>
        </nav>
      </header>

      {/* Hero */}
      <main className="container mx-auto px-6 pt-24 pb-32">
        <div className="max-w-3xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#edf8f3] border border-[#0f9d76] text-[#0f9d76] font-bold text-sm mb-8 shadow-sm">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#0f9d76] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#0f9d76]"></span>
            </span>
            Threat Intelligence Platform
          </div>

          <h1 className="text-5xl md:text-6xl font-black leading-tight tracking-tight mb-6 text-[#1d1d1d]">
            Protect Your Digital
            <span className="bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] bg-clip-text text-transparent">
              {" "}Assets{" "}
            </span>
            with Intelligence
          </h1>

          <p className="text-lg text-[#4f4a45] font-medium max-w-xl mx-auto mb-10 leading-relaxed">
            TIBSA is a comprehensive threat intelligence platform that helps you scan URLs,
            analyze files, and detect threats using advanced security analysis.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              href="/register"
              className="w-full sm:w-auto bg-[linear-gradient(135deg,#0f9d76,#0b7d5d)] !text-white px-8 py-3.5 rounded-xl text-sm font-bold transition-all shadow-sm hover:shadow-md"
            >
              Start Scanning →
            </Link>
            <Link
              href="/login"
              className="w-full sm:w-auto border border-[#e7ddd1] bg-[#ffffff] text-[#1d1d1d] hover:bg-[#edf8f3] hover:border-[#0f9d76] px-8 py-3.5 rounded-xl text-sm font-bold transition-all shadow-sm"
            >
              Sign In
            </Link>
          </div>
        </div>

        {/* Feature Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-24 max-w-4xl mx-auto">
          <div className="bg-[#fffaf4] border border-[#e7ddd1] rounded-2xl p-6 hover:bg-[#ffffff] transition-all shadow-sm">
            <div className="text-3xl mb-4">🔍</div>
            <h3 className="text-lg font-bold mb-2 text-[#1d1d1d]">URL Scanning</h3>
            <p className="text-sm text-[#4f4a45] leading-relaxed">
              Scan suspicious URLs and get detailed threat analysis reports.
            </p>
          </div>
          <div className="bg-[#fffaf4] border border-[#e7ddd1] rounded-2xl p-6 hover:bg-[#ffffff] transition-all shadow-sm">
            <div className="text-3xl mb-4">🛡️</div>
            <h3 className="text-lg font-bold mb-2 text-[#1d1d1d]">Threat Intelligence</h3>
            <p className="text-sm text-[#4f4a45] leading-relaxed">
              Access real-time threat feeds and IOC lookups for comprehensive protection.
            </p>
          </div>
          <div className="bg-[#fffaf4] border border-[#e7ddd1] rounded-2xl p-6 hover:bg-[#ffffff] transition-all shadow-sm">
            <div className="text-3xl mb-4">📊</div>
            <h3 className="text-lg font-bold mb-2 text-[#1d1d1d]">Security Reports</h3>
            <p className="text-sm text-[#4f4a45] leading-relaxed">
              Generate detailed reports with threat levels and actionable insights.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#e7ddd1] py-8 text-center text-sm font-medium text-[#8a8178]">
        <p>&copy; {new Date().getFullYear()} TIBSA — Graduation Project</p>
      </footer>
    </div>
  );
}
