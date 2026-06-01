"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Globe, Clock, Sparkles, Sliders } from "lucide-react";

const NAV_ITEMS = [
  { href: "/dashboard/infra-investigations",          label: "Scanner",    icon: <Globe className="w-3.5 h-3.5" />,    exact: true  },
  { href: "/dashboard/infra-investigations/history",   label: "History",    icon: <Clock className="w-3.5 h-3.5" />,    exact: true  },
  { href: "/dashboard/infra-investigations/reports",   label: "AI Reports", icon: <Sparkles className="w-3.5 h-3.5" />, exact: true  },
  { href: "/dashboard/infra-investigations/settings",  label: "Settings",   icon: <Sliders className="w-3.5 h-3.5" />,  exact: true  },
];

export function InfraSubHeader() {
  const pathname = usePathname();

  return (
    <div className="space-y-4">
      {/* Dynamic Glassmorphic Hero Title Section */}
      <div className="bg-gradient-to-r from-cyan-900/20 via-[#263554]/30 to-[#0f172a] border border-white/[0.04] p-6 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6 shadow-md">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-widest">
              Threat Intelligence Pipeline
            </span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">
            Threat Infrastructure Intelligence
          </h1>
          <p className="text-slate-400 max-w-xl text-sm leading-relaxed">
            Passive profiling of Domains, URLs, IP addresses, ASNs, CIDRs, and hashes. Real-time enrichment via passive DNS, RDAP WHOIS, SSL records, and AI attribution.
          </p>
        </div>
        <Globe className="w-12 h-12 text-cyan-500/20 hidden md:block" />
      </div>

      {/* Glassmorphic Tabbed Navigation Row */}
      <div className="flex bg-slate-950/40 border border-white/[0.05] p-1 rounded-xl w-fit max-w-full overflow-x-auto gap-1">
        {NAV_ITEMS.map((item) => {
          const isActive = item.exact
            ? pathname === item.href
            : pathname === item.href || pathname === item.href + "/history";
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all duration-200 whitespace-nowrap cursor-pointer ${
                isActive
                  ? "bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 shadow-inner shadow-cyan-500/5"
                  : "border border-transparent text-slate-400 hover:text-slate-200 hover:bg-white/[0.03]"
              }`}
            >
              {item.icon}
              {item.label}
            </Link>
          );
        })}
      </div>
    </div>
  );
}
