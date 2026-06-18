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
      <div className="bg-gradient-to-r from-blue-900/10 via-[#1c2942]/20 to-[#0f172a] border border-[var(--border-soft)] p-6 rounded-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6 shadow-md">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[var(--primary)] animate-ping" />
            <span className="text-[10px] font-bold text-[var(--primary)] uppercase tracking-widest">
              Threat Intelligence Pipeline
            </span>
          </div>
          <h1 className="text-2xl font-black text-[var(--text-primary)] tracking-tight">
            Threat Infrastructure Intelligence
          </h1>
          <p className="text-[var(--text-muted)] mt-1 max-w-xl text-sm leading-relaxed">
            Passive profiling of Domains, URLs, IP addresses, ASNs, CIDRs, and hashes. Real-time enrichment via passive DNS, RDAP WHOIS, SSL records, and AI attribution.
          </p>
        </div>
        <Globe className="w-12 h-12 text-[var(--primary)]/20 hidden md:block" />
      </div>

      {/* Glassmorphic Tabbed Navigation Row */}
      <div className="flex bg-[#ffffff] border border-[#e7ddd1] p-1.5 rounded-2xl w-fit max-w-full overflow-x-auto gap-1 shadow-sm">
        {NAV_ITEMS.map((item) => {
          const isActive = item.exact
            ? pathname === item.href
            : pathname === item.href || pathname === item.href + "/history";
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition-all duration-180 hover:-translate-y-[1px] active:scale-[0.97] whitespace-nowrap cursor-pointer ${
                isActive
                  ? "bg-[#edf8f3] border border-[#0f9d76] text-[#0f9d76] shadow-sm font-bold"
                  : "border border-transparent text-[#4f4a45] hover:text-[#0f9d76] hover:bg-[#edf8f3] hover:border-[#0f9d76]"
              } motion-reduce:transition-colors motion-reduce:hover:transform-none`}
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
