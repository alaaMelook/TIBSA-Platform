import React, { useState } from "react";
import { ChevronUp, ChevronDown, Copy, Command } from "lucide-react";

export interface CollapsibleSectionProps {
  title: string;
  content: string | null | undefined;
  icon: any;
  defaultOpen?: boolean;
  mono?: boolean;
}

export const CollapsibleSection = ({
  title,
  content,
  icon: Icon,
  defaultOpen = false,
  mono = true
}: CollapsibleSectionProps) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  if (!content) return null;

  return (
    <div className="border border-white/5 rounded-xl overflow-hidden bg-slate-950/20 mb-3">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-white/5 transition-all group cursor-pointer"
      >
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 group-hover:text-slate-200">
          <Icon className="w-3.5 h-3.5" />
          {title}
        </div>
        {isOpen ? <ChevronUp className="w-3.5 h-3.5 text-slate-500" /> : <ChevronDown className="w-3.5 h-3.5 text-slate-500" />}
      </button>
      {isOpen && (
        <div className="px-4 pb-4">
          <div className={`p-3 rounded-lg bg-black/40 border border-white/5 text-[11px] ${mono ? 'font-mono' : 'font-sans'} text-slate-300 break-all whitespace-pre-wrap relative group`}>
            {content}
            <button
              onClick={(e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(content);
              }}
              className="absolute top-2 right-2 p-1.5 bg-slate-800/50 hover:bg-purple-600/50 rounded-md transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
            >
              <Copy className="w-3 h-3 text-white" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export interface ReproductionCurlProps {
  url: string;
  method: string;
  data?: any;
  cookies?: string;
}

export const ReproductionCurl = ({ url, method, data, cookies }: ReproductionCurlProps) => {
  // Mask cookies: PHPSESSID=... -> PHPSESSID=<redacted>
  const maskCookies = (c: string | undefined) => {
    if (!c) return "PHPSESSID=<redacted>";
    return c.replace(/PHPSESSID=[^;]+/g, "PHPSESSID=<redacted>");
  };

  const curl = `curl -X ${method} "${url}" \\\n  -H "Cookie: ${maskCookies(cookies)}" \\\n  -H "User-Agent: TIBSA-Scanner/4.0" ${data ? `\\\n  -d '${JSON.stringify(data)}'` : ''}`;

  return (
    <CollapsibleSection title="Reproduction Command (Curl)" content={curl} icon={Command} />
  );
};
