import React, { useState } from "react";
import { CheckCircle2, Copy } from "lucide-react";

export interface TechnicalEvidenceTableProps {
  evidence: any;
}

export const TechnicalEvidenceTable = ({ evidence }: TechnicalEvidenceTableProps) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [expandedKeys, setExpandedKeys] = useState<Record<string, boolean>>({});

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleExpand = (key: string) => {
    setExpandedKeys(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const copyableFields = ['PAYLOAD', 'URL', 'VERIFICATION URL', 'TESTED URL', 'CURL', 'COMMAND', 'IMPLEMENTATION FIX', 'FIX', 'EVIDENCE', 'DATA'];

  // Parsing logic
  let rows: { key: string, value: string }[] = [];
  
  if (typeof evidence === 'object' && evidence !== null) {
    rows = Object.entries(evidence)
      .filter(([k]) => k !== "sqlmap")
      .map(([k, v]) => ({ 
        key: k.replace(/_/g, ' ').toUpperCase(), 
        value: typeof v === 'object' ? JSON.stringify(v) : String(v) 
      }));
  } else if (typeof evidence === 'string') {
    const lines = evidence.split(/\n/);
    lines.forEach(line => {
      const trimmed = line.trim();
      if (!trimmed) return;
      const match = trimmed.match(/^-?\s*([^:]+):\s*(.*)$/);
      if (match) {
        rows.push({ key: match[1].trim().toUpperCase(), value: match[2].trim() });
      } else {
        if (rows.length > 0 && !trimmed.includes(':')) {
           rows[rows.length - 1].value += "\n" + trimmed;
        } else {
           rows.push({ key: "DATA", value: trimmed });
        }
      }
    });
  }

  const renderValue = (key: string, value: string, rowKey: string) => {
    // Special handling for Preserved Parameters (JSON)
    if (key.includes('PRESERVED PARAMETERS') || (key.includes('PARAMETERS') && value.startsWith('{'))) {
      try {
        const parsed = JSON.parse(value);
        if (typeof parsed === 'object' && parsed !== null && Object.keys(parsed).length > 0) {
          return (
            <div className="space-y-1.5 py-1 w-full">
              {Object.entries(parsed).map(([pk, pv]) => (
                  <div key={pk} className="flex flex-col sm:flex-row sm:gap-3 text-[10px] border-l border-[#E6DDD2] pl-3">
                    <span className="text-[#7C6F64] font-bold sm:min-w-[120px]">{pk}:</span>
                    <span className="text-[#1F2933] break-all">{String(pv)}</span>
                  </div>
              ))}
            </div>
          );
        }
      } catch (e) {}
    }

    const isLong = value.length > 100;
    const isExpanded = expandedKeys[rowKey];
    const displayValue = isLong && !isExpanded ? value.substring(0, 100) + "..." : value;

    return (
      <div className="flex-1 whitespace-pre-wrap leading-relaxed pr-10">
        {displayValue}
        {isLong && (
          <button 
            onClick={() => toggleExpand(rowKey)}
            className="ml-3 text-[9px] font-black text-[#10B981] hover:text-[#10B981]/80 transition-colors uppercase underline underline-offset-2 cursor-pointer"
          >
            {isExpanded ? "[Collapse]" : "[Show Full]"}
          </button>
        )}
      </div>
    );
  };

  return (
    <div className="bg-white border border-[#E6DDD2] rounded-[20px] overflow-hidden shadow-sm font-mono text-[11px] w-full">
      <div className="flex flex-col divide-y divide-[#E6DDD2]">
        {rows.map((row, idx) => {
          const rowKey = `${row.key}-${idx}`;
          const isCopyable = copyableFields.some(f => row.key.includes(f));

          return (
            <div key={idx} className="flex flex-col md:grid md:grid-cols-[220px_1fr] group hover:bg-[#FAF7F1] transition-colors relative">
              {/* Key Column */}
              <div className="px-5 py-4 text-[#7C6F64] bg-[#FAF7F1]/50 border-b md:border-b-0 md:border-r border-[#E6DDD2] font-sans uppercase text-[10px] font-black tracking-widest flex items-center whitespace-nowrap overflow-hidden text-ellipsis">
                {row.key}
              </div>
              
              {/* Value Column */}
              <div className="px-5 py-4 text-[#1F2933] font-semibold relative flex items-start group/val">
                {renderValue(row.key, row.value, rowKey)}
                
                {/* Copy Button on the right */}
                {isCopyable && (
                  <button 
                    onClick={() => copyToClipboard(row.value, rowKey)}
                    className="absolute right-4 top-4 p-1.5 bg-white hover:bg-[#FAF7F1] border border-[#E6DDD2] rounded-md text-[#7C6F64] transition-all opacity-0 group-hover:opacity-100 flex items-center gap-1.5 z-10 cursor-pointer shadow-sm"
                    title="Copy Value"
                  >
                    {copiedKey === rowKey ? <CheckCircle2 className="w-3 h-3 text-[#10B981]" /> : <Copy className="w-3 h-3" />}
                    {copiedKey === rowKey && <span className="text-[9px] font-bold text-[#10B981]">COPIED</span>}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
