"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { 
  ShieldCheck, AlertTriangle, Search, Activity, 
  Server, Target, CheckCircle2, ChevronLeft, Save, FileJson, 
  Download, Plus, Trash2, ShieldAlert
} from "lucide-react";

interface ScannerJson {
  scan_id: string;
  target: any;
  detected_technologies: any[];
  detected_assets: any[];
  findings: any[];
}

export default function ClientReviewPage() {
  const router = useRouter();
  const [scannerData, setScannerData] = useState<ScannerJson | null>(null);
  
  // Editable State
  const [technologies, setTechnologies] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  
  // Business Context State
  const [businessContext, setBusinessContext] = useState({
    hosting: "",
    cloud_provider: "",
    waf_cdn: "",
    auth_provider: "",
    payment_provider: "",
    business_criticality: "medium",
    sensitive_data_types: "",
    internal_only_routes: "",
    notes: ""
  });

  // Finding Notes: finding_id -> note
  const [findingNotes, setFindingNotes] = useState<Record<string, string>>({});

  useEffect(() => {
    const raw = localStorage.getItem("tibsa_scanner_json");
    if (raw) {
      try {
        const data = JSON.parse(raw);
        setScannerData(data);
        setTechnologies(data.detected_technologies || []);
        setAssets(data.detected_assets || []);
      } catch (e) {
        console.error("Failed to parse scanner json", e);
      }
    }
  }, []);

  if (!scannerData) {
    return (
      <div className="p-8 text-center text-[var(--text-muted)]">
        <Activity className="w-8 h-8 animate-spin mx-auto mb-4" />
        <p>Loading scanner payload...</p>
      </div>
    );
  }

  // Generators for Reviewed Payload
  const generateReviewedPayload = () => {
    return {
      scan_id: scannerData.scan_id,
      target: scannerData.target,
      technologies: technologies,
      assets: assets,
      findings: scannerData.findings,
      business_context: {
        ...businessContext,
        sensitive_data_types: businessContext.sensitive_data_types.split(",").map(s => s.trim()).filter(Boolean),
        internal_only_routes: businessContext.internal_only_routes.split(",").map(s => s.trim()).filter(Boolean)
      },
      finding_notes: Object.entries(findingNotes).map(([id, note]) => ({
        finding_id: id,
        client_note: note
      }))
    };
  };

  const handleExportReviewed = () => {
    const payload = generateReviewedPayload();
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `reviewed_payload_${scannerData.scan_id}.json`;
    a.click();
  };

  const handleExportScannerOnly = () => {
    const blob = new Blob([JSON.stringify(scannerData, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `scanner_context_${scannerData.scan_id}.json`;
    a.click();
  };

  const addTechnology = () => {
    setTechnologies([...technologies, { name: "New Technology", category: "unknown", confidence: "high", evidence: "Manually added by client" }]);
  };

  const removeTechnology = (index: number) => {
    setTechnologies(technologies.filter((_, i) => i !== index));
  };

  const updateTechnology = (index: number, field: string, value: string) => {
    const newTechs = [...technologies];
    newTechs[index] = { ...newTechs[index], [field]: value };
    setTechnologies(newTechs);
  };

  const addAsset = () => {
    setAssets([...assets, { type: "custom_endpoint", url: "https://", confidence: "high" }]);
  };

  const removeAsset = (index: number) => {
    setAssets(assets.filter((_, i) => i !== index));
  };

  const updateAsset = (index: number, field: string, value: string) => {
    const newAssets = [...assets];
    newAssets[index] = { ...newAssets[index], [field]: value };
    setAssets(newAssets);
  };

  return (
    <div className="min-h-screen bg-[var(--bg-main)] text-[var(--text-secondary)] font-sans pb-20">
      
      {/* Header */}
      <div className="bg-[var(--bg-card)] border-b border-[var(--border-soft)] sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button onClick={() => router.back()} className="p-2 hover:bg-[var(--bg-elevated)] rounded-lg transition-all text-[var(--text-muted)]">
              <ChevronLeft className="w-5 h-5" />
            </button>
            <div>
              <h1 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
                Client Review
              </h1>
              <div className="text-xs text-[var(--text-muted)] font-mono mt-0.5">{scannerData.target.url}</div>
            </div>
          </div>
          <div className="flex gap-3">
            <button 
              onClick={handleExportScannerOnly}
              className="flex items-center gap-2 px-4 py-2 bg-[var(--bg-elevated)] hover:bg-[var(--bg-elevated)] text-[var(--text-secondary)] rounded-lg text-sm font-medium transition-all"
            >
              <FileJson className="w-4 h-4" /> Scanner JSON
            </button>
            <button 
              onClick={handleExportReviewed}
              className="flex items-center gap-2 px-6 py-2 bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] !text-white hover:opacity-90 rounded-lg text-sm font-bold shadow-lg shadow-[var(--primary-soft)] transition-all"
            >
              <Save className="w-4 h-4" /> Confirm & Export Reviewed Payload
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        
        {/* 1. Technologies Review */}
        <section className="bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-2xl overflow-hidden shadow-xl">
          <div className="px-6 py-4 border-b border-[var(--border-soft)] flex items-center justify-between bg-[var(--bg-card)]/30">
            <h2 className="text-lg font-bold text-[var(--text-primary)] flex items-center gap-2">
              <Server className="w-5 h-5 text-emerald-400" /> Technologies Review
            </h2>
            <button onClick={addTechnology} className="flex items-center gap-1 text-xs font-bold text-emerald-400 hover:text-emerald-300 transition-colors">
              <Plus className="w-3 h-3" /> ADD TECHNOLOGY
            </button>
          </div>
          <div className="p-6 space-y-4">
            {technologies.map((tech, i) => (
              <div key={i} className="flex items-center gap-4 bg-[var(--bg-card)]/50 p-4 rounded-xl border border-[var(--border-soft)] hover:border-[var(--border-strong)] transition-colors">
                <input 
                  type="text" value={tech.name} onChange={e => updateTechnology(i, "name", e.target.value)}
                  className="flex-1 bg-black/40 border border-[var(--border-strong)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-emerald-500/50 outline-none"
                  placeholder="Technology Name"
                />
                <input 
                  type="text" value={tech.category} onChange={e => updateTechnology(i, "category", e.target.value)}
                  className="w-40 bg-black/40 border border-[var(--border-strong)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-emerald-500/50 outline-none"
                  placeholder="Category"
                />
                <select 
                  value={tech.confidence} onChange={e => updateTechnology(i, "confidence", e.target.value)}
                  className="w-32 bg-black/40 border border-[var(--border-strong)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-emerald-500/50 outline-none appearance-none"
                >
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <button onClick={() => removeTechnology(i)} className="p-2 text-[var(--text-muted)] hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-all">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </section>

        {/* 2. Attack Surface Review */}
        <section className="bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-2xl overflow-hidden shadow-xl">
          <div className="px-6 py-4 border-b border-[var(--border-soft)] flex items-center justify-between bg-[var(--bg-card)]/30">
            <h2 className="text-lg font-bold text-[var(--text-primary)] flex items-center gap-2">
              <Target className="w-5 h-5 text-orange-400" /> Attack Surface Assets Review
            </h2>
            <button onClick={addAsset} className="flex items-center gap-1 text-xs font-bold text-orange-400 hover:text-orange-300 transition-colors">
              <Plus className="w-3 h-3" /> ADD ASSET
            </button>
          </div>
          <div className="p-6 space-y-4">
            {assets.map((asset, i) => (
              <div key={i} className="flex items-center gap-4 bg-[var(--bg-card)]/50 p-4 rounded-xl border border-[var(--border-soft)] hover:border-[var(--border-strong)] transition-colors">
                <input 
                  type="text" value={asset.type} onChange={e => updateAsset(i, "type", e.target.value)}
                  className="w-48 bg-black/40 border border-[var(--border-strong)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] focus:border-orange-500/50 outline-none"
                  placeholder="Asset Type (e.g. login_page)"
                />
                <input 
                  type="text" value={asset.url} onChange={e => updateAsset(i, "url", e.target.value)}
                  className="flex-1 bg-black/40 border border-[var(--border-strong)] rounded-lg px-3 py-2 text-sm font-mono text-[var(--text-primary)] focus:border-orange-500/50 outline-none"
                  placeholder="https://..."
                />
                <button onClick={() => removeAsset(i)} className="p-2 text-[var(--text-muted)] hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-all">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </section>

        {/* 3. Business Context */}
        <section className="bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-2xl overflow-hidden shadow-xl">
          <div className="px-6 py-4 border-b border-[var(--border-soft)] bg-[var(--bg-card)]/30">
            <h2 className="text-lg font-bold text-[var(--text-primary)] flex items-center gap-2">
              <Activity className="w-5 h-5 text-[var(--primary)]" /> Business Context
            </h2>
          </div>
          <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-2">Hosting / Cloud Provider</label>
                <input 
                  type="text" value={businessContext.hosting} onChange={e => setBusinessContext({...businessContext, hosting: e.target.value})}
                  className="w-full bg-black/40 border border-[var(--border-strong)] rounded-lg px-4 py-3 text-sm text-[var(--text-primary)] focus:border-[var(--primary)] outline-none" placeholder="e.g. AWS, Vercel"
                />
              </div>
              <div>
                <label className="block text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-2">WAF / CDN</label>
                <input 
                  type="text" value={businessContext.waf_cdn} onChange={e => setBusinessContext({...businessContext, waf_cdn: e.target.value})}
                  className="w-full bg-black/40 border border-[var(--border-strong)] rounded-lg px-4 py-3 text-sm text-[var(--text-primary)] focus:border-[var(--primary)] outline-none" placeholder="e.g. Cloudflare, AWS WAF"
                />
              </div>
              <div>
                <label className="block text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-2">Authentication Provider</label>
                <input 
                  type="text" value={businessContext.auth_provider} onChange={e => setBusinessContext({...businessContext, auth_provider: e.target.value})}
                  className="w-full bg-black/40 border border-[var(--border-strong)] rounded-lg px-4 py-3 text-sm text-[var(--text-primary)] focus:border-[var(--primary)] outline-none" placeholder="e.g. Auth0, Custom JWT"
                />
              </div>
              <div>
                <label className="block text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-2">Business Criticality</label>
                <select 
                  value={businessContext.business_criticality} onChange={e => setBusinessContext({...businessContext, business_criticality: e.target.value})}
                  className="w-full bg-black/40 border border-[var(--border-strong)] rounded-lg px-4 py-3 text-sm text-[var(--text-primary)] focus:border-[var(--primary)] outline-none appearance-none"
                >
                  <option value="low">Low - Informational / Marketing</option>
                  <option value="medium">Medium - Standard App</option>
                  <option value="high">High - Revenue Generating</option>
                  <option value="critical">Critical - Core Infrastructure</option>
                </select>
              </div>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-2">Sensitive Data Types (comma separated)</label>
                <input 
                  type="text" value={businessContext.sensitive_data_types} onChange={e => setBusinessContext({...businessContext, sensitive_data_types: e.target.value})}
                  className="w-full bg-black/40 border border-[var(--border-strong)] rounded-lg px-4 py-3 text-sm text-[var(--text-primary)] focus:border-[var(--primary)] outline-none" placeholder="e.g. PII, PCI, PHI"
                />
              </div>
              <div>
                <label className="block text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-2">Internal Only Routes (comma separated)</label>
                <input 
                  type="text" value={businessContext.internal_only_routes} onChange={e => setBusinessContext({...businessContext, internal_only_routes: e.target.value})}
                  className="w-full bg-black/40 border border-[var(--border-strong)] rounded-lg px-4 py-3 text-sm text-[var(--text-primary)] focus:border-[var(--primary)] outline-none" placeholder="e.g. /admin, /internal/api"
                />
              </div>
              <div className="h-full flex flex-col">
                <label className="block text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider mb-2">General Notes</label>
                <textarea 
                  value={businessContext.notes} onChange={e => setBusinessContext({...businessContext, notes: e.target.value})}
                  className="w-full flex-1 min-h-[100px] bg-black/40 border border-[var(--border-strong)] rounded-lg px-4 py-3 text-sm text-[var(--text-primary)] focus:border-[var(--primary)] outline-none resize-none" placeholder="Additional context about the target..."
                />
              </div>
            </div>
          </div>
        </section>

        {/* 4. Scanner Findings (Read Only + Client Note) */}
        <section className="bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-2xl overflow-hidden shadow-xl">
          <div className="px-6 py-4 border-b border-[var(--border-soft)] bg-[var(--bg-card)]/30">
            <h2 className="text-lg font-bold text-[var(--text-primary)] flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-[var(--primary)]" /> Scanner Findings
              <span className="text-xs font-normal text-[var(--text-muted)] ml-2">(Read-Only)</span>
            </h2>
          </div>
          <div className="p-6 space-y-6">
            {scannerData.findings.map(finding => (
              <div key={finding.finding_id} className="bg-[var(--bg-card)]/50 border border-[var(--border-soft)] rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-[var(--border-soft)] flex items-start justify-between">
                  <div>
                    <h3 className="font-bold text-[var(--text-primary)] text-base">{finding.title}</h3>
                    <div className="text-xs text-[var(--text-muted)] font-mono mt-1">{finding.affected_url}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider ${
                      finding.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      finding.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      finding.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-[var(--primary)]/20 text-[var(--primary)]'
                    }`}>
                      {finding.severity}
                    </span>
                  </div>
                </div>
                <div className="p-5 grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div>
                    <div className="text-xs font-bold text-[var(--text-muted)] uppercase mb-2">Evidence</div>
                    <div className="text-sm text-[var(--text-secondary)] bg-black/40 p-3 rounded-lg border border-[var(--border-soft)] font-mono max-h-32 overflow-y-auto">
                      {finding.evidence || 'No specific evidence provided.'}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs font-bold text-[var(--primary)] uppercase mb-2">Client Note (Optional)</div>
                    <textarea 
                      value={findingNotes[finding.finding_id] || ""}
                      onChange={e => setFindingNotes({...findingNotes, [finding.finding_id]: e.target.value})}
                      className="w-full bg-black/40 border border-[var(--border-strong)] rounded-lg px-4 py-3 text-sm text-[var(--text-primary)] focus:border-[var(--primary)] outline-none resize-none h-24" 
                      placeholder="Add business context, false positive justification, or mitigation notes here..."
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

      </div>
    </div>
  );
}
