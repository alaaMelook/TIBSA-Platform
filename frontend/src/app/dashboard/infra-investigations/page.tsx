"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/lib/api";
import { Card, Button, Input } from "@/components/ui";
import { InfraSubHeader } from "@/components/infra-investigation/InfraSubHeader";
import {
  Globe,
  Search,
  Play,
  Database,
  Sparkles,
  Cpu,
  Network,
  ShieldCheck,
  Zap,
  Layers,
  X,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
} from "lucide-react";
import { InfraTargetType } from "@/types/infra_investigation";

const TARGET_TYPES: { key: InfraTargetType; label: string; desc: string; example: string }[] = [
  { key: "domain",  label: "Domain",  desc: "Resolve, enumerate and correlate domain infrastructure", example: "evil-domain.com"     },
  { key: "ip",      label: "IP",      desc: "Reputation lookup, GeoIP, ASN, and abuse reports",       example: "185.220.101.45"     },
  { key: "url",     label: "URL",     desc: "Full URL analysis including domain + path heuristics",    example: "http://phish.xyz/r" },
  { key: "hash",    label: "Hash",    desc: "IOC hash lookup across threat intelligence feeds",        example: "a3f8c..."            },
  { key: "email",   label: "Email",   desc: "Email domain reputation and spoofing vector analysis",    example: "ceo@evil-corp.ru"   },
];

const PIPELINE_STAGES = [
  { step: "01", name: "Target Parsing", desc: "Validate target schema and extract indicators" },
  { step: "02", name: "DNS Resolution", desc: "A, AAAA, MX, NS and TXT record resolution" },
  { step: "03", name: "WHOIS & RDAP", desc: "Registrar details, creation date, and ownership" },
  { step: "04", name: "SSL Certificate", desc: "Enrich Certificate Authority and issuer dates" },
  { step: "05", name: "GeoIP & ASN", desc: "Lookup physical location, ISP, and network routing" },
  { step: "06", name: "Passive DNS", desc: "Map historical IP-to-domain mapping graphs" },
  { step: "07", name: "Reputation Feeds", desc: "Cross-reference IOC against threat intelligence lists" },
  { step: "08", name: "AI Categorization", desc: "Summarize findings and attribute campaigns" },
];

interface StageDetail {
  desc: string;
  iocDetails: Record<string, string[] | null>; // domain, ip, url, hash, email
}

const STAGE_DETAILS: Record<string, StageDetail> = {
  "01": {
    desc: "Validates input formats, cleans protocol headers, and extracts sub-components.",
    iocDetails: {
      domain: [
        "Validates domain name syntax against RFC standards.",
        "Extracts the root domain and top-level domain (TLD).",
        "Detects potential IDN (Internationalized Domain Name) homograph spoofing attempts."
      ],
      ip: [
        "Detects IPv4 or IPv6 format.",
        "Checks if the IP belongs to a private, loopback, or multicast subnet range."
      ],
      url: [
        "Parses protocol schema (HTTP/HTTPS/FTP).",
        "Extracts port number, hostname, directory path, file extension, and query parameters.",
        "Identifies credentials embedded in the URL (UserInfo)."
      ],
      hash: [
        "Identifies signature type based on length: MD5 (32 hex characters), SHA-1 (40 hex), SHA-256 (64 hex).",
        "Validates hexadecimal character integrity."
      ],
      email: [
        "Validates email address syntax structure (local-part@domain).",
        "Extracts the domain component for further infrastructure checks."
      ]
    }
  },
  "02": {
    desc: "Queries global name servers for active resource records and configuration directives.",
    iocDetails: {
      domain: [
        "A & AAAA Records: Resolves active IPv4 and IPv6 host addresses.",
        "MX (Mail Exchange): Finds target mail servers.",
        "TXT Records: Checks SPF, DKIM, and custom verification strings.",
        "NS Records: Identifies authoritative nameservers.",
        "CNAME Records: Tracks canonical alias records."
      ],
      ip: [
        "PTR (Pointer) Record: Performs Reverse DNS (rDNS) lookup to identify the primary host domain associated with the IP."
      ],
      url: [
        "Extracts the hostname from the URL.",
        "Resolves standard DNS records (A, AAAA, CNAME) for the hosting server."
      ],
      hash: null, // Not applicable
      email: [
        "MX Records: Resolves mail exchange servers for the email domain.",
        "TXT Records: Verifies SPF, DKIM, and DMARC records to check spoofing protection."
      ]
    }
  },
  "03": {
    desc: "Queries Regional Internet Registries (RIRs) and domain registrars for ownership details.",
    iocDetails: {
      domain: [
        "Registrar Name: Identifies the registration provider (e.g. GoDaddy, Namecheap).",
        "Dates: Retrieves Creation, Update, and Expiration timestamps.",
        "Domain Status Codes: Checks registry status (e.g. clientTransferProhibited).",
        "Contact Info: Extracts registrant name, organization, and country if not redacted."
      ],
      ip: [
        "NetRange & CIDR: Finds allocated block details.",
        "RIR Authority: Identifies the registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC).",
        "Abuse Contacts: Retrieves network abuse reporting emails."
      ],
      url: [
        "Extracts root domain from the URL and queries registration WHOIS data.",
        "Retraces historical owner changes."
      ],
      hash: null, // Not applicable
      email: [
        "WHOIS Lookup: Inspects the registration age of the email domain to spot newly registered spam domains."
      ]
    }
  },
  "04": {
    desc: "Establishes a secure TLS handshake to fetch, parse, and validate certificate records.",
    iocDetails: {
      domain: [
        "Common Name (CN) & SANs: Inspects certificates for valid hosts and subdomains.",
        "Issuer Name: Identifies Certificate Authority (CA) e.g., Let's Encrypt, DigiCert.",
        "Validity Dates: Captures issue date, expiry date, and active duration."
      ],
      ip: [
        "Webserver TLS Handshake: Probes port 443 of the IP to fetch certificates.",
        "Extracts certificate details if the server hosts SSL directly."
      ],
      url: [
        "Handshake: Connects directly to the URL endpoint to extract certificate details.",
        "Domain Match: Verifies that the host matches the Common Name or SANs in the cert."
      ],
      hash: null,
      email: [
        "Probes MX mail server ports (25, 465, 587) for opportunistic TLS certificate details."
      ]
    }
  },
  "05": {
    desc: "Translates indicators to physical locations and Autonomous System networks.",
    iocDetails: {
      domain: [
        "IP Lookup: Resolves domain to active server IPs.",
        "Geographic Location: Maps hosting IP to Country, City, and coordinates.",
        "ASN details: Identifies ISP and Autonomous System Number."
      ],
      ip: [
        "Geographic mapping: Details Country, City, Region, Latitude/Longitude.",
        "ISP Name: Identifies the hosting organization (e.g. DigitalOcean, AWS, Cloudflare).",
        "Autonomous System: Retrieves ASN and AS organization description."
      ],
      url: [
        "Extracts server IP of the URL hostname and maps its physical hosting location and network provider."
      ],
      hash: null,
      email: [
        "MX Geolocation: Geolocates the physical location of the resolved MX mail server IPs."
      ]
    }
  },
  "06": {
    desc: "Maps historical IP-to-domain resolutions over time to discover structural connections.",
    iocDetails: {
      domain: [
        "Historical IPs: Retrieves prior server IPs this domain has resolved to.",
        "Domain Flapping: Detects frequent IP changes that indicate fast-flux DNS configurations."
      ],
      ip: [
        "Historical Domains: Retrieves all hostnames that have historically resolved to this IP.",
        "Shared Hosting Analysis: Identifies potentially malicious domain neighbors on the same IP."
      ],
      url: [
        "Passive DNS Check: Looks up resolution history for the URL's domain."
      ],
      hash: null,
      email: [
        "Passive DNS Check: Resolves historical mappings of the email domain."
      ]
    }
  },
  "07": {
    desc: "Cross-references indicators against dozens of open-source and commercial threat intelligence feeds.",
    iocDetails: {
      domain: [
        "Threat Feeds: Checks AlienVault OTX, Abuse.ch URLhaus, and Spamhaus.",
        "Malicious Hits: Identifies malware hosting history or C2 server listings."
      ],
      ip: [
        "IP Blacklists: Checks for botnet traffic, brute-force scanning, or spam emissions.",
        "Exit Nodes: Detects if the IP is a Tor exit node, VPN, or public proxy."
      ],
      url: [
        "URL Blocklists: Scans for active phishing paths, credential harvesting, or malware downloads."
      ],
      hash: [
        "Hash Matches: Queries database (VirusTotal, MalwareBazaar) for file signature matches.",
        "Detections: Retrieves AV detection ratios, malware classification family, and behavior tags."
      ],
      email: [
        "Spam lists: Checks against known disposable email providers, spam domains, or fraud registers."
      ]
    }
  },
  "08": {
    desc: "Synthesizes multi-stage profiling outputs via AI to model threat profiles.",
    iocDetails: {
      domain: [
        "Actor Attribution: Synthesizes registry and history to suggest threat actors.",
        "Campaign Mapping: Links the domain to active cyber campaigns."
      ],
      ip: [
        "Role Assessment: Evaluates server telemetry to classify node role (e.g. Proxy, C2 node, Scanner)."
      ],
      url: [
        "Attack Category: Evaluates directory path structures to detect social engineering or drive-by payload vectors."
      ],
      hash: [
        "Capabilities Summary: Evaluates behavior telemetry to explain virus functionality.",
        "Mitigation Rules: Recommends detection rules (YARA or Sigma)."
      ],
      email: [
        "Phishing Assessment: Flags Business Email Compromise (BEC) risks or impersonation vectors."
      ]
    }
  }
};

export default function InfraScannerPage() {
  const router = useRouter();
  const { token } = useAuth();

  const [target, setTarget]             = useState("");
  const [targetType, setTargetType]     = useState<InfraTargetType>("domain");
  const [enablePassiveDns, setPassiveDns] = useState(true);
  const [enableAiSummary, setAiSummary]   = useState(true);

  const [isLaunching, setIsLaunching]       = useState(false);
  const [launchError, setLaunchError]       = useState<string | null>(null);

  // Modal State
  const [selectedStageKey, setSelectedStageKey] = useState<string | null>(null);
  const [activeIocTab, setActiveIocTab]         = useState<string>("domain");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim() || !token) return;
    setIsLaunching(true);
    setLaunchError(null);
    try {
      const res = await api.infraInvestigations.create({
        target: target.trim(),
        enable_passive_dns: enablePassiveDns,
        enable_ai_summary:  enableAiSummary,
      }, token);
      if (res?.success && res?.data) {
        router.push(`/dashboard/infra-investigations/${res.data.id}`);
      } else {
        setLaunchError("Failed to start — invalid response.");
      }
    } catch (err: any) {
      setLaunchError(err.message || "An error occurred.");
    } finally {
      setIsLaunching(false);
    }
  };

  const selectedType = TARGET_TYPES.find((t) => t.key === targetType);
  const selectedStage = selectedStageKey ? PIPELINE_STAGES.find(s => s.step === selectedStageKey) : null;
  const stageDetails = selectedStageKey ? STAGE_DETAILS[selectedStageKey] : null;

  return (
    <div className="space-y-6">
      {/* SubHeader Component */}
      <InfraSubHeader />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Launch Form */}
        <div className="lg:col-span-1 space-y-4">
          <Card title="New Investigation" description="Submit an IOC or infrastructure indicator">
            <form onSubmit={handleSubmit} className="space-y-4 mt-2">

              {/* Target type selector */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider block">
                  Target Type
                </label>
                <div className="grid grid-cols-5 gap-1">
                  {TARGET_TYPES.map((t) => (
                    <button
                      key={t.key}
                      type="button"
                      onClick={() => setTargetType(t.key)}
                      className={`py-1.5 rounded-lg border text-[10px] font-bold capitalize transition-all cursor-pointer ${
                        targetType === t.key
                          ? "border-[var(--primary)] bg-[var(--primary-soft)] text-[var(--primary)] font-extrabold shadow-sm"
                          : "border-[var(--border-strong)] bg-[var(--bg-page)]/20 text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                      }`}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
                {selectedType && (
                  <p className="text-[10px] text-[var(--text-muted)] leading-tight transition-all duration-300 mt-1">
                    {selectedType.desc}
                  </p>
                )}
              </div>

              {/* Target input */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-[var(--text-muted)] uppercase tracking-wider block">
                  Target Value
                </label>
                <div className="relative">
                  <Search className="absolute left-3 top-3 w-4 h-4 text-[var(--text-muted)]" />
                  <Input
                    placeholder={selectedType?.example || "Enter indicator..."}
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    required
                    className="pl-9 bg-[var(--bg-page)]/40 border-[var(--border-soft)] focus:border-[var(--primary)]"
                  />
                </div>
              </div>

              {/* Options */}
              <div className="border-t border-[var(--border-strong)] pt-3 space-y-3">
                <span className="text-[10px] font-bold text-[var(--text-muted)] uppercase tracking-widest block">
                  Pipeline Options
                </span>

                {[
                  {
                    id: "passive-dns",
                    label: "Enable Passive DNS",
                    desc:  "Map historical resolution data via OTX",
                    state: enablePassiveDns,
                    set:   setPassiveDns,
                    icon:  <Network className="w-3.5 h-3.5" />,
                  },
                  {
                    id: "ai-summary",
                    label: "Enable AI Summary",
                    desc:  "Generate AI-powered threat classification",
                    state: enableAiSummary,
                    set:   setAiSummary,
                    icon:  <Sparkles className="w-3.5 h-3.5" />,
                  },
                ].map((opt) => (
                  <div
                    key={opt.id}
                    onClick={() => opt.set(!opt.state)}
                    className={`flex items-center justify-between p-2.5 rounded-xl border cursor-pointer select-none transition-all duration-200 ${
                      opt.state
                        ? "border-[var(--primary)] bg-[var(--primary-soft)]"
                        : "border-[var(--border-soft)] bg-[var(--bg-page)]/20 hover:bg-[var(--bg-card)]/30"
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className={`p-1.5 rounded-lg border transition-colors ${
                        opt.state
                          ? "text-[var(--primary)] bg-[var(--primary)]/10 border-[var(--primary)]/20"
                          : "text-[var(--text-muted)] bg-[var(--bg-card)]/40 border-[var(--border-soft)]"
                      }`}>
                        {opt.icon}
                      </div>
                      <div>
                        <p className="text-[11px] font-bold text-[var(--text-primary)]">{opt.label}</p>
                        <p className="text-[9px] text-[var(--text-muted)] leading-none mt-0.5">{opt.desc}</p>
                      </div>
                    </div>
                    <div className={`relative inline-flex h-4 w-7 rounded-full border-transparent transition-colors duration-200 ease-in-out ${
                      opt.state ? "bg-[var(--primary)]" : "bg-[var(--bg-elevated)]"
                    }`}>
                      <span className={`inline-block h-3 w-3 transform rounded-full bg-white shadow-md transition duration-200 ease-in-out mt-[2px] ml-[2px] ${
                        opt.state ? "translate-x-3.5" : "translate-x-0"
                      }`} />
                    </div>
                  </div>
                ))}
              </div>

              {launchError && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-xs font-medium">
                  {launchError}
                </div>
              )}

              <Button
                type="submit"
                variant="primary"
                isLoading={isLaunching}
                className="w-full justify-center gap-2 mt-2 bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] !text-white shadow-md shadow-[var(--primary-soft)] hover:shadow-lg hover:shadow-[var(--primary-soft)] text-xs font-bold transition-all duration-200"
              >
                <Play className="w-3.5 h-3.5" /> Launch Intelligence Scan
              </Button>
            </form>
          </Card>

          {/* Quick Stats Grid */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Data Sources", value: "8+",     icon: <Database className="w-4 h-4 text-[var(--primary)]" />,    color: "text-[var(--primary)]" },
              { label: "Pipeline Stages", value: "8 Steps",   icon: <Layers className="w-4 h-4 text-[var(--primary)]" />,       color: "text-[var(--primary)]" },
              { label: "AI Analysis",   value: "Llama 3.1",    icon: <Sparkles className="w-4 h-4 text-[var(--primary)]" />,    color: "text-[var(--primary)]" },
              { label: "No VT API Keys",   value: "Zero Cost",   icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />, color: "text-emerald-400" },
            ].map((s) => (
              <div key={s.label} className="bg-[var(--bg-card)]/40 border border-[var(--border-soft)] rounded-xl p-3 flex items-center gap-3">
                <div className="p-2 bg-[var(--bg-page)]/60 rounded-lg border border-[var(--border-soft)]">{s.icon}</div>
                <div>
                  <p className={`text-xs font-extrabold ${s.color}`}>{s.value}</p>
                  <p className="text-[9px] text-[var(--text-muted)] uppercase font-semibold">{s.label}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Pipeline Steps & Description */}
        <div className="lg:col-span-2 space-y-4">
          <Card title="Investigation Pipeline Architecture" description="Multi-stage profiling runs sequentially in the background. Click any stage to inspect specific indicators collected.">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
              {PIPELINE_STAGES.map((stage) => (
                <div 
                  key={stage.step} 
                  onClick={() => {
                    setSelectedStageKey(stage.step);
                    // Reset tab to match currently selected target type if applicable, or default to domain
                    setActiveIocTab(targetType);
                  }}
                  className="p-3 rounded-xl border border-[var(--border-soft)] bg-[var(--bg-page)]/20 hover:bg-[var(--bg-card)]/40 hover:border-[var(--primary)] transition-all duration-200 flex items-start gap-3 group cursor-pointer shadow-sm relative overflow-hidden"
                >
                  <div className="text-xs font-black text-[var(--primary)] bg-[var(--primary-soft)] border border-[var(--primary)]/30 px-2 py-0.5 rounded-lg group-hover:bg-[var(--primary)]/20 transition-colors">
                    {stage.step}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-extrabold text-[var(--text-primary)] group-hover:text-[var(--primary)] transition-colors">
                        {stage.name}
                      </h4>
                      <span className="text-[9px] text-transparent group-hover:text-[var(--primary)] font-bold transition-all duration-300">
                        Details &rarr;
                      </span>
                    </div>
                    <p className="text-[10px] text-[var(--text-muted)] mt-0.5 leading-snug">
                      {stage.desc}
                    </p>
                  </div>
                  {/* Subtle top border accent on hover */}
                  <div className="absolute top-0 left-0 right-0 h-[1.5px] bg-gradient-to-r from-transparent via-[var(--primary)] to-transparent opacity-0 group-hover:opacity-60 transition-opacity duration-300" />
                </div>
              ))}
            </div>

            <div className="mt-4 p-4 rounded-xl border border-[var(--primary)]/20 bg-[var(--primary-soft)] flex gap-3.5 items-start">
              <Zap className="w-5 h-5 text-[var(--primary)] flex-shrink-0 mt-0.5" />
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-[var(--text-primary)]">Continuous Enrichment</h4>
                <p className="text-[10px] text-[var(--text-muted)] leading-relaxed">
                  The infrastructure pipeline correlates indicators using free open-source threat intelligence datasets, reverse lookup databases, and passive DNS records. Once completed, a relational graph is compiled to show connections between entities.
                </p>
              </div>
            </div>
          </Card>
        </div>

      </div>

      {/* ── Pipeline Details Modal ───────────────────────── */}
      {selectedStageKey && selectedStage && stageDetails && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-md animate-fadeIn">
          {/* Backdrop closer */}
          <div className="absolute inset-0" onClick={() => setSelectedStageKey(null)} />

          {/* Modal Container */}
          <div 
            className="relative w-full max-w-2xl bg-[var(--bg-card)] border border-[var(--border-soft)] rounded-2xl shadow-sm p-6 overflow-hidden max-h-[90vh] flex flex-col z-10 animate-scaleUp"
          >
            {/* Top decorative line */}
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-[var(--primary)] to-transparent" />

            {/* Header */}
            <div className="flex items-start justify-between border-b border-[var(--border-strong)] pb-4 mb-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[10px] font-black text-[var(--primary)] bg-[var(--primary-soft)] border border-[var(--primary)]/30 px-2 py-0.5 rounded uppercase">
                    Stage {selectedStage.step}
                  </span>
                  <span className="text-[10px] text-[var(--text-muted)] font-bold uppercase tracking-wider">
                    Pipeline Schema
                  </span>
                </div>
                <h3 className="text-lg font-black text-[var(--text-primary)]">{selectedStage.name} Details</h3>
                <p className="text-xs text-[var(--text-muted)] mt-1 leading-relaxed">{stageDetails.desc}</p>
              </div>
              <button 
                onClick={() => setSelectedStageKey(null)}
                className="p-1.5 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border-soft)] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] transition-all cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* IOC Type Tabs row */}
            <div className="flex bg-[var(--bg-page)]/40 border border-[var(--border-soft)] p-1 rounded-xl w-fit max-w-full overflow-x-auto gap-1 mb-4">
              {["domain", "ip", "url", "hash", "email"].map((iocTab) => {
                const isActive = activeIocTab === iocTab;
                return (
                  <button
                    key={iocTab}
                    onClick={() => setActiveIocTab(iocTab)}
                    className={`px-4 py-2 rounded-lg text-xs font-bold capitalize transition-all duration-200 whitespace-nowrap cursor-pointer border ${
                      isActive
                        ? "bg-[var(--primary-soft)] border-[var(--primary)] text-[var(--primary)] shadow-sm"
                        : "border-[var(--border-strong)] bg-[var(--bg-card)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-elevated)]"
                    }`}
                  >
                    {iocTab}
                  </button>
                );
              })}
            </div>

            {/* Tab Content Area */}
            <div className="flex-1 overflow-y-auto min-h-[220px] bg-[var(--bg-elevated)] border border-[var(--border-soft)] p-4 rounded-xl">
              {stageDetails.iocDetails[activeIocTab] ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 mb-2 text-xs font-bold text-[var(--text-secondary)] uppercase tracking-widest">
                    <CheckCircle2 className="w-4 h-4 text-[var(--primary)]" />
                    Indicators Collected for {activeIocTab.toUpperCase()} Target
                  </div>
                  <ul className="space-y-2.5">
                    {stageDetails.iocDetails[activeIocTab]?.map((detailText, index) => (
                      <li key={index} className="flex items-start gap-2.5 text-xs text-[var(--text-secondary)] leading-relaxed animate-fadeIn">
                        <span className="w-1.5 h-1.5 rounded-full bg-[var(--primary)] mt-2 shrink-0 shadow-[0_0_8px_rgba(15,157,118,0.5)]" />
                        <span>{detailText}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="h-full flex flex-col items-center justify-center py-12 text-[var(--text-muted)] select-none">
                  <AlertCircle className="w-8 h-8 mb-2 text-[var(--text-muted)] opacity-60" />
                  <p className="text-xs font-bold uppercase tracking-wider text-[var(--text-muted)]">Not Applicable</p>
                  <p className="text-[10px] text-[var(--text-muted)] text-center max-w-sm mt-1 leading-normal">
                    This pipeline stage is not executed and gathers no parameters when investigating a <span className="font-mono font-bold text-[var(--text-muted)]">{activeIocTab.toUpperCase()}</span> indicator.
                  </p>
                </div>
              )}
            </div>

            {/* Bottom Actions footer */}
            <div className="border-t border-[var(--border-strong)] pt-4 mt-4 flex items-center justify-between">
              <span className="text-[9px] text-[var(--text-muted)] font-mono font-medium">TIBSA Platform Flow 2 Pipeline Telemetry</span>
              <button 
                onClick={() => setSelectedStageKey(null)}
                className="px-4 py-2 bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] !text-white rounded-lg text-xs font-bold transition-all duration-200 shadow-sm"
              >
                Close Details
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}
