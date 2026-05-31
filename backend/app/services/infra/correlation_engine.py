"""
Correlation Engine – Stage 6 of the Infra Intelligence Pipeline.

Evaluates a fixed rule-set against all accumulated pipeline data and
produces InfraCorrelationResult containing:
  • A list of rule evaluations (triggered / not triggered)
  • An overall confidence assessment

Rules:
  R1  Multi-Source Confirmation      – 3+ sources flagged the target
  R2  Known Campaign Infrastructure  – OTX pulses share malware family tags
  R3  Phishing Infrastructure Combo  – URLhaus + newly registered domain
  R4  AbuseIPDB + ThreatFox Overlap  – IP reported on both platforms
  R5  Brand Impersonation + SSL Mismatch
  R6  Passive DNS Shared IP          – same IP seen across multiple hostnames
  R7  High Entropy + Suspicious TLD
  R8  Newly Registered + AbuseIPDB   – fresh IP already abused
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.schemas.infra_investigation import (
    InfraCorrelationResult,
    InfraCorrelationRule,
)


class CorrelationEngine:

    def run(
        self,
        reputation: Optional[Dict[str, Any]],
        enrichment: Optional[Dict[str, Any]],
        passive_dns: Optional[Dict[str, Any]],
        indicators: Optional[Dict[str, Any]],
    ) -> InfraCorrelationResult:
        rules: List[InfraCorrelationRule] = []

        # ── Unpack sub-sections ───────────────────────────────────────────────
        rep = reputation or {}
        enr = enrichment or {}
        whois = enr.get("whois") or {}
        ssl = enr.get("ssl") or {}

        abuseipdb = rep.get("abuseipdb") or {}
        urlhaus   = rep.get("urlhaus")   or {}
        threatfox = rep.get("threatfox") or {}
        otx       = rep.get("otx")       or {}

        ind = indicators or {}
        checks = {c["id"]: c for c in (ind.get("checks") or [])}

        def _triggered(check_id: str) -> bool:
            return bool((checks.get(check_id) or {}).get("triggered"))

        passive_entries = (passive_dns or {}).get("passive_dns") or []

        # ── Helper to append a rule ───────────────────────────────────────────
        def add(
            rule_id: str,
            rule_name: str,
            triggered: bool,
            confidence: str,
            description: str,
            evidence: List[str],
            relationship_type: str,
        ) -> None:
            rules.append(
                InfraCorrelationRule(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    triggered=triggered,
                    confidence=confidence,
                    description=description,
                    evidence=evidence,
                    relationship_type=relationship_type,
                )
            )

        # ── R1: Multi-Source Confirmation ─────────────────────────────────────
        sources_flagged = 0
        r1_evidence: List[str] = []
        if isinstance(abuseipdb, dict) and abuseipdb.get("abuse_confidence_score", 0) >= 25:
            sources_flagged += 1
            r1_evidence.append(f"AbuseIPDB confidence: {abuseipdb['abuse_confidence_score']}%")
        if isinstance(urlhaus, dict) and urlhaus.get("query_status") == "is_listed":
            sources_flagged += 1
            r1_evidence.append("URLhaus: host is listed")
        if isinstance(threatfox, dict) and (threatfox.get("iocs") or []):
            sources_flagged += 1
            r1_evidence.append(f"ThreatFox: {len(threatfox['iocs'])} IOC match(es)")
        if isinstance(otx, dict) and otx.get("pulse_count", 0) >= 1:
            sources_flagged += 1
            r1_evidence.append(f"OTX: {otx['pulse_count']} pulse(s)")

        add(
            "R1", "Multi-Source Threat Confirmation",
            sources_flagged >= 3,
            "high" if sources_flagged >= 3 else "medium",
            f"Target flagged by {sources_flagged} independent reputation sources.",
            r1_evidence,
            "multi_source_confirmation",
        )

        # ── R2: Known Campaign Infrastructure ────────────────────────────────
        r2_evidence: List[str] = []
        malware_families: List[str] = []
        if isinstance(otx, dict):
            for pulse in otx.get("pulses") or []:
                for fam in pulse.get("malware_families") or []:
                    if fam and fam not in malware_families:
                        malware_families.append(fam)
        tf_malwares: List[str] = []
        if isinstance(threatfox, dict):
            for ioc in threatfox.get("iocs") or []:
                mp = ioc.get("malware_printable", "")
                if mp and mp not in tf_malwares:
                    tf_malwares.append(mp)
        shared = set(malware_families) & set(tf_malwares)
        campaign_triggered = bool(shared) or (len(malware_families) >= 2)
        if malware_families:
            r2_evidence.append(f"OTX malware families: {', '.join(malware_families[:5])}")
        if tf_malwares:
            r2_evidence.append(f"ThreatFox malware: {', '.join(tf_malwares[:5])}")
        add(
            "R2", "Known Campaign Infrastructure",
            campaign_triggered,
            "high" if shared else "medium",
            "Target infrastructure attributed to known malware campaigns.",
            r2_evidence,
            "campaign_attribution",
        )

        # ── R3: Phishing Infrastructure Combo ────────────────────────────────
        urlhaus_listed = isinstance(urlhaus, dict) and urlhaus.get("query_status") == "is_listed"
        newly_registered = isinstance(whois, dict) and whois.get("is_newly_registered", False)
        brand_impersonation = _triggered("C06")
        phishing_combo = urlhaus_listed and newly_registered
        r3_evidence: List[str] = []
        if urlhaus_listed:
            r3_evidence.append("Host listed in URLhaus malware database")
        if newly_registered:
            age = whois.get("domain_age_days")
            r3_evidence.append(f"Domain age: {age} day(s)" if age is not None else "Newly registered domain")
        if brand_impersonation:
            r3_evidence.append("Brand impersonation keyword detected in hostname")
        add(
            "R3", "Phishing Infrastructure Signature",
            phishing_combo or (brand_impersonation and newly_registered),
            "high",
            "Combination of indicators strongly suggests phishing infrastructure.",
            r3_evidence,
            "phishing_infrastructure",
        )

        # ── R4: AbuseIPDB + ThreatFox Overlap ────────────────────────────────
        abuse_high = isinstance(abuseipdb, dict) and abuseipdb.get("abuse_confidence_score", 0) >= 50
        tf_match = isinstance(threatfox, dict) and bool(threatfox.get("iocs"))
        r4_evidence: List[str] = []
        if abuse_high:
            r4_evidence.append(f"AbuseIPDB score: {abuseipdb.get('abuse_confidence_score')}%")
        if tf_match:
            r4_evidence.append(f"ThreatFox IOC match count: {len(threatfox.get('iocs', []))}")
        add(
            "R4", "AbuseIPDB + ThreatFox IP Overlap",
            abuse_high and tf_match,
            "high",
            "IP is both actively abused (AbuseIPDB) and matches ThreatFox IOC records.",
            r4_evidence,
            "ip_threat_overlap",
        )

        # ── R5: Brand Impersonation + SSL Mismatch ────────────────────────────
        ssl_mismatch = _triggered("C11")
        r5_evidence: List[str] = []
        if brand_impersonation:
            r5_evidence.append("Brand keyword found in hostname")
        if ssl_mismatch:
            r5_evidence.append(f"SSL CN mismatch — cert CN: '{(ssl or {}).get('subject_cn')}'")
        add(
            "R5", "Brand Impersonation with SSL Anomaly",
            brand_impersonation and ssl_mismatch,
            "high",
            "Domain impersonates a brand and has a mismatched TLS certificate.",
            r5_evidence,
            "brand_impersonation",
        )

        # ── R6: Passive DNS Shared Infrastructure ────────────────────────────
        unique_ips = {e.get("address") for e in passive_entries if e.get("address")}
        # Flag if a single IP has hosted many different domains (shared infra abuse)
        # We also flag if the passive DNS record count is large (lots of domains → bulletproof hosting)
        shared_infra = len(passive_entries) >= 10
        r6_evidence: List[str] = []
        if passive_entries:
            r6_evidence.append(f"Passive DNS records: {len(passive_entries)}")
            r6_evidence.append(f"Unique IPs in history: {len(unique_ips)}")
        add(
            "R6", "Passive DNS Shared Infrastructure",
            shared_infra,
            "medium",
            "High volume of passive DNS records indicates shared or bulletproof hosting.",
            r6_evidence,
            "shared_infrastructure",
        )

        # ── R7: High Entropy + Suspicious TLD ────────────────────────────────
        high_entropy = _triggered("C04")
        sus_tld = _triggered("C01")
        r7_evidence: List[str] = []
        if high_entropy:
            r7_evidence.append("Domain label has high Shannon entropy (potential DGA)")
        if sus_tld:
            r7_evidence.append("Suspicious TLD used")
        add(
            "R7", "DGA-Like Domain with Suspicious TLD",
            high_entropy and sus_tld,
            "medium",
            "High-entropy domain combined with a suspicious TLD suggests automated generation.",
            r7_evidence,
            "dga_pattern",
        )

        # ── R8: Newly Registered + AbuseIPDB ────────────────────────────────
        r8_evidence: List[str] = []
        if newly_registered:
            r8_evidence.append(f"Domain age: {whois.get('domain_age_days')} day(s)")
        if abuse_high:
            r8_evidence.append(f"AbuseIPDB score: {abuseipdb.get('abuse_confidence_score')}%")
        add(
            "R8", "Freshly Registered + Actively Abused",
            newly_registered and abuse_high,
            "high",
            "Domain is newly registered and its hosting IP is already actively abused.",
            r8_evidence,
            "fresh_abuse",
        )

        # ── Summary ───────────────────────────────────────────────────────────
        triggered_rules = [r for r in rules if r.triggered]
        n = len(triggered_rules)
        if n >= 4:
            overall = "high"
        elif n >= 2:
            overall = "medium"
        else:
            overall = "low"

        return InfraCorrelationResult(
            rules_evaluated=len(rules),
            rules_triggered=n,
            relationships=rules,
            overall_confidence=overall,
        )
