"""
Risk Engine – Stage 7 of the Infra Intelligence Pipeline.

Implements the weighted composite scoring formula:

    R_total = 0.40 × R_reputation + 0.30 × R_infrastructure + 0.30 × R_phishing

Outputs InfraRiskBreakdown with:
  • Per-component scores (0–100)
  • weighted_total (0–100)
  • risk_label: Clean | Low | Medium | High | Critical
  • contributing_factors: human-readable explanations
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.schemas.infra_investigation import InfraRiskBreakdown


def _clamp(val: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, val))


class RiskEngine:

    def run(
        self,
        reputation: Optional[Dict[str, Any]],
        enrichment: Optional[Dict[str, Any]],
        passive_dns: Optional[Dict[str, Any]],
        indicators: Optional[Dict[str, Any]],
        correlation: Optional[Dict[str, Any]],
    ) -> InfraRiskBreakdown:
        factors: List[str] = []

        # ── 1. Reputation Score (0–100) ───────────────────────────────────────
        rep_score = 0.0
        rep = reputation or {}

        abuseipdb = rep.get("abuseipdb") or {}
        urlhaus   = rep.get("urlhaus")   or {}
        threatfox = rep.get("threatfox") or {}
        otx       = rep.get("otx")       or {}

        # AbuseIPDB – direct confidence score
        if isinstance(abuseipdb, dict) and not abuseipdb.get("error"):
            abuse_conf = abuseipdb.get("abuse_confidence_score", 0)
            rep_score += float(abuse_conf)  # already 0-100
            if abuse_conf >= 50:
                factors.append(f"AbuseIPDB confidence {abuse_conf}%")

        # URLhaus – binary hit = +40 points
        if isinstance(urlhaus, dict) and urlhaus.get("query_status") == "is_listed":
            rep_score += 40.0
            factors.append("URLhaus malware blocklist hit")

        # ThreatFox – scale by number of matching IOCs (cap at +30)
        if isinstance(threatfox, dict) and not threatfox.get("error"):
            iocs = threatfox.get("iocs") or []
            if iocs:
                tf_contribution = min(30.0, len(iocs) * 5.0)
                rep_score += tf_contribution
                factors.append(f"ThreatFox {len(iocs)} IOC match(es)")

        # OTX – scale by pulse count (cap at +20)
        if isinstance(otx, dict) and not otx.get("error"):
            pulses = otx.get("pulse_count", 0)
            if pulses > 0:
                otx_contribution = min(20.0, pulses * 3.0)
                rep_score += otx_contribution
                factors.append(f"OTX {pulses} threat pulse(s)")

        rep_score = _clamp(rep_score)

        # ── 2. Infrastructure Score (0–100) ───────────────────────────────────
        infra_score = 0.0
        enr = enrichment or {}
        whois = enr.get("whois") or {}
        ssl   = enr.get("ssl")   or {}

        # Newly registered domain = +40
        if isinstance(whois, dict) and whois.get("is_newly_registered"):
            infra_score += 40.0
            age = whois.get("domain_age_days")
            factors.append(f"Newly registered domain ({age}d old)" if age else "Newly registered domain")

        # Expired SSL = +25
        if isinstance(ssl, dict) and ssl.get("is_expired"):
            infra_score += 25.0
            factors.append("Expired TLS certificate")

        # Self-signed SSL = +15
        if isinstance(ssl, dict) and ssl.get("is_self_signed"):
            infra_score += 15.0
            factors.append("Self-signed TLS certificate")

        # SSL CN mismatch = +20
        ind = indicators or {}
        checks_map = {c["id"]: c for c in (ind.get("checks") or [])}
        def _check(cid: str) -> bool:
            return bool((checks_map.get(cid) or {}).get("triggered"))

        if _check("C11"):
            infra_score += 20.0
            factors.append("SSL Common Name mismatch")

        # Large passive DNS footprint = +10
        pdns = passive_dns or {}
        pdns_count = pdns.get("count", 0)
        if pdns_count >= 10:
            infra_score += 10.0
            factors.append(f"Large passive DNS footprint ({pdns_count} records)")

        infra_score = _clamp(infra_score)

        # ── 3. Phishing Score (0–100) from indicator service ─────────────────
        phishing_score = float((ind.get("phishing_score") or 0.0))
        phishing_score = _clamp(phishing_score)

        if phishing_score >= 50:
            factors.append(f"High phishing indicator score ({phishing_score:.1f}/100)")

        # Brand impersonation is especially serious
        if _check("C06"):
            factors.append("Brand impersonation keyword in hostname")
        if _check("C03"):
            factors.append("IP-only URL (no domain)")

        # Correlation bonus – each triggered high-confidence rule adds +5 (cap +20)
        corr = correlation or {}
        triggered_rules = [
            r for r in (corr.get("relationships") or [])
            if r.get("triggered") and r.get("confidence") in ("high", "medium")
        ]
        corr_bonus = min(20.0, len(triggered_rules) * 5.0)
        if corr_bonus > 0:
            factors.append(f"{len(triggered_rules)} correlation rule(s) triggered (+{corr_bonus:.0f}pts)")

        # ── 4. Weighted Total ─────────────────────────────────────────────────
        weighted = (
            0.40 * rep_score
            + 0.30 * infra_score
            + 0.30 * phishing_score
            + corr_bonus
        )
        weighted = _clamp(weighted)

        # ── 5. Risk Label ─────────────────────────────────────────────────────
        if weighted <= 20:
            label = "Clean"
        elif weighted <= 40:
            label = "Low"
        elif weighted <= 60:
            label = "Medium"
        elif weighted <= 80:
            label = "High"
        else:
            label = "Critical"

        return InfraRiskBreakdown(
            reputation_score=round(rep_score, 1),
            infrastructure_score=round(infra_score, 1),
            phishing_score=round(phishing_score, 1),
            weighted_total=round(weighted, 1),
            risk_label=label,
            contributing_factors=factors,
        )
