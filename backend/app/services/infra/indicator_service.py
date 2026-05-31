"""
Threat Indicator Service – Stage 5 of the Infra Intelligence Pipeline.

Runs a battery of deterministic heuristic checks against the enrichment
data collected in stages 2–4 and produces:
  • A list of ThreatIndicatorCheck objects (triggered / not triggered)
  • A composite phishing_score (0–100)
  • A count of triggered checks

Checks cover:
  - Suspicious TLD
  - Newly registered domain (< 90 days)
  - IP-only URL (no domain)
  - High-entropy domain name
  - Long subdomain chain
  - Known brand impersonation keyword
  - Numeric-heavy domain
  - Sensitive URL path keywords
  - Expired or self-signed SSL certificate
  - SSL CN mismatch
  - High AbuseIPDB confidence score
  - URLhaus blacklist hit
  - ThreatFox IOC match
  - OTX pulse attribution
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional

from app.schemas.infra_investigation import (
    ThreatIndicatorCheck,
    ThreatIndicatorsResult,
)

# ─── Brand keyword list for impersonation detection ───────────────────────────
BRAND_KEYWORDS = {
    "paypal", "google", "facebook", "amazon", "apple", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "ebay", "bank",
    "wellsfargo", "chase", "citibank", "barclays", "hsbc", "irs",
    "binance", "coinbase", "blockchain", "metamask", "trustwallet",
    "dropbox", "onedrive", "icloud", "steam", "discord", "whatsapp",
}

# ─── Suspicious TLDs ──────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "click", "link", "loan",
    "win", "bid", "trade", "work", "review",
    "accountant", "stream", "download", "zip", "mov",
    "ru", "cn",  # flagged for context, lower severity
}

# ─── Sensitive URL path keywords ──────────────────────────────────────────────
SENSITIVE_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "secure", "account", "password", "credential", "update",
    "confirm", "wallet", "billing", "checkout", "bank",
    "paypal", "authenticate", "auth", "access",
]


def _domain_entropy(domain: str) -> float:
    """Shannon entropy of a domain string (higher = more random = suspicious)."""
    freq: Dict[str, int] = {}
    for ch in domain:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(domain)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class IndicatorService:
    """
    Evaluates threat indicator checks and computes a composite phishing score.

    All inputs are optional so the service degrades gracefully when upstream
    stages partially fail.
    """

    def run(
        self,
        target: str,
        target_type: str,
        hostname: str,
        whois: Optional[Dict[str, Any]] = None,
        ssl_cert: Optional[Dict[str, Any]] = None,
        reputation: Optional[Dict[str, Any]] = None,
    ) -> ThreatIndicatorsResult:
        checks: List[ThreatIndicatorCheck] = []

        # Helper to add a check
        def add(
            check_id: str,
            name: str,
            description: str,
            triggered: bool,
            severity: str,
            detail: Optional[str] = None,
        ) -> None:
            checks.append(
                ThreatIndicatorCheck(
                    id=check_id,
                    name=name,
                    description=description,
                    triggered=triggered,
                    severity=severity,
                    detail=detail if triggered else None,
                )
            )

        # ── C01: Suspicious TLD ───────────────────────────────────────────────
        tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname else ""
        is_sus_tld = tld in SUSPICIOUS_TLDS
        add(
            "C01", "Suspicious TLD",
            "Domain uses a TLD commonly associated with free/abused registrations.",
            is_sus_tld, "high" if tld in {"tk","ml","ga","cf","gq"} else "medium",
            f"TLD '.{tld}' is in the suspicious list." if is_sus_tld else None,
        )

        # ── C02: Newly Registered Domain ─────────────────────────────────────
        age_days: Optional[int] = (whois or {}).get("domain_age_days")
        newly_reg = (whois or {}).get("is_newly_registered", False)
        add(
            "C02", "Newly Registered Domain",
            "Domain was registered fewer than 90 days ago — high phishing risk.",
            bool(newly_reg), "high",
            f"Domain is only {age_days} day(s) old." if newly_reg and age_days is not None else None,
        )

        # ── C03: IP-Only URL ──────────────────────────────────────────────────
        is_ip_url = target_type == "url" and re.search(
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", target
        )
        add(
            "C03", "IP-Only URL",
            "URL uses a raw IP address instead of a domain name.",
            bool(is_ip_url), "high",
            f"URL resolves directly to an IP: {target}" if is_ip_url else None,
        )

        # ── C04: High-Entropy Domain ──────────────────────────────────────────
        # Use the registered-domain part only (strip subdomains)
        parts = hostname.split(".")
        domain_part = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        entropy = _domain_entropy(domain_part.split(".")[0])  # just the SLD
        high_entropy = entropy > 3.8
        add(
            "C04", "High-Entropy Domain Name",
            "Domain label has high Shannon entropy, typical of DGA or random-name abuse.",
            high_entropy, "medium",
            f"Entropy of '{domain_part.split('.')[0]}' = {entropy:.2f} (threshold 3.8)."
            if high_entropy else None,
        )

        # ── C05: Long Subdomain Chain ─────────────────────────────────────────
        subdomain_depth = max(0, len(hostname.split(".")) - 2)
        deep_subdomains = subdomain_depth >= 4
        add(
            "C05", "Deep Subdomain Chain",
            "Target has 4+ subdomain levels — common in phishing kits.",
            deep_subdomains, "medium",
            f"{subdomain_depth} subdomain levels detected." if deep_subdomains else None,
        )

        # ── C06: Brand Impersonation ──────────────────────────────────────────
        full_lower = hostname.lower().replace("-", "").replace(".", "")
        matched_brand = next(
            (b for b in BRAND_KEYWORDS if b in full_lower and b != full_lower), None
        )
        add(
            "C06", "Brand Impersonation Keyword",
            "Target hostname contains a well-known brand name, suggesting impersonation.",
            bool(matched_brand), "critical",
            f"Detected brand keyword '{matched_brand}' in '{hostname}'."
            if matched_brand else None,
        )

        # ── C07: Numeric-Heavy Domain ─────────────────────────────────────────
        sld = domain_part.split(".")[0]
        digit_ratio = sum(c.isdigit() for c in sld) / max(len(sld), 1)
        numeric_heavy = digit_ratio > 0.45
        add(
            "C07", "Numeric-Heavy Domain",
            "More than 45% of the domain label consists of digits.",
            numeric_heavy, "low",
            f"Digit ratio: {digit_ratio:.0%} in '{sld}'." if numeric_heavy else None,
        )

        # ── C08: Sensitive URL Path Keywords ─────────────────────────────────
        url_path = ""
        if target_type in ("url",):
            from urllib.parse import urlparse
            try:
                url_path = urlparse(target).path.lower()
            except Exception:
                pass
        matched_path_kw = next(
            (kw for kw in SENSITIVE_PATH_KEYWORDS if kw in url_path), None
        )
        add(
            "C08", "Sensitive URL Path Keyword",
            "URL path contains a keyword associated with credential-harvesting pages.",
            bool(matched_path_kw), "high",
            f"Found '{matched_path_kw}' in path '{url_path}'." if matched_path_kw else None,
        )

        # ── C09: Expired SSL Certificate ─────────────────────────────────────
        ssl_expired = (ssl_cert or {}).get("is_expired", False)
        add(
            "C09", "Expired SSL Certificate",
            "The server's TLS certificate has passed its expiration date.",
            bool(ssl_expired), "high",
            f"Certificate expired on: {(ssl_cert or {}).get('not_after')}"
            if ssl_expired else None,
        )

        # ── C10: Self-Signed Certificate ─────────────────────────────────────
        ssl_self = (ssl_cert or {}).get("is_self_signed", False)
        add(
            "C10", "Self-Signed Certificate",
            "Certificate issuer matches the subject — self-signed, not CA-validated.",
            bool(ssl_self), "medium",
            f"Subject CN = Issuer CN = '{(ssl_cert or {}).get('subject_cn')}'."
            if ssl_self else None,
        )

        # ── C11: SSL CN Mismatch ──────────────────────────────────────────────
        subject_cn = (ssl_cert or {}).get("subject_cn") or ""
        san_domains = (ssl_cert or {}).get("san_domains") or []
        cn_match = (
            hostname in subject_cn
            or subject_cn.lstrip("*.") == hostname
            or any(hostname.endswith(s.lstrip("*.")) for s in san_domains)
        )
        ssl_available = bool(ssl_cert and not (ssl_cert or {}).get("error"))
        cn_mismatch = ssl_available and not cn_match
        add(
            "C11", "SSL CN Mismatch",
            "The certificate's Common Name does not match the queried hostname.",
            cn_mismatch, "high",
            f"Hostname '{hostname}' ≠ cert CN '{subject_cn}'." if cn_mismatch else None,
        )

        # ── C12: AbuseIPDB High Confidence ───────────────────────────────────
        abuse_score = (reputation or {}).get("abuseipdb", {})
        if isinstance(abuse_score, dict):
            conf_score = abuse_score.get("abuse_confidence_score", 0)
        else:
            conf_score = 0
        high_abuse = conf_score >= 50
        add(
            "C12", "AbuseIPDB High Confidence Score",
            "IP has an AbuseIPDB confidence score ≥ 50, indicating active abuse reports.",
            high_abuse, "critical" if conf_score >= 80 else "high",
            f"Confidence score: {conf_score}/100." if high_abuse else None,
        )

        # ── C13: URLhaus Blacklist Hit ────────────────────────────────────────
        urlhaus_data = (reputation or {}).get("urlhaus", {})
        if isinstance(urlhaus_data, dict):
            urlhaus_hit = urlhaus_data.get("query_status") == "is_listed"
        else:
            urlhaus_hit = False
        add(
            "C13", "URLhaus Malware Blacklist",
            "Target host is listed in the URLhaus malware URL database.",
            urlhaus_hit, "critical",
            "Host appears in the URLhaus malware URL blacklist." if urlhaus_hit else None,
        )

        # ── C14: ThreatFox IOC Match ──────────────────────────────────────────
        threatfox_data = (reputation or {}).get("threatfox", {})
        if isinstance(threatfox_data, dict):
            tf_iocs = threatfox_data.get("iocs") or []
            tf_hit = len(tf_iocs) > 0
        else:
            tf_hit = False
        add(
            "C14", "ThreatFox IOC Match",
            "Target matches one or more IOCs in the ThreatFox threat-intelligence database.",
            tf_hit, "critical",
            f"Found {len(tf_iocs) if tf_hit else 0} matching IOC(s) in ThreatFox."
            if tf_hit else None,
        )

        # ── C15: OTX Pulse Attribution ────────────────────────────────────────
        otx_data = (reputation or {}).get("otx", {})
        if isinstance(otx_data, dict):
            otx_pulses = otx_data.get("pulse_count", 0)
            otx_hit = otx_pulses > 0
        else:
            otx_hit = False
            otx_pulses = 0
        add(
            "C15", "OTX Threat Pulse Attribution",
            "Target appears in AlienVault OTX threat pulses authored by the community.",
            otx_hit, "high" if otx_pulses >= 3 else "medium",
            f"Attributed to {otx_pulses} OTX pulse(s)." if otx_hit else None,
        )

        # ── Phishing Score ────────────────────────────────────────────────────
        severity_weights = {
            "critical": 25.0,
            "high": 15.0,
            "medium": 8.0,
            "low": 3.0,
            "info": 0.5,
        }
        raw_score = sum(
            severity_weights.get(c.severity, 0)
            for c in checks
            if c.triggered
        )
        # Normalize to 0–100 (max possible ≈ 2 critical + 5 high + 5 medium = 145)
        phishing_score = round(min(100.0, raw_score / 1.45), 1)
        triggered = [c for c in checks if c.triggered]

        return ThreatIndicatorsResult(
            checks=checks,
            phishing_score=phishing_score,
            total_triggered=len(triggered),
        )
