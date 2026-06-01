"""
Cybersecurity URL Threat Analyst Engine.

Combines VirusTotal URL results + heuristic URL feature analysis to classify:
  classification: Phishing | Malicious | Suspicious | Legitimate
  confidence: 0-100
  risk_level: Critical | High | Medium | Low | None
  explanation: brief reasoning
  signals: list of detected indicators

Rules:
  - Don't rely solely on VirusTotal
  - Combine heuristic + intelligence
  - Detect obfuscation techniques
  - Check domain reputation signals
  - Consider behavioral indicators
"""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Suspicious TLDs frequently used in phishing ──────────────────────────────
SUSPICIOUS_TLDS = frozenset([
    "xyz", "top", "club", "work", "buzz", "gq", "ml", "cf", "ga", "tk",
    "icu", "rest", "surf", "monster", "click", "link", "info", "biz",
    "online", "site", "live", "win", "loan", "racing", "review",
])

# ── Brand keywords commonly impersonated ─────────────────────────────────────
BRAND_KEYWORDS = frozenset([
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "telegram", "bank", "chase",
    "wellsfargo", "citibank", "hsbc", "dropbox", "icloud", "outlook",
    "linkedin", "twitter", "coinbase", "binance", "metamask",
])

# ── Obfuscation patterns ─────────────────────────────────────────────────────
_HEX_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")
_PUNYCODE_RE = re.compile(r"xn--")
_DATA_URI_RE = re.compile(r"^data:", re.IGNORECASE)
_IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass
class URLAnalysisResult:
    classification: str   # Phishing | Malicious | Suspicious | Legitimate
    confidence: int       # 0-100
    risk_level: str       # Critical | High | Medium | Low | None
    explanation: str
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "explanation": self.explanation,
            "signals": self.signals,
        }


def _extract_heuristic_signals(url: str) -> tuple[list[str], float]:
    """Extract heuristic signals and return (signals, risk_score 0.0-1.0)."""
    signals: list[str] = []
    score = 0.0

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        signals.append("URL parsing failed — malformed URL")
        return signals, 0.7

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()

    # HTTPS check
    if parsed.scheme == "http":
        signals.append("No HTTPS — unencrypted connection")
        score += 0.05

    # IP address as hostname
    if _IP_HOST_RE.match(hostname):
        signals.append("IP address used as hostname")
        score += 0.25

    # Suspicious TLD
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        signals.append(f"Suspicious TLD: .{tld}")
        score += 0.15

    # URL length (phishing URLs tend to be very long)
    if len(url) > 150:
        signals.append(f"Unusually long URL ({len(url)} chars)")
        score += 0.1
    elif len(url) > 100:
        score += 0.05

    # Subdomain depth
    parts = hostname.split(".")
    if len(parts) > 4:
        signals.append(f"Deep subdomain nesting ({len(parts)} levels)")
        score += 0.15

    # @ symbol in URL (credential harvesting trick)
    if "@" in full:
        signals.append("@ symbol in URL — possible credential trick")
        score += 0.2

    # Hex encoding density
    hex_count = len(_HEX_ENCODED_RE.findall(full))
    if hex_count > 5:
        signals.append(f"Heavy URL encoding ({hex_count} encoded chars)")
        score += 0.15

    # Punycode / IDN homograph
    if _PUNYCODE_RE.search(hostname):
        signals.append("Punycode domain (IDN homograph risk)")
        score += 0.2

    # Data URI
    if _DATA_URI_RE.match(url):
        signals.append("Data URI scheme — obfuscation technique")
        score += 0.3

    # Brand impersonation
    for brand in BRAND_KEYWORDS:
        if brand in hostname and brand not in hostname.split(".")[-2:-1]:
            signals.append(f"Brand keyword '{brand}' in subdomain (impersonation risk)")
            score += 0.2
            break

    # Multiple hyphens (common in DGA / phishing)
    if hostname.count("-") >= 3:
        signals.append(f"Multiple hyphens in hostname ({hostname.count('-')})")
        score += 0.1

    # Non-standard port
    if parsed.port and parsed.port not in (80, 443, None):
        signals.append(f"Non-standard port: {parsed.port}")
        score += 0.1

    # Path contains suspicious keywords
    path_lower = path.lower()
    phish_paths = ["login", "signin", "verify", "account", "secure", "update",
                   "confirm", "password", "credential", "suspend", "alert"]
    found_paths = [kw for kw in phish_paths if kw in path_lower]
    if found_paths:
        signals.append(f"Suspicious path keywords: {', '.join(found_paths)}")
        score += 0.1 * min(len(found_paths), 3)

    return signals, min(1.0, score)


def analyze_url(
    url: str,
    vt_data: dict[str, Any] | None,
    ai_data: dict[str, Any] | None,
) -> URLAnalysisResult:
    """
    Multi-layer URL threat analysis.

    Parameters
    ----------
    url : str
        The target URL being analyzed.
    vt_data : dict | None
        VirusTotal URL scan result.
    ai_data : dict | None
        AI phishing classifier result from MLEngine.
    """
    signals: list[str] = []
    reasons: list[str] = []

    # ── Layer 1: Heuristic URL analysis ───────────────────────────────────
    heuristic_signals, heuristic_score = _extract_heuristic_signals(url)
    signals.extend(heuristic_signals)

    # ── Layer 2: VirusTotal intelligence ──────────────────────────────────
    vt_score = 0.0
    vt_available = vt_data is not None and not vt_data.get("error")
    if vt_available:
        vt_mal = vt_data.get("malicious", 0)
        vt_sus = vt_data.get("suspicious", 0)
        vt_total = vt_data.get("total_engines", 0)

        if vt_total > 0:
            vt_ratio = (vt_mal + vt_sus) / vt_total
            vt_score = vt_ratio
            if vt_mal > 0:
                signals.append(f"VT: {vt_mal}/{vt_total} flagged malicious")
            if vt_sus > 0:
                signals.append(f"VT: {vt_sus} engines suspicious")

            # Check for phishing-specific VT categories
            vt_level = vt_data.get("threat_level", "clean")
            if vt_level in ("high", "medium"):
                signals.append(f"VT threat level: {vt_level}")

    # ── Layer 3: AI phishing classifier ───────────────────────────────────
    ai_score = 0.0
    ai_available = ai_data is not None and ai_data.get("model_available", ai_data.get("model") != "model_not_loaded")
    if ai_available:
        is_phishing = ai_data.get("is_phishing", False)
        p_phishing = ai_data.get("phishing_probability")
        if p_phishing is None:
            # Legacy format: confidence stored raw P(phishing)
            p_phishing = ai_data.get("confidence", 0.0)
        ai_score = min(1.0, max(0.0, float(p_phishing)))
        p_safe = 1.0 - ai_score
        if is_phishing:
            signals.append(f"AI: classified as phishing ({ai_score:.1%} probability)")
        else:
            signals.append(f"AI: classified as safe ({p_safe:.1%} confidence)")

    # ── Weighted combination ──────────────────────────────────────────────
    # Weights: Heuristic 20%, VT 50%, AI 30% (VT-dominant, aligned with primary scorer)
    weights = []
    scores = []

    weights.append(0.20)
    scores.append(heuristic_score)

    if vt_available:
        weights.append(0.50)
        scores.append(vt_score)

    if ai_available:
        weights.append(0.30)
        scores.append(ai_score)

    # Normalize weights
    total_weight = sum(weights)
    combined = sum(w * s for w, s in zip(weights, scores)) / total_weight if total_weight > 0 else heuristic_score

    # ── Classification ────────────────────────────────────────────────────
    vt_mal_count = vt_data.get("malicious", 0) if vt_available else 0
    ai_phishing = ai_data.get("is_phishing", False) if ai_available else False

    if combined >= 0.70 or vt_mal_count >= 10:
        if ai_phishing and heuristic_score >= 0.3:
            classification = "Phishing"
            reasons.append("Multiple layers confirm phishing indicators")
        else:
            classification = "Malicious"
            reasons.append("High threat score from combined analysis")
        risk_level = "Critical" if combined >= 0.8 else "High"
        confidence = min(98, int(60 + combined * 40))

    elif combined >= 0.45 or vt_mal_count >= 3:
        if ai_phishing:
            classification = "Phishing"
            reasons.append("AI flagged phishing with supporting signals")
        else:
            classification = "Suspicious"
            reasons.append("Moderate threat indicators detected")
        risk_level = "High" if combined >= 0.55 else "Medium"
        confidence = min(90, int(45 + combined * 60))

    elif combined >= 0.20:
        classification = "Suspicious"
        risk_level = "Medium" if combined >= 0.30 else "Low"
        confidence = min(75, int(35 + combined * 80))
        reasons.append("Some risk indicators present — proceed with caution")

    else:
        classification = "Legitimate"
        risk_level = "None"
        confidence = min(95, int(70 + (1 - combined) * 30))
        reasons.append("No significant threats detected across all layers")

    explanation = ". ".join(reasons)
    signals.append(
        f"Combined score: {combined:.2f} "
        f"(Heuristic={heuristic_score:.2f}"
        f"{f', VT={vt_score:.2f}' if vt_available else ''}"
        f"{f', AI={ai_score:.2f}' if ai_available else ''})"
    )

    return URLAnalysisResult(
        classification=classification,
        confidence=confidence,
        risk_level=risk_level,
        explanation=explanation,
        signals=signals,
    )
