"""
Threat-scoring helper.

Combines VirusTotal results with AI phishing model predictions into
a single threat score, verdict, and threat level.

Scoring policy (security-first):
  - VirusTotal weight: 70%
  - AI model weight:    30%
  - Brand-impersonation lexical rules never allow a CLEAN verdict when
    suspicious TLD + brand keyword are present (minimum MEDIUM).
"""

from __future__ import annotations

import logging
from typing import Any

from app.services.phishing_features import assess_brand_impersonation

logger = logging.getLogger(__name__)

VT_WEIGHT = 0.70
AI_WEIGHT = 0.30

OVERRIDE_MALICIOUS_HIGH = 10
OVERRIDE_MALICIOUS_MEDIUM = 3
OVERRIDE_WEIGHTED_HIGH = 0.65
OVERRIDE_WEIGHTED_MEDIUM = 0.40
OVERRIDE_WEIGHTED_LOW = 0.20

# Brand impersonation floors
BRAND_IMPERSONATION_MIN_SCORE = 0.50
BRAND_IMPERSONATION_CREDENTIAL_MIN_SCORE = 0.65


def _normalize_vt_score(
    vt_malicious: int,
    vt_suspicious: int,
    vt_total: int,
) -> float:
    if vt_total <= 0:
        return 0.0
    weighted_hits = vt_malicious + (vt_suspicious * 0.5)
    return min(1.0, weighted_hits / vt_total)


def _normalize_ai_score(phishing_probability: float | None) -> float | None:
    if phishing_probability is None:
        return None
    return min(1.0, max(0.0, float(phishing_probability)))


def _apply_brand_impersonation_floors(
    url: str | None,
    threat_score: float,
    verdict: str,
    final_level: str,
    breakdown: dict[str, Any],
) -> tuple[float, str, str, str | None]:
    """Enforce minimum verdict/score for brand-impersonation typosquats."""
    if not url:
        return threat_score, verdict, final_level, None

    brand_meta = assess_brand_impersonation(url)
    breakdown["brand_impersonation"] = brand_meta

    if not brand_meta.get("is_brand_impersonation"):
        return threat_score, verdict, final_level, None

    override_reason: str | None = None
    suspicious_tld = bool(brand_meta.get("suspicious_tld"))
    has_cred = bool(
        brand_meta.get("contains_login_keyword")
        or brand_meta.get("contains_verify_keyword")
        or brand_meta.get("contains_account_keyword")
    )

    if suspicious_tld and final_level == "clean":
        final_level = "medium"
        verdict = "Suspicious"
        threat_score = max(threat_score, BRAND_IMPERSONATION_MIN_SCORE)
        override_reason = "brand_impersonation+suspicious_tld:min_medium"

    if has_cred:
        threat_score = max(threat_score, BRAND_IMPERSONATION_CREDENTIAL_MIN_SCORE)
        if verdict == "Clean" or final_level == "clean":
            verdict = "Suspicious"
            final_level = "medium"
        elif threat_score >= 0.80:
            verdict = "Malicious"
            final_level = "high"
        override_reason = override_reason or "brand_impersonation+credential_keywords"

    if suspicious_tld and has_cred and threat_score < 0.80:
        threat_score = max(threat_score, BRAND_IMPERSONATION_CREDENTIAL_MIN_SCORE)
        verdict = "Suspicious"
        final_level = "medium"
        override_reason = override_reason or "brand_impersonation+tld+credentials"

    return threat_score, verdict, final_level, override_reason


def compute_threat_score(
    vt_malicious: int,
    vt_total: int,
    ai_is_phishing: bool,
    ai_confidence: float,
    *,
    vt_suspicious: int = 0,
    ai_phishing_probability: float | None = None,
    ai_model_available: bool = True,
    url: str | None = None,
) -> tuple[float, str, str, dict[str, Any]]:
    """Combine VirusTotal and AI phishing results into a single threat score."""
    vt_score = _normalize_vt_score(vt_malicious, vt_suspicious, vt_total)

    if ai_phishing_probability is not None:
        ai_score = _normalize_ai_score(ai_phishing_probability)
    elif ai_model_available:
        ai_score = _normalize_ai_score(ai_confidence)
    else:
        ai_score = None

    vt_available = vt_total > 0
    ai_available = ai_model_available and ai_score is not None

    if vt_available and ai_available:
        weighted_before_override = (VT_WEIGHT * vt_score) + (AI_WEIGHT * ai_score)
        vt_weight_used = VT_WEIGHT
        ai_weight_used = AI_WEIGHT
    elif vt_available:
        weighted_before_override = vt_score
        vt_weight_used = 1.0
        ai_weight_used = 0.0
    elif ai_available:
        weighted_before_override = ai_score
        vt_weight_used = 0.0
        ai_weight_used = 1.0
    else:
        weighted_before_override = 0.0
        vt_weight_used = 0.0
        ai_weight_used = 0.0

    threat_score = weighted_before_override
    verdict = "Clean"
    final_level = "clean"
    override_applied: str | None = None

    if vt_malicious >= OVERRIDE_MALICIOUS_HIGH or threat_score >= OVERRIDE_WEIGHTED_HIGH:
        verdict = "Malicious"
        final_level = "high"
        if threat_score < 0.80:
            override_applied = (
                f"raised_to_0.80: vt_malicious>={OVERRIDE_MALICIOUS_HIGH} "
                f"or weighted>={OVERRIDE_WEIGHTED_HIGH}"
            )
        threat_score = max(threat_score, 0.80)
    elif vt_malicious >= OVERRIDE_MALICIOUS_MEDIUM or threat_score >= OVERRIDE_WEIGHTED_MEDIUM:
        verdict = "Suspicious"
        final_level = "medium"
        if threat_score < 0.50:
            override_applied = (
                f"raised_to_0.50: vt_malicious>={OVERRIDE_MALICIOUS_MEDIUM} "
                f"or weighted>={OVERRIDE_WEIGHTED_MEDIUM}"
            )
        threat_score = max(threat_score, 0.50)
    elif threat_score >= OVERRIDE_WEIGHTED_LOW:
        verdict = "Warning"
        final_level = "low"
    else:
        verdict = "Clean"
        final_level = "clean"

    breakdown: dict[str, Any] = {
        "vt_score": round(vt_score, 4),
        "ai_score": round(ai_score, 4) if ai_score is not None else None,
        "vt_weight": vt_weight_used,
        "ai_weight": ai_weight_used,
        "weighted_score_before_override": round(weighted_before_override, 4),
        "weighted_score": round(threat_score, 4),
        "override_applied": override_applied,
        "vt_malicious": vt_malicious,
        "vt_suspicious": vt_suspicious,
        "vt_total": vt_total,
        "ai_phishing_probability": (
            round(ai_phishing_probability, 4)
            if ai_phishing_probability is not None
            else (round(ai_score, 4) if ai_score is not None else None)
        ),
        "ai_model_available": ai_model_available,
        "override_rules": {
            "malicious_high": OVERRIDE_MALICIOUS_HIGH,
            "malicious_medium": OVERRIDE_MALICIOUS_MEDIUM,
            "weighted_high": OVERRIDE_WEIGHTED_HIGH,
            "weighted_medium": OVERRIDE_WEIGHTED_MEDIUM,
        },
    }

    threat_score, verdict, final_level, brand_override = _apply_brand_impersonation_floors(
        url, threat_score, verdict, final_level, breakdown
    )
    if brand_override:
        prev = breakdown.get("override_applied")
        breakdown["override_applied"] = f"{prev}; {brand_override}" if prev else brand_override
        breakdown["weighted_score"] = round(threat_score, 4)

    logger.info(
        "Threat score: vt=%.4f (mal=%d sus=%d total=%d) ai=%s "
        "weighted_before=%.4f weighted_final=%.4f override=%s → %s (%s)",
        vt_score,
        vt_malicious,
        vt_suspicious,
        vt_total,
        f"{ai_score:.4f}" if ai_score is not None else "N/A",
        weighted_before_override,
        threat_score,
        breakdown.get("override_applied") or "none",
        verdict,
        final_level,
    )

    return threat_score, verdict, final_level, breakdown
