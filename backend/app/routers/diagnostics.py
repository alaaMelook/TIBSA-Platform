"""
Diagnostics endpoints for VirusTotal + threat scoring (admin/debug).
"""
from __future__ import annotations

import logging
from typing import Any, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.config import settings
from app.dependencies import get_current_user
from app.services.ml_engine import MLEngine
from app.services.threat_scoring import compute_threat_score
from app.services.virustotal_service import (
    VirusTotalService,
    normalize_url_for_vt,
)

logger = logging.getLogger(__name__)
router = APIRouter()

DEFAULT_TEST_URLS = [
    "https://google.com",
    "https://microsoft.com",
    "https://github.com",
]


class VTDiagnosticRequest(BaseModel):
    urls: List[str] = Field(default_factory=lambda: list(DEFAULT_TEST_URLS))
    include_ai: bool = True


@router.post(
    "/vt-url-scan",
    summary="Diagnose VT URL scan + threat scoring for trusted URLs",
)
async def diagnose_vt_url_scan(
    body: VTDiagnosticRequest | None = None,
    current_user: dict = Depends(get_current_user),
):
    """
    Run the full VirusTotal workflow (or mock) and threat scoring for each URL.
    Returns raw VT payloads, verification metadata, and scoring breakdown.
    """
    _ = current_user
    body = body or VTDiagnosticRequest()

    api_key = settings.virustotal_api_key
    vt = VirusTotalService(api_key, demo_mode=settings.demo_mode)
    ml = MLEngine()

    results: list[dict[str, Any]] = []

    for raw_url in body.urls:
        submitted = normalize_url_for_vt(raw_url)
        entry: dict[str, Any] = {
            "input_url": raw_url,
            "submitted_url": submitted,
        }

        try:
            vt_diag = await vt.scan_url_diagnostic(raw_url)
            entry["virustotal_diagnostic"] = vt_diag

            vt_parsed = vt_diag.get("parsed_result") or vt_diag.get("mock_result") or {}
            if not vt_parsed and vt_diag.get("uses_mock_data"):
                vt_parsed = await vt.scan_url(raw_url)

            vt_malicious = int(vt_parsed.get("malicious", 0))
            vt_suspicious = int(vt_parsed.get("suspicious", 0))
            vt_total = int(vt_parsed.get("total_engines", 0))

            entry["virustotal_summary"] = {
                "malicious": vt_malicious,
                "suspicious": vt_suspicious,
                "total_engines": vt_total,
                "stats": vt_parsed.get("stats"),
                "analysis_id": vt_parsed.get("analysis_id"),
                "source": vt_parsed.get("source", "mock" if vt.uses_mock_data else "live"),
                "verification": vt_parsed.get("verification"),
            }

            if body.include_ai:
                ai = await ml.phishing_classifier(submitted)
                entry["ai_classifier"] = ai
                p_phish = ai.get("phishing_probability")
                threat_score, verdict, level, breakdown = compute_threat_score(
                    vt_malicious=vt_malicious,
                    vt_total=vt_total,
                    vt_suspicious=vt_suspicious,
                    ai_is_phishing=ai.get("is_phishing", False),
                    ai_confidence=ai.get("confidence", 0.0),
                    ai_phishing_probability=p_phish if ai.get("model_available") else None,
                    ai_model_available=ai.get("model_available", False),
                    url=submitted,
                )
                entry["threat_scoring"] = {
                    "threat_score": threat_score,
                    "verdict": verdict,
                    "threat_level": level,
                    "breakdown": breakdown,
                    "explanation": _scoring_explanation(breakdown, vt_malicious),
                }
        except Exception as exc:
            logger.exception("Diagnostic failed for %s", raw_url)
            entry["error"] = str(exc)

        results.append(entry)

    return {
        "demo_mode_setting": settings.demo_mode,
        "virustotal_uses_mock": vt.uses_mock_data,
        "has_api_key": bool(api_key),
        "results": results,
    }


def _scoring_explanation(breakdown: dict, vt_malicious: int) -> str:
    before = breakdown.get("weighted_score_before_override")
    after = breakdown.get("weighted_score")
    override = breakdown.get("override_applied")
    if override:
        return (
            f"Weighted score before override was {before}; "
            f"vt_malicious={vt_malicious} triggered override ({override}), "
            f"final score raised to {after}."
        )
    return f"No override applied; final weighted score is {after}."


@router.get("/vt-config", summary="Show VT integration mode (mock vs live)")
async def vt_config(current_user: dict = Depends(get_current_user)):
    _ = current_user
    api_key = settings.virustotal_api_key
    vt = VirusTotalService(api_key, demo_mode=settings.demo_mode)
    return {
        "demo_mode_setting": settings.demo_mode,
        "has_api_key": bool(api_key),
        "uses_mock_data": vt.uses_mock_data,
        "note": (
            "When an API key is present, URL scans use live VirusTotal even if "
            "DEMO_MODE=true. Mock data is only used when no API key is configured."
        ),
    }
