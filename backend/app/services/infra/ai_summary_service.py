"""
AI Summary Service – Stage 8 of the Infra Intelligence Pipeline.

Calls OpenRouter (configured in app.config.settings) with a structured
prompt synthesising all collected pipeline data into an analyst-grade report.

Output fields match the InfraAISummary schema:
  • executive_summary      – 2–3 sentence overview for non-technical stakeholders
  • threat_classification  – single-label category (e.g. "Phishing Infrastructure")
  • why_suspicious         – concise technical rationale
  • recommended_actions    – actionable bullet-point list
  • confidence             – 0.0–1.0 model self-reported confidence
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

import httpx

from app.config import settings
from app.schemas.infra_investigation import InfraAISummary

logger = logging.getLogger(__name__)

_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_TIMEOUT = httpx.Timeout(45.0, connect=8.0)


def _build_prompt(
    target: str,
    target_type: str,
    risk: Optional[Dict[str, Any]],
    indicators: Optional[Dict[str, Any]],
    correlation: Optional[Dict[str, Any]],
    reputation: Optional[Dict[str, Any]],
    enrichment: Optional[Dict[str, Any]],
) -> str:
    """Build a structured analyst prompt from pipeline results."""

    risk_label = (risk or {}).get("risk_label", "Unknown")
    risk_score = (risk or {}).get("weighted_total", 0)
    factors = (risk or {}).get("contributing_factors", [])
    phishing_score = (indicators or {}).get("phishing_score", 0)
    triggered_checks = [
        c["name"] for c in (indicators or {}).get("checks", []) if c.get("triggered")
    ]
    triggered_rules = [
        r["rule_name"] for r in (correlation or {}).get("relationships", []) if r.get("triggered")
    ]
    urlhaus_hit = (reputation or {}).get("urlhaus", {})
    urlhaus_listed = isinstance(urlhaus_hit, dict) and urlhaus_hit.get("query_status") == "is_listed"
    otx_pulses = (reputation or {}).get("otx", {})
    pulse_count = (otx_pulses or {}).get("pulse_count", 0) if isinstance(otx_pulses, dict) else 0
    whois = (enrichment or {}).get("whois") or {}
    domain_age = whois.get("domain_age_days")
    newly_reg = whois.get("is_newly_registered", False)
    registrar = whois.get("registrar", "Unknown")

    context_block = f"""
TARGET: {target} (type: {target_type})
RISK SCORE: {risk_score}/100 — {risk_label}
PHISHING SCORE: {phishing_score}/100
TRIGGERED INDICATOR CHECKS: {', '.join(triggered_checks) or 'None'}
TRIGGERED CORRELATION RULES: {', '.join(triggered_rules) or 'None'}
URLHAUS BLACKLISTED: {urlhaus_listed}
OTX PULSE COUNT: {pulse_count}
DOMAIN AGE (DAYS): {domain_age if domain_age is not None else 'N/A'}
NEWLY REGISTERED: {newly_reg}
REGISTRAR: {registrar}
CONTRIBUTING RISK FACTORS: {'; '.join(factors) or 'None detected'}
""".strip()

    return (
        "You are a senior threat intelligence analyst at a cybersecurity operations centre.\n"
        "Analyse the following infrastructure intelligence data and produce a JSON object "
        "with EXACTLY these keys:\n"
        "  \"executive_summary\"    : 2-3 sentence summary for a non-technical manager\n"
        "  \"threat_classification\": single label such as 'Phishing Infrastructure', "
        "'C2 Server', 'Benign', 'Malware Distribution', 'Spam Infrastructure', "
        "'Unknown / Insufficient Data'\n"
        "  \"why_suspicious\"       : concise technical rationale (≤ 100 words)\n"
        "  \"recommended_actions\"  : JSON array of 3-5 actionable strings\n"
        "  \"confidence\"           : float 0.0-1.0 representing your certainty\n\n"
        "Return ONLY valid JSON. Do not include markdown fences or extra text.\n\n"
        "--- INTELLIGENCE DATA ---\n"
        + context_block
    )


class AISummaryService:
    """Generates an AI-written analyst report via OpenRouter."""

    @staticmethod
    async def generate(
        target: str,
        target_type: str,
        risk: Optional[Dict[str, Any]],
        indicators: Optional[Dict[str, Any]],
        correlation: Optional[Dict[str, Any]],
        reputation: Optional[Dict[str, Any]],
        enrichment: Optional[Dict[str, Any]],
    ) -> InfraAISummary:
        api_key = settings.openrouter_api_key
        if not api_key:
            return InfraAISummary(error="OpenRouter API key not configured.")

        prompt = _build_prompt(
            target, target_type, risk, indicators, correlation, reputation, enrichment
        )
        model = getattr(settings, "openrouter_model", "openrouter/auto")

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    _OPENROUTER_URL,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": getattr(settings, "openrouter_max_tokens", 800),
                        "temperature": 0.2,
                    },
                )
                resp.raise_for_status()
                raw = resp.json()

            # v2 — Nemotron/reasoning models return content=None; text is in 'reasoning' field
            choice = (raw.get("choices") or [{}])[0]
            message = choice.get("message") or {}
            content = (
                message.get("content")
                or message.get("reasoning")
                or message.get("refusal")
                or ""
            )
            content = content.strip() if content else ""

            if not content:
                logger.warning("[AI] Model returned empty content. Full response: %s", raw)
                return InfraAISummary(
                    error="AI model returned an empty response. Try re-running the investigation."
                )

            # Strip markdown fences if present
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            content = content.strip()

            parsed = json.loads(content)
            actions = parsed.get("recommended_actions", [])
            if isinstance(actions, str):
                actions = [actions]

            return InfraAISummary(
                executive_summary=parsed.get("executive_summary", ""),
                threat_classification=parsed.get("threat_classification", "Unknown"),
                why_suspicious=parsed.get("why_suspicious", ""),
                recommended_actions=actions[:8],
                confidence=float(parsed.get("confidence", 0.5)),
            )

        except json.JSONDecodeError as exc:
            logger.warning("[AI] JSON parse error: %s\nContent was: %s", exc, content[:300] if 'content' in dir() else "N/A")
            return InfraAISummary(error=f"AI response was not valid JSON: {exc}")
        except Exception as exc:
            logger.warning("[AI] OpenRouter error: %s", exc)
            return InfraAISummary(error=str(exc))
