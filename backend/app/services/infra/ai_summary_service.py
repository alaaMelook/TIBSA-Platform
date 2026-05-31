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

    # ── AbuseIPDB Details ──
    abuseipdb_hit = (reputation or {}).get("abuseipdb", {})
    abuse_details = "N/A"
    if isinstance(abuseipdb_hit, dict) and abuseipdb_hit.get("abuse_confidence_score", 0) > 0:
        score = abuseipdb_hit.get("abuse_confidence_score", 0)
        reports = abuseipdb_hit.get("total_reports", 0)
        country = abuseipdb_hit.get("country_code", "Unknown")
        isp = abuseipdb_hit.get("isp", "Unknown")
        abuse_details = f"Abuse Confidence Score: {score}%, Total Reports: {reports}, Country: {country}, ISP: {isp}"

    # ── URLhaus Details ──
    urlhaus_hit = (reputation or {}).get("urlhaus", {})
    urlhaus_listed = isinstance(urlhaus_hit, dict) and urlhaus_hit.get("query_status") == "is_listed"
    urlhaus_details = "N/A"
    if urlhaus_listed:
        urls_on_host = urlhaus_hit.get("urls_on_this_host") or []
        url_items = []
        for u in urls_on_host[:5]:
            url_items.append(f"URL: {u.get('url')} (Threat: {u.get('threat')}, Status: {u.get('url_status')})")
        urlhaus_details = f"Listed (Active threats matching on this host:\n" + "\n".join(url_items) + ")"

    # ── ThreatFox Details ──
    threatfox_hit = (reputation or {}).get("threatfox", {})
    threatfox_iocs = []
    if isinstance(threatfox_hit, dict) and threatfox_hit.get("query_status") == "ok":
        threatfox_iocs = threatfox_hit.get("iocs") or []
    threatfox_details = "None matched"
    if threatfox_iocs:
        tf_items = []
        for ioc in threatfox_iocs[:10]:
            malware = ioc.get("malware_printable") or ioc.get("malware") or "Unknown malware"
            threat_type = ioc.get("threat_type") or "Unknown threat type"
            confidence = ioc.get("confidence_level") or 0
            tf_items.append(f"- Malware: {malware} (Type: {threat_type}, Confidence: {confidence}%)")
        threatfox_details = "\n".join(tf_items)

    # ── AlienVault OTX Details ──
    otx_pulses = (reputation or {}).get("otx", {})
    pulse_count = (otx_pulses or {}).get("pulse_count", 0) if isinstance(otx_pulses, dict) else 0
    otx_details = "None matched"
    if isinstance(otx_pulses, dict) and pulse_count > 0:
        pulses = otx_pulses.get("pulses") or []
        otx_items = []
        for p in pulses[:5]:
            p_name = p.get("name", "Unnamed pulse")
            p_malware = ", ".join(p.get("malware_families") or [])
            if p_malware:
                otx_items.append(f"- Pulse Name: {p_name} (Malware Family: {p_malware})")
            else:
                otx_items.append(f"- Pulse Name: {p_name}")
        otx_details = "\n".join(otx_items)

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

[REPUTATION INTELLIGENCE]
ABUSEIPDB: {abuse_details}
URLHAUS BLACKLISTED: {urlhaus_listed}
URLHAUS THREAT DETAILS: {urlhaus_details}
THREATFOX IOC MATCHES:
{threatfox_details}
OTX PULSE COUNT: {pulse_count}
OTX PULSES DETAILS:
{otx_details}

[WHOIS & DOMAIN ENRICHMENT]
DOMAIN AGE (DAYS): {domain_age if domain_age is not None else 'N/A'}
NEWLY REGISTERED: {newly_reg}
REGISTRAR: {registrar}

[RISK ENGINE FACTORS]
CONTRIBUTING RISK FACTORS: {'; '.join(factors) or 'None detected'}
""".strip()

    return (
        "You are an expert security analyst and threat intelligence researcher. "
        "Review the target and the provided reputation database context to generate a comprehensive, highly detailed analyst report. "
        "Your report must be returned as a valid JSON object containing exactly the following keys, with no markdown styling around the JSON, and no explanation text before or after the JSON:\n"
        '  "executive_summary": A detailed, high-level summary of the threat findings and potential organizational impact (2 to 4 sentences, 60-100 words). Do not use placeholders or generic sentences. State the classification and risk level clearly.\n'
        '  "threat_classification": Categorise the threat. Must be one of: Benign | Phishing Infrastructure | C2 Server | Malware Distribution | Spam Infrastructure | Unknown\n'
        '  "why_suspicious": A detailed, technical analysis of why this target was flagged (3 to 6 sentences, 100-150 words). Explicitly reference contributing threat intelligence sources (like ThreatFox malware names, OTX pulse details, registrar anomalies, or phishing indicator triggers).\n'
        '  "recommended_actions": A list of 3 to 6 actionable mitigation and remediation steps. Make them specific and technical (e.g. including the target identifier, security systems, specific hunting rules or blocklist protocols).\n'
        '  "confidence": A float between 0.0 and 1.0 representing your confidence in this assessment based on the quality of intelligence matches.\n\n'
        "DATA:\n"
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
                        "max_tokens": 2000,
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

            # Strip markdown fences if present (robust check)
            if "```" in content:
                parts = content.split("```")
                if len(parts) > 1:
                    inner = parts[1]
                    if inner.startswith("json"):
                        inner = inner[4:]
                    content = inner.strip()

            # Best-effort repair for truncated JSON (max_tokens cut off mid-stream)
            if content and not content.endswith("}"):
                # Count open braces/brackets and close them
                open_braces   = content.count("{") - content.count("}")
                open_brackets = content.count("[") - content.count("]")
                # If we're inside a string, close it first
                in_string = content.count('"') % 2 == 1
                if in_string:
                    content += '"'
                content += "]" * max(open_brackets, 0)
                content += "}" * max(open_braces, 0)
                logger.warning("[AI] Truncated JSON repaired — added closing chars")

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
            logger.warning("[AI] JSON parse error: %s\nContent was: %s", exc, content[:300] if 'content' in locals() else "N/A")
            return InfraAISummary(error=f"AI response was not valid JSON: {exc}")
        except Exception as exc:
            logger.warning("[AI] OpenRouter error: %s", exc)
            return InfraAISummary(error=str(exc))
