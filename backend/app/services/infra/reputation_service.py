"""
Reputation Service – Stage 2 of the Infra Intelligence Pipeline.

Queries four external threat-intelligence sources in parallel:
  • AbuseIPDB  (IP abuse reports)     – requires ABUSEIPDB_API_KEY
  • URLhaus    (URL/domain blocklist)  – public API, no key needed
  • ThreatFox  (IOC repository)       – public API, no key needed
  • AlienVault OTX (pulses/general)   – requires OTX_API_KEY

All failures are caught and surfaced as `error` fields, never raising.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

import httpx

from app.config import settings
from app.schemas.infra_investigation import (
    AbuseIPDBResult,
    OTXPulsesResult,
    ReputationResults,
    ThreatFoxResult,
    URLhausResult,
)

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


class ReputationService:
    """
    Runs all four reputation lookups concurrently and returns a
    consolidated `ReputationResults` object.
    """

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────

    @staticmethod
    async def _check_abuseipdb(ip: str) -> AbuseIPDBResult:
        api_key = getattr(settings, "abuseipdb_api_key", "")
        if not api_key:
            return AbuseIPDBResult(error="AbuseIPDB API key not configured.")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": api_key, "Accept": "application/json"},
                    params={
                        "ipAddress": ip,
                        "maxAgeInDays": 90,
                        "verbose": "",
                    },
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
                return AbuseIPDBResult(
                    is_public=data.get("isPublic", False),
                    abuse_confidence_score=data.get("abuseConfidenceScore", 0),
                    country_code=data.get("countryCode") or "",
                    isp=data.get("isp") or "",
                    domain=data.get("domain") or "",
                    total_reports=data.get("totalReports", 0),
                    last_reported_at=data.get("lastReportedAt"),
                )
        except Exception as exc:
            logger.warning("[AbuseIPDB] Error for %s: %s", ip, exc)
            return AbuseIPDBResult(error=str(exc))

    # ── URLhaus ───────────────────────────────────────────────────────────────

    @staticmethod
    async def _check_urlhaus(host: str) -> URLhausResult:
        api_key = getattr(settings, "abuse_ch_api_key", "")
        if not api_key:
            return URLhausResult(error="URLhaus API key not configured.")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": host},
                    headers={"Auth-Key": api_key},
                )
                resp.raise_for_status()
                data = resp.json()
                qs = data.get("query_status", "no_results")
                urls_raw = data.get("urls") or []
                urls = [
                    {
                        "url": u.get("url", ""),
                        "url_status": u.get("url_status", ""),
                        "threat": u.get("threat", ""),
                        "date_added": u.get("date_added", ""),
                    }
                    for u in urls_raw[:20]  # cap at 20 entries
                ]
                return URLhausResult(
                    query_status=qs,
                    urlhaus_reference=data.get("urlhaus_reference"),
                    blacklists=data.get("blacklists"),
                    urls_on_this_host=urls if urls else None,
                )
        except Exception as exc:
            logger.warning("[URLhaus] Error for %s: %s", host, exc)
            return URLhausResult(error=str(exc))

    # ── ThreatFox ─────────────────────────────────────────────────────────────

    @staticmethod
    async def _check_threatfox(query: str) -> ThreatFoxResult:
        api_key = getattr(settings, "abuse_ch_api_key", "")
        if not api_key:
            return ThreatFoxResult(error="ThreatFox API key not configured.")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    json={"query": "search_ioc", "search_term": query},
                    headers={"Auth-Key": api_key},
                )
                resp.raise_for_status()
                data = resp.json()
                qs = data.get("query_status", "no_results")
                iocs_raw = data.get("data") or []
                iocs: Optional[list] = None
                if isinstance(iocs_raw, list) and iocs_raw:
                    iocs = [
                        {
                            "ioc": i.get("ioc", ""),
                            "ioc_type": i.get("ioc_type", ""),
                            "threat_type": i.get("threat_type", ""),
                            "malware": i.get("malware", ""),
                            "malware_printable": i.get("malware_printable", ""),
                            "confidence_level": i.get("confidence_level", 0),
                            "first_seen": i.get("first_seen", ""),
                            "last_seen": i.get("last_seen") or "",
                        }
                        for i in iocs_raw[:20]
                    ]
                return ThreatFoxResult(query_status=qs, iocs=iocs)
        except Exception as exc:
            logger.warning("[ThreatFox] Error for %s: %s", query, exc)
            return ThreatFoxResult(error=str(exc))

    # ── AlienVault OTX ────────────────────────────────────────────────────────

    @staticmethod
    async def _check_otx(
        hostname: str,
        target_type: str,
    ) -> OTXPulsesResult:
        api_key = settings.otx_api_key
        if not api_key:
            return OTXPulsesResult(error="OTX API key not configured.")
        try:
            # Choose OTX endpoint based on type
            if target_type == "ip":
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{hostname}/general"
            elif target_type in ("domain", "url"):
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{hostname}/general"
            else:
                return OTXPulsesResult(error=f"OTX: unsupported type '{target_type}'")

            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers={"X-OTX-API-KEY": api_key})
                resp.raise_for_status()
                data = resp.json()

            pulses_raw = data.get("pulse_info", {}).get("pulses", [])
            pulses = [
                {
                    "name": p.get("name", ""),
                    "description": p.get("description", "")[:300],
                    "tags": p.get("tags", [])[:10],
                    "malware_families": [
                        m.get("display_name", "") for m in p.get("malware_families", [])
                    ],
                    "targeted_countries": p.get("targeted_countries", [])[:10],
                }
                for p in pulses_raw[:15]
            ]
            return OTXPulsesResult(
                pulse_count=data.get("pulse_info", {}).get("count", len(pulses_raw)),
                pulses=pulses,
            )
        except Exception as exc:
            logger.warning("[OTX] Error for %s: %s", hostname, exc)
            return OTXPulsesResult(error=str(exc))

    # ── Public facade ─────────────────────────────────────────────────────────

    async def run(
        self,
        target: str,
        target_type: str,
        hostname: str,
    ) -> ReputationResults:
        """
        Run all four checks concurrently.

        Parameters
        ----------
        target      : raw target (URL/domain/IP/hash)
        target_type : classified IOC type
        hostname    : extracted hostname (e.g. "evil.example.com" from URL)
        """
        async def _none() -> None:
            return None

        is_hash = target_type == "hash"

        # ── AbuseIPDB: IP only ─────────────────────────────────────────────────
        abuseipdb_task = (
            self._check_abuseipdb(hostname)
            if target_type == "ip"
            else _none()
        )

        # ── URLhaus: not applicable for hashes ────────────────────────────────
        urlhaus_task = (
            _none()
            if is_hash
            else self._check_urlhaus(hostname)
        )

        # ── ThreatFox: search by hash directly, or by hostname ────────────────
        # ThreatFox supports MD5/SHA1/SHA256 lookups natively
        threatfox_query = target if is_hash else hostname
        threatfox_task = self._check_threatfox(threatfox_query)

        # ── OTX: only for ip/domain/url ────────────────────────────────────────
        otx_task = (
            self._check_otx(hostname, target_type)
            if target_type in ("ip", "domain", "url")
            else _none()
        )

        results = await asyncio.gather(
            abuseipdb_task,
            urlhaus_task,
            threatfox_task,
            otx_task,
            return_exceptions=True,
        )

        abuseipdb_res, urlhaus_res, threatfox_res, otx_res = results

        def _safe(val: Any, default: Any) -> Any:
            """Return val if it's not an exception, else default."""
            return val if not isinstance(val, BaseException) else default

        return ReputationResults(
            abuseipdb=_safe(abuseipdb_res, AbuseIPDBResult(error="Task failed."))
            if target_type == "ip" else None,
            urlhaus=_safe(urlhaus_res, URLhausResult(error="Task failed."))
            if not is_hash else None,
            threatfox=_safe(threatfox_res, ThreatFoxResult(error="Task failed.")),
            otx=_safe(otx_res, OTXPulsesResult(error="Task failed."))
            if target_type in ("ip", "domain", "url") else None,
        )
