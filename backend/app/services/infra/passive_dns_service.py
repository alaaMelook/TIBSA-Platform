"""
Passive DNS Service – Stage 4 of the Infra Intelligence Pipeline.

Queries AlienVault OTX Passive DNS for historical A/AAAA resolution records.
This reveals historical IP addresses the target domain has resolved to,
which is critical for detecting shared infrastructure and campaign pivots.

Falls back gracefully when OTX key is absent or unavailable.
"""
from __future__ import annotations

import logging

import httpx

from app.config import settings
from app.schemas.infra_investigation import PassiveDNSEntry, PassiveDNSResult

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


class PassiveDNSService:
    """
    Retrieves passive DNS records from AlienVault OTX.
    Only meaningful for domain and URL target types.
    """

    @staticmethod
    async def query(hostname: str, target_type: str) -> PassiveDNSResult:
        """
        Parameters
        ----------
        hostname    : the extracted hostname / IP
        target_type : IOC type ('domain', 'url', 'ip', …)
        """
        if target_type not in ("domain", "url"):
            return PassiveDNSResult(
                error=f"Passive DNS not applicable for target type '{target_type}'."
            )

        api_key = settings.otx_api_key
        if not api_key:
            return PassiveDNSResult(error="OTX API key not configured.")

        try:
            url = (
                f"https://otx.alienvault.com/api/v1"
                f"/indicators/domain/{hostname}/passive_dns"
            )
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers={"X-OTX-API-KEY": api_key})
                resp.raise_for_status()
                data = resp.json()

            raw_entries = data.get("passive_dns") or []
            entries: list[PassiveDNSEntry] = []

            for entry in raw_entries[:100]:  # cap at 100 records
                address = entry.get("address", "")
                hostname_val = entry.get("hostname", "")
                if not address:
                    continue
                entries.append(
                    PassiveDNSEntry(
                        hostname=hostname_val or hostname,
                        address=address,
                        first=entry.get("first", ""),
                        last=entry.get("last", ""),
                        asn=entry.get("asn") or None,
                        # OTX returns country_code directly (e.g. "US")
                        # flag_url is something like "/img/flags/us.png" — do NOT slice it
                        country_code=entry.get("country_code") or None,
                    )
                )

            return PassiveDNSResult(passive_dns=entries, count=len(entries))

        except Exception as exc:
            logger.warning("[PassiveDNS] Error for %s: %s", hostname, exc)
            return PassiveDNSResult(error=str(exc))
