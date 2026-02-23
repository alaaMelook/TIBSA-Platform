"""
VirusTotal API v3 integration.

Supports:
  - URL scanning
  - File hash lookup (MD5 / SHA-1 / SHA-256)
  - File upload scanning (files up to 650 MB via large-file upload URL)
"""

import asyncio
import httpx

VT_BASE       = "https://www.virustotal.com/api/v3"
POLL_INTERVAL = 5    # seconds between status checks
MAX_POLLS     = 12   # give up after 60 s (12 × 5 s)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _threat_level(malicious: int, suspicious: int) -> str:
    if malicious >= 5:
        return "high"
    if malicious > 0:
        return "medium"
    if suspicious > 0:
        return "low"
    return "clean"


# ── Service class ─────────────────────────────────────────────────────────────

class VirusTotalService:
    """Async VirusTotal v3 client."""

    def __init__(self, api_key: str):
        self._headers = {"x-apikey": api_key}

    # ── URL scan ──────────────────────────────────────────────────────────────

    async def scan_url(self, url: str) -> dict:
        """Submit a URL and wait for analysis to complete."""
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"{VT_BASE}/urls",
                headers=self._headers,
                data={"url": url},
            )
            r.raise_for_status()
            analysis_id = r.json()["data"]["id"]
            return await self._poll_analysis(client, analysis_id)

    # ── Hash lookup ───────────────────────────────────────────────────────────

    async def lookup_hash(self, file_hash: str) -> dict:
        """
        Look up a file hash (MD5/SHA-1/SHA-256) on VirusTotal.
        Returns immediately — no polling needed.
        """
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(
                f"{VT_BASE}/files/{file_hash}",
                headers=self._headers,
            )
            if r.status_code == 404:
                return {
                    "found": False,
                    "status": "completed",
                    "threat_level": "unknown",
                    "stats": {},
                    "total_engines": 0,
                    "malicious": 0,
                    "suspicious": 0,
                }
            r.raise_for_status()
            return self._parse_file_attrs(r.json()["data"]["attributes"])

    # ── File upload ───────────────────────────────────────────────────────────

    async def scan_file(self, filename: str, content: bytes) -> dict:
        """
        Upload a file to VirusTotal and wait for analysis.
        Files > 32 MB use the large-file upload URL endpoint.
        """
        async with httpx.AsyncClient(timeout=120) as client:
            if len(content) > 32 * 1024 * 1024:
                url_r = await client.get(
                    f"{VT_BASE}/files/upload_url",
                    headers=self._headers,
                )
                url_r.raise_for_status()
                upload_url = url_r.json()["data"]
            else:
                upload_url = f"{VT_BASE}/files"

            r = await client.post(
                upload_url,
                headers=self._headers,
                files={"file": (filename, content, "application/octet-stream")},
            )
            r.raise_for_status()
            analysis_id = r.json()["data"]["id"]
            return await self._poll_analysis(client, analysis_id)

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _poll_analysis(
        self,
        client: httpx.AsyncClient,
        analysis_id: str,
    ) -> dict:
        """Poll /analyses/{id} until status == 'completed' or we time out."""
        for _ in range(MAX_POLLS):
            r = await client.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=self._headers,
            )
            r.raise_for_status()
            data  = r.json()["data"]
            attrs = data["attributes"]

            if attrs["status"] == "completed":
                return self._parse_analysis_attrs(attrs, analysis_id)

            await asyncio.sleep(POLL_INTERVAL)

        # Timed out — return what we know
        return {
            "found": None,
            "status": "timeout",
            "threat_level": "unknown",
            "stats": {},
            "total_engines": 0,
            "malicious": 0,
            "suspicious": 0,
            "analysis_id": analysis_id,
        }

    @staticmethod
    def _parse_analysis_attrs(attrs: dict, analysis_id: str) -> dict:
        stats      = attrs.get("stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return {
            "found": True,
            "status": "completed",
            "threat_level": _threat_level(malicious, suspicious),
            "stats": stats,
            "total_engines": sum(stats.values()),
            "malicious": malicious,
            "suspicious": suspicious,
            "analysis_id": analysis_id,
        }

    @staticmethod
    def _parse_file_attrs(attrs: dict) -> dict:
        stats      = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return {
            "found": True,
            "status": "completed",
            "threat_level": _threat_level(malicious, suspicious),
            "stats": stats,
            "total_engines": sum(stats.values()),
            "malicious": malicious,
            "suspicious": suspicious,
            "file_name": attrs.get("meaningful_name", "unknown"),
            "file_type": attrs.get("type_description", "unknown"),
        }
