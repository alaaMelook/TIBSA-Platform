"""
VirusTotal API v3 integration.

Supports:
  - URL scanning
  - File hash lookup (MD5 / SHA-1 / SHA-256)
  - File upload scanning (files up to 650 MB via large-file upload URL)
"""

import asyncio
import logging
import httpx
import random

logger = logging.getLogger(__name__)

VT_BASE       = "https://www.virustotal.com/api/v3"
POLL_INTERVAL = 10   # seconds between status checks
MAX_POLLS     = 30   # give up after 5 min (30 × 10 s)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _threat_level(malicious: int, suspicious: int) -> str:
    """Determine threat level based on total detecting engines.

    0 detections  → clean
    1-2           → low
    3-4           → medium
    5+            → high
    """
    threat_count = malicious + suspicious
    if threat_count == 0:
        return "clean"
    if threat_count <= 2:
        return "low"
    if threat_count <= 4:
        return "medium"
    return "high"


# ── Service class ─────────────────────────────────────────────────────────────

class VirusTotalService:
    """Async VirusTotal v3 client with Demo Mode support."""

    def __init__(self, api_key: str, demo_mode: bool = False):
        self._headers = {"x-apikey": api_key}
        self._demo_mode = demo_mode
        if self._demo_mode:
            logger.info("VirusTotalService initialized in DEMO MODE")

    def _get_client(self, timeout: int = 30) -> httpx.AsyncClient:
        """Create an httpx client with optimal settings for VirusTotal."""
        # Force HTTP/1.1 to avoid common 'All connection attempts failed' errors with HTTP/2 on some networks
        return httpx.AsyncClient(timeout=timeout, http2=False)

    # ── URL scan ──────────────────────────────────────────────────────────────

    async def scan_url(self, url: str) -> dict:
        """Submit a URL and wait for analysis to complete."""
        if self._demo_mode:
            await asyncio.sleep(1.5)  # Simulate network delay
            return self._mock_url_result(url)

        async with self._get_client(timeout=30) as client:
            try:
                r = await client.post(
                    f"{VT_BASE}/urls",
                    headers=self._headers,
                    data={"url": url},
                )
                r.raise_for_status()
                analysis_id = r.json()["data"]["id"]
                return await self._poll_analysis(client, analysis_id)
            except httpx.HTTPError as exc:
                logger.error("VT URL scan failed: %s", exc)
                raise

    def _mock_url_result(self, url: str) -> dict:
        """Realistic mock data for URL scans."""
        # Predictable 'random' based on URL length to keep it consistent
        is_bad = len(url) % 7 == 0
        malicious = random.randint(10, 45) if is_bad else 0
        suspicious = random.randint(1, 5) if is_bad else 0
        harmless = 93 - malicious - suspicious
        
        stats = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": 0
        }
        return {
            "found": True,
            "status": "completed",
            "threat_level": _threat_level(malicious, suspicious),
            "stats": stats,
            "total_engines": 93,
            "malicious": malicious,
            "suspicious": suspicious,
            "analysis_id": f"demo-url-{random.getrandbits(32):x}",
        }

    # ── Hash lookup ───────────────────────────────────────────────────────────

    async def lookup_hash(self, file_hash: str) -> dict:
        """
        Look up a file hash (MD5/SHA-1/SHA-256) on VirusTotal.
        """
        if self._demo_mode:
            await asyncio.sleep(0.5)
            # eicar hash check
            if "44d88612" in file_hash.lower():
                return self._mock_file_result(file_hash, malicious=58)
            return self._mock_file_result(file_hash, malicious=0)

        async with self._get_client(timeout=30) as client:
            try:
                r = await client.get(
                    f"{VT_BASE}/files/{file_hash}",
                    headers=self._headers,
                )
                if r.status_code == 404:
                    return {
                        "found": False,
                        "status": "completed",
                        "threat_level": "not_found",
                        "stats": {},
                        "total_engines": 0,
                        "malicious": 0,
                        "suspicious": 0,
                    }
                r.raise_for_status()
                return self._parse_file_attrs(r.json()["data"]["attributes"])
            except httpx.HTTPError as exc:
                logger.error("VT hash lookup failed: %s", exc)
                raise

    # ── File upload ───────────────────────────────────────────────────────────

    async def scan_file(self, filename: str, content: bytes) -> dict:
        """
        Upload a file to VirusTotal and wait for analysis.
        """
        if self._demo_mode:
            await asyncio.sleep(2.0)
            is_malicious = "eicar" in filename.lower() or b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in content
            return self._mock_file_result(filename, malicious=60 if is_malicious else 0)

        async with self._get_client(timeout=120) as client:
            try:
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
            except httpx.HTTPError as exc:
                logger.error("VT file scan failed: %s", exc)
                raise

    def _mock_file_result(self, target: str, malicious: int = 0) -> dict:
        """Realistic mock data for file scans."""
        suspicious = 1 if malicious > 0 else 0
        harmless = 72 - malicious - suspicious
        stats = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": 0
        }
        return {
            "found": True,
            "status": "completed",
            "threat_level": _threat_level(malicious, suspicious),
            "stats": stats,
            "total_engines": 72,
            "malicious": malicious,
            "suspicious": suspicious,
            "file_name": target,
            "file_type": "Executable" if malicious > 0 else "Document",
        }

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
            "threat_level": "timeout",
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
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        # Only count engines that gave a decisive result (exclude timeout/failure/type-unsupported)
        total_engines = malicious + suspicious + harmless + undetected
        return {
            "found": True,
            "status": "completed",
            "threat_level": _threat_level(malicious, suspicious),
            "stats": stats,
            "total_engines": total_engines,
            "malicious": malicious,
            "suspicious": suspicious,
            "analysis_id": analysis_id,
        }

    @staticmethod
    def _parse_file_attrs(attrs: dict) -> dict:
        stats      = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        # Only count engines that gave a decisive result (exclude timeout/failure/type-unsupported)
        total_engines = malicious + suspicious + harmless + undetected
        return {
            "found": True,
            "status": "completed",
            "threat_level": _threat_level(malicious, suspicious),
            "stats": stats,
            "total_engines": total_engines,
            "malicious": malicious,
            "suspicious": suspicious,
            "file_name": attrs.get("meaningful_name", "unknown"),
            "file_type": attrs.get("type_description", "unknown"),
        }
