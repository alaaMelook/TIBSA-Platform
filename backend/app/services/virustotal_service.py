"""
VirusTotal API v3 integration.

Supports:
  - URL scanning (submit → poll analysis → verify URL object)
  - File hash lookup (MD5 / SHA-1 / SHA-256)
  - File upload scanning (files up to 650 MB via large-file upload URL)

When an API key is configured, live VirusTotal is always used for URL/file scans
even if DEMO_MODE is enabled (demo mocks apply only without a key).
"""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any
from urllib.parse import urlparse

import httpx
import random

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
POLL_INTERVAL = 10   # seconds between status checks
MAX_POLLS = 30   # give up after 5 min (30 × 10 s)

# Known benign hosts — demo mocks return clean stats for these
_DEMO_SAFE_HOSTS = frozenset({
    "google.com", "www.google.com",
    "microsoft.com", "www.microsoft.com",
    "github.com", "www.github.com",
    "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com",
})


def normalize_url_for_vt(url: str) -> str:
    """Canonical URL form for VT submission and ID generation."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def vt_url_object_id(url: str) -> str:
    """VirusTotal URL object ID (URL-safe base64, no padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _threat_level(malicious: int, suspicious: int) -> str:
    """Determine threat level based on total detecting engines."""
    threat_count = malicious + suspicious
    if threat_count == 0:
        return "clean"
    if threat_count <= 2:
        return "low"
    if threat_count <= 4:
        return "medium"
    return "high"


def _count_decisive_engines(stats: dict) -> int:
    """Engines with a definitive verdict (excludes failure/timeout buckets)."""
    return sum(
        int(stats.get(k, 0) or 0)
        for k in ("malicious", "suspicious", "harmless", "undetected")
    )


def _hosts_match(submitted: str, reported: str | None) -> bool:
    if not reported:
        return False
    try:
        a = (urlparse(submitted).hostname or "").lower().rstrip(".")
        b = (urlparse(reported).hostname or "").lower().rstrip(".")
        return bool(a and b and (a == b or a.endswith(f".{b}") or b.endswith(f".{a}")))
    except Exception:
        return submitted.strip().lower() in (reported or "").lower()


class VirusTotalService:
    """Async VirusTotal v3 client with optional demo mocks when no API key."""

    def __init__(self, api_key: str, demo_mode: bool = False):
        self._api_key = (api_key or "").strip()
        self._headers = {"x-apikey": self._api_key} if self._api_key else {}
        self._demo_mode = demo_mode
        # Live VT whenever a key exists; mocks only without a key
        self._use_mock = not self._api_key
        if demo_mode and self._api_key:
            logger.warning(
                "DEMO_MODE is enabled but VIRUSTOTAL_API_KEY is set — "
                "using live VirusTotal for scans (not mock data)."
            )
        elif self._use_mock:
            logger.info("VirusTotalService using MOCK data (no API key)")

    @property
    def uses_mock_data(self) -> bool:
        return self._use_mock

    def _get_client(self, timeout: int = 30) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, http2=False)

    # ── URL scan ──────────────────────────────────────────────────────────────

    async def scan_url(self, url: str, *, debug: bool = False) -> dict:
        """Submit a URL and wait for analysis to complete."""
        submitted = normalize_url_for_vt(url)
        vt_object_id = vt_url_object_id(submitted)

        logger.info(
            "[VT] scan_url start submitted=%r normalized=%r vt_url_id=%s mock=%s",
            url,
            submitted,
            vt_object_id[:48],
            self._use_mock,
        )

        if self._use_mock:
            await asyncio.sleep(1.5)
            result = self._mock_url_result(submitted)
            result["submitted_url"] = submitted
            result["vt_url_object_id"] = vt_object_id
            result["source"] = "mock"
            return result

        async with self._get_client(timeout=30) as client:
            try:
                r = await client.post(
                    f"{VT_BASE}/urls",
                    headers=self._headers,
                    data={"url": submitted},
                )
                r.raise_for_status()
                post_body = r.json()
                analysis_id = post_body["data"]["id"]
                logger.info(
                    "[VT] POST /urls ok analysis_id=%s submitted=%r",
                    analysis_id,
                    submitted,
                )
                if debug:
                    logger.debug("[VT] POST /urls raw response: %s", post_body)

                result = await self._poll_analysis(
                    client, analysis_id, submitted_url=submitted, debug=debug
                )
                result = await self._verify_url_scan(
                    client, submitted, analysis_id, result, debug=debug
                )
                result["submitted_url"] = submitted
                result["vt_url_object_id"] = vt_object_id
                result["source"] = "live"
                return result
            except httpx.HTTPError as exc:
                logger.error("[VT] URL scan failed submitted=%r: %s", submitted, exc)
                raise

    async def scan_url_diagnostic(self, url: str) -> dict:
        """Full VT workflow with raw API payloads for debugging."""
        submitted = normalize_url_for_vt(url)
        out: dict[str, Any] = {
            "input_url": url,
            "submitted_url": submitted,
            "vt_url_object_id": vt_url_object_id(submitted),
            "uses_mock_data": self._use_mock,
            "demo_mode_setting": self._demo_mode,
            "has_api_key": bool(self._api_key),
        }

        if self._use_mock:
            mock = self._mock_url_result(submitted)
            out["mock_result"] = mock
            out["note"] = (
                "No VIRUSTOTAL_API_KEY — returning mock data. "
                "Set a key and disable reliance on mocks for real VT results."
            )
            return out

        async with self._get_client(timeout=60) as client:
            uid = out["vt_url_object_id"]
            url_report: dict[str, Any] = {"status_code": None}
            try:
                r0 = await client.get(f"{VT_BASE}/urls/{uid}", headers=self._headers)
                url_report["status_code"] = r0.status_code
                if r0.status_code == 200:
                    attrs0 = r0.json().get("data", {}).get("attributes", {})
                    url_report["url"] = attrs0.get("url")
                    url_report["last_analysis_stats"] = attrs0.get("last_analysis_stats")
                    url_report["last_analysis_date"] = attrs0.get("last_analysis_date")
                else:
                    url_report["body"] = r0.text[:500]
            except Exception as exc:
                url_report["error"] = str(exc)
            out["pre_scan_url_report"] = url_report

            r = await client.post(
                f"{VT_BASE}/urls",
                headers=self._headers,
                data={"url": submitted},
            )
            out["post_scan"] = {
                "status_code": r.status_code,
                "analysis_id": r.json().get("data", {}).get("id") if r.status_code < 400 else None,
                "raw": r.json() if r.status_code < 400 else r.text[:1000],
            }
            r.raise_for_status()
            analysis_id = r.json()["data"]["id"]

            poll_log: list[dict[str, Any]] = []
            final_attrs: dict | None = None
            for attempt in range(MAX_POLLS):
                ra = await client.get(
                    f"{VT_BASE}/analyses/{analysis_id}",
                    headers=self._headers,
                )
                ra.raise_for_status()
                body = ra.json()
                attrs = body["data"]["attributes"]
                entry = {
                    "attempt": attempt + 1,
                    "status": attrs.get("status"),
                    "stats": attrs.get("stats"),
                }
                poll_log.append(entry)
                if attrs.get("status") == "completed":
                    final_attrs = attrs
                    out["completed_analysis_raw"] = body
                    break
                await asyncio.sleep(3 if attempt < 3 else POLL_INTERVAL)

            out["poll_log"] = poll_log

            if final_attrs:
                parsed = self._parse_analysis_attrs(final_attrs, analysis_id)
                parsed = await self._verify_url_scan(
                    client, submitted, analysis_id, parsed, debug=True
                )
                out["parsed_result"] = parsed
            else:
                out["parsed_result"] = {
                    "status": "timeout",
                    "analysis_id": analysis_id,
                }

            try:
                ri = await client.get(
                    f"{VT_BASE}/analyses/{analysis_id}/item",
                    headers=self._headers,
                )
                out["analysis_item"] = {
                    "status_code": ri.status_code,
                    "raw": ri.json() if ri.status_code == 200 else ri.text[:500],
                }
            except Exception as exc:
                out["analysis_item"] = {"error": str(exc)}

        return out

    def _mock_url_result(self, url: str) -> dict:
        """Demo mock — safe for known brands; suspicious patterns otherwise."""
        submitted = normalize_url_for_vt(url)
        host = (urlparse(submitted).hostname or "").lower()

        if host in _DEMO_SAFE_HOSTS or any(
            host == h or host.endswith(f".{h}") for h in _DEMO_SAFE_HOSTS
        ):
            malicious, suspicious = 0, 0
        elif any(
            kw in submitted.lower()
            for kw in ("login", "verify", "secure", "paypal", "bank", ".xyz", ".top")
        ):
            malicious, suspicious = 18, 3
        else:
            malicious, suspicious = 0, 0

        harmless = max(0, 93 - malicious - suspicious)
        stats = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": 0,
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
            "mock": True,
        }

    # ── Hash lookup ───────────────────────────────────────────────────────────

    async def lookup_hash(self, file_hash: str) -> dict:
        if self._use_mock:
            await asyncio.sleep(0.5)
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
        if self._use_mock:
            await asyncio.sleep(2.0)
            is_malicious = (
                "eicar" in filename.lower()
                or b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                in content
            )
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
        suspicious = 1 if malicious > 0 else 0
        harmless = 72 - malicious - suspicious
        stats = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": 0,
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
            "mock": True,
        }

    async def _poll_analysis(
        self,
        client: httpx.AsyncClient,
        analysis_id: str,
        *,
        submitted_url: str | None = None,
        debug: bool = False,
    ) -> dict:
        for poll_num in range(1, MAX_POLLS + 1):
            r = await client.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=self._headers,
            )
            r.raise_for_status()
            body = r.json()
            data = body["data"]
            attrs = data["attributes"]
            status = attrs.get("status")

            logger.debug(
                "[VT] poll %d/%d analysis_id=%s status=%s submitted=%r",
                poll_num,
                MAX_POLLS,
                analysis_id,
                status,
                submitted_url,
            )

            if status == "completed":
                if debug:
                    logger.debug(
                        "[VT] analysis completed analysis_id=%s stats=%s raw=%s",
                        analysis_id,
                        attrs.get("stats"),
                        body,
                    )
                logger.info(
                    "[VT] analysis completed analysis_id=%s stats=%s submitted=%r",
                    analysis_id,
                    attrs.get("stats"),
                    submitted_url,
                )
                return self._parse_analysis_attrs(attrs, analysis_id, raw_analysis=body if debug else None)

            await asyncio.sleep(POLL_INTERVAL)

        logger.warning(
            "[VT] analysis timeout analysis_id=%s submitted=%r",
            analysis_id,
            submitted_url,
        )
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

    async def _verify_url_scan(
        self,
        client: httpx.AsyncClient,
        submitted_url: str,
        analysis_id: str,
        result: dict,
        *,
        debug: bool = False,
    ) -> dict:
        """Cross-check analysis stats against the URL object and /analyses/.../item."""
        verification: dict[str, Any] = {
            "submitted_url": submitted_url,
            "analysis_id": analysis_id,
            "analysis_stats": result.get("stats"),
            "host_match": None,
            "stats_match": None,
        }
        object_id = vt_url_object_id(submitted_url)
        verification["expected_vt_url_object_id"] = object_id

        # URL object by canonical ID
        try:
            ru = await client.get(
                f"{VT_BASE}/urls/{object_id}",
                headers=self._headers,
            )
            verification["url_object_status"] = ru.status_code
            if ru.status_code == 200:
                uattrs = ru.json().get("data", {}).get("attributes", {})
                reported_url = uattrs.get("url") or uattrs.get("last_final_url")
                verification["url_object_url"] = reported_url
                verification["url_object_id_from_api"] = ru.json().get("data", {}).get("id")
                verification["last_analysis_stats"] = uattrs.get("last_analysis_stats")
                verification["host_match"] = _hosts_match(submitted_url, reported_url)
                las = uattrs.get("last_analysis_stats") or {}
                a_stats = result.get("stats") or {}
                verification["stats_match"] = (
                    las.get("malicious") == a_stats.get("malicious")
                    and las.get("suspicious") == a_stats.get("suspicious")
                )
        except Exception as exc:
            verification["url_object_error"] = str(exc)

        # Analysis → item relationship
        try:
            ri = await client.get(
                f"{VT_BASE}/analyses/{analysis_id}/item",
                headers=self._headers,
            )
            verification["item_status"] = ri.status_code
            if ri.status_code == 200:
                iattrs = ri.json().get("data", {}).get("attributes", {})
                verification["item_url"] = iattrs.get("url")
                verification["item_last_analysis_stats"] = iattrs.get("last_analysis_stats")
                if verification.get("host_match") is None:
                    verification["host_match"] = _hosts_match(
                        submitted_url, iattrs.get("url")
                    )
        except Exception as exc:
            verification["item_error"] = str(exc)

        result["verification"] = verification

        if verification.get("host_match") is False:
            logger.error(
                "[VT] URL host mismatch analysis_id=%s submitted=%r reported=%r",
                analysis_id,
                submitted_url,
                verification.get("url_object_url") or verification.get("item_url"),
            )
        elif debug:
            logger.info("[VT] verification %s", verification)

        return result

    @staticmethod
    def _parse_analysis_attrs(
        attrs: dict,
        analysis_id: str,
        *,
        raw_analysis: dict | None = None,
    ) -> dict:
        stats = attrs.get("stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total_engines = _count_decisive_engines(stats)

        parsed = {
            "found": True,
            "status": "completed",
            "threat_level": _threat_level(malicious, suspicious),
            "stats": stats,
            "total_engines": total_engines,
            "malicious": malicious,
            "suspicious": suspicious,
            "analysis_id": analysis_id,
        }
        if raw_analysis is not None:
            parsed["raw_analysis"] = raw_analysis
        return parsed

    @staticmethod
    def _parse_file_attrs(attrs: dict) -> dict:
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total_engines = _count_decisive_engines(stats)
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
