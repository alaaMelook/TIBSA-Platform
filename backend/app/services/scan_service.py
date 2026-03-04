"""
Scan service.
Handles URL/file scanning logic using VirusTotal, local malice Docker AV
engines, and report generation.
"""
import asyncio
import logging
import uuid
from typing import List

from fastapi import BackgroundTasks, HTTPException, status
from supabase import Client

from app.config import settings
from app.services.virustotal_service import VirusTotalService
from app.services import malice_service

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, supabase: Client):
        self.supabase = supabase
        api_key = settings.virustotal_api_key
        self.vt: VirusTotalService | None = (
            VirusTotalService(api_key) if api_key else None
        )

    # ── Public scan methods ───────────────────────────────────────────────────

    async def scan_url(
        self, user_id: str, url: str, background_tasks: BackgroundTasks
    ) -> dict:
        """Create a URL scan record and kick off VirusTotal analysis."""
        scan_id = str(uuid.uuid4())
        saved = self._insert_scan(scan_id, user_id, "url", url)
        if self.vt:
            background_tasks.add_task(self._run_url_scan, scan_id, url)
        return saved

    async def scan_file(
        self, user_id: str, file_hash: str, background_tasks: BackgroundTasks
    ) -> dict:
        """Create a file-hash scan record and kick off VirusTotal lookup."""
        scan_id = str(uuid.uuid4())
        saved = self._insert_scan(scan_id, user_id, "file", file_hash)
        if self.vt:
            background_tasks.add_task(self._run_hash_scan, scan_id, file_hash)
        return saved

    async def scan_uploaded_file(
        self,
        user_id: str,
        filename: str,
        content: bytes,
        background_tasks: BackgroundTasks,
    ) -> dict:
        """Upload a real file, scan it via VirusTotal + local malice AV engines."""
        scan_id = str(uuid.uuid4())
        saved = self._insert_scan(scan_id, user_id, "file_upload", filename)
        background_tasks.add_task(
            self._run_combined_file_upload_scan, scan_id, filename, content
        )
        return saved

    async def list_user_scans(self, user_id: str) -> List[dict]:
        """List all scans for a specific user."""
        response = self.supabase.table("scans") \
            .select("*") \
            .eq("user_id", user_id) \
            .order("created_at", desc=True) \
            .execute()

        return response.data or []

    async def get_report(self, scan_id: str, user_id: str) -> dict:
        """Get the full report for a scan."""
        # Verify ownership
        scan = self.supabase.table("scans") \
            .select("*") \
            .eq("id", scan_id) \
            .eq("user_id", user_id) \
            .single() \
            .execute()

        if not scan.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        # Get report
        report = self.supabase.table("scan_reports") \
            .select("*") \
            .eq("scan_id", scan_id) \
            .single() \
            .execute()

        if not report.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not yet available",
            )

        return report.data

    # ── Private helpers ───────────────────────────────────────────────────────

    def _insert_scan(
        self, scan_id: str, user_id: str, scan_type: str, target: str
    ) -> dict:
        scan_data = {
            "id": scan_id,
            "user_id": user_id,
            "scan_type": scan_type,
            "target": target,
            "status": "pending",
            "threat_level": None,
        }
        response = self.supabase.table("scans").insert(scan_data).execute()
        return response.data[0] if response.data else scan_data

    # ── Background tasks (called by FastAPI BackgroundTasks) ──────────────────

    async def _run_url_scan(self, scan_id: str, url: str) -> None:
        if not self.vt:
            return
        await self._execute_vt_scan(
            scan_id=scan_id,
            vt_call=self.vt.scan_url(url),
        )

    async def _run_hash_scan(self, scan_id: str, file_hash: str) -> None:
        if not self.vt:
            return
        await self._execute_vt_scan(
            scan_id=scan_id,
            vt_call=self.vt.lookup_hash(file_hash),
        )

    async def _run_combined_file_upload_scan(
        self, scan_id: str, filename: str, content: bytes
    ) -> None:
        """Run VirusTotal and all malice Docker AV engines in parallel."""
        await self._execute_combined_scan(
            scan_id=scan_id,
            filename=filename,
            content=content,
        )

    async def cancel_scan(self, scan_id: str, user_id: str) -> dict:
        """Cancel a pending or in-progress scan."""
        scan = (
            self.supabase.table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user_id)
            .single()
            .execute()
        )
        if not scan.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )
        current = scan.data.get("status")
        if current not in ("pending", "in_progress"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel a scan with status '{current}'",
            )
        result = (
            self.supabase.table("scans")
            .update({"status": "cancelled"})
            .eq("id", scan_id)
            .execute()
        )
        return result.data[0] if result.data else {**scan.data, "status": "cancelled"}

    async def delete_scan(self, scan_id: str, user_id: str) -> dict:
        """Permanently delete a scan and its report from the database."""
        scan = (
            self.supabase.table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user_id)
            .single()
            .execute()
        )
        if not scan.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )
        # Delete associated report first (FK constraint)
        self.supabase.table("scan_reports").delete().eq("scan_id", scan_id).execute()
        # Delete the scan
        self.supabase.table("scans").delete().eq("id", scan_id).execute()
        return scan.data

    async def _execute_vt_scan(self, scan_id: str, vt_call) -> None:
        """
        Core background worker:
          1. Check if already cancelled
          2. Mark scan in_progress
          3. Call VirusTotal
          4. Check again for cancellation
          5. Update scan + insert report
          6. On error → mark scan failed (unless cancelled)
        """
        def _is_cancelled() -> bool:
            try:
                chk = (
                    self.supabase.table("scans")
                    .select("status")
                    .eq("id", scan_id)
                    .single()
                    .execute()
                )
                return bool(chk.data and chk.data.get("status") == "cancelled")
            except Exception:
                return False

        try:
            if _is_cancelled():
                return

            self.supabase.table("scans").update(
                {"status": "in_progress"}
            ).eq("id", scan_id).execute()

            result: dict = await vt_call

            if _is_cancelled():
                return

            malicious = result.get("malicious", 0)
            total     = result.get("total_engines", 0)
            level     = result.get("threat_level", "unknown")

            self.supabase.table("scans").update({
                "status": "completed",
                "threat_level": level,
            }).eq("id", scan_id).execute()

            self.supabase.table("scan_reports").insert({
                "id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "summary": (
                    f"{malicious}/{total} engines flagged this target as malicious. "
                    f"Threat level: {level}."
                ),
                "details": result,
                "indicators": [],
            }).execute()

        except Exception as exc:  # noqa: BLE001
            logger.error("VirusTotal scan failed for %s: %s", scan_id, exc)
            if not _is_cancelled():
                self.supabase.table("scans").update(
                    {"status": "failed"}
                ).eq("id", scan_id).execute()

    async def _execute_combined_scan(
        self, scan_id: str, filename: str, content: bytes
    ) -> None:
        """
        Run VirusTotal and malice Docker AV engines concurrently.
        Stores a unified report that contains both sets of results.
        """
        def _is_cancelled() -> bool:
            try:
                chk = (
                    self.supabase.table("scans")
                    .select("status")
                    .eq("id", scan_id)
                    .single()
                    .execute()
                )
                return bool(chk.data and chk.data.get("status") == "cancelled")
            except Exception:
                return False

        try:
            if _is_cancelled():
                return

            self.supabase.table("scans").update(
                {"status": "in_progress"}
            ).eq("id", scan_id).execute()

            # Build concurrent tasks
            vt_task = (
                self.vt.scan_file(filename, content)
                if self.vt
                else asyncio.sleep(0, result=None)  # no-op coroutine
            )
            malice_task = malice_service.scan_file_with_malice(filename, content)

            vt_result, malice_result = await asyncio.gather(
                vt_task, malice_task, return_exceptions=True
            )

            if _is_cancelled():
                return

            # ── Handle VirusTotal result ──────────────────────────────────
            vt_data: dict = {}
            if isinstance(vt_result, Exception):
                logger.error("VT scan failed for %s: %s", scan_id, vt_result)
                vt_data = {"error": str(vt_result)}
            elif vt_result is not None:
                vt_data = vt_result

            # ── Handle malice result ──────────────────────────────────────
            malice_data: dict = {}
            if isinstance(malice_result, Exception):
                logger.error(
                    "Malice scan failed for %s: %s (%s)",
                    scan_id, malice_result, type(malice_result).__name__,
                    exc_info=malice_result,
                )
                malice_data = {"error": str(malice_result)}
            elif malice_result is not None:
                malice_data = malice_result
            else:
                logger.warning("Malice scan returned None for %s", scan_id)

            logger.info(
                "Scan %s results — VT: %s, Malice engines: %d, detected: %d",
                scan_id,
                "error" if vt_data.get("error") else f"{vt_data.get('malicious', 0)}/{vt_data.get('total_engines', 0)}",
                malice_data.get("total_engines", 0),
                malice_data.get("detected_by", 0),
            )

            # ── Determine overall threat level ────────────────────────────
            vt_level    = vt_data.get("threat_level", "unknown")
            malice_level = malice_data.get("threat_level", "clean")

            level_rank = {"clean": 0, "unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            ranked = max(
                level_rank.get(vt_level, 0),
                level_rank.get(malice_level, 0),
            )
            level_map = {0: "clean", 1: "low", 2: "medium", 3: "high", 4: "critical"}
            final_level = level_map[ranked]

            # ── Stats for summary ─────────────────────────────────────────
            vt_malicious  = vt_data.get("malicious", 0)
            vt_total      = vt_data.get("total_engines", 0)
            mal_detected  = malice_data.get("detected_by", 0)
            mal_total     = malice_data.get("total_engines", 0)

            top_threat = (
                malice_data.get("top_result")
                or (f"{vt_malicious}/{vt_total} VT engines" if vt_malicious else None)
            )

            summary_parts = []
            if vt_data and not vt_data.get("error"):
                summary_parts.append(
                    f"VirusTotal: {vt_malicious}/{vt_total} engines flagged as malicious"
                )
            if malice_data and not malice_data.get("error"):
                summary_parts.append(
                    f"Local AV engines: {mal_detected}/{mal_total} detected malware"
                    + (f" ({top_threat})" if top_threat and mal_detected else "")
                )
            summary = ". ".join(summary_parts) + f". Overall threat level: {final_level}."

            self.supabase.table("scans").update({
                "status": "completed",
                "threat_level": final_level,
            }).eq("id", scan_id).execute()

            self.supabase.table("scan_reports").insert({
                "id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "summary": summary,
                "details": {
                    "virustotal": vt_data,
                    "malice": malice_data,
                    "threat_level": final_level,
                },
                "indicators": [],
            }).execute()

        except Exception as exc:  # noqa: BLE001
            logger.error("Combined scan failed for %s: %s", scan_id, exc)
            if not _is_cancelled():
                self.supabase.table("scans").update(
                    {"status": "failed"}
                ).eq("id", scan_id).execute()
