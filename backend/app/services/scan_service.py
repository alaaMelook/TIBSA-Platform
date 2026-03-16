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
from app.services.ml_engine import MLEngine
from app.services.notification_service import NotificationService
from app.services.threat_scoring import compute_threat_score

logger = logging.getLogger(__name__)


class ScanService:
    _vt_missing_warned: bool = False

    def __init__(self, supabase: Client):
        self.supabase = supabase
        api_key = settings.virustotal_api_key
        self.vt: VirusTotalService | None = (
            VirusTotalService(api_key) if api_key else None
        )
        self.ml = MLEngine()
        self.notifs = NotificationService(supabase)

        if not self.vt and not ScanService._vt_missing_warned:
            logger.warning(
                "VirusTotal integration is disabled (missing VIRUSTOTAL_API_KEY). "
                "URL/hash scan submissions will be rejected with 503."
            )
            ScanService._vt_missing_warned = True

    def _ensure_vt_configured(self) -> None:
        if self.vt:
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "VirusTotal is not configured on this deployment. "
                "Set the VIRUSTOTAL_API_KEY environment variable and redeploy."
            ),
        )

    # ── Public scan methods ───────────────────────────────────────────────────

    async def scan_url(
        self, user_id: str, url: str, background_tasks: BackgroundTasks
    ) -> dict:
        """Create a URL scan record and kick off VirusTotal + AI analysis."""
        if not self.vt and not self.ml.is_model_loaded():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "Neither VirusTotal nor the AI phishing model is available. "
                    "Configure VIRUSTOTAL_API_KEY or train the phishing model."
                ),
            )
        scan_id = str(uuid.uuid4())
        saved = self._insert_scan(scan_id, user_id, "url", url)
        background_tasks.add_task(self._run_url_scan, scan_id, url)
        return saved

    async def scan_file(
        self, user_id: str, file_hash: str, background_tasks: BackgroundTasks
    ) -> dict:
        """Create a file-hash scan record and kick off VirusTotal lookup."""
        self._ensure_vt_configured()
        scan_id = str(uuid.uuid4())
        saved = self._insert_scan(scan_id, user_id, "file", file_hash)
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

    def _get_scan_meta(self, scan_id: str) -> dict | None:
        """Fetch scan row to get user_id / target / scan_type."""
        try:
            resp = (
                self.supabase.table("scans")
                .select("user_id, scan_type, target")
                .eq("id", scan_id)
                .single()
                .execute()
            )
            return resp.data
        except Exception:
            return None

    def _notify_completion(self, scan_id: str, threat_level: str) -> None:
        meta = self._get_scan_meta(scan_id)
        if not meta:
            return
        try:
            self.notifs.notify_scan_completed(
                user_id=meta["user_id"],
                scan_id=scan_id,
                scan_type=meta["scan_type"],
                target=meta["target"],
                threat_level=threat_level,
            )
        except Exception as exc:
            logger.warning("Notification creation failed: %s", exc)

    def _notify_failure(self, scan_id: str) -> None:
        meta = self._get_scan_meta(scan_id)
        if not meta:
            return
        try:
            self.notifs.notify_scan_failed(
                user_id=meta["user_id"],
                scan_id=scan_id,
                scan_type=meta["scan_type"],
                target=meta["target"],
            )
        except Exception as exc:
            logger.warning("Notification creation failed: %s", exc)

    # ── Background tasks (called by FastAPI BackgroundTasks) ──────────────────

    async def _run_url_scan(self, scan_id: str, url: str) -> None:
        """Run VirusTotal + AI phishing classifier in parallel for URL scans."""
        await self._execute_url_combined_scan(scan_id, url)

    async def _run_hash_scan(self, scan_id: str, file_hash: str) -> None:
        if not self.vt:
            logger.error("VirusTotal API key not configured — cannot scan hash %s", file_hash)
            self.supabase.table("scans").update(
                {"status": "failed", "threat_level": "unknown"}
            ).eq("id", scan_id).execute()
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

            self._notify_completion(scan_id, level)

        except Exception as exc:  # noqa: BLE001
            logger.error("VirusTotal scan failed for %s: %s", scan_id, exc)
            if not _is_cancelled():
                self.supabase.table("scans").update(
                    {"status": "failed"}
                ).eq("id", scan_id).execute()
                self._notify_failure(scan_id)

    async def _execute_url_combined_scan(self, scan_id: str, url: str) -> None:
        """
        Run VirusTotal + AI phishing classifier in parallel for URL scans.
        Merges results using the logic:
          - VT malicious/suspicious OR AI phishing → High
          - Both sources say safe                  → Clean
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
                self.vt.scan_url(url)
                if self.vt
                else asyncio.sleep(0, result=None)
            )
            ai_task = self.ml.phishing_classifier(url)

            vt_result, ai_result = await asyncio.gather(
                vt_task, ai_task, return_exceptions=True,
            )

            if _is_cancelled():
                return

            # ── Handle VirusTotal result ──────────────────────────────
            vt_data: dict = {}
            if isinstance(vt_result, Exception):
                logger.error("VT URL scan failed for %s: %s", scan_id, vt_result)
                vt_data = {"error": str(vt_result)}
            elif vt_result is not None:
                vt_data = vt_result

            # ── Handle AI result ──────────────────────────────────────
            ai_data: dict = {}
            if isinstance(ai_result, Exception):
                logger.error("AI classifier failed for %s: %s", scan_id, ai_result)
                ai_data = {"error": str(ai_result), "is_phishing": False, "confidence": 0.0}
            elif ai_result is not None:
                ai_data = ai_result

            # ── Determine combined threat level ───────────────────────
            vt_malicious  = vt_data.get("malicious", 0)
            vt_suspicious = vt_data.get("suspicious", 0)
            vt_total      = vt_data.get("total_engines", 0)

            ai_is_phishing = ai_data.get("is_phishing", False)
            ai_confidence  = ai_data.get("confidence", 0.0)

            threat_score, verdict, final_level = compute_threat_score(
                vt_malicious=vt_malicious,
                vt_total=vt_total,
                ai_is_phishing=ai_is_phishing,
                ai_confidence=ai_confidence,
            )

            # ── Build summary ─────────────────────────────────────────
            summary_parts = []
            if vt_data and not vt_data.get("error"):
                summary_parts.append(
                    f"VirusTotal: {vt_malicious}/{vt_total} engines flagged as malicious"
                )
            elif vt_data.get("error"):
                summary_parts.append("VirusTotal: scan failed")

            ai_label = "phishing" if ai_is_phishing else "safe"
            if ai_data.get("model") != "model_not_loaded":
                summary_parts.append(
                    f"AI Model: classified as {ai_label} "
                    f"(confidence: {ai_confidence:.1%})"
                )
            else:
                summary_parts.append("AI Model: not loaded")

            summary = ". ".join(summary_parts) + f". Threat Score: {threat_score:.2f} ({verdict}). Overall threat level: {final_level}."

            logger.info(
                "URL scan %s — VT: %s/%s malicious, AI: %s (%.2f), Score: %.2f, Verdict: %s, level: %s",
                scan_id, vt_malicious, vt_total, ai_label, ai_confidence, threat_score, verdict, final_level,
            )

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
                    "ai_classifier": ai_data,
                    "threat_score": threat_score,
                    "verdict": verdict,
                    "threat_level": final_level,
                },
                "indicators": [],
            }).execute()

            self._notify_completion(scan_id, final_level)

        except Exception as exc:  # noqa: BLE001
            logger.error("URL combined scan failed for %s: %s", scan_id, exc)
            if not _is_cancelled():
                self.supabase.table("scans").update(
                    {"status": "failed"}
                ).eq("id", scan_id).execute()
                self._notify_failure(scan_id)

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

            # ── Determine overall threat level dynamically ─────────────
            # Combine detecting-engine counts from both sources
            vt_malicious_count  = vt_data.get("malicious", 0)
            vt_suspicious_count = vt_data.get("suspicious", 0)
            malice_detected     = malice_data.get("detected_by", 0)

            threat_count = vt_malicious_count + vt_suspicious_count + malice_detected

            if threat_count == 0:
                final_level = "clean"
            elif threat_count <= 2:
                final_level = "low"
            elif threat_count <= 4:
                final_level = "medium"
            else:
                final_level = "high"

            # ── Stats for summary ─────────────────────────────────────────
            vt_total      = vt_data.get("total_engines", 0)
            mal_detected  = malice_data.get("detected_by", 0)
            mal_total     = malice_data.get("total_engines", 0)

            top_threat = (
                malice_data.get("top_result")
                or (f"{vt_malicious_count}/{vt_total} VT engines" if vt_malicious_count else None)
            )

            summary_parts = []
            if vt_data and not vt_data.get("error"):
                summary_parts.append(
                    f"VirusTotal: {vt_malicious_count}/{vt_total} engines flagged as malicious"
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
                    "threat_count": threat_count,
                },
                "indicators": [],
            }).execute()

            self._notify_completion(scan_id, final_level)

        except Exception as exc:  # noqa: BLE001
            logger.error("Combined scan failed for %s: %s", scan_id, exc)
            if not _is_cancelled():
                self.supabase.table("scans").update(
                    {"status": "failed"}
                ).eq("id", scan_id).execute()
                self._notify_failure(scan_id)
