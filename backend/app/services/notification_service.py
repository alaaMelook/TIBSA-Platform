"""
Notification service.
Creates real notifications in the database when scans complete or fail.
"""
import logging
import uuid

from supabase import Client

logger = logging.getLogger(__name__)


class NotificationService:
    """Manages user notifications stored in the notifications table."""

    def __init__(self, supabase: Client):
        self.supabase = supabase

    # ── Core create ──────────────────────────────────────────

    def create(
        self,
        user_id: str,
        title: str,
        body: str,
        notif_type: str = "system",
        scan_id: str | None = None,
    ) -> dict | None:
        """Insert a notification row. Returns the row or None on error."""
        try:
            row = {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "title": title,
                "body": body,
                "type": notif_type,
                "read": False,
            }
            if scan_id:
                row["scan_id"] = scan_id
            resp = self.supabase.table("notifications").insert(row).execute()
            return resp.data[0] if resp.data else row
        except Exception as exc:
            logger.warning("Failed to create notification: %s", exc)
            return None

    # ── Scan-specific helpers ────────────────────────────────

    def notify_scan_completed(
        self,
        user_id: str,
        scan_id: str,
        scan_type: str,
        target: str,
        threat_level: str,
    ) -> None:
        """Create a notification when a scan finishes successfully."""
        type_label = "URL" if scan_type == "url" else "File"
        short_target = target if len(target) <= 50 else target[:47] + "..."

        if threat_level in ("high", "critical"):
            title = f"High-severity threat detected"
            body = f"{type_label} scan for {short_target} — threat level: {threat_level}."
            notif_type = "threat"
        elif threat_level in ("medium", "low"):
            title = f"Scan completed — {threat_level} risk"
            body = f"{type_label} scan for {short_target} found {threat_level}-level threats."
            notif_type = "scan"
        else:
            title = "Scan completed — clean"
            body = f"{type_label} scan for {short_target} found no threats."
            notif_type = "scan"

        self.create(user_id, title, body, notif_type, scan_id)

    def notify_scan_failed(
        self,
        user_id: str,
        scan_id: str,
        scan_type: str,
        target: str,
    ) -> None:
        """Create a notification when a scan fails."""
        type_label = "URL" if scan_type == "url" else "File"
        short_target = target if len(target) <= 50 else target[:47] + "..."
        self.create(
            user_id,
            "Scan failed",
            f"{type_label} scan for {short_target} failed. Please try again.",
            "system",
            scan_id,
        )

    # ── Query helpers ────────────────────────────────────────

    def list_for_user(self, user_id: str, limit: int = 30) -> list[dict]:
        """Return recent notifications for a user, newest first."""
        resp = (
            self.supabase.table("notifications")
            .select("*")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return resp.data or []

    def unread_count(self, user_id: str) -> int:
        """Return the number of unread notifications."""
        resp = (
            self.supabase.table("notifications")
            .select("id", count="exact")
            .eq("user_id", user_id)
            .eq("read", False)
            .execute()
        )
        return resp.count or 0

    def mark_read(self, notification_id: str, user_id: str) -> dict | None:
        """Mark a single notification as read."""
        resp = (
            self.supabase.table("notifications")
            .update({"read": True})
            .eq("id", notification_id)
            .eq("user_id", user_id)
            .execute()
        )
        return resp.data[0] if resp.data else None

    def mark_all_read(self, user_id: str) -> int:
        """Mark all unread notifications as read. Returns count updated."""
        resp = (
            self.supabase.table("notifications")
            .update({"read": True})
            .eq("user_id", user_id)
            .eq("read", False)
            .execute()
        )
        return len(resp.data) if resp.data else 0

