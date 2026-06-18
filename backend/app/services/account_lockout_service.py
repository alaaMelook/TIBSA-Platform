"""
Account Lockout Service.
Enforces account lockout after consecutive failed login attempts.
- 5 failed attempts within 30 minutes → account locked for 30 minutes.
- Creates a notification for the user and logs a security audit event.
"""
import logging
from datetime import datetime, timezone, timedelta
from supabase import Client

logger = logging.getLogger("security")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_MINUTES = 30
LOCKOUT_DURATION_MINUTES = 30


class AccountLockoutService:
    """Manages brute-force account lockout logic."""

    def __init__(self, supabase: Client):
        self.supabase = supabase

    def is_locked(self, email: str) -> tuple[bool, int, str | None]:
        """
        Check if an email is currently locked.
        Returns (is_locked: bool, remaining_seconds: int, reason: str | None).
        """
        if not email:
            return False, 0, None
            
        try:
            now = datetime.now(timezone.utc).isoformat()
            result = (
                self.supabase.table("account_lockouts")
                .select("locked_until")
                .eq("email", email.lower())
                .gt("locked_until", now)
                .order("locked_until", desc=True)
                .limit(1)
                .execute()
            )
            if result.data:
                locked_until = datetime.fromisoformat(
                    result.data[0]["locked_until"].replace("Z", "+00:00")
                )
                remaining = int((locked_until - datetime.now(timezone.utc)).total_seconds())
                return True, max(remaining, 0), "account_locked"
            return False, 0, None
        except Exception as e:
            logger.error(f"Error checking lockout status: {e}", exc_info=True)
            return True, 1800, "lockout_check_failed"

    def record_failed_attempt(self, email: str, ip_address: str) -> bool:
        """
        Record a failed login attempt.
        If the threshold is reached, create a lockout.
        Returns True if the account is now locked.
        """
        try:
            email_lower = email.lower()
            window_start = (
                datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)
            ).isoformat()

            # Count recent consecutive failures
            result = (
                self.supabase.table("login_attempts")
                .select("id", count="exact")
                .eq("email", email_lower)
                .eq("status", "failed")
                .gt("created_at", window_start)
                .execute()
            )
            failure_count = result.count or 0

            if failure_count >= MAX_FAILED_ATTEMPTS:
                return self._create_lockout(email_lower, ip_address, failure_count)

        except Exception as e:
            logger.error(f"Error recording failed attempt: {e}")
        return False

    def clear_on_success(self, email: str) -> None:
        """
        On successful login, remove any active lockout records for this email.
        The login_attempts history is preserved for auditing.
        """
        try:
            self.supabase.table("account_lockouts").delete().eq(
                "email", email.lower()
            ).execute()
        except Exception as e:
            logger.error(f"Error clearing lockout: {e}")

    def _create_lockout(self, email: str, ip_address: str, attempt_count: int) -> bool:
        """Create a lockout record and send notifications."""
        try:
            locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=LOCKOUT_DURATION_MINUTES
            )

            # Upsert lockout record
            self.supabase.table("account_lockouts").insert(
                {
                    "email": email,
                    "locked_until": locked_until.isoformat(),
                    "attempt_count": attempt_count,
                }
            ).execute()

            # Audit log entry
            self.supabase.table("audit_logs").insert(
                {
                    "action_type": "ACCOUNT_LOCKED",
                    "severity": "critical",
                    "message": f"Account locked for {email} after {attempt_count} failed attempts.",
                    "ip_address": ip_address,
                    "metadata": {
                        "resource": "auth",
                        "email": email,
                        "attempt_count": attempt_count,
                        "locked_until": locked_until.isoformat(),
                    },
                }
            ).execute()

            # In-app notification for the user (if they have a profile)
            try:
                user_result = (
                    self.supabase.table("users")
                    .select("id")
                    .eq("email", email)
                    .limit(1)
                    .execute()
                )
                if user_result.data:
                    user_id = user_result.data[0]["id"]
                    from app.services.notification_service import NotificationService
                    notif_service = NotificationService(self.supabase)
                    notif_service.create(
                        user_id=user_id,
                        title="Account Temporarily Locked",
                        body=(
                            f"Your account has been locked for {LOCKOUT_DURATION_MINUTES} minutes "
                            f"due to {attempt_count} consecutive failed login attempts. "
                            f"If this wasn't you, please change your password immediately."
                        ),
                        notif_type="security",
                    )
            except Exception as e:
                logger.error(f"Error sending lockout notification: {e}")

            logger.warning(
                f"ACCOUNT LOCKED: {email} — {attempt_count} failed attempts. "
                f"Locked until {locked_until.isoformat()}"
            )
            return True
        except Exception as e:
            logger.error(f"Error creating lockout: {e}")
            return False
