"""
Authentication service.
Handles Supabase Auth operations (login, register, token refresh).
"""
from fastapi import HTTPException, status
from supabase import Client


import logging
import secrets
import time
from typing import Dict

logger = logging.getLogger("security")
logger.setLevel(logging.INFO)
# Basic console handler for security logs
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - SECURITY - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

PENDING_MFA_STORE: Dict[str, dict] = {}

def store_pending_mfa(access_token: str, refresh_token: str, user_id: str) -> str:
    now = time.time()
    stale = [k for k, v in list(PENDING_MFA_STORE.items()) if now - v.get("created_at", 0) > 600]
    for k in stale:
        del PENDING_MFA_STORE[k]
        
    mfa_token = secrets.token_urlsafe(32)
    PENDING_MFA_STORE[mfa_token] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_id": user_id,
        "created_at": now,
        "failed_attempts": 0
    }
    return mfa_token

def get_pending_mfa(mfa_token: str) -> dict | None:
    now = time.time()
    data = PENDING_MFA_STORE.get(mfa_token)
    if data and now - data.get("created_at", 0) <= 600:
        return data
    return None

def increment_failed_mfa(mfa_token: str) -> int:
    """Increments the failed_attempts counter and returns the new count. Returns 0 if not found."""
    if mfa_token in PENDING_MFA_STORE:
        PENDING_MFA_STORE[mfa_token]["failed_attempts"] += 1
        return PENDING_MFA_STORE[mfa_token]["failed_attempts"]
    return 0

def delete_pending_mfa(mfa_token: str) -> None:
    if mfa_token in PENDING_MFA_STORE:
        del PENDING_MFA_STORE[mfa_token]

def mask_email(email: str) -> str:
    """Mask email for security logging."""
    if not email or "@" not in email:
        return "***"
    try:
        username, domain = email.split("@", 1)
        masked_username = username[0] + "***" if username else "***"
        return f"{masked_username}@{domain}"
    except Exception:
        return "***"

def parse_user_agent(ua: str) -> str:
    """Parse raw user agent into a clean human-readable OS and Browser string."""
    if not ua:
        return "Unknown Device"
    
    ua_lower = ua.lower()
    
    # Identify Operating System
    os_name = "Unknown OS"
    if "windows nt 10.0" in ua_lower:
        os_name = "Windows 10/11"
    elif "windows nt 6.1" in ua_lower:
        os_name = "Windows 7"
    elif "macintosh" in ua_lower or "mac os x" in ua_lower:
        os_name = "macOS"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os_name = "iOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
        
    # Identify Browser
    browser_name = "Unknown Browser"
    if "edg/" in ua_lower:
        browser_name = "Edge"
    elif "chrome/" in ua_lower:
        browser_name = "Chrome"
    elif "safari/" in ua_lower:
        browser_name = "Safari"
    elif "firefox/" in ua_lower:
        browser_name = "Firefox"
    elif "opera/" in ua_lower or "opr/" in ua_lower:
        browser_name = "Opera"
        
    return f"{browser_name} ({os_name})"

class AuthService:
    def __init__(self, supabase: Client):
        self.supabase = supabase
        from app.dependencies import get_supabase
        self.system_supabase = get_supabase()
        from app.services.account_lockout_service import AccountLockoutService
        self.lockout_service = AccountLockoutService(self.system_supabase)

    async def login(self, email: str, password: str, ip_address: str = "0.0.0.0", user_agent: str = "Unknown") -> dict:
        """Authenticate user via Supabase Auth."""
        try:
            # ── Account Lockout Check ─────────────────────────────
            lockout_res = self.lockout_service.is_locked(email)
            
            # Defensive check before unpacking
            if not isinstance(lockout_res, tuple) or len(lockout_res) != 3:
                logger.error(f"Lockout check returned invalid type/length: {lockout_res}")
                is_locked, remaining_secs, reason = True, 1800, "invalid_return"
            else:
                is_locked, remaining_secs, reason = lockout_res

            if is_locked:
                minutes_left = max(1, remaining_secs // 60)
                logger.warning(f"Login blocked for locked account: {mask_email(email)}, Reason: {reason}")
                raise HTTPException(
                    status_code=429,
                    detail="Too many failed login attempts. Please try again after 30 minutes.",
                )

            response = self.supabase.auth.sign_in_with_password({
                "email": email,
                "password": password,
            })

            if not response.session:
                logger.warning(f"Failed login attempt for email: {mask_email(email)}")
                try:
                    self.system_supabase.table("audit_logs").insert({
                        "action_type": "LOGIN_FAILED",
                        "severity": "critical",
                        "message": f"Failed login attempt for {email}",
                        "ip_address": ip_address,
                        "metadata": {
                            "resource": "auth", 
                            "email": email, 
                            "user_agent": parse_user_agent(user_agent)
                        }
                    }).execute()
                    self.system_supabase.table("login_attempts").insert({
                        "email": email,
                        "ip_address": ip_address,
                        "user_agent": user_agent,
                        "status": "failed"
                    }).execute()
                    self.lockout_service.record_failed_attempt(email, ip_address)
                except Exception:
                    pass
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                )

            # Fetch user profile from DB
            user_data = self.system_supabase.table("users") \
                .select("*") \
                .eq("id", response.user.id) \
                .single() \
                .execute()

            # Clear any existing lockout on successful login
            self.lockout_service.clear_on_success(email)

            logger.info(f"Successful login for email: {mask_email(email)}")
            
            try:
                self.system_supabase.table("audit_logs").insert({
                    "user_id": response.user.id,
                    "action_type": "LOGIN",
                    "severity": "info",
                    "message": "User logged in successfully.",
                    "ip_address": ip_address,
                    "metadata": {
                        "resource": "auth",
                        "user_agent": parse_user_agent(user_agent)
                    }
                }).execute()
            except Exception as e:
                logger.error(f"Error inserting audit log: {str(e)}")
            
            try:
                self.system_supabase.table("login_attempts").insert({
                    "email": email,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "status": "success"
                }).execute()
            except Exception as e:
                logger.error(f"Error inserting login attempt: {str(e)}")

            mfa_required = False
            factor_id = None
            if getattr(response.user, "factors", None):
                for factor in response.user.factors:
                    if getattr(factor, "status", None) == "verified" and getattr(factor, "factor_type", None) == "totp":
                        mfa_required = True
                        factor_id = getattr(factor, "id", None)
                        break

            if mfa_required:
                pending_mfa_token = store_pending_mfa(
                    response.session.access_token,
                    response.session.refresh_token,
                    response.user.id
                )
                return {
                    "mfa_required": True,
                    "factor_id": factor_id,
                    "mfa_token": pending_mfa_token,
                    "token_type": "bearer",
                }

            return {
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token,
                "token_type": "bearer",
                "user": user_data.data if user_data.data else None,
                "mfa_required": False,
            }
        except HTTPException:
            raise
        except Exception as e:
            error_reason = "Invalid credentials"
            if hasattr(e, "message") and e.message:
                error_reason = e.message
            elif str(e):
                error_reason = str(e)
                if "AuthApiError" in error_reason or "APIError" in error_reason:
                    error_reason = error_reason.split(":")[-1].strip()

            logger.warning(f"Failed login attempt for email: {mask_email(email)} - Reason: {error_reason}")
            try:
                self.system_supabase.table("audit_logs").insert({
                    "action_type": "LOGIN_FAILED",
                    "severity": "critical",
                    "message": f"Failed login attempt for {email} ({error_reason})",
                    "ip_address": ip_address,
                    "metadata": {
                        "resource": "auth", 
                        "email": email, 
                        "reason": error_reason, 
                        "user_agent": parse_user_agent(user_agent)
                    }
                }).execute()
                self.system_supabase.table("login_attempts").insert({
                    "email": email,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "status": "failed"
                }).execute()
                self.lockout_service.record_failed_attempt(email, ip_address)
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

    async def register(self, email: str, password: str, full_name: str, ip_address: str = "0.0.0.0", user_agent: str = "Unknown") -> dict:
        """Register a new user. Role defaults to 'user'."""
        try:
            # Check if email is already registered to prevent duplicate key and foreign key constraint errors
            existing = self.system_supabase.table("users").select("id").eq("email", email).execute()
            if existing.data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email is already registered. Please sign in instead.",
                )

            # 1. Create in Supabase Auth
            response = self.supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {"data": {"full_name": full_name}},
            })

            if not response.user:
                logger.warning(f"Failed registration attempt for email: {mask_email(email)}")
                try:
                    self.system_supabase.table("audit_logs").insert({
                        "action_type": "SIGNUP_FAILED",
                        "severity": "critical",
                        "message": f"Failed signup attempt for {email}",
                        "ip_address": ip_address,
                        "metadata": {
                            "resource": "auth", 
                            "email": email,
                            "user_agent": parse_user_agent(user_agent)
                        }
                    }).execute()
                    self.system_supabase.table("login_attempts").insert({
                        "email": email,
                        "ip_address": ip_address,
                        "user_agent": user_agent,
                        "status": "failed"
                    }).execute()
                except Exception:
                    pass
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Registration failed",
                )

            # 2. Create profile in users table (role = "user" by default)
            self.system_supabase.table("users").insert({
                "id": response.user.id,
                "email": email,
                "full_name": full_name,
                "role": "user",
                "is_active": True,
            }).execute()

            logger.info(f"Successful registration for email: {mask_email(email)}")
            
            try:
                self.system_supabase.table("audit_logs").insert({
                    "user_id": response.user.id,
                    "action_type": "SIGNUP",
                    "severity": "info",
                    "message": "User registered and logged in successfully.",
                    "ip_address": ip_address,
                    "metadata": {
                        "resource": "auth",
                        "user_agent": parse_user_agent(user_agent)
                    }
                }).execute()
                self.system_supabase.table("login_attempts").insert({
                    "email": email,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "status": "success"
                }).execute()
            except Exception:
                pass

            return {
                "access_token": response.session.access_token if response.session else "",
                "refresh_token": response.session.refresh_token if response.session else "",
                "token_type": "bearer",
            }
        except HTTPException:
            raise
        except Exception as e:
            error_reason = "Registration failed"
            if hasattr(e, "message") and e.message:
                error_reason = e.message
            elif str(e):
                error_reason = str(e)
                if "AuthApiError" in error_reason or "APIError" in error_reason:
                    error_reason = error_reason.split(":")[-1].strip()

            logger.warning(f"Failed registration attempt for email: {mask_email(email)} - Reason: {error_reason}")
            try:
                self.system_supabase.table("audit_logs").insert({
                    "action_type": "SIGNUP_FAILED",
                    "severity": "critical",
                    "message": f"Failed signup attempt for {email} ({error_reason})",
                    "ip_address": ip_address,
                    "metadata": {
                        "resource": "auth", 
                        "email": email, 
                        "reason": error_reason,
                        "user_agent": parse_user_agent(user_agent)
                    }
                }).execute()
                self.system_supabase.table("login_attempts").insert({
                    "email": email,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "status": "failed"
                }).execute()
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_reason,
            )

    async def refresh_token(self, refresh_token: str) -> dict:
        """Refresh an access token."""
        try:
            response = self.supabase.auth.refresh_session(refresh_token)
            return {
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token,
                "token_type": "bearer",
            }
        except Exception as e:
            logger.warning(f"Failed token refresh attempt")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token refresh failed",
            )
