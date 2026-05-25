"""
Authentication service.
Handles Supabase Auth operations (login, register, token refresh).
"""
from fastapi import HTTPException, status
from supabase import Client


import logging

logger = logging.getLogger("security")
logger.setLevel(logging.INFO)
# Basic console handler for security logs
if not logger.handlers:
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - SECURITY - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

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

    async def login(self, email: str, password: str, ip_address: str = "0.0.0.0", user_agent: str = "Unknown") -> dict:
        """Authenticate user via Supabase Auth."""
        try:
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

            return {
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token,
                "token_type": "bearer",
                "user": user_data.data if user_data.data else None,
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
