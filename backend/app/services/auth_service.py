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

class AuthService:
    def __init__(self, supabase: Client):
        self.supabase = supabase

    async def login(self, email: str, password: str) -> dict:
        """Authenticate user via Supabase Auth."""
        try:
            response = self.supabase.auth.sign_in_with_password({
                "email": email,
                "password": password,
            })

            if not response.session:
                logger.warning(f"Failed login attempt for email: {mask_email(email)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                )

            # Fetch user profile from DB
            user_data = self.supabase.table("users") \
                .select("*") \
                .eq("id", response.user.id) \
                .single() \
                .execute()

            logger.info(f"Successful login for email: {mask_email(email)}")
            return {
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token,
                "token_type": "bearer",
                "user": user_data.data if user_data.data else None,
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Failed login attempt for email: {mask_email(email)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

    async def register(self, email: str, password: str, full_name: str) -> dict:
        """Register a new user. Role defaults to 'user'."""
        try:
            # 1. Create in Supabase Auth
            response = self.supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {"data": {"full_name": full_name}},
            })

            if not response.user:
                logger.warning(f"Failed registration attempt for email: {mask_email(email)}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Registration failed",
                )

            # 2. Create profile in users table (role = "user" by default)
            self.supabase.table("users").insert({
                "id": response.user.id,
                "email": email,
                "full_name": full_name,
                "role": "user",
                "is_active": True,
            }).execute()

            logger.info(f"Successful registration for email: {mask_email(email)}")
            return {
                "access_token": response.session.access_token if response.session else "",
                "refresh_token": response.session.refresh_token if response.session else "",
                "token_type": "bearer",
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.warning(f"Failed registration attempt for email: {mask_email(email)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration failed",
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
