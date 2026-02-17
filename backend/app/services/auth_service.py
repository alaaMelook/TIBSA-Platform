"""
Authentication service.
Handles Supabase Auth operations (login, register, token refresh).
"""
from fastapi import HTTPException, status
from supabase import Client


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

            return {
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token,
                "token_type": "bearer",
                "user": user_data.data if user_data.data else None,
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Login failed: {str(e)}",
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

            return {
                "access_token": response.session.access_token if response.session else "",
                "refresh_token": response.session.refresh_token if response.session else "",
                "token_type": "bearer",
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Registration failed: {str(e)}",
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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token refresh failed: {str(e)}",
            )
