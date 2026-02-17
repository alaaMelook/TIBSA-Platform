"""
Dependency injection for FastAPI.
Provides Supabase client and authenticated user extraction.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client, Client

from app.config import settings

security = HTTPBearer()


# ─── Supabase Client ─────────────────────────────────────────
def get_supabase() -> Client:
    """Get a Supabase client with service role key (full access)."""
    return create_client(settings.supabase_url, settings.supabase_service_role_key)


# ─── Current User Extraction ─────────────────────────────────
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    supabase: Client = Depends(get_supabase),
) -> dict:
    """
    Extract and verify the current user from the JWT token.
    Returns the user data from Supabase Auth.
    """
    try:
        token = credentials.credentials
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )
        return {"auth_user": user_response.user, "token": token}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}",
        )


# ─── Admin-Only Dependency ───────────────────────────────────
async def require_admin(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
) -> dict:
    """
    Require the current user to have the 'admin' role.
    Checks the users table in Supabase for the role field.
    """
    auth_user = current_user["auth_user"]
    response = supabase.table("users").select("role").eq("id", auth_user.id).single().execute()

    if not response.data or response.data.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return current_user
