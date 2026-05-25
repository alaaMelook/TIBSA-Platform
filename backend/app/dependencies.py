"""
Dependency injection for FastAPI.
Provides Supabase client and authenticated user extraction.
"""
import time
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client, Client

from app.config import settings

security = HTTPBearer()


# ─── Supabase Client (singleton) ─────────────────────────────
_supabase_client: Client | None = None


def get_supabase() -> Client:
    """Get a fresh Supabase client with service role key (full access)."""
    return create_client(
        settings.supabase_url, settings.supabase_service_role_key
    )


# ─── Token verification cache (5 min TTL) ────────────────────
_token_cache: dict[str, tuple[object, float]] = {}
_TOKEN_CACHE_TTL = 300  # seconds


def _get_cached_user(token: str):
    """Return cached user if token was verified within TTL, else None."""
    entry = _token_cache.get(token)
    if entry and (time.time() - entry[1]) < _TOKEN_CACHE_TTL:
        return entry[0]
    return None


def _cache_user(token: str, user) -> None:
    """Store a verified user in the cache."""
    # Evict stale entries periodically (keep cache bounded)
    if len(_token_cache) > 500:
        now = time.time()
        stale = [k for k, (_, ts) in _token_cache.items() if now - ts >= _TOKEN_CACHE_TTL]
        for k in stale:
            del _token_cache[k]
    _token_cache[token] = (user, time.time())


# In-memory user presence cache: user_id -> last_seen_iso_str
ACTIVE_PRESENCE: dict[str, str] = {}


def _update_db_last_seen(supabase: Client, user_id: str) -> None:
    """Update last_seen timestamp in public.users table."""
    try:
        from datetime import datetime, timezone
        supabase.table("users").update({
            "last_seen": datetime.now(timezone.utc).isoformat()
        }).eq("id", user_id).execute()
    except Exception:
        pass


# ─── Current User Extraction ─────────────────────────────────
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    supabase: Client = Depends(get_supabase),
) -> dict:
    """
    Extract and verify the current user from the JWT token.
    Uses in-memory cache to avoid hitting Supabase Auth on every request.
    """
    try:
        token = credentials.credentials

        # Check cache first — avoids a network round-trip
        cached = _get_cached_user(token)
        if cached:
            from datetime import datetime, timezone
            ACTIVE_PRESENCE[cached.id] = datetime.now(timezone.utc).isoformat()
            _update_db_last_seen(supabase, cached.id)
            return {"auth_user": cached, "token": token}

        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )

        _cache_user(token, user_response.user)
        from datetime import datetime, timezone
        ACTIVE_PRESENCE[user_response.user.id] = datetime.now(timezone.utc).isoformat()
        _update_db_last_seen(supabase, user_response.user.id)
        return {"auth_user": user_response.user, "token": token}
    except HTTPException:
        raise
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
