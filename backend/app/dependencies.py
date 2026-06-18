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
    Detects OAuth logins (Google, GitHub) and logs them to audit_logs.
    Auto-creates a profile row for new OAuth users.
    """
    try:
        token = credentials.credentials

        import jwt
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            aal = decoded.get("aal", "aal1")
        except Exception:
            aal = "aal1"

        def _enforce_aal2(user_obj):
            factors = getattr(user_obj, "factors", []) or []
            mfa_enrolled = any(getattr(f, "status", None) == "verified" and getattr(f, "factor_type", None) == "totp" for f in factors)
            if mfa_enrolled and aal == "aal1":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="MFA verification required (AAL2)",
                )

        # Check cache first — avoids a network round-trip
        cached = _get_cached_user(token)
        if cached:
            _enforce_aal2(cached)
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

        auth_user = user_response.user
        _enforce_aal2(auth_user)

        # Check if user is inactive in the users table
        user_record = supabase.table("users").select("is_active").eq("id", auth_user.id).execute()
        if user_record.data and user_record.data[0].get("is_active") is False:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account has been deactivated. Please contact support.",
            )

        # ── Auto-create profile for new OAuth users ───────────────
        if not user_record.data:
            try:
                email = auth_user.email or ""
                meta = auth_user.user_metadata or {}
                full_name = (
                    meta.get("full_name")
                    or meta.get("name")
                    or meta.get("user_name")
                    or (email.split("@")[0] if email else "User")
                )
                supabase.table("users").insert({
                    "id": auth_user.id,
                    "email": email,
                    "full_name": full_name,
                    "role": "user",
                    "is_active": True,
                }).execute()
            except Exception:
                pass  # Ignore duplicate inserts (concurrent requests)

        # ── Audit log for OAuth logins (first appearance in session) ──
        if auth_user.id not in ACTIVE_PRESENCE:
            try:
                app_meta = auth_user.app_metadata or {}
                provider = app_meta.get("provider", "email")
                if provider in ("google", "github"):
                    from datetime import datetime, timezone
                    supabase.table("audit_logs").insert({
                        "user_id": auth_user.id,
                        "action_type": "LOGIN",
                        "severity": "info",
                        "message": f"User signed in via {provider.title()} OAuth.",
                        "metadata": {
                            "resource": "auth",
                            "provider": provider,
                        },
                    }).execute()
            except Exception:
                pass  # Never block auth on audit failure

        _cache_user(token, auth_user)
        from datetime import datetime, timezone
        ACTIVE_PRESENCE[auth_user.id] = datetime.now(timezone.utc).isoformat()
        _update_db_last_seen(supabase, auth_user.id)
        return {"auth_user": auth_user, "token": token}
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
