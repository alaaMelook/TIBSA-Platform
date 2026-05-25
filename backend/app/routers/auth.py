"""
Authentication router.
Handles login, register, token refresh, and MFA verification.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from supabase import Client

from app.dependencies import get_supabase, get_current_user
from app.models.user import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    RefreshTokenRequest,
)
from app.services.auth_service import AuthService
from app.utils.limiter import limiter

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(request: Request, payload: LoginRequest, supabase: Client = Depends(get_supabase)):
    """Authenticate user and return access token."""
    print("[RATE LIMIT] login limiter active")
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    service = AuthService(supabase)
    return await service.login(payload.email, payload.password, client_ip, user_agent)


@router.post("/register", response_model=TokenResponse)
@limiter.limit("3/minute")
async def register(request: Request, payload: RegisterRequest, supabase: Client = Depends(get_supabase)):
    """Register a new user (defaults to 'user' role)."""
    print("[RATE LIMIT] register limiter active")
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    service = AuthService(supabase)
    return await service.register(
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        ip_address=client_ip,
        user_agent=user_agent,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest, supabase: Client = Depends(get_supabase)
):
    """Refresh an access token."""
    service = AuthService(supabase)
    return await service.refresh_token(request.refresh_token)


@router.post("/logout")
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Sign out the current user."""
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    try:
        auth_user = current_user["auth_user"]
        
        # 1. Update last_seen in DB
        try:
            from datetime import datetime, timezone
            supabase.table("users").update({
                "last_seen": datetime.now(timezone.utc).isoformat()
            }).eq("id", auth_user.id).execute()
        except Exception:
            pass
            
        # 2. Write LOGOUT audit log
        try:
            from app.services.auth_service import parse_user_agent
            supabase.table("audit_logs").insert({
                "user_id": auth_user.id,
                "action_type": "LOGOUT",
                "severity": "info",
                "message": "User logged out successfully.",
                "ip_address": client_ip,
                "metadata": {
                    "resource": "auth",
                    "user_agent": parse_user_agent(user_agent)
                }
            }).execute()
        except Exception:
            pass

        supabase.auth.sign_out()
        return {"message": "Logged out successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}",
        )
