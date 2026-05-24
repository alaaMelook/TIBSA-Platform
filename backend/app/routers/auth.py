"""
Authentication router.
Handles login, register, token refresh, and MFA verification.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from supabase import Client

from app.dependencies import get_supabase
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
    service = AuthService(supabase)
    return await service.login(payload.email, payload.password)


@router.post("/register", response_model=TokenResponse)
@limiter.limit("3/minute")
async def register(request: Request, payload: RegisterRequest, supabase: Client = Depends(get_supabase)):
    """Register a new user (defaults to 'user' role)."""
    print("[RATE LIMIT] register limiter active")
    service = AuthService(supabase)
    return await service.register(
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest, supabase: Client = Depends(get_supabase)
):
    """Refresh an access token."""
    service = AuthService(supabase)
    return await service.refresh_token(request.refresh_token)


@router.post("/logout")
async def logout(supabase: Client = Depends(get_supabase)):
    """Sign out the current user."""
    try:
        supabase.auth.sign_out()
        return {"message": "Logged out successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}",
        )
