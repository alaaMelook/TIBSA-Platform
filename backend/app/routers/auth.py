"""
Authentication router.
Handles login, register, token refresh, and MFA verification.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from supabase import Client

from app.dependencies import get_supabase
from app.models.user import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    RefreshTokenRequest,
)
from app.services.auth_service import AuthService

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, supabase: Client = Depends(get_supabase)):
    """Authenticate user and return access token."""
    service = AuthService(supabase)
    return await service.login(request.email, request.password)


@router.post("/register", response_model=TokenResponse)
async def register(request: RegisterRequest, supabase: Client = Depends(get_supabase)):
    """Register a new user (defaults to 'user' role)."""
    service = AuthService(supabase)
    return await service.register(
        email=request.email,
        password=request.password,
        full_name=request.full_name,
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
