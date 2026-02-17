"""
Users router.
Handles user profiles, role management (admin-only), and user CRUD.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from supabase import Client

from app.dependencies import get_supabase, get_current_user, require_admin
from app.models.user import UserResponse, UserRegisterProfile, UpdateRoleRequest
from app.services.user_service import UserService

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_my_profile(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Get the current user's profile."""
    service = UserService(supabase)
    auth_user = current_user["auth_user"]
    return await service.get_profile(auth_user.id)


@router.post("/register")
async def register_profile(
    data: UserRegisterProfile,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Create a user profile after Supabase Auth registration."""
    service = UserService(supabase)
    auth_user = current_user["auth_user"]
    return await service.create_profile(
        user_id=auth_user.id,
        email=data.email,
        full_name=data.full_name,
    )


@router.put("/me", response_model=UserResponse)
async def update_my_profile(
    data: UserRegisterProfile,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Update the current user's profile."""
    service = UserService(supabase)
    auth_user = current_user["auth_user"]
    return await service.update_profile(auth_user.id, data.dict(exclude_unset=True))


# ─── Admin-Only Endpoints ────────────────────────────────────

@router.get("/", response_model=List[UserResponse])
async def list_users(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """List all users (admin only)."""
    service = UserService(supabase)
    return await service.list_all_users()


@router.patch("/{user_id}/role")
async def update_user_role(
    user_id: str,
    data: UpdateRoleRequest,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """Change a user's role (admin only). This is how admins promote users."""
    service = UserService(supabase)
    return await service.update_role(user_id, data.role)
