"""
User-related Pydantic models (request/response schemas).
"""
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


# ─── Request Models ──────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserRegisterProfile(BaseModel):
    email: EmailStr
    full_name: str


class UpdateRoleRequest(BaseModel):
    """Used by admins to change a user's role."""
    role: str  # "user" or "admin"


class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None


# ─── Response Models ─────────────────────────────────────────

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: Optional[UserResponse] = None
