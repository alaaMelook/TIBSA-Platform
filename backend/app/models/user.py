"""
User-related Pydantic models (request/response schemas).
"""
import re
from pydantic import BaseModel, EmailStr, field_validator
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
    
    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one number")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("Password must contain at least one special character")
        return v


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
