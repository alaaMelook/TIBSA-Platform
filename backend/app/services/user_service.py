"""
User service.
Handles user profile CRUD and role management.
"""
from fastapi import HTTPException, status
from supabase import Client
from typing import List


class UserService:
    def __init__(self, supabase: Client):
        self.supabase = supabase

    async def get_profile(self, user_id: str) -> dict:
        """Get a user's profile by ID."""
        response = self.supabase.table("users") \
            .select("*") \
            .eq("id", user_id) \
            .single() \
            .execute()

        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User profile not found",
            )
        return response.data

    async def create_profile(self, user_id: str, email: str, full_name: str) -> dict:
        """Create a new user profile (called after Supabase Auth signup)."""
        response = self.supabase.table("users").insert({
            "id": user_id,
            "email": email,
            "full_name": full_name,
            "role": "user",       # ← Always defaults to "user"
            "is_active": True,
        }).execute()

        return response.data[0] if response.data else {}

    async def update_profile(self, user_id: str, data: dict) -> dict:
        """Update a user's profile."""
        response = self.supabase.table("users") \
            .update(data) \
            .eq("id", user_id) \
            .execute()

        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return response.data[0]

    async def list_all_users(self) -> List[dict]:
        """List all users (admin only)."""
        response = self.supabase.table("users") \
            .select("*") \
            .order("created_at", desc=True) \
            .execute()

        return response.data or []

    async def update_role(self, user_id: str, new_role: str) -> dict:
        """
        Update a user's role (admin only).
        Only 'user' and 'admin' are valid roles.
        """
        if new_role not in ("user", "admin"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid role. Must be 'user' or 'admin'.",
            )

        response = self.supabase.table("users") \
            .update({"role": new_role}) \
            .eq("id", user_id) \
            .execute()

        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        return {"message": f"User role updated to '{new_role}'", "user": response.data[0]}
