"""
User repository.
Data access layer for user-related Supabase queries.
"""
from supabase import Client
from typing import Optional, List


class UserRepository:
    def __init__(self, supabase: Client):
        self.supabase = supabase
        self.table = "users"

    async def find_by_id(self, user_id: str) -> Optional[dict]:
        response = self.supabase.table(self.table) \
            .select("*") \
            .eq("id", user_id) \
            .single() \
            .execute()
        return response.data

    async def find_by_email(self, email: str) -> Optional[dict]:
        response = self.supabase.table(self.table) \
            .select("*") \
            .eq("email", email) \
            .single() \
            .execute()
        return response.data

    async def find_all(self) -> List[dict]:
        response = self.supabase.table(self.table) \
            .select("*") \
            .order("created_at", desc=True) \
            .execute()
        return response.data or []

    async def create(self, data: dict) -> dict:
        response = self.supabase.table(self.table) \
            .insert(data) \
            .execute()
        return response.data[0] if response.data else {}

    async def update(self, user_id: str, data: dict) -> Optional[dict]:
        response = self.supabase.table(self.table) \
            .update(data) \
            .eq("id", user_id) \
            .execute()
        return response.data[0] if response.data else None

    async def delete(self, user_id: str) -> bool:
        response = self.supabase.table(self.table) \
            .delete() \
            .eq("id", user_id) \
            .execute()
        return bool(response.data)
