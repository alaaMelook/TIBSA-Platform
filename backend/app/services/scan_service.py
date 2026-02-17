"""
Scan service.
Handles URL/file scanning logic and report generation.
"""
from fastapi import HTTPException, status
from supabase import Client
from typing import List
import uuid


class ScanService:
    def __init__(self, supabase: Client):
        self.supabase = supabase

    async def scan_url(self, user_id: str, url: str) -> dict:
        """Create a new URL scan."""
        scan_data = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "scan_type": "url",
            "target": url,
            "status": "pending",
            "threat_level": None,
        }

        response = self.supabase.table("scans").insert(scan_data).execute()

        # TODO: Trigger async scan processing (e.g., via background task or queue)
        # This is where you'd integrate with the ML Engine / Sandbox services

        return response.data[0] if response.data else scan_data

    async def scan_file(self, user_id: str, file_hash: str) -> dict:
        """Create a new file scan."""
        scan_data = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "scan_type": "file",
            "target": file_hash,
            "status": "pending",
            "threat_level": None,
        }

        response = self.supabase.table("scans").insert(scan_data).execute()

        # TODO: Trigger async file analysis

        return response.data[0] if response.data else scan_data

    async def list_user_scans(self, user_id: str) -> List[dict]:
        """List all scans for a specific user."""
        response = self.supabase.table("scans") \
            .select("*") \
            .eq("user_id", user_id) \
            .order("created_at", desc=True) \
            .execute()

        return response.data or []

    async def get_report(self, scan_id: str, user_id: str) -> dict:
        """Get the full report for a scan."""
        # Verify ownership
        scan = self.supabase.table("scans") \
            .select("*") \
            .eq("id", scan_id) \
            .eq("user_id", user_id) \
            .single() \
            .execute()

        if not scan.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        # Get report
        report = self.supabase.table("scan_reports") \
            .select("*") \
            .eq("scan_id", scan_id) \
            .single() \
            .execute()

        if not report.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not yet available",
            )

        return report.data
