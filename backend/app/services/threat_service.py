"""
Threat Intelligence service.
Handles threat feeds, IOC lookups, and reputation checks.
"""
from supabase import Client
from typing import List


class ThreatService:
    def __init__(self, supabase: Client):
        self.supabase = supabase

    async def list_feeds(self) -> List[dict]:
        """List all active threat intelligence feeds."""
        response = self.supabase.table("threat_feeds") \
            .select("*") \
            .eq("is_active", True) \
            .execute()

        return response.data or []

    async def lookup_ioc(self, indicator_type: str, value: str) -> List[dict]:
        """
        Look up an Indicator of Compromise.
        Searches the threat_indicators table.
        """
        response = self.supabase.table("threat_indicators") \
            .select("*") \
            .eq("type", indicator_type) \
            .eq("value", value) \
            .execute()

        return response.data or []

    async def check_reputation(self, target: str) -> dict:
        """
        Check the reputation of a domain/IP/URL.
        TODO: Integrate with external threat intel APIs (VirusTotal, AbuseIPDB, etc.)
        """
        # Placeholder — check local DB first
        response = self.supabase.table("threat_indicators") \
            .select("*") \
            .eq("value", target) \
            .execute()

        if response.data:
            highest_threat = max(response.data, key=lambda x: self._threat_score(x.get("threat_level", "safe")))
            return {
                "target": target,
                "reputation_score": self._threat_score(highest_threat.get("threat_level", "safe")),
                "threat_level": highest_threat.get("threat_level", "safe"),
                "details": {"matches": len(response.data)},
                "sources_checked": ["local_db"],
            }

        return {
            "target": target,
            "reputation_score": 0.0,
            "threat_level": "safe",
            "details": {},
            "sources_checked": ["local_db"],
        }

    async def merge_feeds(self) -> dict:
        """
        Merge and update all threat feeds (admin action).
        TODO: Implement feed fetching and merging logic.
        """
        # Placeholder for feed merge logic
        return {"message": "Feed merge initiated", "status": "pending"}

    @staticmethod
    def _threat_score(level: str) -> float:
        """Convert threat level to numeric score."""
        scores = {
            "safe": 0.0,
            "low": 25.0,
            "medium": 50.0,
            "high": 75.0,
            "critical": 100.0,
        }
        return scores.get(level, 0.0)
