#backend/app/routers/threats.py
"""
Threat Intelligence router.
Handles threat feeds, IOC lookups, and reputation checks.
"""
from fastapi import APIRouter, Depends
from typing import List
from supabase import Client

from app.dependencies import get_supabase, get_current_user, require_admin
from app.models.threat import (
    ThreatIndicatorResponse,
    ThreatFeedResponse,
    ThreatFeedCreate,
    IOCLookupRequest,
    ReputationCheckRequest,
    ReputationCheckResponse,
)
from app.services.threat_service import ThreatService

router = APIRouter()


@router.get("/feeds", response_model=List[ThreatFeedResponse])
async def list_threat_feeds(
    active_only: bool = False,
    _current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """List threat intelligence feeds."""
    service = ThreatService(supabase)
    return await service.list_feeds(active_only=active_only)


@router.post("/feeds", response_model=ThreatFeedResponse)
async def create_threat_feed(
    payload: ThreatFeedCreate,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """Create a new threat intelligence feed (admin only)."""
    service = ThreatService(supabase)
    return await service.create_feed(payload.model_dump())


@router.patch("/feeds/{feed_id}/toggle", response_model=ThreatFeedResponse)
async def toggle_threat_feed(
    feed_id: str,
    is_active: bool,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """Toggle a threat intelligence feed active status (admin only)."""
    service = ThreatService(supabase)
    return await service.toggle_feed(feed_id, is_active)


@router.delete("/feeds/{feed_id}")
async def delete_threat_feed(
    feed_id: str,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """Delete a threat intelligence feed (admin only)."""
    service = ThreatService(supabase)
    return await service.delete_feed(feed_id)


@router.post("/lookup", response_model=List[ThreatIndicatorResponse])
async def lookup_ioc(
    request: IOCLookupRequest,
    _current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Look up an Indicator of Compromise (IOC)."""
    service = ThreatService(supabase)
    return await service.lookup_ioc(request.indicator_type, request.value)


@router.post("/reputation", response_model=ReputationCheckResponse)
async def check_reputation(
    request: ReputationCheckRequest,
    _current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Check the reputation of a domain, IP, or URL."""
    service = ThreatService(supabase)
    return await service.check_reputation(request.target)


# ─── Admin-Only ──────────────────────────────────────────────

@router.post("/feeds/merge")
async def merge_feeds(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """Merge and update all threat feeds (admin only)."""
    service = ThreatService(supabase)
    return await service.merge_feeds()
