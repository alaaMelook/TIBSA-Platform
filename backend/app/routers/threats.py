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
    IOCLookupRequest,
    ReputationCheckRequest,
    ReputationCheckResponse,
)
from app.services.threat_service import ThreatService

router = APIRouter()


@router.get("/feeds", response_model=List[ThreatFeedResponse])
async def list_threat_feeds(
    _current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """List all active threat intelligence feeds."""
    service = ThreatService(supabase)
    return await service.list_feeds()


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
