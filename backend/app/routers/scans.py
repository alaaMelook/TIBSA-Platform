"""
Scans router.
Handles URL scanning, file scanning, and scan reports.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from supabase import Client

from app.dependencies import get_supabase, get_current_user
from app.models.scan import ScanRequest, ScanResponse, ScanReportResponse
from app.services.scan_service import ScanService

router = APIRouter()


@router.post("/url", response_model=ScanResponse)
async def scan_url(
    request: ScanRequest,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Submit a URL for scanning."""
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    return await service.scan_url(user_id=auth_user.id, url=request.target)


@router.post("/file", response_model=ScanResponse)
async def scan_file(
    request: ScanRequest,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Submit a file hash for scanning."""
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    return await service.scan_file(user_id=auth_user.id, file_hash=request.target)


@router.get("/", response_model=List[ScanResponse])
async def list_my_scans(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """List all scans for the current user."""
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    return await service.list_user_scans(auth_user.id)


@router.get("/{scan_id}", response_model=ScanReportResponse)
async def get_scan_report(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Get a detailed scan report."""
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    return await service.get_report(scan_id=scan_id, user_id=auth_user.id)
