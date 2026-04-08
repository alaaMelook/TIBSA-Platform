"""
Website Scanner router.
Runs security tests against a target website.
"""
import uuid
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from supabase import Client

from app.dependencies import get_supabase, get_current_user
from app.models.website_scan import (
    WebsiteScanRequest,
    WebsiteScanResponse,
    WebsiteScanHistoryItem,
    WebsiteScanDetail,
)
from app.services.website_scanner_service import WebsiteScannerService

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/scan", response_model=WebsiteScanResponse, summary="Scan a website for vulnerabilities")
async def scan_website(
    request: WebsiteScanRequest,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """
    Run security tests against a target URL.
    Available tests: security_headers, xss, sqli, endpoint_crawling, cookie_analysis.
    """
    # Validate URL
    target = request.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    valid_tests = {
        "sqli", "xss",
        "security_headers", "endpoint_crawling", "cookie_analysis",
        "misconfiguration", "directory_discovery", "brute_force",
    }
    selected = [t for t in request.tests if t in valid_tests]
    if not selected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one valid test must be selected.",
        )

    # Map frontend-friendly keys → backend internal keys (set deduplicates)
    key_map = {
        "security_headers": "misconfiguration",
        "endpoint_crawling": "directory_discovery",
        "cookie_analysis": "brute_force",
    }
    internal_tests = list({key_map.get(t, t) for t in selected})

    scanner = WebsiteScannerService()
    result = await scanner.scan(target, internal_tests)

    # Save to database
    try:
        auth_user = current_user["auth_user"]
        supabase.table("website_scans").insert({
            "id": str(uuid.uuid4()),
            "user_id": auth_user.id,
            "target": target,
            "findings": result.get("findings", []),
            "summary": {
                "scan_id": result["scan_id"],
                "high": result["high"],
                "medium": result["medium"],
                "low": result["low"],
                "total": result["total"],
                "endpoints_found": result["endpoints_found"],
                "duration": result["duration"],
                "started_at": result["started_at"],
            },
        }).execute()
    except Exception as exc:
        logger.warning("Failed to save website scan to DB: %s", exc)

    return result


# ─── History Endpoints ────────────────────────────────────────


@router.get("/history", response_model=List[WebsiteScanHistoryItem], summary="List past scans")
async def list_scan_history(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Return the current user's past website scans, newest first."""
    auth_user = current_user["auth_user"]
    try:
        resp = (
            supabase.table("website_scans")
            .select("id, target, summary, created_at")
            .eq("user_id", auth_user.id)
            .order("created_at", desc=True)
            .limit(50)
            .execute()
        )
        return resp.data or []
    except Exception as exc:
        logger.error("Failed to fetch scan history: %s", exc)
        raise HTTPException(status_code=500, detail="Could not load history.")


@router.get("/history/{scan_id}", response_model=WebsiteScanDetail, summary="Get a past scan")
async def get_scan_detail(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Return full details for a single past scan."""
    auth_user = current_user["auth_user"]
    try:
        resp = (
            supabase.table("website_scans")
            .select("id, target, summary, findings, created_at")
            .eq("id", scan_id)
            .eq("user_id", auth_user.id)
            .single()
            .execute()
        )
        if not resp.data:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return resp.data
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to fetch scan detail: %s", exc)
        raise HTTPException(status_code=500, detail="Could not load scan.")
