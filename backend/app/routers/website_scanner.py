"""
Website Scanner router.
Runs security tests against a target website.
"""
import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from supabase import Client

from app.dependencies import get_supabase, get_current_user
from app.models.website_scan import WebsiteScanRequest, WebsiteScanResponse
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

    valid_tests = {"sqli", "xss", "misconfiguration", "directory_discovery", "brute_force"}
    selected = [t for t in request.tests if t in valid_tests]
    if not selected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one valid test must be selected.",
        )

    scanner = WebsiteScannerService()
    result = await scanner.scan(target, selected)

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
