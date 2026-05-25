"""
Website Scanner router — v4 (Modular Architecture).
Routes scan requests to the PentestOrchestrator.
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
from app.services.pentest import PentestOrchestrator
from app.services.pentest.models import ScanConfig

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
    Available tests: security_headers, xss, sqli, endpoint_crawling, cookie_analysis,
                     misconfiguration, directory_discovery, auth_security.
    Scan modes: passive, safe, aggressive.
    """
    target = request.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    valid_tests = {
        "sqli", "xss", "bac",
        "security_headers", "endpoint_crawling", "cookie_analysis",
        "misconfiguration", "directory_discovery", "auth_security",
    }
    selected = [t for t in request.tests if t in valid_tests]
    if not selected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one valid test must be selected.",
        )

    # Create scan config with mode
    config = ScanConfig(
        target=target,
        tests=selected,
        mode=request.mode or "safe",
        session_cookie=request.session_cookie,
        auth_config=request.auth,
        enable_sqlmap=request.enable_sqlmap,
        auth_browser_analysis=request.auth_browser_analysis,
        authorized_auth_mode=request.authorized_auth_mode,
        auth_lifecycle_checks=request.auth_lifecycle_checks,
        authz_transition_checks=request.authz_transition_checks,
    )

    print(f"[DEBUG API] target = {target}")
    print(f"[DEBUG API] mode = {config.mode.value}")
    print(f"[DEBUG API] tests = {selected}")
    print(f"[DEBUG API] enable_sqlmap = {request.enable_sqlmap}")
    print(f"[DEBUG ORCH] enable_sqlmap = {getattr(config, 'enable_sqlmap', False)}")

    orchestrator = PentestOrchestrator(config=config)
    result = await orchestrator.scan(target, selected, mode=request.mode or "safe")

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
                "critical": result.get("critical", 0),
                "high": result.get("high", 0),
                "medium": result.get("medium", 0),
                "low": result.get("low", 0),
                "info": result.get("info", 0),
                "total": result.get("total", 0),
                "endpoints_found": result.get("endpoints_found", 0),
                "raw_requests_count": result.get("raw_requests_count", 0),
                "attack_surface_endpoints_count": result.get("attack_surface_endpoints_count", 0),
                "meaningful_attack_surface_count": result.get("meaningful_attack_surface_count", 0),
                "duration": result["duration"],
                "started_at": result["started_at"],
                "risk_score": result.get("risk_score", 0),
                "mode": result.get("mode", "safe"),
                "detected_technologies": result.get("detected_technologies", []),
                "detected_assets": result.get("detected_assets", []),
                "technology_metadata": result.get("technology_metadata", []),
                "scanner_json": result.get("scanner_json", {}),
                **({"error": result["error"]} if result.get("error") else {}),
            },
            "headers": result.get("headers", {}),
            "endpoints": result.get("endpoints", []),
            "false_positives_filtered": result.get("false_positives_filtered", []),
            "error": result.get("error"),
        }).execute()
    except Exception as exc:
        logger.warning("Failed to save website scan to DB: %s", exc)

    print(f"[API RESPONSE] detected_technologies count = {len(result.get('detected_technologies', []))}")
    print(f"[API RESPONSE] detected_assets count = {len(result.get('detected_assets', []))}")
    print(f"[API RESPONSE] technology_metadata count = {len(result.get('technology_metadata', []))}")
    print(f"[API RESPONSE] scanner_json exists = {'true' if result.get('scanner_json') else 'false'}")

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
            .select("id, target, summary, findings, headers, endpoints, false_positives_filtered, error, created_at")
            .eq("id", scan_id)
            .eq("user_id", auth_user.id)
            .single()
            .execute()
        )
        if not resp.data:
            raise HTTPException(status_code=404, detail="Scan not found.")
            
        data = resp.data
        summary = data.get("summary") or {}
        
        # Robustly handle nullable/empty/incorrectly typed fields for historical scans
        findings = data.get("findings")
        data["findings"] = findings if isinstance(findings, list) else []

        headers = data.get("headers")
        data["headers"] = headers if isinstance(headers, dict) else {}

        endpoints = data.get("endpoints")
        data["endpoints"] = endpoints if isinstance(endpoints, list) else []

        false_positives = data.get("false_positives_filtered")
        data["false_positives_filtered"] = false_positives if isinstance(false_positives, list) else []

        detected_technologies = summary.get("detected_technologies")
        data["detected_technologies"] = detected_technologies if isinstance(detected_technologies, list) else []

        detected_assets = summary.get("detected_assets")
        data["detected_assets"] = detected_assets if isinstance(detected_assets, list) else []

        technology_metadata = summary.get("technology_metadata")
        data["technology_metadata"] = technology_metadata if isinstance(technology_metadata, list) else []

        scanner_json = summary.get("scanner_json")
        data["scanner_json"] = scanner_json if isinstance(scanner_json, dict) else {}

        print(f"[HISTORY RESPONSE] detected_technologies count = {len(data['detected_technologies'])}")
        print(f"[HISTORY RESPONSE] detected_assets count = {len(data['detected_assets'])}")
        print(f"[HISTORY RESPONSE] technology_metadata count = {len(data['technology_metadata'])}")
        print(f"[HISTORY RESPONSE] scanner_json exists = {'true' if data['scanner_json'] else 'false'}")

        return data
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to fetch scan detail: %s", exc)
        raise HTTPException(status_code=500, detail="Could not load scan.")