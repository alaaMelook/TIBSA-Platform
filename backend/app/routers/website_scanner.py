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
    WebsiteScanHistoryItem,
    WebsiteScanDetail,
)
from app.schemas.investigation import TIInvestigationResponse
from app.services.pentest import PentestOrchestrator
from app.services.pentest.models import ScanConfig
from app.services.translators.finding_normalizer import FindingNormalizer
from app.services.ti_processing_service import TIProcessingService

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/scan", response_model=TIInvestigationResponse, summary="Scan a website for vulnerabilities")
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

    print(f"[API RESPONSE] TI Findings count = {len(result.get('ti_findings', []))}")

    # Ensure frontend only receives TI results
    investigation_id = result.get("scan_id", str(uuid.uuid4()))
    ti_response = {
        "investigation_id": investigation_id,
        "scan_id": investigation_id,
        "status": "completed" if not result.get("error") else "failed",
        "risk_score": result.get("risk_score", 0.0),
        "target": target,
        "mode": result.get("mode", "safe"),
        "started_at": result.get("started_at"),
        "duration": result.get("duration", 0.0),
        "critical": result.get("critical", 0),
        "high": result.get("high", 0),
        "medium": result.get("medium", 0),
        "low": result.get("low", 0),
        "info": result.get("info", 0),
        "total": result.get("total", 0),
        "summary": {
            "duration": result.get("duration", 0.0),
            "critical": result.get("critical", 0),
            "high": result.get("high", 0),
            "medium": result.get("medium", 0),
            "low": result.get("low", 0),
            "info": result.get("info", 0),
            "total": result.get("total", 0),
        },
        "ti_findings": result.get("ti_findings", []),
        "findings": result.get("findings", []),
        "reputation_context": result.get("shared_state", {}).get("reputation_context", {}),
        "detected_technologies": result.get("detected_technologies", []),
        "detected_assets": result.get("detected_assets", []),
        "technology_metadata": result.get("technology_metadata", []),
        "scanner_json": result.get("scanner_json", {}),
        "error": result.get("error"),
        "executions_confirmed": result.get("executions_confirmed", 0),
    }

    return ti_response


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


@router.get("/history/{scan_id}", response_model=TIInvestigationResponse, summary="Get a past scan")
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
        
        # Process raw findings through TI layer dynamically
        raw_findings = data.get("findings", [])
        
        normalized_base = []
        for raw in raw_findings:
            n_f = FindingNormalizer.normalize(raw, default_url=data.get("target", ""), include_ti=True)
            normalized_base.append(n_f)
            
        ti_findings_objs = TIProcessingService.process_findings(normalized_base)
        ti_findings_dicts = [t.model_dump() for t in ti_findings_objs]
        overall_risk = sum([t.risk_score for t in ti_findings_objs]) / max(len(ti_findings_objs), 1)

        # Build TI response for history detail
        investigation_id = data.get("id", str(uuid.uuid4()))
        
        # Hydrate technology fields if nested in summary
        detected_technologies = summary.get("detected_technologies") or data.get("detected_technologies") or []
        detected_assets = summary.get("detected_assets") or data.get("detected_assets") or []
        technology_metadata = summary.get("technology_metadata") or data.get("technology_metadata") or []
        scanner_json = summary.get("scanner_json") or data.get("scanner_json") or {}
        
        ti_response = {
            "investigation_id": investigation_id,
            "scan_id": investigation_id,
            "status": "completed" if not data.get("error") else "failed",
            "risk_score": min(overall_risk, 100.0),
            "target": data.get("target"),
            "mode": summary.get("mode", "safe"),
            "started_at": summary.get("started_at") or data.get("created_at"),
            "duration": summary.get("duration", 0.0),
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "info": summary.get("info", 0),
            "total": summary.get("total", 0),
            "summary": summary,
            "ti_findings": ti_findings_dicts,
            "findings": raw_findings,
            "reputation_context": {},
            "detected_technologies": detected_technologies if isinstance(detected_technologies, list) else [],
            "detected_assets": detected_assets if isinstance(detected_assets, list) else [],
            "technology_metadata": technology_metadata if isinstance(technology_metadata, list) else [],
            "scanner_json": scanner_json if isinstance(scanner_json, dict) else {},
            "error": data.get("error"),
            "executions_confirmed": summary.get("executions_confirmed", 0),
        }
        
        return ti_response
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to fetch scan detail: %s", exc)
        raise HTTPException(status_code=500, detail="Could not load scan.")
