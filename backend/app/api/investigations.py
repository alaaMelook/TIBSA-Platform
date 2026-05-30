"""
Investigations API Router.
Uses Supabase PostgreSQL client.
"""
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, status
from fastapi.responses import StreamingResponse
from supabase import Client
from typing import List, Dict, Any, Optional
from io import BytesIO

from app.dependencies import get_supabase, get_current_user
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationResponse,
    InvestigationStatusResponse,
    TIFinding
)
from app.schemas.responses import APIResponse
from app.services.orchestrator.investigation_orchestrator import InvestigationOrchestrator

router = APIRouter()

def _build_ti_response(inv: Dict[str, Any]) -> InvestigationResponse:
    """Helper to strictly separate and extract only TI findings for the frontend."""
    state = inv.get("pipeline_state") or {}
    status_val = inv.get("status")
    if status_val == "failed" and inv.get("current_stage") == "Stopped":
        status_val = "stopped"
    
    return InvestigationResponse(
        investigation_id=inv.get("id"),
        scan_id=inv.get("scan_id"),
        target=inv.get("target"),
        status=status_val,
        risk_score=inv.get("risk_score", 0.0),
        current_stage=inv.get("current_stage", "Pending"),
        progress_percent=inv.get("progress_percent", 0.0),
        pipeline_state=inv.get("pipeline_state"),
        summary=state.get("risk_summary", {}),
        ti_findings=state.get("ti_findings", []),
        reputation_context=state.get("reputation_context", {}),
        final_result=inv.get("final_result")
    )


@router.post("/start", response_model=APIResponse[InvestigationResponse], summary="Start a new security investigation")
async def start_investigation(
    request: InvestigationCreate,
    background_tasks: BackgroundTasks,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """
    Submits a target website for security scanning and analysis.
    The process runs in the background. Check status using GET /investigations/{id}/status.
    """
    target = request.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Validate target format (must contain a valid domain suffix, localhost, or IP)
    from urllib.parse import urlparse
    import re
    try:
        parsed = urlparse(target)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError()
        is_ip = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname) or (hostname.startswith("[") and hostname.endswith("]"))
        is_localhost = hostname.lower() == "localhost"
        has_dot = "." in hostname
        if not (is_ip or is_localhost or has_dot):
            raise ValueError()
    except Exception:
        # Extract the user's original target prefix/hostname if possible to make the example logical
        example_domain = request.target.strip()
        for prefix in ["https://", "http://"]:
            if example_domain.lower().startswith(prefix):
                example_domain = example_domain[len(prefix):]
        # Clean trailing slashes/paths
        example_domain = example_domain.split("/")[0].split("?")[0].split("#")[0]
        if not example_domain:
            example_domain = "example.com"
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target format. Please insert a valid URL/domain with a proper suffix (e.g. '{example_domain}.com' or 'https://{example_domain}.com')."
        )

    orchestrator = InvestigationOrchestrator(supabase)
    auth_user = current_user["auth_user"]
    
    try:
        # Create investigation in pending state
        investigation = await orchestrator.create_investigation(
            target=target,
            tests=request.tests,
            user_id=auth_user.id,
            mode=request.mode or "safe",
            include_ti=request.include_ti if request.include_ti is not None else True,
            tm_mode=request.tm_mode or "enhanced",
            enable_strict_correlation_hardening=request.enable_strict_correlation_hardening if request.enable_strict_correlation_hardening is not None else True
        )
        
        # Dispatch background task to execute the full pipeline
        from app.dependencies import get_supabase
        async def run_pipeline_task(
            inv_id: str,
            run_tests: List[str],
            run_mode: str,
            enable_sqlmap: bool,
            auth_browser_analysis: bool,
            authorized_auth_mode: bool,
            auth_lifecycle_checks: bool,
            authz_transition_checks: bool,
            session_cookie: Optional[str],
            enable_strict_correlation_hardening: bool
        ):
            bg_supabase = get_supabase()
            bg_orch = InvestigationOrchestrator(bg_supabase)
            await bg_orch.run_investigation_pipeline(
                investigation_id=inv_id,
                tests=run_tests,
                mode=run_mode,
                enable_sqlmap=enable_sqlmap,
                auth_browser_analysis=auth_browser_analysis,
                authorized_auth_mode=authorized_auth_mode,
                auth_lifecycle_checks=auth_lifecycle_checks,
                authz_transition_checks=authz_transition_checks,
                session_cookie=session_cookie,
                enable_strict_correlation_hardening=enable_strict_correlation_hardening
            )

        background_tasks.add_task(
            run_pipeline_task,
            investigation.get("id"),
            request.tests,
            request.mode or "safe",
            request.enable_sqlmap or False,
            request.auth_browser_analysis or False,
            request.authorized_auth_mode or False,
            request.auth_lifecycle_checks or False,
            request.authz_transition_checks or False,
            request.session_cookie,
            request.enable_strict_correlation_hardening if request.enable_strict_correlation_hardening is not None else True
        )
        
        return APIResponse(
            success=True,
            message="Investigation started successfully.",
            data=_build_ti_response(investigation)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start investigation: {str(e)}"
        )


@router.get("/", response_model=APIResponse[List[InvestigationStatusResponse]], summary="List all security investigations")
async def list_investigations(
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """Fetch the list of all investigations for the history table, newest first."""
    try:
        resp = supabase.table("investigations").select("id, scan_id, target, status, risk_score, started_at, completed_at, current_stage, progress_percent").order("started_at", desc=True).execute()
        raw_data = resp.data or []
        for inv in raw_data:
            if inv.get("status") == "failed" and inv.get("current_stage") == "Stopped":
                inv["status"] = "stopped"
        validated = [InvestigationStatusResponse.model_validate(inv) for inv in raw_data]
        return APIResponse(success=True, data=validated)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch investigations list: {str(e)}"
        )


@router.get("/{id}", response_model=APIResponse[InvestigationResponse], summary="Get full investigation details")
async def get_investigation(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """Fetch TI details and reports for an investigation."""
    resp = supabase.table("investigations").select("*").eq("id", id).execute()
    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found."
        )
    
    return APIResponse(
        success=True,
        data=_build_ti_response(resp.data[0])
    )


@router.get("/{id}/status", response_model=APIResponse[InvestigationStatusResponse], summary="Get investigation status")
async def get_investigation_status(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """Check only the current execution state and risk score for an investigation."""
    resp = supabase.table("investigations").select("id, scan_id, target, status, risk_score, started_at, completed_at, current_stage, progress_percent").eq("id", id).execute()
    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found."
        )
    inv = resp.data[0]
    if inv.get("status") == "failed" and inv.get("current_stage") == "Stopped":
        inv["status"] = "stopped"
        
    return APIResponse(
        success=True,
        data=InvestigationStatusResponse.model_validate(inv)
    )


@router.get("/{id}/findings", response_model=APIResponse[List[TIFinding]], summary="Get TI investigation findings")
async def get_investigation_findings(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """List all TI findings generated by this investigation."""
    resp = supabase.table("investigations").select("pipeline_state").eq("id", id).execute()
    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found."
        )
    
    state = resp.data[0].get("pipeline_state") or {}
    ti_findings = state.get("ti_findings", [])
    
    validated = [TIFinding.model_validate(f) for f in ti_findings]
    return APIResponse(
        success=True,
        data=validated
    )


@router.get("/{id}/results", response_model=APIResponse[InvestigationResponse], summary="Get final investigation results")
async def get_investigation_results(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """Fetch complete TI details of a finished investigation. Returns 409 if not completed yet."""
    resp = supabase.table("investigations").select("*").eq("id", id).execute()
    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found."
        )
    
    investigation = resp.data[0]
    if investigation.get("status") != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Investigation results are not ready yet. Current status: {investigation.get('status')}"
        )
        
    return APIResponse(
        success=True,
        data=_build_ti_response(investigation)
    )


# ─── Export Endpoints ─────────────────────────────────────────────


@router.get("/{id}/export/json", summary="Export investigation report as JSON")
async def export_investigation_json(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """
    Export a completed investigation as a structured JSON file.
    Returns a downloadable JSON file containing all pipeline outputs.
    """
    resp = supabase.table("investigations").select("*").eq("id", id).execute()
    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found."
        )

    investigation = resp.data[0]
    if investigation.get("status") != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Investigation is not completed yet. Current status: {investigation.get('status')}"
        )

    try:
        from app.services.investigation.report_exporter import ReportExporter

        findings_resp = supabase.table("findings").select("*").eq("investigation_id", id).execute()
        assets_resp = supabase.table("assets").select("*").eq("investigation_id", id).execute()

        exporter = ReportExporter()
        investigation_data = {
            "target": investigation.get("target"),
            "status": investigation.get("status"),
            "risk_score": investigation.get("risk_score"),
            "started_at": investigation.get("started_at"),
            "completed_at": investigation.get("completed_at"),
            "scan_id": investigation.get("scan_id"),
            "findings": findings_resp.data or [],
            "assets": assets_resp.data or [],
            "final_result": investigation.get("final_result"),
            "pipeline_state": investigation.get("pipeline_state"),
        }

        result = await exporter.export_json(id, investigation_data)

        return StreamingResponse(
            BytesIO(result["content"]),
            media_type=result["mime_type"],
            headers={
                "Content-Disposition": f'attachment; filename="{result["filename"]}"',
                "Content-Length": str(result["size_bytes"]),
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export JSON: {str(e)}"
        )


@router.get("/{id}/export/pdf", summary="Export investigation report as PDF")
async def export_investigation_pdf(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """
    Export a completed investigation as a professional PDF report.
    Includes metadata, risk score, findings, correlated threats,
    STRIDE matrix, AI summaries, and recommendations.
    """
    resp = supabase.table("investigations").select("*").eq("id", id).execute()
    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found."
        )

    investigation = resp.data[0]
    if investigation.get("status") != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Investigation is not completed yet. Current status: {investigation.get('status')}"
        )

    try:
        from app.services.investigation.report_exporter import ReportExporter

        findings_resp = supabase.table("findings").select("*").eq("investigation_id", id).execute()
        assets_resp = supabase.table("assets").select("*").eq("investigation_id", id).execute()

        exporter = ReportExporter()
        investigation_data = {
            "target": investigation.get("target"),
            "status": investigation.get("status"),
            "risk_score": investigation.get("risk_score"),
            "started_at": investigation.get("started_at"),
            "completed_at": investigation.get("completed_at"),
            "scan_id": investigation.get("scan_id"),
            "findings": findings_resp.data or [],
            "assets": assets_resp.data or [],
            "final_result": investigation.get("final_result"),
            "pipeline_state": investigation.get("pipeline_state"),
        }

        result = await exporter.export_pdf(id, investigation_data)

        return StreamingResponse(
            BytesIO(result["content"]),
            media_type=result["mime_type"],
            headers={
                "Content-Disposition": f'attachment; filename="{result["filename"]}"',
                "Content-Length": str(result["size_bytes"]),
            },
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export PDF: {str(e)}"
        )


@router.post("/{id}/stop", response_model=APIResponse[Dict[str, Any]], summary="Stop a running security investigation")
async def stop_investigation(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """Stop/cancel a running investigation pipeline."""
    try:
        # Check current status
        resp = supabase.table("investigations").select("status, pipeline_state").eq("id", id).execute()
        if not resp.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Investigation not found."
            )
        
        investigation = resp.data[0]
        current_status = investigation.get("status")
        current_stage = investigation.get("current_stage")
        if current_status == "failed" and current_stage == "Stopped":
            current_status = "stopped"
        
        if current_status in ["completed", "failed", "stopped"]:
            return APIResponse(
                success=True,
                message=f"Investigation is already in a terminal state: {current_status}.",
                data={"status": current_status}
            )
        
        # Update status to stopped
        pipeline_state = investigation.get("pipeline_state") or {}
        pipeline_state["stage"] = "Stopped"
        pipeline_state["progress"] = 100.0
        
        # Add timeline event
        if "timeline" not in pipeline_state:
            pipeline_state["timeline"] = []
        
        from datetime import datetime
        pipeline_state["timeline"].append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "stage": "System",
            "status": "completed",
            "message": "Investigation stop requested by user"
        })
        
        supabase.table("investigations").update({
            "status": "failed",
            "current_stage": "Stopped",
            "progress_percent": 100.0,
            "pipeline_state": pipeline_state
        }).eq("id", id).execute()
        
        return APIResponse(
            success=True,
            message="Investigation stop request submitted.",
            data={"status": "stopped"}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop investigation: {str(e)}"
        )
