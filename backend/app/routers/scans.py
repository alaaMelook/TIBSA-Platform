"""
Scans router.
Handles URL scanning, file hash scanning, file upload scanning, and scan reports.
"""
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status, Request
from typing import List
from supabase import Client

from app.dependencies import get_supabase, get_current_user
from app.models.scan import ScanRequest, ScanResponse, ScanReportResponse
from app.services.scan_service import ScanService

router = APIRouter()

# Maximum file size allowed for upload (32 MB)
MAX_FILE_SIZE = 32 * 1024 * 1024


@router.post("/url", response_model=ScanResponse, summary="Scan a URL")
async def scan_url(
    request: Request,
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Submit a URL for VirusTotal scanning. Returns immediately; result is saved in the background."""
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    
    try:
        from app.services.auth_service import parse_user_agent
        supabase.table("audit_logs").insert({
            "user_id": auth_user.id,
            "action_type": "SCAN_CREATED",
            "severity": "info",
            "message": f"User started scan for target: {payload.target}",
            "ip_address": client_ip,
            "metadata": {
                "resource": "scan",
                "target": payload.target,
                "scan_type": "url",
                "user_agent": parse_user_agent(user_agent)
            }
        }).execute()
    except Exception:
        pass

    return await service.scan_url(
        user_id=auth_user.id,
        url=payload.target,
        background_tasks=background_tasks,
    )


@router.post("/file", response_model=ScanResponse, summary="Scan a file by hash")
async def scan_file_hash(
    request: Request,
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Look up a file hash (MD5 / SHA-1 / SHA-256) on VirusTotal."""
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    
    try:
        from app.services.auth_service import parse_user_agent
        supabase.table("audit_logs").insert({
            "user_id": auth_user.id,
            "action_type": "SCAN_CREATED",
            "severity": "info",
            "message": f"User started scan for target hash: {payload.target}",
            "ip_address": client_ip,
            "metadata": {
                "resource": "scan",
                "target": payload.target,
                "scan_type": "file_hash",
                "user_agent": parse_user_agent(user_agent)
            }
        }).execute()
    except Exception:
        pass

    return await service.scan_file(
        user_id=auth_user.id,
        file_hash=payload.target,
        background_tasks=background_tasks,
    )


@router.post("/file/upload", response_model=ScanResponse, summary="Upload and scan a file")
async def scan_file_upload(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="File to scan (max 32 MB)"),
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """
    Upload a file directly for VirusTotal scanning.
    The scan runs in the background — poll GET /scans/{id} for the result.
    """
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024 * 1024)} MB.",
        )

    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    
    try:
        from app.services.auth_service import parse_user_agent
        supabase.table("audit_logs").insert({
            "user_id": auth_user.id,
            "action_type": "SCAN_CREATED",
            "severity": "info",
            "message": f"User uploaded and started scan for file: {file.filename or 'unknown'}",
            "ip_address": client_ip,
            "metadata": {
                "resource": "scan",
                "target": file.filename or "unknown",
                "scan_type": "file_upload",
                "user_agent": parse_user_agent(user_agent)
            }
        }).execute()
    except Exception:
        pass

    return await service.scan_uploaded_file(
        user_id=auth_user.id,
        filename=file.filename or "unknown",
        content=content,
        background_tasks=background_tasks,
    )


@router.get("/", response_model=List[ScanResponse], summary="List my scans")
async def list_my_scans(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """List all scans for the current user (newest first)."""
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    return await service.list_user_scans(auth_user.id)


@router.get("/{scan_id}", response_model=ScanReportResponse, summary="Get scan report")
async def get_scan_report(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Get the full VirusTotal report for a completed scan."""
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    return await service.get_report(scan_id=scan_id, user_id=auth_user.id)


@router.post("/{scan_id}/cancel", response_model=ScanResponse, summary="Cancel a scan")
async def cancel_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Cancel a pending or in-progress scan."""
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    return await service.cancel_scan(scan_id=scan_id, user_id=auth_user.id)


@router.delete("/{scan_id}", summary="Delete a scan permanently")
async def delete_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Permanently delete a scan and its report from the database."""
    service = ScanService(supabase)
    auth_user = current_user["auth_user"]
    await service.delete_scan(scan_id=scan_id, user_id=auth_user.id)
    return {"message": "Scan deleted successfully"}
