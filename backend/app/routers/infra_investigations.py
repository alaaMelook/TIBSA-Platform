"""
Infra Investigations Router – /api/v1/infra-investigations

Endpoints:
  POST /start                  – submit a new target for analysis
  GET  /                       – list all investigations for current user (history)
  GET  /{id}                   – full investigation detail (results blob)
  GET  /{id}/status            – lightweight status poll (no results)
  POST /{id}/stop              – request pipeline cancellation
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from supabase import Client

from app.dependencies import get_current_user, get_supabase
from app.schemas.infra_investigation import (
    InfraCreateRequest,
    InfraInvestigationDetail,
    InfraInvestigationListItem,
)
from app.schemas.responses import APIResponse
from app.services.infra.orchestrator import InfraOrchestrator

router = APIRouter()
logger = logging.getLogger(__name__)


# ── Helper: resolve dict → Pydantic model ────────────────────────────────────

def _to_detail(row: dict) -> InfraInvestigationDetail:
    """Map a raw Supabase row to InfraInvestigationDetail."""
    results_raw = row.get("results")
    results = None
    if results_raw:
        from app.schemas.infra_investigation import InfraInvestigationResults
        try:
            results = InfraInvestigationResults.model_validate(results_raw)
        except Exception:
            results = None  # Don't crash if schema has changed

    return InfraInvestigationDetail(
        id=row["id"],
        target=row["target"],
        target_type=row.get("target_type", "url"),
        status=row["status"],
        current_stage=row.get("current_stage", "Pending"),
        progress_percent=float(row.get("progress_percent", 0.0)),
        risk_score=float(row.get("risk_score", 0.0)),
        started_at=row["started_at"],
        completed_at=row.get("completed_at"),
        results=results,
        error=row.get("error"),
    )


# ── POST /start ───────────────────────────────────────────────────────────────

@router.post(
    "/start",
    response_model=APIResponse[InfraInvestigationDetail],
    summary="Submit a target IOC for infrastructure threat investigation",
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_infra_investigation(
    request: InfraCreateRequest,
    background_tasks: BackgroundTasks,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """
    Accepts a URL, domain, or IP address and starts the 8-stage
    infrastructure intelligence pipeline in the background.

    Returns the investigation row immediately in `pending` state.
    Poll `GET /{id}/status` for live progress.
    """
    auth_user = current_user["auth_user"]
    orch = InfraOrchestrator(supabase)

    try:
        investigation = await orch.create(
            target=request.target,
            user_id=auth_user.id,
            enable_passive_dns=request.enable_passive_dns,
            enable_ai_summary=request.enable_ai_summary,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception as exc:
        logger.exception("Failed to create infra investigation: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create investigation: {exc}",
        )

    inv_id = investigation["id"]
    target = investigation["target"]
    enable_passive_dns = request.enable_passive_dns
    enable_ai_summary = request.enable_ai_summary

    # Dispatch pipeline as a background task
    async def _run_pipeline():
        bg_supabase = get_supabase()
        bg_orch = InfraOrchestrator(bg_supabase)
        await bg_orch.run_pipeline(
            investigation_id=inv_id,
            target=target,
            enable_passive_dns=enable_passive_dns,
            enable_ai_summary=enable_ai_summary,
        )

    background_tasks.add_task(_run_pipeline)

    return APIResponse(
        success=True,
        message="Investigation submitted. Pipeline running in background.",
        data=_to_detail(investigation),
    )


# ── GET / (history) ───────────────────────────────────────────────────────────

@router.get(
    "/",
    response_model=APIResponse[List[InfraInvestigationListItem]],
    summary="List all infra investigations for the current user",
)
async def list_infra_investigations(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None, alias="status"),
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """
    Returns all investigations ordered newest-first.
    Supports optional `status` query param to filter by status.
    """
    auth_user = current_user["auth_user"]
    try:
        query = (
            supabase.table("infra_investigations")
            .select(
                "id, target, target_type, status, current_stage, "
                "progress_percent, risk_score, started_at, completed_at"
            )
            .eq("user_id", auth_user.id)
            .order("started_at", desc=True)
            .range(offset, offset + limit - 1)
        )
        if status_filter:
            query = query.eq("status", status_filter)

        resp = query.execute()
        rows = resp.data or []
        items = [InfraInvestigationListItem.model_validate(r) for r in rows]
        return APIResponse(success=True, data=items)
    except Exception as exc:
        logger.exception("Failed to list infra investigations: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch investigations: {exc}",
        )


# ── GET /{id} (full detail) ───────────────────────────────────────────────────

@router.get(
    "/{id}",
    response_model=APIResponse[InfraInvestigationDetail],
    summary="Get full investigation detail including results",
)
async def get_infra_investigation(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """Returns the complete investigation row, including the results JSONB blob."""
    auth_user = current_user["auth_user"]
    resp = (
        supabase.table("infra_investigations")
        .select("*")
        .eq("id", id)
        .eq("user_id", auth_user.id)
        .execute()
    )
    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )
    return APIResponse(success=True, data=_to_detail(resp.data[0]))


# ── GET /{id}/status (lightweight poll) ──────────────────────────────────────

@router.get(
    "/{id}/status",
    response_model=APIResponse[InfraInvestigationListItem],
    summary="Poll investigation status and progress",
)
async def get_infra_investigation_status(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """
    Lightweight endpoint — returns only status, stage, and progress fields.
    Intended for frequent polling while the pipeline is running.
    """
    auth_user = current_user["auth_user"]
    resp = (
        supabase.table("infra_investigations")
        .select(
            "id, target, target_type, status, current_stage, "
            "progress_percent, risk_score, started_at, completed_at"
        )
        .eq("id", id)
        .eq("user_id", auth_user.id)
        .execute()
    )
    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )
    item = InfraInvestigationListItem.model_validate(resp.data[0])
    return APIResponse(success=True, data=item)


# ── POST /{id}/stop ───────────────────────────────────────────────────────────

@router.post(
    "/{id}/stop",
    response_model=APIResponse[dict],
    summary="Request cancellation of a running investigation",
)
async def stop_infra_investigation(
    id: str,
    supabase: Client = Depends(get_supabase),
    current_user: dict = Depends(get_current_user),
):
    """
    Marks the investigation as `stopped`. The background pipeline checks this
    flag between each stage and exits cleanly.
    """
    auth_user = current_user["auth_user"]
    resp = (
        supabase.table("infra_investigations")
        .select("status")
        .eq("id", id)
        .eq("user_id", auth_user.id)
        .execute()
    )
    if not resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    current_status = resp.data[0].get("status")
    if current_status in ("completed", "failed", "stopped"):
        return APIResponse(
            success=True,
            message=f"Investigation is already in terminal state: {current_status}.",
            data={"status": current_status},
        )

    supabase.table("infra_investigations").update({
        "status": "stopped",
        "current_stage": "Stopped",
        "progress_percent": 100.0,
    }).eq("id", id).eq("user_id", auth_user.id).execute()

    return APIResponse(
        success=True,
        message="Stop signal sent. Pipeline will exit after current stage.",
        data={"status": "stopped"},
    )
