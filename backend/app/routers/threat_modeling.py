"""
Threat Modeling – FastAPI router.

Endpoints
---------
POST   /api/v1/threat-modeling/analyze                    Stateless analysis (no DB)
POST   /api/v1/threat-modeling/analyses                   Run legacy analysis + persist
POST   /api/v1/threat-modeling/analyses/comprehensive    Run comprehensive analysis + persist
GET    /api/v1/threat-modeling/analyses                   List user's analyses
GET    /api/v1/threat-modeling/analyses/{id}              Get single analysis
GET    /api/v1/threat-modeling/analyses/{id}/export       Export analysis
DELETE /api/v1/threat-modeling/analyses/{id}              Delete analysis
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import StreamingResponse
from supabase import Client

from app.dependencies import get_supabase, get_current_user
from app.models.threat_modeling import (
    ThreatModelCreateRequest,
    ThreatModelAnalysisResponse,
    ThreatModelAnalyzeResponse,
    ThreatModelListItem,
    ThreatModelAnalysis,
    DeleteResponse,
    ExportFormat,
    ThreatModelScanHistoryResponse,
    ThreatModelScanHistorySummary,
)
from app.services.threat_modeling_engine import (
    analyze as engine_analyze,
    analyze_stride as engine_analyze_stride,
)
from app.services.threat_modeling_service import ThreatModelingService

router = APIRouter()


# ─── Stateless Analyze (no persistence) ──────────────────────────────

@router.post(
    "/analyze",
    response_model=ThreatModelAnalyzeResponse,
    summary="Stateless threat analysis",
    description=(
        "Run the threat engine against the submitted form and return generated "
        "threats + risk score without saving anything to the database."
    ),
)
async def analyze_stateless(
    req: ThreatModelCreateRequest,
    _current_user: dict = Depends(get_current_user),
):
    """
    Mirrors the frontend's generateThreats() call.
    Useful for live previews before the user saves a report.
    """
    return engine_analyze(req)

@router.post(
    "/analyze/stride",
    response_model=ThreatModelAnalyzeResponse,
    summary="STRIDE-based stateless analysis",
    description=(
        "Run threat modeling using the STRIDE framework. Returns generated threats, "
        "mitigations, and optional heatmap data without saving the analysis."
    ),
)
async def analyze_stride(
    req: ThreatModelCreateRequest,
    generate_heatmap: bool = Query(default=False, description="Generate heatmap data"),
    _current_user: dict = Depends(get_current_user),
):
    return engine_analyze_stride(req, generate_heatmap=generate_heatmap)

# ─── Create (persist) ────────────────────────────────────────────────

@router.post(
    "/analyses",
    response_model=ThreatModelAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create & persist a threat model analysis",
    description=(
        "Run the threat engine, save the analysis to the database, and return "
        "the full result including the generated UUID and timestamps."
    ),
)
async def create_analysis(
    req: ThreatModelCreateRequest,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    user_id: str = current_user["auth_user"].id
    service = ThreatModelingService(supabase)

    try:
        result = await service.create_analysis(req, user_id=user_id)
        print(f"✅ Threat model created: {result.id}")
        return result
    except RuntimeError as exc:
        print(f"❌ RuntimeError creating threat model: {str(exc)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )
    except Exception as exc:
        print(f"❌ Error creating threat model: {type(exc).__name__}: {str(exc)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create threat model: {str(exc)}",
        )


@router.post(
    "/analyses/comprehensive",
    response_model=ThreatModelAnalysis,
    status_code=status.HTTP_201_CREATED,
    summary="Create & persist a comprehensive threat model analysis",
    description=(
        "Run the enhanced threat modeling engine with all features (STRIDE, CAPEC, "
        "ASVS, heatmaps, etc.), save to database, and return the full comprehensive result."
    ),
)
async def create_comprehensive_analysis(
    req: ThreatModelCreateRequest,
    generate_heatmap: bool = Query(default=True, description="Generate risk heatmap"),
    include_summaries: bool = Query(default=True, description="Include LLM summaries"),
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    user_id: str = current_user["auth_user"].id
    service = ThreatModelingService(supabase)

    try:
        return await service.create_comprehensive_analysis(
            req,
            user_id=user_id,
            generate_heatmap=generate_heatmap,
            include_summaries=include_summaries
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ─── List ────────────────────────────────────────────────────────────

@router.get(
    "/analyses",
    response_model=List[ThreatModelListItem],
    summary="List threat model analyses",
    description="Return a paginated list of the authenticated user's saved analyses.",
)
async def list_analyses(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    analysis_type: str = Query(default=None, description="Filter by analysis type ('legacy' or 'comprehensive')"),
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    user_id: str = current_user["auth_user"].id
    service = ThreatModelingService(supabase)
    return await service.list_analyses(
        user_id=user_id,
        limit=limit,
        offset=offset,
        analysis_type=analysis_type
    )


# ─── Get single ──────────────────────────────────────────────────────

@router.get(
    "/analyses/{analysis_id}",
    response_model=ThreatModelAnalysisResponse,
    summary="Get a single threat model analysis",
)
async def get_analysis(
    analysis_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    user_id: str = current_user["auth_user"].id
    service = ThreatModelingService(supabase)

    result = await service.get_analysis(analysis_id, user_id=user_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found.",
        )
    return result


@router.get(
    "/analyses/{analysis_id}/comprehensive",
    response_model=ThreatModelAnalysis,
    summary="Get a comprehensive threat model analysis",
)
async def get_comprehensive_analysis(
    analysis_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    user_id: str = current_user["auth_user"].id
    service = ThreatModelingService(supabase)

    result = await service.get_comprehensive_analysis(analysis_id, user_id=user_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Comprehensive analysis '{analysis_id}' not found.",
        )
    return result


# ─── Export ──────────────────────────────────────────────────────────

@router.get(
    "/analyses/{analysis_id}/export",
    summary="Export a threat model analysis",
    description="Export a threat model analysis in various formats (JSON, CSV, XML, PDF).",
)
async def export_analysis(
    analysis_id: str,
    format: ExportFormat = Query(..., description="Export format"),
    include_heatmap: bool = Query(default=True, description="Include heatmap data in export"),
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    user_id: str = current_user["auth_user"].id
    service = ThreatModelingService(supabase)

    try:
        export_data = await service.export_analysis(
            analysis_id, format, user_id, include_heatmap
        )
        if export_data is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' not found.",
            )

        # Determine content type
        content_types = {
            ExportFormat.JSON: "application/json",
            ExportFormat.CSV: "text/csv",
            ExportFormat.XML: "application/xml",
            ExportFormat.PDF: "application/pdf",
        }

        filename = f"threat_model_{analysis_id}.{format.value.lower()}"

        return StreamingResponse(
            iter([export_data]),
            media_type=content_types[format],
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Export failed: {str(exc)}",
        )


# ─── Delete ──────────────────────────────────────────────────────────

@router.delete(
    "/analyses/{analysis_id}",
    response_model=DeleteResponse,
    summary="Delete a threat model analysis",
)
async def delete_analysis(
    analysis_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    user_id: str = current_user["auth_user"].id
    service = ThreatModelingService(supabase)

    deleted = await service.delete_analysis(analysis_id, user_id=user_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis '{analysis_id}' not found or you do not have permission to delete it.",
        )
    return DeleteResponse(message="Analysis deleted successfully.", id=analysis_id)


# ─── Scan History ────────────────────────────────────────────────────

@router.get(
    "/scan-history",
    response_model=ThreatModelScanHistoryResponse,
    summary="Get threat modeling scan history",
    description="Retrieve the authenticated user's threat modeling scan history with statistics.",
)
async def get_scan_history(
    limit: int = Query(default=50, ge=1, le=200, description="Number of scans to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Get scan history for the authenticated user."""
    user_id: str = current_user["auth_user"].id
    service = ThreatModelingService(supabase)

    try:
        return await service.get_scan_history(user_id, limit=limit, offset=offset)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve scan history: {str(exc)}",
        )


@router.get(
    "/scan-history/summary",
    response_model=ThreatModelScanHistorySummary,
    summary="Get threat modeling scan history summary",
    description="Retrieve summary statistics for the authenticated user's threat modeling scans.",
)
async def get_scan_history_summary(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Get scan history summary statistics for the authenticated user."""
    user_id: str = current_user["auth_user"].id
    service = ThreatModelingService(supabase)

    try:
        return await service.get_scan_history_summary(user_id)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve scan history summary: {str(exc)}",
        )
