"""
Scans API Router.
Placeholder to support future scan-specific endpoints.
"""
from fastapi import APIRouter, Depends
from app.dependencies import get_current_user
from app.schemas.responses import APIResponse

router = APIRouter()

@router.get("/", response_model=APIResponse[dict], summary="List all scans (metadata)")
async def list_scans(
    current_user: dict = Depends(get_current_user),
):
    """Placeholder endpoint for direct scanner operations."""
    return APIResponse(
        success=True,
        message="Scanner engine is active and operational.",
        data={"scans": []}
    )
