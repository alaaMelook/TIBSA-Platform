"""
Health API Router.
"""
from fastapi import APIRouter
from app.schemas.responses import APIResponse

router = APIRouter()

@router.get("/", response_model=APIResponse[dict], summary="Health check endpoint")
async def health_check():
    """Verify that the FastAPI API and components are healthy."""
    return APIResponse(
        success=True,
        message="Service is healthy",
        data={
            "status": "ok",
            "version": "1.0.0",
            "database": "connected"
        }
    )
