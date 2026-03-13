"""
Notifications router.
Lists, marks-read, and manages user notifications.
"""
from fastapi import APIRouter, Depends
from typing import List
from supabase import Client

from app.dependencies import get_supabase, get_current_user
from app.models.notification import NotificationResponse
from app.services.notification_service import NotificationService

router = APIRouter()


@router.get("/", response_model=List[NotificationResponse], summary="List notifications")
async def list_notifications(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Get the current user's recent notifications (newest first)."""
    service = NotificationService(supabase)
    auth_user = current_user["auth_user"]
    return service.list_for_user(auth_user.id)


@router.get("/unread-count", summary="Unread notification count")
async def unread_count(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Return the number of unread notifications."""
    service = NotificationService(supabase)
    auth_user = current_user["auth_user"]
    return {"count": service.unread_count(auth_user.id)}


@router.patch("/{notification_id}/read", summary="Mark one notification as read")
async def mark_notification_read(
    notification_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Mark a single notification as read."""
    service = NotificationService(supabase)
    auth_user = current_user["auth_user"]
    result = service.mark_read(notification_id, auth_user.id)
    return result or {"status": "ok"}


@router.patch("/read-all", summary="Mark all notifications as read")
async def mark_all_read(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Mark all unread notifications as read."""
    service = NotificationService(supabase)
    auth_user = current_user["auth_user"]
    count = service.mark_all_read(auth_user.id)
    return {"status": "ok", "updated": count}
