"""
Notification-related Pydantic models.
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class NotificationResponse(BaseModel):
    id: str
    user_id: str
    title: str
    body: str
    type: str  # "threat" | "scan" | "system"
    read: bool
    scan_id: Optional[str] = None
    created_at: Optional[datetime] = None
