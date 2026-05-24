"""
Pydantic schemas for the AI Chatbot request/response models.
"""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class ChatContext(BaseModel):
    """Optional context about where the user is in the platform."""
    page: str = Field(default="dashboard", description="Current page the user is on")
    module: str = Field(default="general", description="Current module context")


class ChatRequest(BaseModel):
    """Request body for the chatbot endpoint."""
    message: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="User's question or message",
    )
    language: str = Field(
        default="auto",
        description="Preferred response language: 'en', 'ar', or 'auto' (detect from message)",
    )
    conversation_id: Optional[str] = Field(
        default=None,
        description="Optional conversation ID for frontend tracking",
    )
    context: Optional[ChatContext] = Field(
        default=None,
        description="Optional context about the user's current location in the platform",
    )


class ChatResponse(BaseModel):
    """Response body from the chatbot endpoint."""
    answer: str = Field(..., description="The AI assistant's response")
    language: str = Field(..., description="Language of the response (en/ar)")
    category: str = Field(
        default="security_explanation",
        description="Category of the response",
    )
    safe: bool = Field(default=True, description="Whether the response passed guardrails")
    provider: str = Field(default="openrouter", description="AI provider used")
    model: str = Field(..., description="Model used for the response")
