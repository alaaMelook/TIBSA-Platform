"""
AI Chatbot router — general-purpose cybersecurity assistant endpoint.

Endpoint:
  POST /api/v1/ai-chatbot/chat
    — Accepts a text message
    — Returns AI-generated security guidance
    — No report/scan context required

Rate limiting:
  10 requests/minute per IP (in-memory sliding window).
  Returns HTTP 429 when exceeded.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict

from fastapi import APIRouter, HTTPException, Request, status

from app.services.ai_chatbot.schemas import ChatRequest, ChatResponse
from app.services.ai_chatbot.service import chat

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Rate Limiting (in-memory, per-IP) ─────────────────────────────────────────
RATE_LIMIT_MAX = 10       # max requests
RATE_LIMIT_WINDOW = 60    # per 60 seconds

_rate_limit_store: dict[str, list[float]] = defaultdict(list)


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(client_ip: str) -> None:
    """
    Sliding-window rate limiter. Raises HTTP 429 if the IP
    has exceeded RATE_LIMIT_MAX requests in the last RATE_LIMIT_WINDOW seconds.
    """
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW

    # Prune expired timestamps
    timestamps = _rate_limit_store[client_ip]
    _rate_limit_store[client_ip] = [t for t in timestamps if t > window_start]

    if len(_rate_limit_store[client_ip]) >= RATE_LIMIT_MAX:
        oldest = min(_rate_limit_store[client_ip])
        retry_after = int(oldest + RATE_LIMIT_WINDOW - now) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    _rate_limit_store[client_ip].append(now)


@router.post(
    "/chat",
    response_model=ChatResponse,
    summary="Chat with TIBSA AI Security Assistant",
    description=(
        "Send a cybersecurity question and receive an AI-generated response. "
        "Supports English and Arabic. No scan or report context required."
    ),
    responses={
        429: {"description": "Rate limit exceeded"},
        503: {"description": "AI service unavailable (API key not configured)"},
        502: {"description": "AI service error"},
    },
)
async def chat_endpoint(
    request: Request,
    body: ChatRequest,
):
    """
    General-purpose AI security chatbot endpoint.
    Answers cybersecurity questions, TIBSA platform questions,
    and provides defensive guidance.
    """
    # ── Rate limiting ─────────────────────────────────────────────
    client_ip = _get_client_ip(request)
    _check_rate_limit(client_ip)

    logger.info(
        "AI Chatbot request — ip=%s, msg_len=%d, lang=%s",
        client_ip,
        len(body.message),
        body.language,
    )

    try:
        result = await chat(body)
    except ValueError as exc:
        # API key not configured or invalid
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    except RuntimeError as exc:
        error_msg = str(exc)
        # Propagate rate limit errors from OpenRouter with 429
        if "rate limit" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=error_msg,
            )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=error_msg,
        )

    return result
