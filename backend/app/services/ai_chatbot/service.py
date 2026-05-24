"""
AI Chatbot service — calls OpenRouter for general security Q&A.

Uses the same httpx-based approach as the existing AI malware analysis service
but with different prompts and no JSON parsing requirements.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.config import settings
from app.services.ai_chatbot.schemas import ChatRequest, ChatResponse, ChatContext
from app.services.ai_chatbot.prompt_builder import (
    build_system_prompt,
    detect_language,
    classify_category,
)
from app.services.ai_chatbot.guardrails import check_guardrails

logger = logging.getLogger(__name__)

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
REQUEST_TIMEOUT = 60  # seconds


async def chat(request: ChatRequest) -> ChatResponse:
    """
    Process a chatbot request:
    1. Detect language
    2. Run guardrails
    3. Build prompt
    4. Call OpenRouter
    5. Return structured response

    Raises:
        ValueError: if the API key is not configured
        RuntimeError: if the API call fails
    """
    # ── Resolve model from config ─────────────────────────────────
    model = settings.openrouter_model

    # ── Detect language ───────────────────────────────────────────
    language = request.language
    if language == "auto":
        language = detect_language(request.message)

    # ── Run guardrails ────────────────────────────────────────────
    is_safe, refusal_message = check_guardrails(request.message, language)
    if not is_safe:
        return ChatResponse(
            answer=refusal_message or "Request blocked by safety guardrails.",
            language=language,
            category="guardrail_block",
            safe=False,
            provider="openrouter",
            model=model,
        )

    # ── Classify question category ────────────────────────────────
    category = classify_category(request.message)

    # ── Build prompts ─────────────────────────────────────────────
    system_prompt = build_system_prompt(request.context)

    # ── Check API key ─────────────────────────────────────────────
    api_key = settings.openrouter_api_key
    if not api_key:
        raise ValueError(
            "OPENROUTER_API_KEY is not configured. "
            "Set it in your .env file to enable the AI chatbot."
        )

    # ── Call OpenRouter ───────────────────────────────────────────
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-Title": "TIBSA Platform",
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": request.message},
        ],
        "temperature": 0.3,
        "max_tokens": settings.openrouter_max_tokens,
    }

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
            )
        except httpx.TimeoutException:
            raise RuntimeError(
                "OpenRouter API request timed out. Please try again."
            )
        except httpx.RequestError as exc:
            raise RuntimeError(f"Failed to connect to OpenRouter: {exc}")

    # ── Handle HTTP errors ────────────────────────────────────────
    if response.status_code == 401:
        raise ValueError(
            "OpenRouter API key is invalid or expired. "
            "Please check your OPENROUTER_API_KEY."
        )

    if response.status_code == 429:
        raise RuntimeError(
            "OpenRouter free model rate limit reached. Please try again later."
        )

    if response.status_code >= 500:
        detail = response.text[:300]
        logger.error("OpenRouter server error %d: %s", response.status_code, detail)
        raise RuntimeError(
            "OpenRouter service is temporarily unavailable. Please try again later."
        )

    if response.status_code != 200:
        detail = response.text[:300]
        logger.error("OpenRouter API error %d: %s", response.status_code, detail)
        raise RuntimeError(
            f"OpenRouter API returned HTTP {response.status_code}."
        )

    # ── Parse response ────────────────────────────────────────────
    try:
        api_data = response.json()
    except Exception:
        raise RuntimeError("OpenRouter returned invalid JSON response.")

    choices = api_data.get("choices", [])
    if not choices:
        raise RuntimeError("OpenRouter returned no choices in the response.")

    answer = choices[0].get("message", {}).get("content", "")
    if not answer:
        raise RuntimeError("OpenRouter returned an empty message.")

    # ── Extract actual model used (OpenRouter may route to a specific model) ──
    actual_model = api_data.get("model", model)

    return ChatResponse(
        answer=answer.strip(),
        language=language,
        category=category,
        safe=True,
        provider="openrouter",
        model=actual_model,
    )
