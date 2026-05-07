"""
OpenRouter API client for AI malware explanation.

Uses httpx (already a project dependency) to call the OpenRouter
chat completions endpoint.  No OpenAI SDK dependency required.

Model: meta-llama/llama-3.3-70b-instruct
Config: low temperature, deterministic, concise security-focused responses.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "meta-llama/llama-3.3-70b-instruct"

# Inference parameters — tuned for deterministic, detailed output
TEMPERATURE = 0
MAX_TOKENS = 2048
REQUEST_TIMEOUT = 90  # seconds


async def call_openrouter(system_prompt: str, user_prompt: str) -> dict[str, Any]:
    """
    Send a chat completion request to OpenRouter and return parsed JSON.

    Raises:
        ValueError: if the API key is not configured
        RuntimeError: if the API call fails or returns unparseable output
    """
    api_key = settings.openrouter_api_key
    if not api_key:
        raise ValueError(
            "OPENROUTER_API_KEY is not configured. "
            "Set it in your .env file to enable AI analysis."
        )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://tibsa.app",
        "X-Title": "TIBSA Malware Analyzer",
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "seed": 42,
        "response_format": {"type": "json_object"},
    }

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
            )
        except httpx.TimeoutException:
            raise RuntimeError("OpenRouter API request timed out after 60 seconds.")
        except httpx.RequestError as exc:
            raise RuntimeError(f"Failed to connect to OpenRouter: {exc}")

    if response.status_code != 200:
        detail = response.text[:500]
        logger.error("OpenRouter API error %d: %s", response.status_code, detail)
        raise RuntimeError(
            f"OpenRouter API returned HTTP {response.status_code}. "
            "Check your API key and account quota."
        )

    # Parse the API response
    try:
        api_data = response.json()
    except Exception:
        raise RuntimeError("OpenRouter returned invalid JSON response.")

    # Extract the assistant message content
    choices = api_data.get("choices", [])
    if not choices:
        raise RuntimeError("OpenRouter returned no choices in the response.")

    content = choices[0].get("message", {}).get("content", "")
    if not content:
        raise RuntimeError("OpenRouter returned an empty message.")

    # Parse the JSON from the model's response
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Try to extract JSON from the response if it's wrapped in text
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(content[start:end])
            except json.JSONDecodeError:
                pass
        logger.error("Failed to parse AI response as JSON: %s", content[:300])
        raise RuntimeError("AI returned a non-JSON response. Please try again.")
