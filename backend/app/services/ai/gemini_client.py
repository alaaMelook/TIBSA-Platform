import datetime
import json
import logging
from typing import Optional

from google import genai
from google.genai import types
from google.genai.errors import APIError

from app.config import settings

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-2.5-flash"


async def call_gemini(
    system_prompt: str,
    user_prompt: str,
    model: str = DEFAULT_MODEL,
    response_schema: Optional[dict] = None,
    timeout: int = 45,
) -> str:
    """
    Calls the Google Gemini API to generate content using the official SDK.
    Returns the raw string output from the model.
    """
    api_key = settings.gemini_api_key
    if not api_key:
        raise ValueError("GEMINI_API_KEY is not set in environment variables.")

    client = genai.Client(api_key=api_key)

    timestamp = datetime.datetime.now().isoformat()
    prompt_len = len(user_prompt)
    logger.info(f"[{timestamp}] GEMINI REQUEST - Model: {model}, Prompt Length: {prompt_len} chars")

    config_kwargs = {
        "system_instruction": system_prompt,
        "temperature": 0.2,
    }
    if response_schema:
        config_kwargs["response_mime_type"] = "application/json"

    config = types.GenerateContentConfig(**config_kwargs)

    try:
        response = await client.aio.models.generate_content(
            model=model,
            contents=user_prompt,
            config=config
        )

        response_text = response.text if response.text else ""
        trunc_body = response_text[:500] + "..." if len(response_text) > 500 else response_text
        logger.info(f"GEMINI RESPONSE - Status: SUCCESS, Body length: {len(response_text)}, Preview: {trunc_body}")

        if not response_text:
            raise ValueError(f"Empty response from Gemini API. Full response object: {response}")

        return response_text
    except APIError as e:
        logger.error(f"GEMINI ERROR - APIError (quota/rate-limit or API issue): {str(e)}")
        raise
    except Exception as e:
        logger.exception(f"GEMINI ERROR - Exception: {str(e)}")
        raise
