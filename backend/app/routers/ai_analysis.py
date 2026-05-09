"""
AI Analysis router — isolated endpoint for AI-powered malware explanation.

Endpoint:
  POST /api/v1/ai-analysis/explain
    — Accepts file upload
    — Runs Malice → YARA → CAPA analysis pipeline
    — Aggregates results into structured JSON
    — Sends to OpenRouter for AI explanation
    — Returns AIExplanationResponse

Rate limiting:
  5 requests/minute per IP (in-memory sliding window).
  Returns HTTP 429 when exceeded.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from typing import Any, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    UploadFile,
    status,
)

from app.dependencies import get_current_user
from app.services.ai.schemas import MalwareScanInput, AIExplanationResponse
from app.services.ai.malware_explainer import explain_malware
from app.services.ai import yara_scanner
from app.services.ai import capa_analyzer
from app.services import malice_service

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Rate Limiting (in-memory, per-IP) ─────────────────────────────────────────
RATE_LIMIT_MAX = 5        # max requests
RATE_LIMIT_WINDOW = 60    # per 60 seconds

_rate_limit_store: dict[str, list[float]] = defaultdict(list)


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
        # Calculate when the oldest request in the window expires
        oldest = min(_rate_limit_store[client_ip])
        retry_after = int(oldest + RATE_LIMIT_WINDOW - now) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    _rate_limit_store[client_ip].append(now)


# ── Maximum file size (32 MB) ────────────────────────────────────────────────
MAX_FILE_SIZE = 32 * 1024 * 1024


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _compute_threat_score(
    malice_detected: int,
    malice_total: int,
    yara_count: int,
    capa_count: int,
) -> int:
    """
    Compute a 0-100 threat score from scan results.
    Weighted: 40% Malice detection ratio, 30% YARA, 30% CAPA.
    """
    # Malice component (0-100)
    if malice_total > 0:
        malice_score = min(100, int((malice_detected / malice_total) * 100))
    else:
        malice_score = 0

    # YARA component — each match adds 15 points, capped at 100
    yara_score = min(100, yara_count * 15)

    # CAPA component — each behavior adds 10 points, capped at 100
    capa_score = min(100, capa_count * 10)

    # Weighted average
    total = int(malice_score * 0.4 + yara_score * 0.3 + capa_score * 0.3)
    return min(100, total)


def _is_json_upload(filename: str, content_type: str | None) -> bool:
    """Detect JSON uploads by extension OR content type."""
    if filename.lower().endswith(".json"):
        return True
    if content_type and content_type.lower().strip() in (
        "application/json", "text/json"
    ):
        return True
    return False


def _parse_and_validate_scan_json(
    filename: str, content: bytes
) -> MalwareScanInput:
    """
    Parse and validate a JSON file.
    Raises HTTPException (400) if JSON is malformed or validation fails.
    """
    from app.services.ai.validators import validate_scan_json, ScanValidationError
    
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON format. The uploaded file contains malformed JSON that cannot be parsed."
        )

    try:
        clean_data, warnings = validate_scan_json(data)
    except ScanValidationError as exc:
        error_str = "Validation Error: " + " | ".join(exc.errors)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_str
        )

    for warning in warnings:
        logger.warning(warning)

    return MalwareScanInput(
        file_name=clean_data["file_name"],
        file_type=clean_data["file_type"],
        detections=clean_data["detections"],
        detection_count=clean_data["detection_count"],
        yara_matches=clean_data["yara_matches"],
        capa_behaviors=clean_data["capa_behaviors"],
        threat_score=clean_data["threat_score"],
    )


@router.post(
    "/explain",
    response_model=AIExplanationResponse,
    summary="Upload a file for AI-powered malware analysis",
    responses={
        429: {"description": "Rate limit exceeded"},
        503: {"description": "AI service unavailable (API key not configured)"},
    },
)
async def explain_file(
    request: Request,
    file: UploadFile = File(..., description="File to analyze (max 32 MB)"),
    current_user: dict = Depends(get_current_user),
):
    """
    Full AI malware analysis pipeline:
    1. Upload file
    2. Run Malice AV scan (Docker engines)
    3. Run YARA rule matching
    4. Run CAPA behavior analysis
    5. Aggregate results
    6. Send to OpenRouter for AI explanation
    7. Return structured analysis
    """
    # ── Rate limiting ─────────────────────────────────────────────
    client_ip = _get_client_ip(request)
    _check_rate_limit(client_ip)

    # ── Read and validate file ────────────────────────────────────
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024 * 1024)} MB.",
        )

    filename = file.filename or "unknown_file"

    logger.info(
        "AI analysis started — file=%s, size=%d bytes, user=%s, ip=%s",
        filename,
        len(content),
        current_user["auth_user"].id,
        client_ip,
    )

    # ── Check for JSON scan data shortcut ─────────────────────────
    # If the user uploaded a .json file containing pre-formatted scan
    # results, use that data directly instead of running empty scanners.
    if _is_json_upload(filename, file.content_type):
        json_scan_input = _parse_and_validate_scan_json(filename, content)
        logger.info(
            "JSON scan data detected — skipping pipeline, using embedded data. "
            "file=%s, detections=%d, yara=%d, capa=%d, score=%d",
            json_scan_input.file_name,
            json_scan_input.detection_count,
            len(json_scan_input.yara_matches),
            len(json_scan_input.capa_behaviors),
            json_scan_input.threat_score,
        )
        try:
            result = await explain_malware(json_scan_input)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"AI analysis failed: {exc}",
            )
        return result

    # ── Run analysis pipeline concurrently ────────────────────────
    # Malice, YARA, and CAPA run in parallel for performance
    malice_task = malice_service.scan_file_with_malice(filename, content)
    yara_task = asyncio.to_thread(yara_scanner.scan_file_bytes, filename, content)
    capa_task = capa_analyzer.analyze_file(filename, content)

    malice_result, yara_matches, capa_behaviors = await asyncio.gather(
        malice_task, yara_task, capa_task, return_exceptions=True,
    )

    # ── Handle errors gracefully ──────────────────────────────────
    # Malice
    malice_data: dict[str, Any] = {}
    if isinstance(malice_result, Exception):
        logger.warning("Malice scan failed: %s", malice_result)
        malice_data = {"error": str(malice_result), "detected_by": 0, "total_engines": 0, "engines": []}
    else:
        malice_data = malice_result or {"detected_by": 0, "total_engines": 0, "engines": []}

    # YARA
    yara_list: list[str] = []
    if isinstance(yara_matches, Exception):
        logger.warning("YARA scan failed: %s", yara_matches)
    else:
        yara_list = yara_matches or []

    # CAPA
    capa_list: list[str] = []
    if isinstance(capa_behaviors, Exception):
        logger.warning("CAPA analysis failed: %s", capa_behaviors)
    else:
        capa_list = capa_behaviors or []

    # ── Extract Malice detection labels ───────────────────────────
    detections: list[str] = []
    for engine in malice_data.get("engines", []):
        if engine.get("malware") and engine.get("result"):
            detections.append(engine["result"])
        elif engine.get("malware"):
            detections.append(engine.get("label", engine.get("engine", "Unknown")))

    malice_detected = malice_data.get("detected_by", 0)
    malice_total = malice_data.get("total_engines", 0)

    # ── Compute threat score ──────────────────────────────────────
    threat_score = _compute_threat_score(
        malice_detected=malice_detected,
        malice_total=malice_total,
        yara_count=len(yara_list),
        capa_count=len(capa_list),
    )

    # ── Determine file type from Malice or filename ───────────────
    file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown"
    file_type_map = {
        "exe": "PE32 executable",
        "dll": "PE32 DLL",
        "pdf": "PDF document",
        "doc": "Microsoft Word document",
        "docx": "Microsoft Word document",
        "xls": "Microsoft Excel spreadsheet",
        "xlsx": "Microsoft Excel spreadsheet",
        "js": "JavaScript file",
        "vbs": "VBScript file",
        "ps1": "PowerShell script",
        "bat": "Batch script",
        "zip": "ZIP archive",
        "rar": "RAR archive",
        "py": "Python script",
    }
    file_type = file_type_map.get(file_ext, f".{file_ext} file")

    # ── Build structured payload ──────────────────────────────────
    scan_input = MalwareScanInput(
        file_name=filename,
        file_type=file_type,
        detections=detections,
        detection_count=malice_detected,
        yara_matches=yara_list,
        capa_behaviors=capa_list,
        threat_score=threat_score,
    )

    logger.info(
        "Scan aggregated — file=%s, detections=%d, yara=%d, capa=%d, score=%d",
        filename,
        malice_detected,
        len(yara_list),
        len(capa_list),
        threat_score,
    )

    # ── Call AI for explanation ────────────────────────────────────
    try:
        result = await explain_malware(scan_input)
    except ValueError as exc:
        # API key not configured
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    except RuntimeError as exc:
        # AI call failed
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"AI analysis failed: {exc}",
        )

    return result
