"""
Malice AV (Docker-based) integration.

Runs locally-pulled malice/<engine> Docker images against uploaded files.
Each image is executed in parallel; results are aggregated and returned.

Supported engines (any subset can be enabled via MALICE_ENGINES env var):
  clamav, windows-defender, mcafee, fprot, escan, comodo, avg, zoner

Removed engines (malice project abandoned ~2018, images no longer functional):
  bitdefender  — binary crash (exit 254)
  avira        — license expired, no replacement available
  avast        — license expired
  kaspersky    — binary crash (exit 2)

Architecture:
  Uses Docker *named volumes* to transfer files to scan containers.
  This is critical on Windows where host-side antivirus (Windows Defender etc.)
  quarantines malware samples written to the host filesystem, making them invisible
  to any subsequent Docker bind-mount.

  Flow:
    1. Create a one-off Docker volume: malice_scan_<uuid>
    2. Pipe the raw file bytes into a tiny Alpine container that writes them
       inside the volume → /data/<filename>
    3. Mount the same volume (read-only) into each malice/engine container
       as /malware, scanning the uploaded file.
    4. Collect JSON stdout from each engine, parse and normalise.
    5. Remove the volume.

Docker requirement:
  - Docker daemon must be running and accessible from the backend process.
  - All engine images must be pulled beforehand:
      docker pull malice/clamav malice/windows-defender ...
  - If the backend runs inside a container, the host Docker socket must be
    mounted:  -v /var/run/docker.sock:/var/run/docker.sock

Malice container JSON output format (nested by engine name):
  {"clamav": {"infected": false, "result": "", "engine": "0.100", ...}}
  {"windows_defender": {"infected": false, "result": "", ...}}
Note: hyphens in engine names become underscores in JSON keys.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# ── Engine registry ───────────────────────────────────────────────────────────

ALL_ENGINES: list[str] = [
    "clamav",
    "windows-defender",
    "mcafee",
    "fprot",
    "escan",
    "comodo",
    "avg",
    "zoner",
]

# Friendly display names
ENGINE_LABELS: dict[str, str] = {
    "clamav":            "ClamAV",
    "windows-defender":  "Windows Defender",
    "mcafee":            "McAfee",
    "fprot":             "F-Prot",
    "escan":             "eScan",
    "comodo":            "Comodo",
    "avg":               "AVG",
    "zoner":             "Zoner",
}

# Per-container timeout in seconds
CONTAINER_TIMEOUT = int(os.getenv("MALICE_CONTAINER_TIMEOUT", "120"))

# Maximum number of AV containers running in parallel (prevents OOM kills)
MAX_PARALLEL = int(os.getenv("MALICE_MAX_PARALLEL", "4"))

# Per-engine memory overrides (ClamAV loads a large virus DB)
ENGINE_MEMORY: dict[str, str] = {
    "clamav": "1g",
}
DEFAULT_MEMORY = "512m"

# Alpine image used for the helper container that writes files into volumes
HELPER_IMAGE = os.getenv("MALICE_HELPER_IMAGE", "alpine:latest")

# Comma-separated list of engines to run (default: all)
_env_engines = os.getenv("MALICE_ENGINES", "")
ENABLED_ENGINES: list[str] = (
    [e.strip() for e in _env_engines.split(",") if e.strip()]
    if _env_engines
    else ALL_ENGINES
)


# ── Helper ────────────────────────────────────────────────────────────────────

def _safe_name(filename: str) -> str:
    """
    Return a shell-safe filename for use inside Docker containers.
    Strips path separators and replaces any non-alphanumeric characters
    (except dot, dash, underscore) with underscores.  This prevents
    filenames like  "report (2).pdf"  from breaking  sh -c "cat > ...".
    """
    base = os.path.basename(filename)
    return re.sub(r"[^\w.\-]", "_", base) or "scanfile"


def _extract_json(raw: str) -> dict[str, Any]:
    """
    Extract the first complete JSON object from Docker stdout.
    Malice containers print one JSON blob; stderr may contain log lines that
    get mixed in — we want the first valid {...} block.
    """
    # Walk through the string finding balanced braces
    depth = 0
    start = None
    for i, ch in enumerate(raw):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                candidate = raw[start : i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    start = None  # keep scanning
    return {}


def _extract_nested(data: dict, engine: str) -> dict[str, Any]:
    """
    Malice containers wrap results under the engine name as the top-level key.
    Hyphens in engine names become underscores in the JSON key.
      e.g. engine="windows-defender" → key="windows_defender"
    Try both forms, then fall back to treating the whole dict as flat.
    """
    key_underscore = engine.replace("-", "_")
    return (
        data.get(key_underscore)
        or data.get(engine)
        or {}
    )


def _str_or_none(value: Any) -> str | None:
    """Return stripped string or None for empty/null values."""
    if not value:
        return None
    s = str(value).strip()
    return s if s and s.lower() not in ("null", "none", "false") else None


def _parse_engine_result(engine: str, raw_stdout: str, exit_code: int) -> dict[str, Any]:
    """
    Normalise a single engine's Docker output into a consistent dict:
      {
        "engine":  str,         # engine key
        "label":   str,         # display name
        "malware": bool,        # detected?
        "result":  str | None,  # virus name / null if clean
        "updated": str | None,  # virus db date
        "error":   str | None,  # if the container crashed or errored
      }

    Malice container output format:
      {"clamav": {"infected": false, "result": "", "engine": "...", ...}}
      {"windows_defender": {"infected": false, "result": "", ...}}
    """
    label = ENGINE_LABELS.get(engine, engine)
    base: dict[str, Any] = {
        "engine":  engine,
        "label":   label,
        "malware": False,
        "result":  None,
        "updated": None,
        "error":   None,
    }

    # Always attempt JSON extraction — some engines return valid JSON even on
    # non-zero exit codes (expired licence, minor warnings, etc.).
    data = _extract_json(raw_stdout)

    if not data:
        # No JSON at all — genuine container failure
        base["error"] = (
            f"Container exited with code {exit_code}" if exit_code != 0
            else "No JSON output from container"
        )
        return base

    # ── Malice nested format ──────────────────────────────────────────────
    # {"clamav": {"infected": ..., "result": ..., "engine": ..., "updated": ..., "error": ""}}
    nested = _extract_nested(data, engine)

    if nested:
        malware = bool(
            nested.get("infected")
            or nested.get("malware")
            or nested.get("Infected")
            or False
        )
        result  = _str_or_none(
            nested.get("result") or nested.get("virus") or nested.get("signature")
        )
        updated = _str_or_none(
            nested.get("updated") or nested.get("database") or nested.get("db_version")
        )
        err     = _str_or_none(nested.get("error"))
    else:
        # Flat JSON fallback (non-standard engine)
        malware = bool(
            data.get("malware") or data.get("infected") or data.get("Infected") or False
        )
        result  = _str_or_none(
            data.get("result") or data.get("virus") or data.get("signature")
        )
        updated = _str_or_none(
            data.get("updated") or data.get("database") or data.get("db_version")
        )
        err     = _str_or_none(data.get("error"))

    base["malware"] = malware
    base["result"]  = result
    base["updated"] = updated
    if err:
        base["error"] = err

    return base


# ── Docker volume helpers ─────────────────────────────────────────────────────
#
# We use subprocess.run() inside asyncio.to_thread() instead of
# asyncio.create_subprocess_exec() because uvicorn on Windows often runs
# a SelectorEventLoop that does NOT support subprocess_exec.
# Running blocking subprocess calls in the thread-pool executor works
# with *any* event loop implementation.
# ──────────────────────────────────────────────────────────────────────────────

async def _create_volume(vol_name: str) -> None:
    """Create a Docker named volume."""
    def _run():
        subprocess.run(
            ["docker", "volume", "create", vol_name],
            capture_output=True,
            check=True,
        )
    await asyncio.to_thread(_run)


async def _remove_volume(vol_name: str) -> None:
    """Remove a Docker named volume (ignore errors if already gone)."""
    def _run():
        subprocess.run(
            ["docker", "volume", "rm", "-f", vol_name],
            capture_output=True,
        )
    await asyncio.to_thread(_run)


async def _write_file_to_volume(
    vol_name: str, filename: str, content: bytes
) -> None:
    """
    Pipe raw file bytes into a tiny Alpine container that writes them inside
    the Docker volume.  This bypasses the host filesystem entirely, so no
    host antivirus (Windows Defender, etc.) can quarantine the file.
    """
    def _run():
        result = subprocess.run(
            [
                "docker", "run", "--rm", "-i",
                "-v", f"{vol_name}:/data",
                HELPER_IMAGE,
                "sh", "-c", f"cat > /data/{filename}",
            ],
            input=content,
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Helper container failed (exit {result.returncode}): "
                f"{result.stderr.decode('utf-8', errors='replace')}"
            )
    await asyncio.to_thread(_run)


# ── Core async runner ─────────────────────────────────────────────────────────

async def _run_one_engine(engine: str, vol_name: str, filename: str) -> dict[str, Any]:
    """
    Run a single malice Docker container against the file stored in a
    Docker named volume.  The volume is mounted read-only as /malware.
    Uses subprocess.run in a thread to work with any event loop.
    """
    image = f"malice/{engine}"
    mem = ENGINE_MEMORY.get(engine, DEFAULT_MEMORY)
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",           # no internet access during scan
        "--memory", mem,
        "-v", f"{vol_name}:/malware:ro",
        image,
        filename,
    ]

    label = ENGINE_LABELS.get(engine, engine)
    try:
        def _run():
            return subprocess.run(
                cmd,
                capture_output=True,
                timeout=CONTAINER_TIMEOUT,
            )

        result = await asyncio.to_thread(_run)
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")

        if stderr:
            logger.debug("[malice/%s] stderr: %s", engine, stderr[:500])

        return _parse_engine_result(engine, stdout, result.returncode)

    except subprocess.TimeoutExpired:
        return {
            "engine":  engine,
            "label":   label,
            "malware": False,
            "result":  None,
            "updated": None,
            "error":   f"Timed out after {CONTAINER_TIMEOUT}s",
        }
    except FileNotFoundError:
        return {
            "engine":  engine,
            "label":   label,
            "malware": False,
            "result":  None,
            "updated": None,
            "error":   "docker not found — is Docker installed and in PATH?",
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("[malice/%s] unexpected error: %s", engine, exc)
        return {
            "engine":  engine,
            "label":   label,
            "malware": False,
            "result":  None,
            "updated": None,
            "error":   str(exc),
        }


# ── Public API ────────────────────────────────────────────────────────────────

async def scan_file_with_malice(
    filename: str,
    content: bytes,
    engines: list[str] | None = None,
) -> dict[str, Any]:
    """
    Scan *content* (raw file bytes) with all enabled malice AV engines.

    Uses a Docker named volume to transfer the file into containers,
    completely bypassing the host filesystem (and any host-side AV
    that would quarantine malware samples).

    Returns:
      {
        "engines":        [ { engine, label, malware, result, updated, error }, ... ],
        "detected_by":    int,   # number of engines that flagged as malware
        "total_engines":  int,
        "threat_level":   str,   # "clean" | "low" | "medium" | "high"
        "top_result":     str | None,  # first non-null detection name
      }
    """
    engines_to_run = engines if engines is not None else ENABLED_ENGINES
    vol_name = f"malice_scan_{uuid.uuid4().hex}"
    safe = _safe_name(filename)

    try:
        # 1. Create a Docker volume
        await _create_volume(vol_name)

        # 2. Pipe file bytes into the volume via a helper container
        await _write_file_to_volume(vol_name, safe, content)

        # 3. Run engines with concurrency cap to avoid OOM kills
        sem = asyncio.Semaphore(MAX_PARALLEL)

        async def _guarded(engine: str) -> dict[str, Any]:
            async with sem:
                return await _run_one_engine(engine, vol_name, safe)

        tasks = [_guarded(engine) for engine in engines_to_run]
        results: list[dict[str, Any]] = await asyncio.gather(*tasks)

    finally:
        # 4. Clean up the volume regardless of outcome
        try:
            await _remove_volume(vol_name)
        except Exception:
            pass

    detected_by = sum(1 for r in results if r.get("malware"))
    total = len([r for r in results if not r.get("error")])  # only engines that ran
    top_result = next(
        (r["result"] for r in results if r.get("malware") and r.get("result")),
        None,
    )

    # Threat level heuristic: 0=clean, 1-2=low, 3-4=medium, 5+=high
    if detected_by == 0:
        threat_level = "clean"
    elif detected_by <= 2:
        threat_level = "low"
    elif detected_by <= 4:
        threat_level = "medium"
    else:
        threat_level = "high"

    return {
        "engines":       results,
        "detected_by":   detected_by,
        "total_engines": total,
        "threat_level":  threat_level,
        "top_result":    top_result,
    }
