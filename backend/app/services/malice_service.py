"""
Malice AV (Docker-based) integration.

Runs locally-pulled malice/<engine> Docker images against uploaded files.
Each image is executed in parallel; results are aggregated and returned.

Supported engines (any subset can be enabled via MALICE_ENGINES env var):
  clamav, windows-defender, bitdefender, mcafee, fprot, escan,
  comodo, avira, avg, avast, kaspersky, zoner

Docker requirement:
  - Docker daemon must be running and accessible.
  - If the backend itself runs inside Docker, the host Docker socket must be
    mounted:  -v /var/run/docker.sock:/var/run/docker.sock
  - The temp directory used for file I/O must be bind-mountable by Docker.
    On Linux/Mac this is usually /tmp.  On Windows use a path inside
    C:\\Users\\... or adjust MALICE_TMP_DIR env var accordingly.
"""

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
import uuid
from typing import Any

logger = logging.getLogger(__name__)

# ── Engine registry ───────────────────────────────────────────────────────────

ALL_ENGINES: list[str] = [
    "clamav",
    "windows-defender",
    "bitdefender",
    "mcafee",
    "fprot",
    "escan",
    "comodo",
    "avira",
    "avg",
    "avast",
    "kaspersky",
    "zoner",
]

# Friendly display names
ENGINE_LABELS: dict[str, str] = {
    "clamav":            "ClamAV",
    "windows-defender":  "Windows Defender",
    "bitdefender":       "Bitdefender",
    "mcafee":            "McAfee",
    "fprot":             "F-Prot",
    "escan":             "eScan",
    "comodo":            "Comodo",
    "avira":             "Avira",
    "avg":               "AVG",
    "avast":             "Avast",
    "kaspersky":         "Kaspersky",
    "zoner":             "Zoner",
}

# Per-container timeout in seconds
CONTAINER_TIMEOUT = int(os.getenv("MALICE_CONTAINER_TIMEOUT", "120"))

# Temp directory accessible to Docker daemon
# On Linux: /tmp works out of the box.
# On Windows with Docker Desktop: must be under a shared drive path.
MALICE_TMP_DIR = os.getenv("MALICE_TMP_DIR", tempfile.gettempdir())

# Comma-separated list of engines to run (default: all)
_env_engines = os.getenv("MALICE_ENGINES", "")
ENABLED_ENGINES: list[str] = (
    [e.strip() for e in _env_engines.split(",") if e.strip()]
    if _env_engines
    else ALL_ENGINES
)


# ── Helper ────────────────────────────────────────────────────────────────────

def _extract_json(raw: str) -> dict[str, Any]:
    """
    Extract the last JSON object from Docker stdout.
    Malice containers usually print a single JSON blob; some prepend log lines.
    """
    # Try to find the last {...} block in the output
    matches = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)?\}", raw, re.DOTALL)
    for candidate in reversed(matches):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    # Fallback: try to parse the whole output
    try:
        return json.loads(raw.strip())
    except json.JSONDecodeError:
        return {}


def _parse_engine_result(engine: str, raw_stdout: str, exit_code: int) -> dict[str, Any]:
    """
    Normalise a single engine's Docker output into a consistent dict:
      {
        "engine":    str,   # engine key
        "label":     str,   # display name
        "malware":   bool,  # detected?
        "result":    str | None,   # virus name / null if clean
        "updated":   str | None,   # virus db date
        "error":     str | None,   # if the container crashed
      }
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

    if exit_code not in (0, 1):
        # exit 1 = malware found (convention for some malice images)
        # anything else = error
        base["error"] = f"Container exited with code {exit_code}"
        return base

    data = _extract_json(raw_stdout)
    if not data:
        base["error"] = "No JSON output from container"
        return base

    # Different malice images use slightly different field names
    malware = (
        data.get("malware")
        or data.get("infected")
        or data.get("Infected")
        or False
    )
    result = (
        data.get("result")
        or data.get("virus")
        or data.get("Virus")
        or data.get("signature")
        or None
    )
    updated = (
        data.get("updated")
        or data.get("database")
        or data.get("db_version")
        or None
    )

    base["malware"] = bool(malware)
    base["result"]  = str(result) if result and result != "null" else None
    base["updated"] = str(updated) if updated else None
    return base


# ── Core async runner ─────────────────────────────────────────────────────────

async def _run_one_engine(engine: str, scan_dir: str, filename: str) -> dict[str, Any]:
    """
    Run a single malice Docker container against the file.
    scan_dir is the host-side temp directory that gets mounted as /malware.
    """
    image = f"malice/{engine}"
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",           # no internet access during scan
        "--memory", "512m",
        "-v", f"{scan_dir}:/malware:ro",
        image,
        filename,
    ]

    label = ENGINE_LABELS.get(engine, engine)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=CONTAINER_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {
                "engine":  engine,
                "label":   label,
                "malware": False,
                "result":  None,
                "updated": None,
                "error":   f"Timed out after {CONTAINER_TIMEOUT}s",
            }

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if stderr:
            logger.debug("[malice/%s] stderr: %s", engine, stderr[:500])

        return _parse_engine_result(engine, stdout, proc.returncode)

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

    # Write file to a temp directory Docker can mount
    scan_dir = os.path.join(MALICE_TMP_DIR, f"malice_scan_{uuid.uuid4().hex}")
    os.makedirs(scan_dir, exist_ok=True)
    file_path = os.path.join(scan_dir, filename)

    try:
        with open(file_path, "wb") as fh:
            fh.write(content)

        # Run all engines concurrently
        tasks = [
            _run_one_engine(engine, scan_dir, filename)
            for engine in engines_to_run
        ]
        results: list[dict[str, Any]] = await asyncio.gather(*tasks)

    finally:
        # Clean up temp dir regardless of outcome
        try:
            shutil.rmtree(scan_dir, ignore_errors=True)
        except Exception:
            pass

    detected_by = sum(1 for r in results if r.get("malware"))
    total = len([r for r in results if not r.get("error")])  # only engines that ran
    top_result = next(
        (r["result"] for r in results if r.get("malware") and r.get("result")),
        None,
    )

    # Threat level heuristic
    if detected_by >= 3:
        threat_level = "high"
    elif detected_by >= 1:
        threat_level = "medium"
    else:
        threat_level = "clean"

    return {
        "engines":       results,
        "detected_by":   detected_by,
        "total_engines": total,
        "threat_level":  threat_level,
        "top_result":    top_result,
    }
