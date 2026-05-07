"""
CAPA behavior analyzer for the AI malware analysis pipeline.

Runs the capa CLI tool as a subprocess to identify behavioral
capabilities in uploaded files (PE, ELF, shellcode, etc.).

The capa binary must be installed on the system and accessible in PATH.
If capa is not installed, the analyzer returns an empty result with
a logged warning — never crashes.

Install capa:
  pip install flare-capa
  OR download from: https://github.com/mandiant/capa/releases
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

# Timeout for capa analysis (seconds)
CAPA_TIMEOUT = 60

# Workspace-local temp directory for files being analyzed
_TEMP_DIR = Path(__file__).resolve().parents[3] / "_capa_temp"


def _is_capa_available() -> bool:
    """Check if the capa CLI is available in PATH."""
    try:
        result = subprocess.run(
            ["capa", "--version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    except Exception:
        return False


async def analyze_file(filename: str, content: bytes) -> List[str]:
    """
    Analyze file bytes with capa and return identified behaviors.

    Returns:
        List of capability/behavior descriptions
        (e.g. ["Steals browser credentials", "Creates registry persistence"]).
        Returns empty list if capa is unavailable or analysis fails.
    """
    def _run_capa() -> List[str]:
        # Check availability
        if not _is_capa_available():
            logger.warning(
                "capa CLI is not installed or not in PATH. "
                "CAPA behavior analysis is disabled. "
                "Install with: pip install flare-capa"
            )
            return []

        # Create temp directory inside workspace
        _TEMP_DIR.mkdir(parents=True, exist_ok=True)

        # Write file to temp location with a safe name
        safe_name = f"capa_{uuid.uuid4().hex}_{os.path.basename(filename)}"
        temp_path = _TEMP_DIR / safe_name

        try:
            temp_path.write_bytes(content)

            # Run capa with JSON output
            result = subprocess.run(
                ["capa", "-j", str(temp_path)],
                capture_output=True,
                timeout=CAPA_TIMEOUT,
            )

            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace")[:500]
                if "unsupported file type" in stderr.lower():
                    logger.info(
                        "capa: unsupported file type for %s (not a PE/ELF)",
                        filename,
                    )
                else:
                    logger.warning(
                        "capa exited with code %d for %s: %s",
                        result.returncode,
                        filename,
                        stderr,
                    )
                return []

            # Parse JSON output
            stdout = result.stdout.decode("utf-8", errors="replace")
            try:
                capa_data = json.loads(stdout)
            except json.JSONDecodeError:
                logger.error("capa returned invalid JSON for %s", filename)
                return []

            # Extract capability names from the rules section
            behaviors = []
            rules = capa_data.get("rules", {})
            for rule_name, rule_data in rules.items():
                # capa rules have a "meta" with a human-readable name
                meta = rule_data.get("meta", {})
                display_name = meta.get("name", rule_name)

                # Filter to only ATT&CK-mapped or high-value capabilities
                # Include all for maximum coverage
                behaviors.append(display_name)

            if behaviors:
                logger.info(
                    "CAPA identified %d behaviors for %s: %s",
                    len(behaviors),
                    filename,
                    ", ".join(behaviors[:5]) + ("..." if len(behaviors) > 5 else ""),
                )

            return behaviors

        except subprocess.TimeoutExpired:
            logger.warning("capa timed out after %ds for %s", CAPA_TIMEOUT, filename)
            return []
        except Exception as exc:
            logger.error("capa analysis failed for %s: %s", filename, exc)
            return []
        finally:
            # Clean up temp file
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass

    # Run blocking subprocess in thread pool
    return await asyncio.to_thread(_run_capa)
