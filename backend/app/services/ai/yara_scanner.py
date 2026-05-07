"""
YARA rule scanner for the AI malware analysis pipeline.

Uses yara-python to load and compile .yar rule files from the
backend/yara_rules/ directory, then scans uploaded file bytes in memory.

Rules are compiled once at first use and cached for performance.
If yara-python is not installed or the rules directory is missing,
the scanner returns an empty result with a logged warning — never crashes.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

# Path to YARA rules directory (relative to backend/)
_RULES_DIR = Path(__file__).resolve().parents[3] / "yara_rules"

# Cached compiled rules
_compiled_rules = None
_rules_loaded = False


def _compile_rules():
    """Compile all .yar files in the rules directory. Called once."""
    global _compiled_rules, _rules_loaded
    _rules_loaded = True

    try:
        import yara  # type: ignore
    except ImportError:
        logger.warning(
            "yara-python is not installed. YARA scanning is disabled. "
            "Install with: pip install yara-python"
        )
        return

    if not _RULES_DIR.is_dir():
        logger.warning(
            "YARA rules directory not found at %s — YARA scanning disabled.",
            _RULES_DIR,
        )
        return

    # Collect all .yar files
    rule_files = {}
    for yar_file in sorted(_RULES_DIR.glob("*.yar")):
        namespace = yar_file.stem  # filename without extension
        rule_files[namespace] = str(yar_file)

    if not rule_files:
        logger.warning("No .yar files found in %s", _RULES_DIR)
        return

    try:
        _compiled_rules = yara.compile(filepaths=rule_files)
        logger.info(
            "YARA rules compiled successfully: %d files (%s)",
            len(rule_files),
            ", ".join(rule_files.keys()),
        )
    except yara.SyntaxError as exc:
        logger.error("YARA rule syntax error: %s", exc)
    except Exception as exc:
        logger.error("Failed to compile YARA rules: %s", exc)


def scan_file_bytes(filename: str, content: bytes) -> List[str]:
    """
    Scan raw file bytes against compiled YARA rules.

    Returns:
        List of matched rule names (e.g. ["credential_stealer", "suspicious_packer"]).
        Returns an empty list if YARA is unavailable or no rules match.
    """
    global _compiled_rules, _rules_loaded

    # Lazy-load rules on first call
    if not _rules_loaded:
        _compile_rules()

    if _compiled_rules is None:
        return []

    try:
        matches = _compiled_rules.match(data=content, timeout=30)
        matched_rules = [match.rule for match in matches]
        if matched_rules:
            logger.info(
                "YARA matches for %s: %s",
                filename,
                ", ".join(matched_rules),
            )
        return matched_rules
    except Exception as exc:
        logger.error("YARA scan failed for %s: %s", filename, exc)
        return []
