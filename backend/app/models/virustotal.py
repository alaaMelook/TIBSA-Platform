"""
Pydantic models for VirusTotal scan results.
"""
from pydantic import BaseModel
from typing import Optional, Dict


class VTScanResult(BaseModel):
    """Parsed result returned by VirusTotalService."""

    found: Optional[bool] = None          # None = not checked, False = hash not in VT DB
    status: str                            # "completed" | "timeout"
    threat_level: str                      # "clean" | "low" | "medium" | "high" | "unknown"
    stats: Dict[str, int] = {}            # e.g. {"malicious": 3, "suspicious": 1, ...}
    total_engines: int = 0
    malicious: int = 0
    suspicious: int = 0
    analysis_id: Optional[str] = None    # VT analysis ID (for URL / file scans)
    file_name: Optional[str] = None      # Only for file hash lookups
    file_type: Optional[str] = None      # Only for file hash lookups
