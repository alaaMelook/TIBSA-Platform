"""
Live scan feedback collector for continuous phishing model improvement.

Stores high-confidence VirusTotal-labelled samples to backend/data/live_feedback.csv
for use during retraining.
"""

from __future__ import annotations

import csv
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

from app.services.phishing_trainer import PHISHING_CLASS, SAFE_CLASS, normalize_url

logger = logging.getLogger(__name__)

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
FEEDBACK_CSV = os.path.join(_DATA_DIR, "live_feedback.csv")

# VT must confirm malicious (same bar as threat-scoring overrides)
VT_MALICIOUS_MIN = 3
# VT clean: zero malicious + zero suspicious + engines responded
VT_CLEAN_MAX_MALICIOUS = 0
VT_CLEAN_MAX_SUSPICIOUS = 0

FEEDBACK_COLUMNS = [
    "url",
    "ai_prediction",
    "ai_phishing_probability",
    "vt_malicious",
    "vt_suspicious",
    "vt_total",
    "final_label",
    "label_source",
    "scan_id",
    "timestamp",
]

_write_lock = threading.Lock()


def _ensure_feedback_file() -> None:
    os.makedirs(_DATA_DIR, exist_ok=True)
    if not os.path.isfile(FEEDBACK_CSV):
        with open(FEEDBACK_CSV, "w", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=FEEDBACK_COLUMNS).writeheader()


def derive_feedback_label(
    *,
    vt_malicious: int,
    vt_suspicious: int,
    vt_total: int,
    ai_is_phishing: bool,
    vt_error: bool = False,
) -> tuple[int | None, str | None]:
    """
    Derive training label from VT + AI with safety controls.

    Returns (final_label, label_source) or (None, None) if not confident enough.
    """
    if vt_error or vt_total <= 0:
        return None, None

    if vt_malicious >= VT_MALICIOUS_MIN:
        return PHISHING_CLASS, "vt_malicious"

    if (
        vt_malicious <= VT_CLEAN_MAX_MALICIOUS
        and vt_suspicious <= VT_CLEAN_MAX_SUSPICIOUS
        and not ai_is_phishing
    ):
        return SAFE_CLASS, "vt_clean_ai_safe"

    return None, None


def record_scan_feedback(
    *,
    url: str,
    scan_id: str,
    ai_data: dict[str, Any],
    vt_data: dict[str, Any],
) -> bool:
    """
    Append one feedback row when VT provides a high-confidence label.

    Returns True if a row was written.
    """
    vt_error = bool(vt_data.get("error"))
    vt_malicious = int(vt_data.get("malicious", 0))
    vt_suspicious = int(vt_data.get("suspicious", 0))
    vt_total = int(vt_data.get("total_engines", 0))

    ai_is_phishing = bool(ai_data.get("is_phishing", False))
    ai_prob = float(ai_data.get("phishing_probability", ai_data.get("confidence", 0.0)))

    final_label, label_source = derive_feedback_label(
        vt_malicious=vt_malicious,
        vt_suspicious=vt_suspicious,
        vt_total=vt_total,
        ai_is_phishing=ai_is_phishing,
        vt_error=vt_error,
    )

    if final_label is None:
        logger.debug(
            "Feedback skipped url=%s — ambiguous VT/AI (mal=%d sus=%d ai_phish=%s)",
            url, vt_malicious, vt_suspicious, ai_is_phishing,
        )
        return False

    row = {
        "url": normalize_url(url),
        "ai_prediction": int(ai_is_phishing),
        "ai_phishing_probability": round(ai_prob, 4),
        "vt_malicious": vt_malicious,
        "vt_suspicious": vt_suspicious,
        "vt_total": vt_total,
        "final_label": final_label,
        "label_source": label_source,
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    with _write_lock:
        _ensure_feedback_file()
        with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=FEEDBACK_COLUMNS).writerow(row)

    logger.info(
        "Live feedback recorded url=%s label=%d source=%s scan_id=%s",
        url, final_label, label_source, scan_id,
    )
    return True


def load_feedback_dataframe():
    """Load live feedback as a pandas DataFrame (empty if file missing)."""
    import pandas as pd

    _ensure_feedback_file()
    try:
        df = pd.read_csv(FEEDBACK_CSV)
        if df.empty:
            return df
        return df.dropna(subset=["url", "final_label"])
    except pd.errors.EmptyDataError:
        return pd.DataFrame(columns=FEEDBACK_COLUMNS)
