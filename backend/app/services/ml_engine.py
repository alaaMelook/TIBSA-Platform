"""
ML Engine service.
Handles machine learning inference for phishing/malware classification.

The phishing model is loaded once at import time from:
    backend/models/phishing_model.joblib
    backend/models/phishing_scaler.joblib

If the model files do not exist the classifier returns a graceful
"model_not_loaded" response so the rest of the system keeps working.
"""

import asyncio
import logging
import os
from typing import Optional

import joblib
import numpy as np
import pandas as pd

from app.services.url_features import extract, FEATURE_NAMES

logger = logging.getLogger(__name__)

# ── Model paths (relative to backend/) ────────────────────────────────────────
_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")
_MODEL_PATH = os.path.join(_BASE_DIR, "phishing_model.joblib")
_SCALER_PATH = os.path.join(_BASE_DIR, "phishing_scaler.joblib")


def _load_model():
    """Load model + scaler from disk (once)."""
    try:
        model = joblib.load(_MODEL_PATH)
        scaler = joblib.load(_SCALER_PATH)
        logger.info("Phishing ML model loaded from %s", _MODEL_PATH)
        return model, scaler
    except FileNotFoundError:
        logger.warning(
            "Phishing model not found at %s — AI URL classification disabled. "
            "Run: python -m app.services.train_phishing_model --csv <dataset.csv>",
            _MODEL_PATH,
        )
        return None, None
    except Exception as exc:
        logger.error("Failed to load phishing model: %s", exc)
        return None, None


_model = None
_scaler = None

class MLEngine:
    """ML Engine for threat classification."""

    @staticmethod
    def _ensure_model_loaded():
        global _model, _scaler
        if _model is not None and _scaler is not None:
            return True
        model, scaler = _load_model()
        if model is not None and scaler is not None:
            _model = model
            _scaler = scaler
            return True
        return False

    @staticmethod
    def is_model_loaded() -> bool:
        """Check if the phishing model is available."""
        return MLEngine._ensure_model_loaded()

    async def phishing_classifier(self, url: str) -> dict:
        """
        Classify a URL as phishing or safe using the trained model.

        Returns:
            {
                "url": str,
                "is_phishing": bool,
                "confidence": float,      # 0.0 – 1.0
                "model": "phishing_rf_v1" | "model_not_loaded",
            }
        """
        if not self.is_model_loaded():
            return {
                "url": url,
                "is_phishing": False,
                "confidence": 0.0,
                "model": "model_not_loaded",
            }

        # Run feature extraction + inference in a thread to avoid blocking
        result = await asyncio.to_thread(self._predict, url)
        return result

    @staticmethod
    def _predict(url: str) -> dict:
        features = extract(url)
        X = pd.DataFrame([features], columns=FEATURE_NAMES)
        X_scaled = _scaler.transform(X)

        prediction = _model.predict(X_scaled)[0]            # 0 = safe, 1 = phishing
        probabilities = _model.predict_proba(X_scaled)[0]    # [p_safe, p_phishing]
        confidence = float(probabilities[1])                  # phishing probability

        return {
            "url": url,
            "is_phishing": bool(prediction == 1),
            "confidence": round(confidence, 4),
            "model": "phishing_rf_v1",
        }

    async def malware_classifier(self, file_hash: str) -> dict:
        """Classify a file as malware or benign (placeholder)."""
        return {
            "file_hash": file_hash,
            "is_malware": False,
            "confidence": 0.0,
            "malware_family": None,
            "model": "malware_v1",
        }

