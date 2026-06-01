"""
ML Engine service — phishing URL classification (v3).

Loads a sklearn Pipeline (TF-IDF + lexical features + LogisticRegression)
trained by train_phishing_model.py.  Applies an additional brand-impersonation
lexical boost so obvious typosquats are not scored as clean.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import joblib
import numpy as np

from app.services.phishing_features import apply_lexical_phishing_boost

logger = logging.getLogger(__name__)

PHISHING_THRESHOLD = 0.35
PHISHING_CLASS = 1
SAFE_CLASS = 0
MODEL_VERSION = "phishing_tfidf_lexical_lr_v3"

_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")
_PIPELINE_PATH = os.path.join(_BASE_DIR, "phishing_pipeline.joblib")
_META_PATH = os.path.join(_BASE_DIR, "phishing_model_meta.joblib")

_pipeline = None
_meta: dict[str, Any] | None = None
_class_indices: dict[int, int] | None = None
_threshold: float = PHISHING_THRESHOLD


def normalize_url(url: str) -> str:
    """Normalize URL string — must match training preprocessing exactly."""
    return url.strip().lower()


def _resolve_class_indices(classifier, meta: dict[str, Any] | None) -> dict[int, int]:
    classes = [int(c) for c in classifier.classes_]
    indices: dict[int, int] = {}

    for label in (SAFE_CLASS, PHISHING_CLASS):
        if label in classes:
            indices[label] = classes.index(label)
        elif meta and label in meta.get("class_to_index", {}):
            indices[label] = int(meta["class_to_index"][label])
        else:
            raise ValueError(
                f"Classifier classes_={classes} missing label {label}. Retrain the model."
            )

    logger.info(
        "Class mapping: classes_=%s | legitimate idx=%d | phishing idx=%d",
        classes,
        indices[SAFE_CLASS],
        indices[PHISHING_CLASS],
    )
    return indices


def _normalize_probabilities(p_safe: float, p_phishing: float) -> tuple[float, float]:
    p_safe = float(np.clip(p_safe, 0.0, 1.0))
    p_phishing = float(np.clip(p_phishing, 0.0, 1.0))
    total = p_safe + p_phishing
    if total <= 0.0:
        logger.warning("Zero-sum probabilities — defaulting to 0.5/0.5")
        return 0.5, 0.5
    if not np.isclose(total, 1.0, atol=1e-4):
        p_safe /= total
        p_phishing /= total
    return p_safe, p_phishing


def _load_model() -> tuple[Any, dict[str, Any], dict[int, int], float] | tuple[None, None, None, None]:
    try:
        if not os.path.isfile(_PIPELINE_PATH):
            raise FileNotFoundError(_PIPELINE_PATH)

        pipeline = joblib.load(_PIPELINE_PATH)
        meta: dict[str, Any] = {}
        if os.path.isfile(_META_PATH):
            meta = joblib.load(_META_PATH)

        threshold = float(meta.get("threshold", PHISHING_THRESHOLD))
        clf = pipeline.named_steps["clf"]
        class_indices = _resolve_class_indices(clf, meta)

        logger.info(
            "Phishing pipeline loaded from %s (version=%s, threshold=%.2f)",
            _PIPELINE_PATH,
            meta.get("model_version", MODEL_VERSION),
            threshold,
        )
        return pipeline, meta, class_indices, threshold

    except FileNotFoundError:
        logger.warning(
            "Phishing pipeline not found at %s — run: "
            "python -m app.services.train_phishing_model --csv <dataset.csv>",
            _PIPELINE_PATH,
        )
        return None, None, None, None
    except Exception as exc:
        logger.error("Failed to load phishing pipeline: %s", exc, exc_info=True)
        return None, None, None, None


class MLEngine:
    """ML Engine for threat classification."""

    @staticmethod
    def _ensure_model_loaded() -> bool:
        global _pipeline, _meta, _class_indices, _threshold
        if _pipeline is not None and _class_indices is not None:
            return True
        pipeline, meta, class_indices, threshold = _load_model()
        if pipeline is not None and class_indices is not None:
            _pipeline = pipeline
            _meta = meta
            _class_indices = class_indices
            _threshold = threshold
            return True
        return False

    @staticmethod
    def is_model_loaded() -> bool:
        return MLEngine._ensure_model_loaded()

    @staticmethod
    def reload() -> bool:
        global _pipeline, _meta, _class_indices, _threshold
        _pipeline = None
        _meta = None
        _class_indices = None
        _threshold = PHISHING_THRESHOLD
        loaded = MLEngine._ensure_model_loaded()
        if loaded:
            logger.info("Phishing pipeline reloaded successfully")
        return loaded

    async def phishing_classifier(self, url: str) -> dict:
        if not self.is_model_loaded():
            logger.warning("Phishing classifier unavailable — pipeline missing")
            return _not_loaded_response(url)

        return await asyncio.to_thread(MLEngine._predict, url)

    @staticmethod
    def _predict(url: str) -> dict:
        normalized = normalize_url(url)
        safe_idx = _class_indices[SAFE_CLASS]
        phish_idx = _class_indices[PHISHING_CLASS]

        probability = _pipeline.predict_proba([normalized])[0]
        p_safe = float(probability[safe_idx])
        p_phishing = float(probability[phish_idx])
        p_safe, p_phishing = _normalize_probabilities(p_safe, p_phishing)

        model_p_phishing = p_phishing
        p_phishing, lexical_meta = apply_lexical_phishing_boost(normalized, p_phishing)
        if p_phishing != model_p_phishing:
            p_safe, p_phishing = _normalize_probabilities(
                1.0 - p_phishing, p_phishing
            )

        is_phishing = p_phishing >= _threshold
        predicted_class = PHISHING_CLASS if is_phishing else SAFE_CLASS
        confidence = max(p_safe, p_phishing)
        confidence_percent = round(confidence * 100, 2)

        logger.info(
            "Phishing inference | url=%s | model_p_phishing=%.4f | final_p_phishing=%.4f | "
            "lexical_boost=%s | impersonation_risk=%s | is_phishing=%s",
            url,
            model_p_phishing,
            p_phishing,
            lexical_meta.get("lexical_boost_applied", False),
            lexical_meta.get("impersonation_risk"),
            is_phishing,
        )

        return {
            "url": url,
            "is_phishing": is_phishing,
            "confidence": round(confidence, 4),
            "confidence_percent": confidence_percent,
            "phishing_probability": round(p_phishing, 4),
            "safe_probability": round(p_safe, 4),
            "model_phishing_probability": round(model_p_phishing, 4),
            "predicted_class": predicted_class,
            "prediction_threshold": _threshold,
            "model_available": True,
            "model": _meta.get("model_version", MODEL_VERSION) if _meta else MODEL_VERSION,
            "lexical_features": lexical_meta,
        }

    async def malware_classifier(self, file_hash: str) -> dict:
        return {
            "file_hash": file_hash,
            "is_malware": False,
            "confidence": 0.0,
            "malware_family": None,
            "model": "malware_v1",
        }


def _not_loaded_response(url: str) -> dict:
    return {
        "url": url,
        "is_phishing": False,
        "confidence": 0.0,
        "confidence_percent": 0.0,
        "phishing_probability": 0.0,
        "safe_probability": 0.0,
        "predicted_class": SAFE_CLASS,
        "prediction_threshold": PHISHING_THRESHOLD,
        "model_available": False,
        "model": "model_not_loaded",
    }


def validate_model(
    safe_url: str | None = None,
    phishing_url: str | None = None,
) -> None:
    import pandas as pd

    if not MLEngine._ensure_model_loaded():
        raise RuntimeError(f"Pipeline not loaded — expected {_PIPELINE_PATH}")

    dataset_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "PhiUSIIL_Phishing_URL_Dataset.csv"
    )
    if phishing_url is None and os.path.isfile(dataset_path):
        df = pd.read_csv(dataset_path, usecols=["URL", "Label"])
        phishing_url = df.loc[df["Label"] == 1, "URL"].iloc[0]
        if safe_url is None:
            safe_url = "https://www.google.com"

    safe_url = safe_url or "https://www.google.com"
    phishing_url = phishing_url or "https://microsoft-account-verify.top"

    for label, test_url in (("safe", safe_url), ("phishing", phishing_url)):
        result = MLEngine._predict(test_url)
        print(
            f"[{label}] {test_url}\n"
            f"  is_phishing={result['is_phishing']} "
            f"p_phishing={result['phishing_probability']:.4f} "
            f"model_p={result.get('model_phishing_probability', 'N/A')}"
        )


if __name__ == "__main__":
    validate_model()
