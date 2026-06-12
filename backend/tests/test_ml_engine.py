"""
Unit tests for phishing ML inference pipeline (TF-IDF + LogisticRegression).
"""

import os

import pytest

from app.services.ml_engine import (
    MLEngine,
    PHISHING_THRESHOLD,
    _normalize_probabilities,
    _resolve_class_indices,
    normalize_url,
)

_PIPELINE_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
_PIPELINE_PATH = os.path.join(_PIPELINE_DIR, "phishing_pipeline.joblib")

pytestmark = pytest.mark.skipif(
    not os.path.isfile(_PIPELINE_PATH),
    reason="Trained pipeline not present — run train_phishing_model first",
)


class TestProbabilityHelpers:
    def test_normalize_renormalizes(self):
        p_safe, p_phish = _normalize_probabilities(0.3, 0.9)
        assert abs(p_safe + p_phish - 1.0) < 1e-6

    def test_normalize_zero_sum_fallback(self):
        p_safe, p_phish = _normalize_probabilities(0.0, 0.0)
        assert p_safe == 0.5 and p_phish == 0.5


class TestPhishingInference:
    def test_model_loads(self):
        assert MLEngine.is_model_loaded()

    def test_normalize_url(self):
        assert normalize_url("  HTTPS://Example.COM/Path ") == "https://example.com/path"

    def test_confidence_is_max_probability(self):
        MLEngine._ensure_model_loaded()
        result = MLEngine._predict("https://www.google.com")
        assert result["confidence"] == pytest.approx(
            max(result["safe_probability"], result["phishing_probability"]), rel=1e-3
        )
        assert result["confidence_percent"] == pytest.approx(result["confidence"] * 100, rel=1e-2)

    def test_class_indices(self):
        import joblib

        pipeline = joblib.load(_PIPELINE_PATH)
        clf = pipeline.named_steps["clf"]
        indices = _resolve_class_indices(clf, {"class_to_index": {0: 0, 1: 1}})
        assert indices[0] == 0
        assert indices[1] == 1

    def test_dataset_phishing_url_detected(self):
        import pandas as pd

        df = pd.read_csv(
            os.path.join(os.path.dirname(__file__), "..", "PhiUSIIL_Phishing_URL_Dataset.csv"),
            usecols=["URL", "Label"],
        )
        url = df.loc[df["Label"] == 1, "URL"].iloc[0]
        result = MLEngine._predict(url)
        assert result["phishing_probability"] > PHISHING_THRESHOLD
        assert result["is_phishing"] is True

    def test_obvious_phishing_pattern(self):
        result = MLEngine._predict("http://login-paypal-secure.xyz/verify?account=update")
        assert result["is_phishing"] is True
        assert result["phishing_probability"] > PHISHING_THRESHOLD
        assert result["confidence"] > 0.5

    def test_wixstudio_url_not_phishing(self):
        result = MLEngine._predict("https://opensees.wixstudio.com/enus")
        assert result["is_phishing"] is False
        assert result["phishing_probability"] < PHISHING_THRESHOLD

    def test_legitimate_domain_low_phishing_score(self):
        result = MLEngine._predict("https://www.google.com")
        assert result["phishing_probability"] < PHISHING_THRESHOLD
        assert result["is_phishing"] is False

    def test_probabilities_vary_across_urls(self):
        MLEngine._ensure_model_loaded()
        r1 = MLEngine._predict("https://www.google.com")
        r2 = MLEngine._predict("http://192.168.0.1/bank/login?verify=1")
        assert r1["phishing_probability"] != r2["phishing_probability"]
