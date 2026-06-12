"""
Tests for lexical phishing features and brand-impersonation rules.
"""

import pytest

from app.services.ml_engine import MLEngine, PHISHING_THRESHOLD
from app.services.phishing_features import (
    apply_lexical_phishing_boost,
    assess_brand_impersonation,
    extract_lexical_features,
)
from app.services.threat_scoring import compute_threat_score


class TestLexicalFeatures:
    def test_microsoft_account_verify_top_signals(self):
        feats = extract_lexical_features("https://microsoft-account-verify.top")
        assert feats["contains_brand_keyword"] == 1.0
        assert feats["contains_account_keyword"] == 1.0
        assert feats["contains_verify_keyword"] == 1.0
        assert feats["suspicious_tld"] == 1.0
        assert feats["hyphen_count"] >= 2.0

    def test_real_microsoft_com_not_brand_signal(self):
        feats = extract_lexical_features("https://www.microsoft.com")
        assert feats["contains_brand_keyword"] == 0.0
        assert feats["suspicious_tld"] == 0.0

    def test_known_good_phishing_urls_detected(self):
        for url in (
            "https://secure-google-auth.click",
            "https://bank-login-update.site",
        ):
            meta = assess_brand_impersonation(url)
            assert meta["is_brand_impersonation"] is True
            assert meta["impersonation_risk"] >= 0.55


class TestBrandImpersonationBoost:
    @pytest.mark.parametrize(
        "url",
        [
            "https://microsoft-account-verify.top",
            "https://office365-login.site",
            "https://paypal-security-update.xyz",
            "https://appleid-verify.click",
        ],
    )
    def test_lexical_boost_raises_low_model_score(self, url: str):
        boosted, meta = apply_lexical_phishing_boost(url, 0.043)
        assert meta["is_brand_impersonation"] is True
        assert boosted >= PHISHING_THRESHOLD
        assert meta.get("lexical_boost_applied") is True


class TestBrandImpersonationThreatScoring:
    def test_microsoft_verify_never_clean_when_vt_zero(self):
        score, verdict, level, bd = compute_threat_score(
            vt_malicious=0,
            vt_total=92,
            vt_suspicious=0,
            ai_is_phishing=False,
            ai_confidence=0.96,
            ai_phishing_probability=0.043,
            ai_model_available=True,
            url="https://microsoft-account-verify.top",
        )
        assert level != "clean"
        assert verdict != "Clean"
        assert score >= 0.50
        assert bd["brand_impersonation"]["is_brand_impersonation"] is True

    def test_real_microsoft_com_can_be_clean(self):
        score, verdict, level, _ = compute_threat_score(
            vt_malicious=0,
            vt_total=92,
            vt_suspicious=0,
            ai_is_phishing=False,
            ai_confidence=0.99,
            ai_phishing_probability=0.01,
            ai_model_available=True,
            url="https://www.microsoft.com",
        )
        assert level == "clean"
        assert verdict == "Clean"


@pytest.mark.skipif(
    not __import__("os").path.isfile(
        __import__("os").path.join(
            __import__("os").path.dirname(__file__), "..", "models", "phishing_pipeline.joblib"
        )
    ),
    reason="Trained pipeline not present",
)
class TestMLEngineBrandURLs:
    @pytest.mark.parametrize(
        "url",
        [
            "https://microsoft-account-verify.top",
            "https://office365-login.site",
            "https://paypal-security-update.xyz",
            "https://appleid-verify.click",
        ],
    )
    def test_brand_impersonation_urls_flagged(self, url: str):
        MLEngine._ensure_model_loaded()
        result = MLEngine._predict(url)
        assert result["is_phishing"] is True
        assert result["phishing_probability"] >= PHISHING_THRESHOLD
