"""
Tests for VirusTotal URL scan integration (mock mode + scoring interaction).
"""

import asyncio

import pytest

from app.services.threat_scoring import compute_threat_score
from app.services.virustotal_service import (
    VirusTotalService,
    normalize_url_for_vt,
    vt_url_object_id,
)


class TestVirusTotalHelpers:
    def test_normalize_adds_https(self):
        assert normalize_url_for_vt("microsoft.com") == "https://microsoft.com"

    def test_vt_url_id_stable(self):
        assert vt_url_object_id("https://microsoft.com") == vt_url_object_id(
            "https://microsoft.com"
        )


class TestMockUrlScan:
    def test_microsoft_not_flagged_in_mock_without_api_key(self):
        vt = VirusTotalService("", demo_mode=True)
        assert vt.uses_mock_data is True
        result = asyncio.run(vt.scan_url("https://microsoft.com"))
        assert result["malicious"] == 0
        assert result["suspicious"] == 0
        assert result.get("mock") is True

    def test_demo_mode_with_api_key_uses_live_not_mock(self):
        vt = VirusTotalService("fake-key-for-unit-test", demo_mode=True)
        assert vt.uses_mock_data is False

    def test_phishing_pattern_mock_flagged(self):
        vt = VirusTotalService("", demo_mode=True)
        result = asyncio.run(vt.scan_url("http://login-paypal-secure.xyz/verify"))
        assert result["malicious"] > 0


class TestMicrosoftScoringScenario:
    """Reproduce user report: mock VT high + AI safe → override raises score."""

    def test_legacy_mock_microsoft_length_trigger(self):
        """Document: len('https://microsoft.com')==21 → old mock used len%7."""
        assert len("https://microsoft.com") % 7 == 0

    def test_fixed_mock_microsoft_clean_score(self):
        vt_malicious, vt_suspicious, vt_total = 0, 0, 93
        ai_prob = 0.0001
        score, verdict, level, bd = compute_threat_score(
            vt_malicious=vt_malicious,
            vt_total=vt_total,
            vt_suspicious=vt_suspicious,
            ai_is_phishing=False,
            ai_confidence=0.99,
            ai_phishing_probability=ai_prob,
            ai_model_available=True,
        )
        assert verdict == "Clean"
        assert level == "clean"
        assert score < 0.20
        assert bd.get("override_applied") is None

    def test_override_explains_015_to_080(self):
        """VT malicious>=10 forces min score 0.80 even when weighted ~0.17."""
        score, verdict, level, bd = compute_threat_score(
            vt_malicious=24,
            vt_total=93,
            vt_suspicious=4,
            ai_is_phishing=False,
            ai_confidence=0.99,
            ai_phishing_probability=0.05,
            ai_model_available=True,
        )
        assert bd["weighted_score_before_override"] < 0.30
        assert score >= 0.80
        assert verdict == "Malicious"
        assert level == "high"
        assert bd["override_applied"] is not None
