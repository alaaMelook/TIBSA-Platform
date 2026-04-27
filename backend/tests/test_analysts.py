"""
Unit tests for the malware analyst and URL analyst engines.
"""
import pytest
from app.services.malware_analyst import analyze_malware, MalwareAnalysisResult
from app.services.url_analyst import analyze_url, URLAnalysisResult


# ═══════════════════════════════════════════════════════════════════
#  Malware Analyst Tests
# ═══════════════════════════════════════════════════════════════════


class TestMalwareAnalyst:
    """Tests for analyze_malware()."""

    def test_clean_high_confidence(self):
        """No detections across many engines → Clean with high confidence."""
        vt = {"malicious": 0, "suspicious": 0, "total_engines": 70,
              "found": True, "status": "completed"}
        result = analyze_malware(vt, None)
        assert result.verdict == "Clean"
        assert result.confidence >= 90

    def test_malicious_high_ratio(self):
        """Many engines detect → Malicious."""
        vt = {"malicious": 40, "suspicious": 5, "total_engines": 70,
              "found": True, "status": "completed"}
        result = analyze_malware(vt, None)
        assert result.verdict == "Malicious"
        assert result.confidence >= 70

    def test_suspicious_moderate(self):
        """3-4 detections from 70 → Suspicious."""
        vt = {"malicious": 3, "suspicious": 0, "total_engines": 70,
              "found": True, "status": "completed"}
        result = analyze_malware(vt, None)
        assert result.verdict in ("Suspicious", "Malicious")

    def test_false_positive_single_engine(self):
        """Single detection from 70 engines → likely FP → Clean."""
        vt = {"malicious": 1, "suspicious": 0, "total_engines": 70,
              "found": True, "status": "completed"}
        result = analyze_malware(vt, None)
        assert result.verdict == "Clean"
        assert "false positive" in result.reason.lower()

    def test_combined_vt_and_local(self):
        """Both VT and local detections → higher confidence."""
        vt = {"malicious": 10, "suspicious": 2, "total_engines": 70,
              "found": True, "status": "completed"}
        malice = {
            "detected_by": 3, "total_engines": 5, "threat_level": "high",
            "top_result": "Win.Trojan.Agent",
            "engines": [
                {"engine": "clamav", "label": "ClamAV", "malware": True,
                 "result": "Win.Trojan.Agent", "error": None},
                {"engine": "avg", "label": "AVG", "malware": True,
                 "result": "Trojan", "error": None},
                {"engine": "comodo", "label": "Comodo", "malware": True,
                 "result": "Malware", "error": None},
            ],
        }
        result = analyze_malware(vt, malice)
        assert result.verdict == "Malicious"
        assert result.confidence >= 80

    def test_no_engines_available(self):
        """No engines at all → Clean with low confidence."""
        result = analyze_malware(None, None)
        assert result.verdict == "Clean"
        assert result.confidence <= 60

    def test_vt_error_local_clean(self):
        """VT errored, local clean → Clean."""
        vt = {"error": "API rate limit exceeded"}
        malice = {
            "detected_by": 0, "total_engines": 5, "threat_level": "clean",
            "engines": [], "top_result": None,
        }
        result = analyze_malware(vt, malice)
        assert result.verdict == "Clean"

    def test_hash_not_found(self):
        """VT hash not found → indicator added."""
        vt = {"found": False, "status": "completed", "malicious": 0,
              "total_engines": 0}
        result = analyze_malware(vt, None)
        assert any("VirusTotal" in ind for ind in result.key_indicators)

    def test_to_dict(self):
        """Result serialises correctly."""
        result = MalwareAnalysisResult(
            verdict="Clean", confidence=90, reason="Test",
            key_indicators=["a", "b"],
        )
        d = result.to_dict()
        assert d["verdict"] == "Clean"
        assert d["confidence"] == 90
        assert len(d["key_indicators"]) == 2


# ═══════════════════════════════════════════════════════════════════
#  URL Analyst Tests
# ═══════════════════════════════════════════════════════════════════


class TestURLAnalyst:
    """Tests for analyze_url()."""

    def test_legitimate_url(self):
        """Safe URL with no detections → Legitimate."""
        vt = {"malicious": 0, "suspicious": 0, "total_engines": 70,
              "found": True, "status": "completed", "threat_level": "clean"}
        ai = {"is_phishing": False, "confidence": 0.05,
              "model": "phishing_rf_v1"}
        result = analyze_url("https://www.google.com", vt, ai)
        assert result.classification == "Legitimate"
        assert result.risk_level == "None"

    def test_phishing_url(self):
        """Phishing signals from AI + heuristics → Phishing."""
        vt = {"malicious": 5, "suspicious": 2, "total_engines": 70,
              "threat_level": "high"}
        ai = {"is_phishing": True, "confidence": 0.92,
              "model": "phishing_rf_v1"}
        result = analyze_url(
            "http://login-paypal-secure.xyz/verify?account=update", vt, ai
        )
        assert result.classification in ("Phishing", "Malicious")
        assert result.risk_level in ("Critical", "High", "Medium")

    def test_suspicious_url(self):
        """Some signals but not definitive → Suspicious."""
        vt = {"malicious": 1, "suspicious": 1, "total_engines": 70,
              "threat_level": "low"}
        ai = {"is_phishing": False, "confidence": 0.3,
              "model": "phishing_rf_v1"}
        result = analyze_url("http://example.xyz/path", vt, ai)
        assert result.classification in ("Suspicious", "Legitimate")

    def test_ip_address_host(self):
        """IP address as hostname → signal detected."""
        result = analyze_url("http://192.168.1.1/login", None, None)
        assert any("IP address" in s for s in result.signals)

    def test_obfuscation_detection(self):
        """Heavy URL encoding → obfuscation signal."""
        encoded_url = "https://evil.com/%2F%2F%2F%2F%2F%2Fpath"
        result = analyze_url(encoded_url, None, None)
        assert any("encoding" in s.lower() for s in result.signals)

    def test_brand_impersonation(self):
        """Brand keyword in subdomain → impersonation signal."""
        result = analyze_url("http://paypal.evil-site.com/login", None, None)
        assert any("paypal" in s.lower() for s in result.signals)

    def test_no_sources(self):
        """URL analysis with heuristics only → still classifies."""
        result = analyze_url("https://example.com", None, None)
        assert result.classification in (
            "Legitimate", "Suspicious", "Phishing", "Malicious"
        )
        assert 0 <= result.confidence <= 100

    def test_deep_subdomains(self):
        """Many subdomain levels → signal."""
        result = analyze_url(
            "http://a.b.c.d.e.evil.com/path", None, None
        )
        assert any("subdomain" in s.lower() for s in result.signals)

    def test_at_symbol(self):
        """@ symbol in URL → credential trick signal."""
        result = analyze_url("http://good.com@evil.com/path", None, None)
        assert any("@" in s for s in result.signals)

    def test_to_dict(self):
        """Result serialises correctly."""
        result = URLAnalysisResult(
            classification="Phishing", confidence=85,
            risk_level="High", explanation="Test",
            signals=["sig1", "sig2"],
        )
        d = result.to_dict()
        assert d["classification"] == "Phishing"
        assert d["risk_level"] == "High"
        assert len(d["signals"]) == 2
