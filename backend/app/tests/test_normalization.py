"""
Unit tests for findings normalization and mapping logic.
"""
import pytest
from app.services.translators.severity_mapper import map_severity
from app.services.translators.finding_normalizer import FindingNormalizer

def test_severity_mapping():
    # Test varying cases and substrings
    assert map_severity("High") == "high"
    assert map_severity("medium risk") == "medium"
    assert map_severity("CRITICAL VULNERABILITY") == "critical"
    assert map_severity("Low severity") == "low"
    assert map_severity("Informational note") == "info"
    assert map_severity(None) == "info"
    assert map_severity("") == "info"
    assert map_severity("unknown-tag") == "info"

def test_finding_normalizer():
    raw = {
        "title": "Cross-Site Scripting (XSS) detected in input form",
        "severity": "High",
        "category": "vulnerability",
        "url": "https://example.com/login",
        "evidence": "Payload injected successfully",
        "tags": ["xss", "owasp"]
    }
    
    normalized = FindingNormalizer.normalize(raw, default_url="https://example.com")
    
    assert normalized.finding_id == "cross_site_scripting_xss_detected_in_input_form"
    assert normalized.title == "Cross-Site Scripting (XSS) detected in input form"
    assert normalized.severity == "high"
    assert normalized.category == "Client-Side Security"
    assert normalized.affected_url == "https://example.com/login"
    assert normalized.evidence == "Payload injected successfully"
    assert "xss" in normalized.tags
    assert "client-side-security" in normalized.tags
