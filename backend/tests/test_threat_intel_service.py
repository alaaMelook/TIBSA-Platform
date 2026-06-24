"""
Tests for the Threat Intelligence Service & Aggregator.
Run with:
    pytest backend/tests/test_threat_intel_service.py -v
"""
from __future__ import annotations

import pytest
from app.services.threat_intel_service import (
    VirusTotalProvider,
    OTXProvider,
    IntelAggregator,
    ThreatIntelService,
)


@pytest.mark.anyio
async def test_vt_missing_api_key():
    provider = VirusTotalProvider()
    provider.api_key = None  # Simulate missing key
    
    res = await provider.lookup("www.google.com", "domain")
    assert res["found"] is False
    assert res["available"] is False
    assert res["status"] == "not_configured"
    assert res["error"] == "VirusTotal API key is not configured"
    assert res["malicious"] == 0


@pytest.mark.anyio
async def test_no_mock_malicious_for_google():
    provider = VirusTotalProvider()
    provider.api_key = None  # Simulate missing key
    # Even if indicator length % 7 == 0 (e.g. www.google.com is 14 -> % 7 == 0)
    res = await provider.lookup("www.google.com", "domain")
    assert res["malicious"] == 0
    assert res["suspicious"] == 0


def test_intel_aggregator_normalization():
    # Scenario A: VirusTotal Malicious Detection (score >= 90)
    vt_res = {"found": True, "status": "completed", "malicious": 5, "suspicious": 1, "total_engines": 72}
    otx_res = {"found": True, "pulses": [{"name": "Campaign A", "description": "Banking malware Campaign", "tags": ["banking"], "malware_families": ["RedLine Stealer"], "targeted_countries": ["US"]}], "pulse_count": 1}
    
    aggregated = IntelAggregator.aggregate("bad-domain.com", "domain", vt_res, otx_res)
    assert aggregated["vt_status"] == "malicious"
    assert aggregated["confidence_score"] >= 90
    assert aggregated["confidence_level"] == "high"
    assert "RedLine Stealer" in aggregated["related_malware_families"]
    assert "banking" in aggregated["threat_tags"]
    assert "Campaign A" in aggregated["campaign_context"]
    assert "VirusTotal" in aggregated["risk_reason"]

    # Scenario B: OTX Pulse match only, VT is clean
    vt_res_clean = {"found": True, "status": "completed", "malicious": 0, "suspicious": 0, "total_engines": 72}
    aggregated_otx = IntelAggregator.aggregate("suspect-domain.com", "domain", vt_res_clean, otx_res)
    assert aggregated_otx["vt_status"] == "clean"
    assert aggregated_otx["confidence_score"] == 10
    assert aggregated_otx["confidence_level"] == "low"
    assert "clean" in aggregated_otx["risk_reason"]

    # Scenario C: Clean / Heuristic (10 score)
    otx_res_empty = {"found": True, "pulses": [], "pulse_count": 0}
    aggregated_clean = IntelAggregator.aggregate("clean-domain.com", "domain", vt_res_clean, otx_res_empty)
    assert aggregated_clean["vt_status"] == "clean"
    assert aggregated_clean["confidence_score"] == 10
    assert aggregated_clean["confidence_level"] == "low"
    assert "clean" in aggregated_clean["risk_reason"]


def test_otx_cannot_change_unknown_vt_state_to_malicious():
    vt_res_unavailable = {"found": False, "status": "not_configured", "error": "VirusTotal API key is not configured"}
    otx_res = {"found": True, "pulses": [{"name": "Campaign B"}], "pulse_count": 1}
    
    aggregated = IntelAggregator.aggregate("some-domain.com", "domain", vt_res_unavailable, otx_res)
    assert aggregated["vt_status"] == "unknown"
    assert aggregated["threat_level"] == "unknown"
    assert aggregated["confidence_score"] == 0
    assert aggregated["flagged"] is False
    assert aggregated["source"] == "VirusTotal unavailable"


@pytest.mark.anyio
async def test_threat_intel_service_orchestration():
    service = ThreatIntelService()
    service.vt.api_key = None # Ensure it runs cleanly as missing
    enriched = await service.enrich_ioc("test-ioc.js", "js_resource")
    assert enriched["ioc"] == "test-ioc.js"
    assert enriched["type"] == "js_resource"
    assert "confidence_score" in enriched
    assert "confidence_level" in enriched
    assert "vt_status" in enriched
    assert "otx_pulses" in enriched
