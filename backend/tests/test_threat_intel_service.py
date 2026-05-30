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
async def test_vt_provider_demo_mode():
    provider = VirusTotalProvider()
    # Test lookup in demo mode or without API key
    res_bad = await provider.lookup("bad-indicator.js", "js_resource")
    assert res_bad["found"] is True
    assert res_bad["status"] == "completed"
    
    # Check that demo mode produces correct structures
    assert "malicious" in res_bad
    assert "suspicious" in res_bad
    assert "total_engines" in res_bad


@pytest.mark.anyio
async def test_otx_provider_demo_mode():
    provider = OTXProvider()
    # Test indicator general lookup in demo mode or without API key
    res = await provider.lookup("threat-domain.com", "domain")
    assert res["found"] is True
    assert "pulses" in res
    assert "pulse_count" in res


def test_intel_aggregator_normalization():
    # Scenario A: VirusTotal Malicious Detection (score >= 90)
    vt_res = {"found": True, "malicious": 5, "suspicious": 1, "total_engines": 72}
    otx_res = {"found": True, "pulses": [{"name": "Campaign A", "description": "Banking malware Campaign", "tags": ["banking"], "malware_families": ["RedLine Stealer"], "targeted_countries": ["US"]}], "pulse_count": 1}
    
    aggregated = IntelAggregator.aggregate("bad-domain.com", "domain", vt_res, otx_res)
    assert aggregated["vt_status"] == "malicious"
    assert aggregated["confidence_score"] >= 90
    assert aggregated["confidence_level"] == "high"
    assert "RedLine Stealer" in aggregated["related_malware_families"]
    assert "banking" in aggregated["threat_tags"]
    assert "Campaign A" in aggregated["campaign_context"]
    assert "VirusTotal" in aggregated["risk_reason"]

    # Scenario B: OTX Pulse match only
    vt_res_clean = {"found": True, "malicious": 0, "suspicious": 0, "total_engines": 72}
    aggregated_otx = IntelAggregator.aggregate("suspect-domain.com", "domain", vt_res_clean, otx_res)
    assert aggregated_otx["vt_status"] == "suspicious"
    assert aggregated_otx["confidence_score"] == 46
    assert aggregated_otx["confidence_level"] == "low"
    assert "suspicious" in aggregated_otx["risk_reason"]

    # Scenario C: Clean / Heuristic (10 score)
    otx_res_empty = {"found": True, "pulses": [], "pulse_count": 0}
    aggregated_clean = IntelAggregator.aggregate("clean-domain.com", "domain", vt_res_clean, otx_res_empty)
    assert aggregated_clean["vt_status"] == "clean"
    assert aggregated_clean["confidence_score"] == 10
    assert aggregated_clean["confidence_level"] == "low"
    assert "clean" in aggregated_clean["risk_reason"]


@pytest.mark.anyio
async def test_threat_intel_service_orchestration():
    service = ThreatIntelService()
    enriched = await service.enrich_ioc("test-ioc.js", "js_resource")
    assert enriched["ioc"] == "test-ioc.js"
    assert enriched["type"] == "js_resource"
    assert "confidence_score" in enriched
    assert "confidence_level" in enriched
    assert "vt_status" in enriched
    assert "otx_pulses" in enriched
