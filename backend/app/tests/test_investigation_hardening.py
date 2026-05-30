"""
Unit tests for the refactored and hardened Investigation pipeline logic.
Validates normalization safe defaults, TI thresholds, weighted scoring multipliers,
correlation path overlap rules, STRIDE sanitization/deduplication, global caps, and report fallbacks.
"""
import pytest
import asyncio
from app.schemas.finding import FindingBase
from app.schemas.stage_outputs import ThreatSeverity, STRIDEType
from app.services.translators.finding_normalizer import FindingNormalizer
from app.services.ti_processing_service import TIProcessingService
from app.services.threat_intel_service import IntelAggregator
from app.services.investigation.correlation_engine import ThreatCorrelationEngine
from app.services.investigation.threat_modeler import AutomatedSTRIDEModeler
from app.services.investigation.ai_reporter import AISecurityReporter


def test_finding_normalization():
    # 1. robots.txt should be Low and heuristic
    raw_robots = {
        "title": "Robots.txt contains sensitive entries",
        "severity": "high",
        "category": "Information Disclosure",
        "url": "https://example.com/robots.txt",
        "evidence": "Disallow: /admin"
    }
    norm_robots = FindingNormalizer.normalize(raw_robots, default_url="https://example.com")
    assert norm_robots.confidence == "heuristic"
    # high -> medium (downgrade) -> cap at low
    assert norm_robots.severity == "low"
    assert norm_robots.title == "Potential Robots.txt contains sensitive entries"

    # 2. Potential Protected Route
    raw_route = {
        "title": "Protected Route found",
        "severity": "medium",
        "category": "auth",
        "url": "https://example.com/admin/settings"
    }
    norm_route = FindingNormalizer.normalize(raw_route)
    assert norm_route.confidence == "heuristic"
    assert norm_route.severity == "low"
    assert norm_route.title == "Potential Protected Route found"

    # 3. Auth Boundary should be info and informational
    raw_auth = {
        "title": "Auth boundary detected",
        "severity": "high",
        "category": "Authentication",
        "url": "https://example.com/login"
    }
    norm_auth = FindingNormalizer.normalize(raw_auth)
    assert norm_auth.confidence == "informational"
    assert norm_auth.severity == "info"

    # 4. Confirmed finding
    raw_confirmed = {
        "title": "SQL Injection in search",
        "severity": "critical",
        "category": "Injection",
        "url": "https://example.com/search",
        "evidence": "Database error: syntax error near SELECT"
    }
    norm_confirmed = FindingNormalizer.normalize(raw_confirmed)
    assert norm_confirmed.confidence == "confirmed"
    assert norm_confirmed.severity == "critical"
    # Should not prepend "Potential"
    assert norm_confirmed.title == "SQL Injection in search"


def test_ti_processing_and_multipliers():
    # Weighted scoring: CRITICAL=40, HIGH=20, MEDIUM=8, LOW=3, INFO=0.5
    # Scaled by 2.5
    
    # 1. Confirmed Critical XSS
    f_critical = FindingBase(
        finding_id="f1",
        title="Reflected XSS",
        severity="critical",
        category="Client-Side Security",
        affected_url="https://example.com",
        confidence="confirmed"
    )
    res_critical = TIProcessingService.process_findings([f_critical])[0]
    # base = 40 * 2.5 = 100
    # confirmed -> confidence=0.9, risk_multiplier=1.5
    # 100 * 0.9 * 1.5 = 135
    assert res_critical.risk_score == 135.0
    assert res_critical.verification_status == "confirmed"

    # 2. Heuristic Medium route
    f_medium = FindingBase(
        finding_id="f2",
        title="Potential Protected Route",
        severity="medium",
        category="Hardening",
        affected_url="https://example.com",
        confidence="heuristic"
    )
    res_medium = TIProcessingService.process_findings([f_medium])[0]
    # base = 8 * 2.5 = 20
    # heuristic -> confidence=0.45, risk_multiplier=0.5
    # 20 * 0.45 * 0.5 = 4.5
    assert res_medium.risk_score == 4.5
    assert res_medium.verification_status == "heuristic"

    # 3. Missing CSP header (heuristic & missing header)
    f_csp = FindingBase(
        finding_id="f3",
        title="Potential Missing Content-Security-Policy Header",
        severity="low",
        category="Hardening",
        affected_url="https://example.com",
        confidence="heuristic"
    )
    res_csp = TIProcessingService.process_findings([f_csp])[0]
    # base = 3 * 2.5 = 7.5
    # missing header -> risk_multiplier = 0.3, verification = heuristic
    # heuristic -> confidence = 0.45
    # 7.5 * 0.45 * 0.3 = 1.01
    assert res_csp.risk_score == 1.01


def test_threat_intel_thresholds():
    # VT malicious < 3 or OTX pulses < 1 -> clean default
    vt_res = {"malicious": 2, "total_engines": 70}
    otx_res = {"pulses": [{"name": "Stealer Campaign", "tags": ["malware"]}], "pulse_count": 1}
    
    clean_agg = IntelAggregator.aggregate("example.com", "domain", vt_res, otx_res)
    assert clean_agg["vt_status"] == "suspicious" # vt >= 1 or OTX >= 1
    # Check that malware claims/campaigns are scrubbed for suspicious (not malicious)
    assert clean_agg["campaign_context"] == []
    # Stealer was scrubbed since it contains 'malware'
    assert "malware" not in clean_agg["threat_tags"]

    # When both thresholds met (VT>=3 AND OTX>=1)
    vt_res_mal = {"malicious": 4, "total_engines": 70}
    mal_agg = IntelAggregator.aggregate("badsite.com", "domain", vt_res_mal, otx_res)
    assert mal_agg["vt_status"] == "malicious"
    assert mal_agg["campaign_context"] == ["Stealer Campaign"]
    assert "malware" in mal_agg["threat_tags"]


@pytest.mark.anyio
async def test_correlation_engine_path_overlap():
    engine = ThreatCorrelationEngine()
    
    # 1. Findings on different hosts -> no correlation
    findings_diff_hosts = [
        {
            "finding_id": "F-001",
            "title": "Reflected XSS",
            "severity": "high",
            "category": "Client-Side Security",
            "affected_url": "https://example.com/search",
            "confidence": "probable",
            "risk_score": 30.0
        },
        {
            "finding_id": "F-002",
            "title": "Missing Content-Security-Policy Header",
            "severity": "medium",
            "category": "Hardening",
            "affected_url": "https://anotherexample.com/search",
            "confidence": "heuristic",
            "risk_score": 3.0
        }
    ]
    res_diff = await engine.correlate("inv-1", findings_diff_hosts, 10.0, {}, [])
    assert len(res_diff.correlated_threats) == 0

    # 2. Findings on same host but mismatching admin/login scopes for CR-005
    findings_diff_scopes = [
        {
            "finding_id": "F-003",
            "title": "Weak Login Page Authentication",
            "severity": "high",
            "category": "Authentication",
            "affected_url": "https://example.com/login",
            "confidence": "probable",
            "risk_score": 30.0
        },
        {
            "finding_id": "F-004",
            "title": "Exposed admin directory",
            "severity": "medium",
            "category": "Directory",
            "affected_url": "https://example.com/admin",
            "confidence": "heuristic",
            "risk_score": 6.0
        },
        {
            "finding_id": "F-005",
            "title": "Brute Force login",
            "severity": "medium",
            "category": "Authentication",
            "affected_url": "https://example.com/login",
            "confidence": "probable",
            "risk_score": 10.0
        }
    ]
    res_scopes = await engine.correlate("inv-2", findings_diff_scopes, 10.0, {}, [])
    # CR-005 should NOT fire since path scopes do not match (one admin, one login)
    assert not any(t.correlation_rule == "CR-005" for t in res_scopes.correlated_threats)


@pytest.mark.anyio
async def test_stride_sanitization_and_deduplication():
    modeler = AutomatedSTRIDEModeler()
    
    # 1. Deduplication and merging test
    # Two identical STRIDE threats (same asset, same category) should be merged
    findings = [
        {
            "finding_id": "F-001",
            "title": "Potential Protected Route /admin",
            "severity": "low",
            "category": "Hardening",
            "affected_url": "https://example.com/admin",
            "confidence": "heuristic"
        },
        {
            "finding_id": "F-002",
            "title": "Potential Protected Route /admin/users",
            "severity": "low",
            "category": "Hardening",
            "affected_url": "https://example.com/admin", # Same asset
            "confidence": "heuristic"
        }
    ]
    
    res = await modeler.model("inv-3", findings, [])
    # Stride matrix disclosure count should be 1 since they merge on same asset and category
    assert res.stride_matrix.information_disclosure_count == 1
    assert len(res.stride_threats) == 1
    assert "F-001" in res.stride_threats[0].related_findings
    assert "F-002" in res.stride_threats[0].related_findings
    
    # 2. STRIDE sanitization check
    # Assert exaggerated words are replaced with neutral wording
    threat = res.stride_threats[0]
    assert "credential theft" not in threat.attack_scenario
    assert "full compromise" not in threat.attack_scenario
    assert "admin takeover" not in threat.attack_scenario


def test_global_risk_score_caps():
    # INFO/LOW only -> max 35
    low_findings = [
        {"severity": "low", "confidence": "heuristic", "risk_score": 15.0},
        {"severity": "info", "confidence": "informational", "risk_score": 1.25}
    ]
    assert TIProcessingService.calculate_aggregate_risk(low_findings) == 15.0
    
    # Let's say a finding has elevated risk score, e.g. 50.0 but highest severity is low
    inflated_low_findings = [
        {"severity": "low", "confidence": "heuristic", "risk_score": 50.0}
    ]
    assert TIProcessingService.calculate_aggregate_risk(inflated_low_findings) == 35.0

    # Highest MEDIUM -> max 65
    medium_findings = [
        {"severity": "medium", "confidence": "heuristic", "risk_score": 75.0}
    ]
    assert TIProcessingService.calculate_aggregate_risk(medium_findings) == 65.0

    # Highest HIGH -> max 85
    high_findings = [
        {"severity": "high", "confidence": "heuristic", "risk_score": 95.0}
    ]
    assert TIProcessingService.calculate_aggregate_risk(high_findings) == 85.0

    # No confirmed exploitability -> max 85
    unconfirmed_critical = [
        {"severity": "critical", "confidence": "heuristic", "risk_score": 98.0}
    ]
    assert TIProcessingService.calculate_aggregate_risk(unconfirmed_critical) == 85.0
    
    # Heuristic-only scans cannot exceed 85
    heuristic_critical = [
        {"severity": "critical", "confidence": "heuristic", "risk_score": 98.0}
    ]
    assert TIProcessingService.calculate_aggregate_risk(heuristic_critical) == 85.0


def test_fallback_ai_reporter_wording():
    reporter = AISecurityReporter()
    
    # 1. No high/critical findings
    findings = [
        {"title": "Potential Protected Route", "severity": "low", "category": "Hardening", "affected_url": "https://example.com/admin"},
        {"title": "Missing HSTS Header", "severity": "low", "category": "Hardening", "affected_url": "https://example.com"}
    ]
    
    res = reporter._generate_fallback_summary("https://example.com", 35.0, findings, [], {}, None)
    
    # Executive summary must contain: "No confirmed critical vulnerabilities were identified during this investigation."
    assert "No confirmed critical vulnerabilities were identified during this investigation." in res.executive_summary
    
    # Threat Intel section must contain indicators counts
    assert "Confirmed Malicious Indicators: 0" in res.threat_intelligence_summary
    assert "Suspicious Indicators: 0" in res.threat_intelligence_summary
    assert "Clean Indicators: 0" in res.threat_intelligence_summary
    
    # Business impact should not be exaggerated
    assert "minimal" in res.business_impact_analysis


def test_trusted_provider_demotions():
    # 1. Target is trusted and not verified, confidence is probable -> should be demoted to heuristic and severity low, with "Potential" prepended to title
    raw_probable = {
        "title": "SQL Injection in search",
        "severity": "high",
        "category": "Injection",
        "url": "https://google.com/search",
        "verified": False,
        "confidence": "probable"
    }
    norm_probable = FindingNormalizer.normalize(raw_probable)
    assert norm_probable.confidence == "heuristic"
    assert norm_probable.severity == "low"
    assert norm_probable.title.startswith("Potential ")

    # 2. Target is trusted and not verified, confidence is heuristic -> should be demoted to informational, severity info, classification/category "Informational"
    raw_heuristic = {
        "title": "Potential Missing Security Header",
        "severity": "medium",
        "category": "Hardening",
        "url": "https://facebook.com/path",
        "verified": False,
        "confidence": "heuristic"
    }
    norm_heuristic = FindingNormalizer.normalize(raw_heuristic)
    assert norm_heuristic.confidence == "informational"
    assert norm_heuristic.severity == "info"
    assert norm_heuristic.category == "Informational"

    raw_verified = {
        "title": "SQL Injection",
        "severity": "critical",
        "category": "Injection",
        "url": "https://google.com/search",
        "verified": True,
        "confidence": "confirmed",
        "evidence": "confirmed"
    }
    norm_verified = FindingNormalizer.normalize(raw_verified)
    assert norm_verified.confidence == "confirmed"
    assert norm_verified.severity == "critical"

    # 4. Target is trusted, finding is a discovery probe (Backup File Exposed) with raw verified=True -> should STILL be demoted because of lack of content proof
    raw_discovery = {
        "title": "Backup File Exposed - /map_tile.php.orig",
        "severity": "high",
        "category": "misconfiguration",
        "url": "https://facebook.com/map_tile.php.orig",
        "verified": True,
        "confidence": "high",
        "evidence": "Returned HTTP 200 with 12345 bytes"
    }
    norm_discovery = FindingNormalizer.normalize(raw_discovery)
    assert norm_discovery.confidence == "heuristic"
    assert norm_discovery.severity == "low"
    assert norm_discovery.title.startswith("Potential ")


@pytest.mark.anyio
async def test_directory_discovery_asset_filtering():
    from app.services.pentest.modules.directory_discovery import DirectoryDiscoveryModule
    from app.services.pentest.models import ScanConfig, ScanMode
    import httpx
    
    config = ScanConfig(target="https://google.com", mode=ScanMode.PASSIVE)
    config.shared_state = {"detected_assets": []}
    
    client = httpx.AsyncClient()
    module = DirectoryDiscoveryModule(config, client)
    
    async def mock_get(url):
        # Return 200 response with empty body, so marker_matched and directory_listing are both False
        resp = httpx.Response(200, content=b"unrelated body content", request=httpx.Request("GET", url))
        return resp, "unrelated body content", len(b"unrelated body content"), False
        
    module._get = mock_get
    module._baseline.is_wildcard = lambda resp, body, length: (False, "")
    
    res = await module._check_path("https://google.com", ".env", 0)
    assert res is None
    
    assets = config.shared_state["detected_assets"]
    assert len(assets) == 1
    assert assets[0]["url"] == "https://google.com/.env"
    assert assets[0]["type"] == "path"


@pytest.mark.anyio
async def test_misconfiguration_upload_asset_filtering():
    from app.services.pentest.modules.misconfiguration import MisconfigurationModule
    from app.services.pentest.models import ScanConfig, ScanMode
    import httpx
    
    config = ScanConfig(target="https://google.com", mode=ScanMode.PASSIVE)
    config.shared_state = {"detected_assets": []}
    
    client = httpx.AsyncClient()
    module = MisconfigurationModule(config, client)
    
    endpoints = [{"url": "https://google.com/upload"}]
    resp = httpx.Response(200, content=b"unrelated body content", request=httpx.Request("GET", "https://google.com"))
    
    findings, fp_log = await module._test_file_upload_exposure("https://google.com", resp, endpoints)
    
    assert len(findings) == 0
    
    assets = config.shared_state["detected_assets"]
    assert len(assets) == 1
    assert assets[0]["url"] == "https://google.com/upload"
    assert assets[0]["type"] == "upload_endpoint"


@pytest.mark.anyio
async def test_end_to_end_evidence_validation_layer():
    from app.services.investigation.ai_reporter import AISecurityReporter
    from app.schemas.stage_outputs import STRIDEType, ThreatSeverity
    
    findings = [
        {
            "finding_id": "F-001",
            "title": "Missing Content-Security-Policy Header",
            "severity": "low",
            "category": "Hardening",
            "affected_url": "https://example.com"
        }
    ]
    
    # Unsupported threat because it points to SQLi which doesn't exist in findings
    correlated_threats = [
        {
            "threat_id": "CT-001",
            "title": "SQL Injection threat",
            "severity": ThreatSeverity.CRITICAL,
            "source_findings": ["F-999"],  # Non-existent finding ID
            "risk_score": 90.0,
        }
    ]
    
    # STRIDE threat pointing to a non-existent finding ID
    stride_threats = [
        {
            "stride_id": "ST-001",
            "category": STRIDEType.TAMPERING,
            "affected_asset": "https://example.com",
            "attack_scenario": "Tampering scenario",
            "severity": ThreatSeverity.CRITICAL,
            "related_findings": ["F-999"]  # Non-existent finding ID
        }
    ]
    
    stride_matrix = {
        "spoofing_count": 0,
        "tampering_count": 1,
        "repudiation_count": 0,
        "information_disclosure_count": 0,
        "denial_of_service_count": 0,
        "elevation_of_privilege_count": 0
    }
    
    ai_summary = {
        "executive_summary": "We identified SQL Injection in our scan. This is a High Risk situation requiring immediate exploitation prevention.",
        "technical_summary": "Technical detail about SQL Injection.",
        "risk_explanation": "Critical Risk of compromise.",
        "correlated_attack_chains": [
            {
                "title": "SQL Injection chain",
                "explanation": "Exploits SQL Injection."
            }
        ],
        "exploitation_scenarios": [
            {
                "threat": "SQL Injection threat",
                "scenario": "Exploitation detail."
            }
        ]
    }
    
    filtered_corr, filtered_stride, filtered_matrix, cleaned_summary = AISecurityReporter.validate_report_consistency(
        findings=findings,
        correlated_threats=correlated_threats,
        stride_threats=stride_threats,
        stride_matrix=stride_matrix,
        ai_summary=ai_summary
    )
    
    # 1. Threat without valid finding references must be suppressed
    assert len(filtered_corr) == 0
    assert len(filtered_stride) == 0
    
    # 2. STRIDE matrix counts must match filtered stride threats (which was suppressed)
    assert filtered_matrix["tampering_count"] == 0
    
    # 3. AI-generated attack scenarios and exploitation scenarios referencing unsupported techniques must be suppressed
    assert len(cleaned_summary["correlated_attack_chains"]) == 0
    assert len(cleaned_summary["exploitation_scenarios"]) == 0
    
    # 4. Narrative contradiction and unsupported technique checks
    # Low severity only -> narrative cannot have SQL Injection, High Risk, Critical, compromise
    exec_sum = cleaned_summary["executive_summary"]
    assert "SQL Injection" not in exec_sum
    assert "High Risk" not in exec_sum
    assert "immediate exploitation" not in exec_sum
    assert "No confirmed critical vulnerabilities were identified during this investigation." in exec_sum


def test_investigation_cancellation_mapping():
    from app.api.investigations import _build_ti_response
    
    # 1. Test failed + Stopped mapping
    inv_stopped = {
        "id": "123",
        "scan_id": "SCAN-123",
        "target": "https://example.com",
        "status": "failed",
        "current_stage": "Stopped",
        "progress_percent": 100.0,
        "pipeline_state": {"stage": "Stopped", "risk_summary": {}, "ti_findings": [], "reputation_context": {}},
        "final_result": None
    }
    resp = _build_ti_response(inv_stopped)
    assert resp.status == "stopped"

    # 2. Test failed + Failed (no mapping)
    inv_failed = {
        "id": "123",
        "scan_id": "SCAN-123",
        "target": "https://example.com",
        "status": "failed",
        "current_stage": "Failed",
        "progress_percent": 100.0,
        "pipeline_state": {"stage": "Failed", "risk_summary": {}, "ti_findings": [], "reputation_context": {}},
        "final_result": None
    }
    resp = _build_ti_response(inv_failed)
    assert resp.status == "failed"

    # 3. Test completed (no mapping)
    inv_completed = {
        "id": "123",
        "scan_id": "SCAN-123",
        "target": "https://example.com",
        "status": "completed",
        "current_stage": "Completed",
        "progress_percent": 100.0,
        "pipeline_state": {"stage": "Completed", "risk_summary": {}, "ti_findings": [], "reputation_context": {}},
        "final_result": None
    }
    resp = _build_ti_response(inv_completed)
    assert resp.status == "completed"


@pytest.mark.anyio
async def test_orchestrator_check_cancelled_stopped():
    from unittest.mock import MagicMock, AsyncMock
    from app.services.orchestrator.investigation_orchestrator import InvestigationOrchestrator

    # Mock supabase client and responses
    mock_supabase = MagicMock()
    mock_query = MagicMock()
    mock_supabase.table.return_value = mock_query
    mock_query.select.return_value = mock_query
    mock_query.eq.return_value = mock_query
    
    # Instance orchestrator
    orchestrator = InvestigationOrchestrator(supabase=mock_supabase)
    
    # Case A: Status is failed and current_stage is Stopped -> Should detect as cancelled/stopped
    mock_execute = MagicMock()
    mock_execute.data = [{"status": "failed", "current_stage": "Stopped"}]
    mock_query.execute.return_value = mock_execute
    orchestrator._update_investigation = AsyncMock()

    pipeline_state = {"stage": "Running", "progress": 50.0}
    is_cancelled = await orchestrator._check_cancelled("123", pipeline_state)
    assert is_cancelled is True
    assert pipeline_state["stage"] == "Stopped"
    assert pipeline_state["progress"] == 100.0

    # Case B: Status is running -> Should not detect as cancelled/stopped
    mock_execute_running = MagicMock()
    mock_execute_running.data = [{"status": "running", "current_stage": "Scanning"}]
    mock_query.execute.return_value = mock_execute_running
    
    pipeline_state_running = {"stage": "Running", "progress": 50.0}
    is_cancelled_running = await orchestrator._check_cancelled("123", pipeline_state_running)
    assert is_cancelled_running is False
    assert pipeline_state_running["stage"] == "Running"

