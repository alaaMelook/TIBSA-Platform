import pytest
import asyncio
from app.services.investigation.threat_modeler import AutomatedSTRIDEModeler
from app.schemas.stage_outputs import ThreatSeverity, STRIDEType

@pytest.fixture
def modeler():
    return AutomatedSTRIDEModeler()

def test_missing_csp_without_confirmed_xss(modeler):
    """
    1. Missing CSP without confirmed XSS
    Expected:
    - no confirmed threat
    - potential scenario generated
    - status = potential
    - confidence = advisory
    - evidence_type = hardening
    - severity <= Medium
    - wording must say "may increase impact if XSS exists"
    - wording must NOT say XSS is confirmed
    """
    finding = {
        "finding_id": "f-1",
        "title": "Missing Header — Content-Security-Policy",
        "category": "hardening",
        "severity": "medium",
        "confidence": "heuristic",
        "evidence": "No CSP found."
    }
    
    output = asyncio.run(modeler.model(
        investigation_id="inv-1",
        findings=[finding],
        correlated_threats=[]
    ))
    
    assert len(output.stride_threats) > 0, "Threat should be generated for CSP"
    threat = output.stride_threats[0]
    
    assert threat.status == "potential"
    assert threat.confidence == "advisory"
    assert threat.evidence_type == "hardening"
    assert threat.severity in [ThreatSeverity.MEDIUM, ThreatSeverity.LOW, ThreatSeverity.INFO]
    
    scenario = threat.attack_scenario.lower()
    assert "if xss exists" in scenario, "Must say if XSS exists"
    assert "xss is confirmed" not in scenario, "Must NOT say XSS is confirmed"

def test_no_xss_confirmation_means_no_confirmed_tampering(modeler):
    """
    2. No XSS confirmation means no confirmed Tampering
    Input: Weak CSP, no XSS.
    Expected: no confirmed Tampering threat, no High Tampering threat
    """
    finding = {
        "finding_id": "f-2",
        "title": "Weak CSP",
        "category": "hardening",
        "severity": "medium",
        "confidence": "heuristic",
        "evidence": "unsafe-inline is used."
    }
    
    output = asyncio.run(modeler.model(
        investigation_id="inv-2",
        findings=[finding],
        correlated_threats=[]
    ))
    
    for threat in output.stride_threats:
        if threat.category == STRIDEType.TAMPERING:
            assert threat.status != "confirmed", "Tampering must not be confirmed without XSS"
            assert threat.severity != ThreatSeverity.HIGH, "Tampering severity must not be High"
            assert threat.severity != ThreatSeverity.CRITICAL

def test_non_sensitive_cookies_must_not_generate_session_hijacking(modeler):
    """
    3. Non-sensitive cookies must not generate session hijacking
    Input: sensitive_cookies=0, jwt_cookies=0, prefix_violations=0
    Expected: no stolen session/hijacking wording, Cookie Hardening Advisory, Info/Low severity
    """
    finding = {
        "finding_id": "f-3",
        "title": "Cookie Missing SameSite Flag",
        "category": "hardening",
        "severity": "low",
        "confidence": "heuristic",
        "evidence": "sensitive_cookies: 0, jwt_cookies: 0"
    }
    
    output = asyncio.run(modeler.model(
        investigation_id="inv-3",
        findings=[finding],
        correlated_threats=[]
    ))
    
    if output.stride_threats:
        threat = output.stride_threats[0]
        scenario = threat.attack_scenario.lower()
        assert "stolen" not in scenario
        assert "session exposure" not in scenario
        assert "session hijacking" not in scenario
        assert "identity impersonation" not in scenario
        assert "account compromise" not in scenario
        assert "session rotation" not in scenario
        assert "clear text" not in scenario
        assert "cookie hardening advisory" in scenario
        
        # Check mitigation string
        mitigation_str = " ".join(threat.mitigations).lower()
        assert "review cookie attributes" in mitigation_str
        assert "session rotation" not in mitigation_str
        
        assert threat.severity in [ThreatSeverity.LOW, ThreatSeverity.INFO]
        assert threat.status == "potential"
        assert threat.confidence == "advisory"

def test_sensitive_cookies_may_generate_session_scenario(modeler):
    """
    4. Sensitive/session cookies may generate session scenario
    Input: sensitive_cookies > 0
    Expected: session-related potential scenario is allowed, severity <= Medium unless confirmed
    """
    finding = {
        "finding_id": "f-4",
        "title": "Session Cookie Missing Secure Flag",
        "category": "hardening",
        "severity": "medium",
        "confidence": "heuristic",
        "evidence": "sensitive_cookies: 1"
    }
    
    output = asyncio.run(modeler.model(
        investigation_id="inv-4",
        findings=[finding],
        correlated_threats=[]
    ))
    
    assert len(output.stride_threats) > 0
    threats = [t for t in output.stride_threats if t.category == STRIDEType.SPOOFING]
    assert len(threats) > 0
    threat = threats[0]
    assert threat.severity in [ThreatSeverity.MEDIUM, ThreatSeverity.LOW, ThreatSeverity.INFO]

def test_robots_txt_and_sitemap_xml_excluded_from_stride(modeler):
    """
    5. robots.txt and sitemap.xml excluded from STRIDE
    """
    f1 = {
        "finding_id": "f-5a",
        "title": "Public File Discovered — /robots.txt",
        "category": "informational",
        "exclude_from_stride": True,
        "evidence": ""
    }
    f2 = {
        "finding_id": "f-5b",
        "title": "Public File Discovered — /sitemap.xml",
        "category": "informational",
        "exclude_from_stride": True,
        "evidence": ""
    }
    
    output = asyncio.run(modeler.model(
        investigation_id="inv-5",
        findings=[f1, f2],
        correlated_threats=[]
    ))
    
    assert len(output.stride_threats) == 0

def test_react_wording_guard(modeler):
    """
    6. React wording guard
    Missing CSP without React -> must NOT mention React
    Missing CSP with React -> must mention React
    """
    finding = {
        "finding_id": "f-6",
        "title": "Missing CSP",
        "category": "hardening",
        "severity": "medium",
        "evidence": ""
    }
    
    # Without React
    output_no_react = asyncio.run(modeler.model(
        investigation_id="inv-6a",
        findings=[finding],
        correlated_threats=[],
        detected_technologies=["Vue"]
    ))
    
    for threat in output_no_react.stride_threats:
        assert "React" not in threat.attack_scenario
        assert "SPA frameworks" not in threat.attack_scenario

    # With React
    output_react = asyncio.run(modeler.model(
        investigation_id="inv-6b",
        findings=[finding],
        correlated_threats=[],
        detected_technologies=["React", "Node"]
    ))
    
    found_react = any("React" in t.attack_scenario for t in output_react.stride_threats)
    assert found_react, "React-specific wording must be present in at least one threat scenario"

def test_potential_severity_cap(modeler):
    """
    7. Potential severity cap
    Any hardening finding -> potential, severity max Medium
    """
    finding = {
        "finding_id": "f-7",
        "title": "Missing X-Frame-Options Header",
        "category": "hardening",
        "severity": "critical", # fake critical severity to ensure cap works
        "evidence": "",
        "confidence": "heuristic"
    }
    
    output = asyncio.run(modeler.model(
        investigation_id="inv-7",
        findings=[finding],
        correlated_threats=[]
    ))
    
    threat = output.stride_threats[0]
    assert threat.status == "potential"
    assert threat.severity in [ThreatSeverity.MEDIUM, ThreatSeverity.LOW, ThreatSeverity.INFO]

def test_evidence_contract(modeler):
    """
    8. Evidence contract
    Every scenario must include: source_module, related_finding, classification,
    confidence, evidence_type, why_generated, why_not_confirmed (if potential)
    """
    finding = {
        "finding_id": "f-8",
        "title": "Weak Cookie Flags",
        "category": "hardening",
        "severity": "medium",
        "confidence": "heuristic",
        "evidence": "",
        "source": "pentest_engine_module"
    }
    
    output = asyncio.run(modeler.model(
        investigation_id="inv-8",
        findings=[finding],
        correlated_threats=[]
    ))
    
    for threat in output.stride_threats:
        assert threat.source_module != "unknown"
        assert threat.related_findings is not None and len(threat.related_findings) > 0
        assert threat.classification != "unknown"
        assert threat.confidence in ["verified", "advisory"]
        assert threat.evidence_type in ["exploit", "vulnerability", "hardening"]
        assert threat.why_generated is not None and threat.why_generated != ""
        
        if threat.status == "potential":
            assert threat.why_not_confirmed is not None and threat.why_not_confirmed != ""
