"""
Regression Snapshot tests for the Threat Correlation Engine.
Simulates scans on google.com, github.com, OWASP Juice Shop, and DVWA to validate:
- Correct risk score ranges and caps
- Correct correlated threat counts (suppression on hardened targets, active chains on vulnerable ones)
- No false CRITICAL chains on hardened targets
- Stable JSON response structures with non-null arrays and frontend-safe fallback fields
"""
import pytest
from app.schemas.finding import FindingBase
from app.services.translators.finding_normalizer import FindingNormalizer
from app.services.ti_processing_service import TIProcessingService
from app.services.investigation.correlation_engine import ThreatCorrelationEngine, ENABLE_STRICT_CORRELATION_HARDENING
from app.schemas.stage_outputs import ThreatSeverity


def normalize_and_process(raw_findings, target_url):
    # 1. Scanner Noise Filtering Layer
    raw_findings_list = [dict(f) for f in raw_findings]
    filtered_raw = FindingNormalizer.filter_noise(raw_findings_list, default_url=target_url)
    
    # 2. Finding Normalizer
    normalized = []
    for raw in filtered_raw:
        n_f = FindingNormalizer.normalize(raw, default_url=target_url, include_ti=True)
        normalized.append(n_f)
        
    # 3. TI Processing & Risk Scoring
    ti_findings = TIProcessingService.process_findings(normalized)
    base_risk = TIProcessingService.calculate_aggregate_risk(ti_findings)
    
    return ti_findings, base_risk


@pytest.mark.anyio
async def test_google_snapshot():
    # google.com: Hardened target.
    # Expect: Low/Info findings, risk score <= 35.0, no correlated threats.
    raw_findings = [
        {
            "finding_id": "google-csp",
            "title": "Missing Content-Security-Policy Header",
            "severity": "medium",
            "category": "Hardening",
            "url": "https://google.com",
            "evidence": "Header not present"
        },
        {
            "finding_id": "google-robots",
            "title": "Robots.txt contains sensitive entries",
            "severity": "high",
            "category": "Information Disclosure",
            "url": "https://google.com/robots.txt",
            "evidence": "Disallow: /search"
        },
        {
            "finding_id": "google-hsts",
            "title": "Missing Strict-Transport-Security Header",
            "severity": "low",
            "category": "Hardening",
            "url": "https://google.com",
            "evidence": "Header not present"
        }
    ]
    
    ti_findings, base_risk = normalize_and_process(raw_findings, "https://google.com")
    
    # Validate normalization and caps
    assert base_risk <= 35.0
    for tf in ti_findings:
        assert tf.severity in ["low", "info"]
        assert tf.exploitability == "low"
        assert tf.verification_status in ["heuristic", "informational"]
        
    # Run through Correlation Engine
    engine = ThreatCorrelationEngine()
    findings_dicts = [tf.model_dump() for tf in ti_findings]
    correlation_output = await engine.correlate(
        investigation_id="google-inv",
        findings=findings_dicts,
        risk_score=base_risk,
        stride_summary={},
        ti_reports=[]
    )
    
    # Assert stable output fields
    assert correlation_output.global_risk_score <= 35.0
    assert len(correlation_output.correlated_threats) == 0
    assert correlation_output.total_correlations == 0
    assert correlation_output.escalated_risks == 0
    assert correlation_output.escalated_risks_count == 0


@pytest.mark.anyio
async def test_github_snapshot():
    # github.com: Hardened target.
    # Expect: Low/Info only, no active chains, risk score <= 35.0.
    raw_findings = [
        {
            "finding_id": "github-xframe",
            "title": "Missing X-Frame-Options Header",
            "severity": "medium",
            "category": "Hardening",
            "url": "https://github.com",
            "evidence": "Header not present"
        },
        {
            "finding_id": "github-cookie",
            "title": "Cookie missing secure flag",
            "severity": "low",
            "category": "Cookie",
            "url": "https://github.com/session",
            "evidence": "Set-Cookie: session_id=123"
        }
    ]
    
    ti_findings, base_risk = normalize_and_process(raw_findings, "https://github.com")
    
    assert base_risk <= 35.0
    for tf in ti_findings:
        assert tf.severity in ["low", "info"]
        
    engine = ThreatCorrelationEngine()
    findings_dicts = [tf.model_dump() for tf in ti_findings]
    correlation_output = await engine.correlate(
        investigation_id="github-inv",
        findings=findings_dicts,
        risk_score=base_risk,
        stride_summary={},
        ti_reports=[]
    )
    
    assert correlation_output.global_risk_score <= 35.0
    assert len(correlation_output.correlated_threats) == 0


@pytest.mark.anyio
async def test_juice_shop_snapshot():
    # OWASP Juice Shop: Vulnerable target.
    # Expect: Valid medium/high chains (e.g. SQLi or XSS + exposed directory/path).
    raw_findings = [
        {
            "finding_id": "juice-sqli",
            "title": "SQL Injection in Search",
            "severity": "critical",
            "category": "Injection Vulnerability",
            "url": "https://juiceshop.herokuapp.com/rest/products/search",
            "evidence": "Database error: sqlite3.OperationalError near SELECT confirmed"
        },
        {
            "finding_id": "juice-backup",
            "title": "Exposed backup directory",
            "severity": "medium",
            "category": "Information Disclosure",
            "url": "https://juiceshop.herokuapp.com/ftp/backup.zip",
            "evidence": "200 OK containing backup.zip"
        }
    ]
    
    ti_findings, base_risk = normalize_and_process(raw_findings, "https://juiceshop.herokuapp.com")
    
    # High/Critical active vulnerability is present (SQLi)
    # Check that it is not capped at 35.0
    assert base_risk > 35.0
    
    engine = ThreatCorrelationEngine()
    findings_dicts = [tf.model_dump() for tf in ti_findings]
    print("\n[TEST JUICE] findings_dicts:", findings_dicts)
    print("[TEST JUICE] ENABLE_STRICT_CORRELATION_HARDENING:", ENABLE_STRICT_CORRELATION_HARDENING)
    correlation_output = await engine.correlate(
        investigation_id="juice-inv",
        findings=findings_dicts,
        risk_score=base_risk,
        stride_summary={},
        ti_reports=[]
    )
    print("[TEST JUICE] output correlated_threats:", correlation_output.correlated_threats)
    
    # Under strict hardening, correlation engine does not escalate base risk, but it generates valid threat chains
    assert len(correlation_output.correlated_threats) >= 1
    
    # Validate the generated threat
    threat = correlation_output.correlated_threats[0]
    assert threat.id is not None
    assert threat.id == threat.threat_id
    assert threat.combined_risk is not None
    assert isinstance(threat.attack_chain, list)
    assert len(threat.attack_chain) > 0
    assert threat.attack_chain[0].evidence_source == "pentest"
    assert threat.risk_label in ["Medium", "High", "Critical"]


@pytest.mark.anyio
async def test_dvwa_snapshot():
    # DVWA: Intentionally highly vulnerable target.
    # Expect: Valid high/critical exploit chains.
    raw_findings = [
        {
            "finding_id": "dvwa-sqli",
            "title": "SQL Injection in User Search",
            "severity": "critical",
            "category": "Injection Vulnerability",
            "url": "https://dvwa.local/vulnerabilities/sqli/",
            "evidence": "Database error: confirmed SQL injection"
        },
        {
            "finding_id": "dvwa-admin",
            "title": "Weak Administrator Authentication",
            "severity": "high",
            "category": "Authentication Security",
            "url": "https://dvwa.local/login.php",
            "evidence": "Brute force successful for admin:password confirmed"
        },
        {
            "finding_id": "dvwa-path",
            "title": "Exposed admin config path",
            "severity": "medium",
            "category": "Information Disclosure",
            "url": "https://dvwa.local/config/",
            "evidence": "Index of /config/ containing config.inc.php"
        }
    ]
    
    ti_findings, base_risk = normalize_and_process(raw_findings, "https://dvwa.local")
    
    assert base_risk >= 75.0
    
    engine = ThreatCorrelationEngine()
    findings_dicts = [tf.model_dump() for tf in ti_findings]
    correlation_output = await engine.correlate(
        investigation_id="dvwa-inv",
        findings=findings_dicts,
        risk_score=base_risk,
        stride_summary={},
        ti_reports=[]
    )
    
    assert len(correlation_output.correlated_threats) >= 1
    
    # Assert JSON-safe response fields & no nulls
    for threat in correlation_output.correlated_threats:
        assert threat.attack_chain is not None
        assert isinstance(threat.attack_chain, list)
        for step in threat.attack_chain:
            assert step.evidence_source is not None
            assert step.finding_ids is not None
        assert threat.id == threat.threat_id
        assert threat.combined_risk == threat.severity.value
        assert threat.confidence == threat.confidence_score
        assert threat.contributing_finding_ids == threat.source_findings
        assert threat.risk_label is not None
        assert threat.risk_label != "Unknown Risk"
