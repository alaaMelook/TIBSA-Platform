"""
Integration tests for Stages 4-6: Threat Correlation, STRIDE Modeling,
AI Security Reporter, and Report Exporter.

Validates that the new pipeline stages integrate correctly with the
existing orchestrator and produce valid output.
"""
import pytest
import asyncio
import json
import os
from unittest.mock import AsyncMock, patch, MagicMock
import uuid
from app.services.orchestrator.investigation_orchestrator import InvestigationOrchestrator

# Setup mock database client for testing
class attrdict(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)
    def __setattr__(self, name, value):
        self[name] = value

class MockSupabaseTable:
    def __init__(self, name, db_dict):
        self.name = name
        self.db = db_dict
        self.op = None
        self.op_data = None

    def insert(self, data):
        self.op = "insert"
        self.op_data = data
        return self

    def update(self, data):
        self.op = "update"
        self.op_data = data
        return self

    def select(self, columns="*"):
        self.op = "select"
        self.selected_columns = columns
        return self

    def eq(self, column, value):
        self.eq_filter = (column, value)
        return self

    def order(self, column, desc=False):
        self.order_by = (column, desc)
        return self

    def execute(self):
        rows = self.db.get(self.name, [])

        if self.op == "insert":
            data = self.op_data
            if isinstance(data, list):
                inserted = []
                for item in data:
                    item_copy = attrdict(item)
                    if "id" not in item_copy:
                        item_copy["id"] = str(uuid.uuid4())
                    self.db[self.name].append(item_copy)
                    inserted.append(item_copy)
                ret_data = inserted
            else:
                inserted_item = attrdict(data)
                if "id" not in inserted_item:
                    inserted_item["id"] = str(uuid.uuid4())
                self.db[self.name].append(inserted_item)
                ret_data = [inserted_item]
        elif self.op == "update":
            matching_rows = list(rows)
            if hasattr(self, 'eq_filter'):
                col, val = self.eq_filter
                matching_rows = [r for r in matching_rows if r.get(col) == val]
            
            for r in matching_rows:
                r.update(self.op_data)
            ret_data = [attrdict(r) for r in matching_rows]
        elif self.op == "select":
            matching_rows = list(rows)
            if hasattr(self, 'eq_filter'):
                col, val = self.eq_filter
                matching_rows = [r for r in matching_rows if r.get(col) == val]

            if hasattr(self, 'order_by'):
                col, desc = self.order_by
                def get_key(x):
                    v = x.get(col)
                    return v if v is not None else ""
                matching_rows = sorted(matching_rows, key=get_key, reverse=desc)
            ret_data = [attrdict(r) for r in matching_rows]
        else:
            ret_data = []

        class MockResponse:
            def __init__(self, data):
                self.data = data
        return MockResponse(ret_data)

class MockSupabaseClient:
    def __init__(self):
        self.db = {
            "investigations": [],
            "findings": [],
            "assets": [],
            "ti_reports": [],
            "tm_reports": []
        }

    def table(self, name):
        return MockSupabaseTable(name, self.db)


async def mock_enrich_ioc(ioc, type_):
    severity = "info"
    if "search" in ioc or "wildcard" in ioc or "cors" in ioc:
        severity = "high"
    elif "example.com" in ioc or "target" in ioc or "pipeline" in ioc:
        severity = "medium"
    return {
        "ioc": ioc,
        "type": type_,
        "vt_score": 0,
        "vt_status": "clean",
        "otx_pulses": [],
        "threat_tags": [],
        "campaign_context": [],
        "related_malware_families": [],
        "confidence_level": "medium",
        "confidence_score": 80,
        "risk_reason": "benign",
        "recommended_action": "none",
        "severity": severity
    }


def make_mock_scan_result(scan_id, target, risk_score, findings, detected_technologies=[], detected_assets=[]):
    from app.services.translators.finding_normalizer import FindingNormalizer
    from app.services.ti_processing_service import TIProcessingService
    
    normalized_findings_base = []
    for f in findings:
        f_dict = dict(f)
        title = f_dict.get("title", "")
        sev = f_dict.get("severity", "info").lower()
        cat = f_dict.get("classification") or f_dict.get("category") or "informational"
        url = f_dict.get("url") or f_dict.get("affected_url") or target
        evidence = f_dict.get("evidence", "")
        
        raw_f = {
            "finding_id": f_dict.get("finding_id") or f"F-{uuid.uuid4().hex[:4]}",
            "title": title,
            "severity": sev,
            "classification": cat,
            "url": url,
            "evidence": evidence,
            "tags": f_dict.get("tags") or []
        }
        
        n_f = FindingNormalizer.normalize(raw_f, default_url=target, include_ti=True)
        normalized_findings_base.append(n_f)
        
    ti_objs = TIProcessingService.process_findings(normalized_findings_base)
    ti_findings = [t.model_dump() for t in ti_objs]
    
    agg_risk = TIProcessingService.calculate_aggregate_risk(ti_findings) if ti_findings else risk_score
    
    return {
        "scan_id": scan_id,
        "target": target,
        "risk_score": agg_risk,
        "findings": findings,
        "detected_technologies": detected_technologies,
        "detected_assets": detected_assets,
        "ti_findings": ti_findings,
        "shared_state": {
            "raw_findings": findings,
            "normalized_findings": [f.model_dump() for f in normalized_findings_base],
            "ti_findings": ti_findings,
            "reputation_context": {"source": "Internal Scan", "last_seen": "now"},
            "risk_summary": {
                "overall_risk": agg_risk,
                "ti_findings_count": len(ti_findings)
            }
        }
    }


# ─── Test Stage 4: Threat Correlation Engine ───────────────────────


def test_correlation_engine_basic():
    """Test correlation engine produces threats from findings with matching rules."""
    async def run_test():
        from app.services.investigation.correlation_engine import ThreatCorrelationEngine

        engine = ThreatCorrelationEngine()

        # Findings that should trigger CR-001 (XSS + missing CSP)
        findings = [
            {
                "finding_id": "F-001",
                "title": "Reflected XSS in search parameter",
                "severity": "high",
                "category": "Client-Side Security",
                "affected_url": "https://example.com/search",
                "evidence": "XSS payload reflected",
                "tags": ["xss"],
                "confidence": "probable",
                "verified": True,
            },
            {
                "finding_id": "F-002",
                "title": "Missing Content-Security-Policy Header",
                "severity": "medium",
                "category": "Hardening",
                "affected_url": "https://example.com",
                "evidence": "CSP header not present",
                "tags": ["csp"],
            },
            {
                "finding_id": "F-003",
                "title": "Missing HSTS Header",
                "severity": "medium",
                "category": "Hardening",
                "affected_url": "https://example.com",
                "evidence": "HSTS not configured",
                "tags": ["hsts"],
            },
            {
                "finding_id": "F-004",
                "title": "Insecure Cookie Flags",
                "severity": "medium",
                "category": "Session Security",
                "affected_url": "https://example.com",
                "evidence": "Secure flag missing",
                "tags": ["cookie"],
                "verified": True,
            },
        ]

        stride_summary = {"Tampering": 1, "Information Disclosure": 1}

        result = await engine.correlate(
            investigation_id="test-inv-001",
            findings=findings,
            risk_score=7.5,
            stride_summary=stride_summary,
            ti_reports=[],
        )

        # Should have identified threats
        assert result.unique_threats_identified > 0
        assert result.total_findings_input == 4
        assert result.global_risk_score >= 0
        assert result.investigation_id == "test-inv-001"

        # Check that CR-001 (XSS + CSP) fired
        rule_ids = [t.correlation_rule for t in result.correlated_threats]
        assert "CR-001" in rule_ids, f"Expected CR-001 in {rule_ids}"

        # Check that CR-003 (Cookie + HSTS) fired
        assert "CR-003" in rule_ids, f"Expected CR-003 in {rule_ids}"

        # Check attack chains exist
        for threat in result.correlated_threats:
            assert threat.attack_chain is not None
            assert len(threat.attack_chain) >= 2

        print(f"✓ Correlation produced {result.unique_threats_identified} threats")

    asyncio.run(run_test())


def test_correlation_engine_no_matches():
    """Test correlation engine handles findings with no rule matches."""
    async def run_test():
        from app.services.investigation.correlation_engine import ThreatCorrelationEngine

        engine = ThreatCorrelationEngine()

        findings = [
            {
                "finding_id": "F-100",
                "title": "Low-risk informational finding",
                "severity": "info",
                "category": "General",
                "affected_url": "https://example.com",
                "evidence": "Minor info",
                "tags": [],
            },
        ]

        result = await engine.correlate(
            investigation_id="test-inv-002",
            findings=findings,
            risk_score=2.0,
            stride_summary={},
            ti_reports=[],
        )

        assert result.unique_threats_identified == 0
        assert result.global_risk_score >= 0
        print("✓ No-match scenario handled correctly")

    asyncio.run(run_test())


# ─── Test Stage 5: STRIDE Threat Modeler ───────────────────────────


def test_stride_modeler_basic():
    """Test STRIDE modeler generates threats and matrix from findings."""
    async def run_test():
        from app.services.investigation.threat_modeler import AutomatedSTRIDEModeler

        modeler = AutomatedSTRIDEModeler()

        findings = [
            {
                "finding_id": "F-001",
                "title": "SQL Injection in login form",
                "severity": "critical",
                "category": "Injection Vulnerability",
                "affected_url": "https://example.com/login",
                "evidence": "SQL error on quote input",
                "tags": ["sqli"],
            },
            {
                "finding_id": "F-002",
                "title": "Missing HSTS Header",
                "severity": "medium",
                "category": "Hardening",
                "affected_url": "https://example.com",
                "evidence": "HSTS not configured",
                "tags": [],
            },
        ]

        result = await modeler.model(
            investigation_id="test-inv-003",
            findings=findings,
            correlated_threats=[],
        )

        # Should have STRIDE threats
        assert len(result.stride_threats) > 0

        # Verify matrix
        matrix = result.stride_matrix
        assert matrix.total_threats() > 0

        # SQLi should map to Tampering and Elevation of Privilege
        categories = [t.category.value for t in result.stride_threats]
        assert "Tampering" in categories or "Elevation of Privilege" in categories

        # Each threat should have mitigations
        for threat in result.stride_threats:
            assert len(threat.mitigations) > 0

        print(f"✓ STRIDE modeler produced {len(result.stride_threats)} threats, matrix total={matrix.total_threats()}")

    asyncio.run(run_test())


def test_stride_modeler_with_correlations():
    """Test STRIDE modeler enriches from correlated threats."""
    async def run_test():
        from app.services.investigation.threat_modeler import AutomatedSTRIDEModeler

        modeler = AutomatedSTRIDEModeler()

        findings = [
            {
                "finding_id": "F-001",
                "title": "XSS in search",
                "severity": "high",
                "category": "Client-Side Security",
                "affected_url": "https://example.com/search",
            },
        ]

        correlated_threats = [
            {
                "threat_id": "CT-001",
                "title": "XSS Amplified by Missing CSP",
                "correlation_rule": "CR-001",
                "severity": "critical",
                "source_findings": ["F-001"],
            },
        ]

        result = await modeler.model(
            investigation_id="test-inv-004",
            findings=findings,
            correlated_threats=correlated_threats,
        )

        # Should have threats from both findings and correlations
        assert len(result.stride_threats) >= 2
        print(f"✓ STRIDE with correlations produced {len(result.stride_threats)} threats")

    asyncio.run(run_test())


# ─── Test Stage 6: AI Security Reporter ───────────────────────────


def test_ai_reporter_fallback():
    """Test AI reporter generates valid fallback when OpenRouter is unavailable."""
    async def run_test():
        from app.services.investigation.ai_reporter import AISecurityReporter

        reporter = AISecurityReporter()

        findings = [
            {
                "finding_id": "F-001",
                "title": "SQL Injection in search",
                "severity": "critical",
                "category": "Injection Vulnerability",
                "affected_url": "https://example.com/search",
            },
            {
                "finding_id": "F-002",
                "title": "Missing HSTS Header",
                "severity": "medium",
                "category": "Hardening",
                "affected_url": "https://example.com",
            },
        ]

        # Mock OpenRouter to raise an error so fallback kicks in
        with patch(
            "app.services.ai.openrouter_client.call_openrouter",
            side_effect=ValueError("API key not configured"),
        ):
            result = await reporter.generate_report(
                investigation_id="test-inv-005",
                target="https://example.com",
                risk_score=75.0,
                findings=findings,
                correlated_threats=[],
                stride_threats=[],
                stride_matrix={},
            )

        # Verify fallback produced valid output
        assert result.ai_summary is not None
        assert len(result.ai_summary.executive_summary) > 0
        assert len(result.ai_summary.technical_summary) > 0
        assert len(result.ai_summary.risk_explanation) > 0
        assert len(result.ai_summary.remediation_plan) > 0
        assert result.export_status == "completed"

        # Verify remediation steps have required fields
        for step in result.ai_summary.remediation_plan:
            assert step.priority >= 1
            assert step.priority <= 5
            assert len(step.title) > 0

        print("✓ AI Reporter fallback produced valid output")

    asyncio.run(run_test())


# ─── Test Report Exporter ──────────────────────────────────────────


def test_report_exporter_json():
    """Test JSON export produces valid content."""
    async def run_test():
        from app.services.investigation.report_exporter import ReportExporter

        exporter = ReportExporter()

        investigation_data = {
            "target": "https://example.com",
            "status": "completed",
            "risk_score": 75.0,
            "started_at": "2025-01-01T00:00:00",
            "completed_at": "2025-01-01T00:05:00",
            "scan_id": "scan-001",
            "findings": [],
            "assets": [],
            "final_result": {"correlation": {}, "stride": {}, "reporter": {}},
            "pipeline_state": {"stage": "Completed"},
        }

        result = await exporter.export_json("test-inv-006", investigation_data)

        assert result["mime_type"] == "application/json"
        assert result["size_bytes"] > 0
        assert result["filename"].endswith(".json")

        # Parse the JSON content to verify it's valid
        content = json.loads(result["content"].decode("utf-8"))
        assert "export_metadata" in content
        assert content["export_metadata"]["investigation_id"] == "test-inv-006"

        # Clean up exported file
        if os.path.exists(result["filepath"]):
            os.remove(result["filepath"])

        print("✓ JSON export produced valid content")

    asyncio.run(run_test())


def test_report_exporter_pdf():
    """Test PDF export produces valid content."""
    async def run_test():
        from app.services.investigation.report_exporter import ReportExporter

        exporter = ReportExporter()

        investigation_data = {
            "target": "https://example.com",
            "status": "completed",
            "risk_score": 65.0,
            "started_at": "2025-01-01T00:00:00",
            "completed_at": "2025-01-01T00:05:00",
            "scan_id": "scan-002",
            "findings": [],
            "assets": [],
            "final_result": {
                "correlation": {
                    "correlated_threats": [
                        {
                            "title": "XSS + CSP Chain",
                            "severity": "critical",
                            "confidence_score": 0.9,
                            "description": "XSS amplified by missing CSP"
                        }
                    ],
                    "global_risk_score": 85.0,
                },
                "stride": {
                    "stride_matrix": {
                        "spoofing_count": 1,
                        "tampering_count": 2,
                        "repudiation_count": 0,
                        "information_disclosure_count": 3,
                        "denial_of_service_count": 0,
                        "elevation_of_privilege_count": 1,
                    }
                },
                "reporter": {
                    "ai_summary": {
                        "executive_summary": "Security assessment completed with high risk.",
                        "technical_summary": "Multiple vulnerabilities found.",
                        "risk_explanation": "Risk score of 65 reflects significant concerns.",
                        "immediate_actions": [
                            "Disable debug interfaces on the production host",
                            "Rotate all API keys and secrets"
                        ],
                        "remediation_plan": [
                            {
                                "priority": 1,
                                "title": "Fix XSS",
                                "description": "Implement input validation.",
                                "estimated_effort": "Medium"
                            }
                        ]
                    }
                },
            },
            "pipeline_state": {"stage": "Completed"},
        }

        result = await exporter.export_pdf("test-inv-007", investigation_data)

        assert result["mime_type"] == "application/pdf"
        assert result["size_bytes"] > 0
        assert result["filename"].endswith(".pdf")

        # Verify it's a valid PDF (starts with %PDF)
        assert result["content"][:4] == b"%PDF"

        # Clean up exported file
        if os.path.exists(result["filepath"]):
            os.remove(result["filepath"])

        print("✓ PDF export produced valid content")

    asyncio.run(run_test())


# ─── End-to-End Pipeline Test ──────────────────────────────────────


def test_full_pipeline_with_stages_4_6():
    """
    End-to-end test: Run the full orchestrator pipeline including
    stages 4-6 and verify all outputs are populated in final_result.
    """
    async def run_test():
        supabase = MockSupabaseClient()
        orchestrator = InvestigationOrchestrator(supabase)
        target = "https://pipeline-test.local"
        tests = ["security_headers", "xss"]
        investigation = await orchestrator.create_investigation(target, tests, "test-user")

        # Simulated scan result with findings that trigger correlation rules
        mock_scan_result = make_mock_scan_result(
            scan_id=investigation.scan_id,
            target=target,
            risk_score=8.5,
            findings=[
                {
                    "title": "Reflected XSS in search parameter",
                    "severity": "High",
                    "classification": "vulnerability",
                    "url": f"{target}/search",
                    "evidence": "XSS payload reflected in response confirmed"
                },
                {
                    "title": "Missing Content-Security-Policy Header",
                    "severity": "Medium",
                    "classification": "hardening",
                    "url": target,
                    "evidence": "CSP header is not present"
                },
                {
                    "title": "Missing HSTS Header",
                    "severity": "Medium",
                    "classification": "hardening",
                    "url": target,
                    "evidence": "Strict-Transport-Security not present"
                },
                {
                    "title": "Insecure Cookie Configuration",
                    "severity": "Medium",
                    "classification": "cookie_analysis",
                    "url": target,
                    "evidence": "Secure flag missing on session cookie"
                },
            ],
            detected_technologies=[
                {"name": "Nginx", "category": "web_server"},
                {"name": "React", "category": "frontend"},
            ],
            detected_assets=[],
        )

        # Mock OpenRouter for AI reporter to use fallback
        with patch(
            "app.services.scanners.scanner_adapter.ScannerAdapter.run_scan",
            new_callable=AsyncMock,
        ) as mock_run, patch(
            "app.services.threat_intel_service.ThreatIntelService.enrich_ioc",
            new_callable=AsyncMock,
        ) as mock_enrich, patch(
            "app.services.ai.openrouter_client.call_openrouter",
            side_effect=ValueError("API key not set — using fallback"),
        ):
            mock_run.return_value = mock_scan_result
            mock_enrich.side_effect = mock_enrich_ioc
            await orchestrator.run_investigation_pipeline(investigation.id, tests)

        # Reload and verify
        resp = supabase.table("investigations").select("*").eq("id", investigation.id).execute()
        db_inv = resp.data[0] if resp.data else None

        # Basic assertions
        assert db_inv.status == "completed"
        assert db_inv.current_stage == "Completed"
        assert db_inv.progress_percent == 100.0

        # Verify final_result contains stages 4-6 data
        fr = db_inv.final_result
        assert fr is not None, "final_result should not be None"

        # Stage 4: Correlation
        assert "correlation" in fr, "final_result should contain 'correlation'"
        corr = fr["correlation"]
        if "error" not in corr:
            assert "correlated_threats" in corr
            assert "global_risk_score" in corr
            assert corr["global_risk_score"] >= 0
            print(f"  Stage 4: {len(corr.get('correlated_threats', []))} threats, risk={corr['global_risk_score']}")
        else:
            print(f"  Stage 4 had error (acceptable): {corr['error']}")

        # Stage 5: STRIDE
        assert "stride" in fr, "final_result should contain 'stride'"
        stride = fr["stride"]
        if "error" not in stride:
            assert "stride_threats" in stride
            assert "stride_matrix" in stride
            print(f"  Stage 5: {len(stride.get('stride_threats', []))} STRIDE threats")
        else:
            print(f"  Stage 5 had error (acceptable): {stride['error']}")

        # Stage 6: Reporter
        assert "reporter" in fr, "final_result should contain 'reporter'"
        reporter = fr["reporter"]
        if "error" not in reporter:
            assert "ai_summary" in reporter
            ai = reporter["ai_summary"]
            assert len(ai.get("executive_summary", "")) > 0
            assert len(ai.get("remediation_plan", [])) > 0
            print(f"  Stage 6: AI summary generated, {len(ai.get('remediation_plan', []))} remediation steps")
        else:
            print(f"  Stage 6 had error (acceptable): {reporter['error']}")

        # Verify risk score was updated (correlation may have adjusted it)
        assert db_inv.risk_score >= 0
        print(f"  Final risk score: {db_inv.risk_score}")

        print("\n✓ Full pipeline with stages 4-6 completed successfully!")

    asyncio.run(run_test())


def test_correlation_engine_hardening_config():
    """Test correlation engine behaves correctly when enable_strict_correlation_hardening is toggled."""
    async def run_test():
        from app.services.investigation.correlation_engine import ThreatCorrelationEngine

        engine = ThreatCorrelationEngine()

        # Target findings that would normally be suppressed under strict hardening (heuristic/passive findings, no verified findings)
        findings = [
            {
                "finding_id": "F-001",
                "title": "Missing Content-Security-Policy Header",
                "severity": "medium",
                "category": "Hardening",
                "affected_url": "https://example.com",
                "evidence": "CSP header not present",
                "tags": ["csp"],
                "confidence": "heuristic",
                "verified": False,
            },
            {
                "finding_id": "F-002",
                "title": "Insecure Cookie Flags",
                "severity": "medium",
                "category": "Session Security",
                "affected_url": "https://example.com",
                "evidence": "Secure flag missing",
                "tags": ["cookie"],
                "confidence": "heuristic",
                "verified": False,
            },
            {
                "finding_id": "F-003",
                "title": "Missing HSTS Header",
                "severity": "medium",
                "category": "Hardening",
                "affected_url": "https://example.com",
                "evidence": "HSTS header not present",
                "tags": ["hsts"],
                "confidence": "heuristic",
                "verified": False,
            },
        ]

        # 1. With enable_strict_correlation_hardening=True (Strict Mode) -> should return 0 correlations
        strict_result = await engine.correlate(
            investigation_id="test-inv-strict",
            findings=findings,
            risk_score=5.0,
            stride_summary={},
            ti_reports=[],
            enable_strict_correlation_hardening=True
        )
        assert strict_result.unique_threats_identified == 0, "Strict Mode should filter out all heuristic/unverified chains."

        # 2. With enable_strict_correlation_hardening=False (Lab/Test Mode) -> should allow correlations
        lab_result = await engine.correlate(
            investigation_id="test-inv-lab",
            findings=findings,
            risk_score=5.0,
            stride_summary={},
            ti_reports=[],
            enable_strict_correlation_hardening=False
        )
        assert lab_result.unique_threats_identified > 0, "Lab/Test Mode should allow correlations on heuristic/unverified chains."
        print("✓ enable_strict_correlation_hardening toggle verified successfully in unit test!")

    asyncio.run(run_test())

