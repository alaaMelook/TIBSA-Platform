"""
Integration tests for the security investigation orchestration pipeline.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.database.base import Base
from app.models.investigation import Investigation
from app.repositories.investigation_repository import InvestigationRepository
from app.services.orchestrator.investigation_orchestrator import InvestigationOrchestrator

# Setup in-memory SQLite async database engine for testing
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

def test_investigation_orchestration_flow():
    async def run_test():
        engine = create_async_engine(TEST_DATABASE_URL, echo=False)
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        # Create all tables in-memory
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with async_session() as session:
            orchestrator = InvestigationOrchestrator(session)

            # 1. Create a pending investigation
            target = "https://example.com"
            tests = ["security_headers", "xss"]
            investigation = await orchestrator.create_investigation(target, tests)
            
            assert investigation.id is not None
            assert investigation.status == "pending"
            assert investigation.target == target
            assert investigation.risk_score == 0.0

            # 2. Mock the scanner adapter output
            mock_scan_result = {
                "scan_id": investigation.scan_id,
                "target": target,
                "risk_score": 7.5,
                "findings": [
                    {
                        "title": "Missing HSTS Header",
                        "severity": "Medium",
                        "classification": "Hardening",
                        "url": "https://example.com",
                        "evidence": "Strict-Transport-Security header is not present"
                    },
                    {
                        "title": "SQL Injection vulnerability in search",
                        "severity": "High",
                        "classification": "vulnerability",
                        "url": "https://example.com/search",
                        "evidence": "Error trace returned on quote input"
                    }
                ],
                "detected_technologies": [
                    {"name": "Nginx", "category": "web_server"},
                    {"name": "React", "category": "frontend"}
                ],
                "detected_assets": [
                    {"type": "subdomain", "url": "https://api.example.com", "technology": "Nginx"}
                ]
            }

            # Run pipeline using mock scan results
            with patch("app.services.scanners.scanner_adapter.ScannerAdapter.run_scan", new_callable=AsyncMock) as mock_run:
                mock_run.return_value = mock_scan_result
                
                # Execute orchestration pipeline
                await orchestrator.run_investigation_pipeline(investigation.id, tests)

            # 3. Reload investigation and verify persistence
            repo = InvestigationRepository(session)
            db_investigation = await repo.get_by_id(investigation.id)
            
            assert db_investigation is not None
            assert db_investigation.status == "completed"
            assert db_investigation.risk_score >= 7.5
            
            # Verify Findings
            assert len(db_investigation.findings) == 2
            f1 = db_investigation.findings[0]
            f2 = db_investigation.findings[1]
            
            assert f1.title == "Missing HSTS Header"
            assert f1.severity == "medium"
            assert f1.category == "Hardening"
            
            assert f2.title == "SQL Injection vulnerability in search"
            assert f2.severity == "high"
            assert f2.category == "Injection Vulnerability"

            # Verify Assets
            # We expect 1 target asset + 2 technology assets + 1 subdomain asset = 4 assets total
            assert len(db_investigation.assets) == 4
            asset_types = [a.asset_type for a in db_investigation.assets]
            assert "target" in asset_types
            assert "technology" in asset_types
            assert "subdomain" in asset_types

            # Verify Threat Intelligence Report
            assert len(db_investigation.ti_reports) == 1
            ti = db_investigation.ti_reports[0]
            assert ti.overall_risk == 7.5
            assert "Missing HSTS Header" in ti.risk_summary or "SQL Injection" in ti.risk_summary or "2 findings" in ti.risk_summary

            # Verify Threat Modeling Report
            assert len(db_investigation.tm_reports) == 1
            tm = db_investigation.tm_reports[0]
            assert tm.stride_summary["Tampering"] == 1
            assert tm.stride_summary["Information Disclosure"] == 1
            assert "Injection Vulnerability" in tm.mitigations
            assert "Hardening" in tm.mitigations

        # Clean up database resources
        await engine.dispose()

    # Execute async wrapper
    asyncio.run(run_test())


def test_scanner_pipeline_integration_direct():
    """
    Explicit integration test verifying:
    - findings are normalized and saved to the DB
    - TI report risk score is > 0
    - TM report STRIDE counts are > 0
    """
    async def run_test():
        engine = create_async_engine(TEST_DATABASE_URL, echo=False)
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with async_session() as session:
            orchestrator = InvestigationOrchestrator(session)
            target = "https://tibsa-target.local"
            tests = ["security_headers", "xss"]
            investigation = await orchestrator.create_investigation(target, tests)
            
            # Simulated raw scanner response that mimics real scanner adapter outputs
            simulated_scan_result = {
                "scan_id": investigation.scan_id,
                "target": target,
                "risk_score": 12.0,
                "findings": [
                    {
                        "title": "Missing Header — Content-Security-Policy",
                        "severity": "Medium",
                        "classification": "hardening",
                        "url": target,
                        "evidence": "CSP is not configured"
                    },
                    {
                        "title": "CORS Wildcard Configuration",
                        "severity": "High",
                        "classification": "misconfiguration",
                        "url": target,
                        "evidence": "Access-Control-Allow-Origin: *"
                    }
                ],
                "detected_technologies": [{"name": "React"}],
                "detected_assets": []
            }

            with patch("app.services.scanners.scanner_adapter.ScannerAdapter.run_scan", new_callable=AsyncMock) as mock_run:
                mock_run.return_value = simulated_scan_result
                await orchestrator.run_investigation_pipeline(investigation.id, tests)

            # Reload to check details
            repo = InvestigationRepository(session)
            db_investigation = await repo.get_by_id(investigation.id)
            
            # 1. Assert findings are saved to DB
            assert len(db_investigation.findings) == 2
            
            # 2. Assert TI report risk_score > 0
            assert len(db_investigation.ti_reports) == 1
            assert db_investigation.ti_reports[0].overall_risk > 0.0
            
            # 3. Assert TM report stride counts > 0
            assert len(db_investigation.tm_reports) == 1
            tm = db_investigation.tm_reports[0]
            assert sum(tm.stride_summary.values()) > 0
            assert tm.stride_summary["Tampering"] > 0
            assert tm.stride_summary["Information Disclosure"] > 0

        await engine.dispose()

    asyncio.run(run_test())


def test_investigation_orchestration_modes():
    """
    Integration test verifying:
    - Mode 1 (include_ti=True, tm_mode="enhanced"): Pentest -> TI -> TM
    - Mode 2 (include_ti=False, tm_mode="standalone"): Pentest -> TM directly (bypassing TI)
    """
    async def run_test():
        engine = create_async_engine(TEST_DATABASE_URL, echo=False)
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Mode 1 Test: Enhanced Mode
        async with async_session() as session:
            orchestrator = InvestigationOrchestrator(session)
            target = "https://enhanced.local"
            tests = ["cookie_analysis"]
            
            # create_investigation with Mode 1
            investigation = await orchestrator.create_investigation(
                target, tests, include_ti=True, tm_mode="enhanced"
            )
            
            simulated_scan_result = {
                "scan_id": investigation.scan_id,
                "target": target,
                "risk_score": 5.0,
                "findings": [
                    {
                        "title": "Weak Session Cookie Flags",
                        "severity": "Medium",
                        "classification": "cookie_analysis",
                        "url": target,
                        "evidence": "Secure flag is missing"
                    }
                ],
                "detected_technologies": [],
                "detected_assets": []
            }

            with patch("app.services.scanners.scanner_adapter.ScannerAdapter.run_scan", new_callable=AsyncMock) as mock_run:
                mock_run.return_value = simulated_scan_result
                await orchestrator.run_investigation_pipeline(investigation.id, tests)

            repo = InvestigationRepository(session)
            db_inv = await repo.get_by_id(investigation.id)
            
            # Verify progress & status
            assert db_inv.status == "completed"
            assert db_inv.current_stage == "Completed"
            assert db_inv.progress_percent == 100.0
            
            # Verify finding category is interpreted by TI
            assert len(db_inv.findings) == 1
            assert db_inv.findings[0].category == "Session Security" # Interpreted category
            
            # Verify TI report exists
            assert len(db_inv.ti_reports) == 1

        # Mode 2 Test: Standalone Mode (include_ti=False)
        async with async_session() as session:
            orchestrator = InvestigationOrchestrator(session)
            target = "https://standalone.local"
            tests = ["cookie_analysis"]
            
            # create_investigation with Mode 2
            investigation = await orchestrator.create_investigation(
                target, tests, include_ti=False, tm_mode="standalone"
            )
            
            simulated_scan_result = {
                "scan_id": investigation.scan_id,
                "target": target,
                "risk_score": 5.0,
                "findings": [
                    {
                        "title": "Weak Session Cookie Flags",
                        "severity": "Medium",
                        "classification": "cookie_analysis",
                        "url": target,
                        "evidence": "Secure flag is missing"
                    }
                ],
                "detected_technologies": [],
                "detected_assets": []
            }

            with patch("app.services.scanners.scanner_adapter.ScannerAdapter.run_scan", new_callable=AsyncMock) as mock_run:
                mock_run.return_value = simulated_scan_result
                await orchestrator.run_investigation_pipeline(investigation.id, tests)

            repo = InvestigationRepository(session)
            db_inv = await repo.get_by_id(investigation.id)
            
            # Verify progress & status
            assert db_inv.status == "completed"
            assert db_inv.current_stage == "Completed"
            assert db_inv.progress_percent == 100.0
            
            # Verify finding category remains original (NOT interpreted by TI)
            assert len(db_inv.findings) == 1
            assert db_inv.findings[0].category == "cookie_analysis" # Original category
            
            # Verify TI report DOES NOT exist
            assert len(db_inv.ti_reports) == 0

        await engine.dispose()

    asyncio.run(run_test())


def test_investigation_results_endpoint_logic():
    """
    Integration test verifying get_investigation_results logic behavior:
    - 409 raised if status is not completed.
    - 200/Success with details returned if completed.
    """
    async def run_test():
        from fastapi import HTTPException
        engine = create_async_engine(TEST_DATABASE_URL, echo=False)
        async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with async_session() as session:
            orchestrator = InvestigationOrchestrator(session)
            # Create a pending investigation
            investigation = await orchestrator.create_investigation(
                "https://results-test.local", ["cookie_analysis"]
            )
            
            from app.api.investigations import get_investigation_results
            
            # Since it's pending, calling the route logic directly should trigger a 409
            with pytest.raises(HTTPException) as excinfo:
                await get_investigation_results(id=investigation.id, db=session, current_user={})
            assert excinfo.value.status_code == 409

            # Now update to completed and verify it succeeds
            repo = InvestigationRepository(session)
            investigation.status = "completed"
            await repo.update(investigation)
            
            res = await get_investigation_results(id=investigation.id, db=session, current_user={})
            assert res.success is True
            assert res.data.status == "completed"

        await engine.dispose()

    asyncio.run(run_test())
