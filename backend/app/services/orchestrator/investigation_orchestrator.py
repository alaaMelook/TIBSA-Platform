"""
Master Investigation Orchestrator.
Coordinates the entire threat intelligence and modeling ingestion pipeline.
"""
import logging
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession

# Models
from app.models.investigation import Investigation
from app.models.finding import Finding
from app.models.asset import Asset
from app.models.ti_report import TIReport
from app.models.tm_report import TMReport

# Repositories
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.finding_repository import FindingRepository
from app.repositories.report_repository import ReportRepository

# Services
from app.services.scanners.scanner_adapter import ScannerAdapter
from app.services.translators.finding_normalizer import FindingNormalizer

logger = logging.getLogger(__name__)

# Basic category-to-STRIDE threat mapping
CATEGORY_TO_STRIDE = {
    "Client-Side Security": "Tampering",
    "Session Security": "Spoofing",
    "Authentication Security": "Spoofing",
    "Authorization Security": "Elevation of Privilege",
    "API Security": "Tampering",
    "Injection Vulnerability": "Tampering",
    "Information Disclosure": "Information Disclosure",
    "Hardening": "Information Disclosure",
    "Informational": "Information Disclosure"
}

# Basic category-to-Mitigation mapping
CATEGORY_TO_MITIGATION = {
    "Client-Side Security": "Implement strong Content Security Policies (CSP) and input validation.",
    "Session Security": "Configure cookies with Secure, HttpOnly, and SameSite flags.",
    "Authentication Security": "Implement rate limiting, multi-factor authentication, and strong password complexity policies.",
    "Authorization Security": "Apply strict broken-access-control defenses and role-based permissions.",
    "API Security": "Authenticate CORS origins strictly and sanitize all input parameters.",
    "Injection Vulnerability": "Use parameterized queries and ORM frameworks to prevent execution injections.",
    "Information Disclosure": "Disable directory listing, restrict access to backup files, and filter technical error traces.",
    "Hardening": "Enforce HTTP Strict Transport Security (HSTS) and remove unsafe response headers.",
    "Informational": "Maintain standard security monitoring and periodic dependency audits."
}

class InvestigationOrchestrator:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.investigation_repo = InvestigationRepository(session)
        self.finding_repo = FindingRepository(session)
        self.report_repo = ReportRepository(session)

    async def create_investigation(self, target: str, tests: List[str], mode: str = "safe", include_ti: bool = True, tm_mode: str = "enhanced") -> Investigation:
        """Create a new investigation in pending state."""
        import time
        scan_id = f"SCAN-{int(time.time())}"
        investigation = Investigation(
            scan_id=scan_id,
            target=target,
            status="pending",
            risk_score=0.0,
            started_at=datetime.utcnow(),
            include_ti=include_ti,
            tm_mode=tm_mode,
            current_stage="Pending",
            progress_percent=0.0
        )
        return await self.investigation_repo.create(investigation)

    async def run_investigation_pipeline(self, investigation_id: str, tests: List[str], mode: str = "safe") -> None:
        """
        Coordinates scanning, normalization, asset discovery, threat context interpretation,
        and database storage for an investigation.
        """
        from app.services.threat_context.context_interpreter import interpret_context

        # Fetch the investigation
        investigation = await self.investigation_repo.get_by_id(investigation_id)
        if not investigation:
            logger.error(f"Investigation with ID {investigation_id} not found.")
            return

        # Transition status to running & stage 1
        investigation.status = "running"
        investigation.current_stage = "Pentest Scanning"
        investigation.progress_percent = 25.0
        investigation.pipeline_state = {
            "stage": "Pentest Scanning",
            "progress": 25.0,
            "updated_at": datetime.utcnow().isoformat()
        }
        await self.investigation_repo.update(investigation)

        try:
            # 1. Run scanner
            print(f"[ORCHESTRATOR] Launching scanner for target: {investigation.target}")
            raw_output = await ScannerAdapter.run_scan(investigation.target, tests, mode)
            
            # Temporary debug logging for analysis
            print("--- DEBUG SCANNER OUTPUT ---")
            print("RAW SCAN RESULTS KEYS:", list(raw_output.keys()) if isinstance(raw_output, dict) else "Not a dict")
            if isinstance(raw_output, dict):
                print("RAW FINDINGS COUNT:", len(raw_output.get("findings", [])))
                print("SCANNER_JSON FINDINGS COUNT:", len(raw_output.get("scanner_json", {}).get("findings", [])))
                print("RAW TECHS COUNT:", len(raw_output.get("detected_technologies", [])))
                print("SCANNER_JSON TECHS COUNT:", len(raw_output.get("scanner_json", {}).get("detected_technologies", [])))
                print("RAW ASSETS COUNT:", len(raw_output.get("detected_assets", [])))
                print("SCANNER_JSON ASSETS COUNT:", len(raw_output.get("scanner_json", {}).get("detected_assets", [])))
                print("RAW RISK SCORE:", raw_output.get("risk_score"))
            print("----------------------------")

            # Extract basic result details
            risk_score = raw_output.get("risk_score", 0.0)
            raw_findings = raw_output.get("findings", [])
            detected_techs = raw_output.get("detected_technologies", [])
            detected_assets = raw_output.get("detected_assets", [])

            # Fallback validation warning
            if not raw_findings:
                logger.warning(f"Scanner completed with zero findings for target {investigation.target}")
                print(f"[WARNING] Scanner completed with zero findings for target {investigation.target}")

            # 2. Transition to stage 2: Normalization
            investigation.current_stage = "Finding Normalization"
            investigation.progress_percent = 50.0
            investigation.pipeline_state = {
                "stage": "Finding Normalization",
                "progress": 50.0,
                "updated_at": datetime.utcnow().isoformat()
            }
            await self.investigation_repo.update(investigation)

            # Retrieve orchestration controls from the database row
            include_ti = getattr(investigation, "include_ti", True)
            tm_mode = getattr(investigation, "tm_mode", "enhanced")

            # Use findings directly from the Pentest TI layer
            raw_findings = raw_output.get("shared_state", {}).get("raw_findings", [])
            ti_findings = raw_output.get("ti_findings", [])
            normalized_findings = raw_output.get("shared_state", {}).get("normalized_findings", [])
            
            # Since the TI Processing Service handles False Positive Reduction, we just use its output
            normalized_findings_objs: List[Finding] = []
            
            for f_dict in normalized_findings:
                finding = Finding(
                    investigation_id=investigation.id,
                    finding_id=f_dict.get("finding_id", "generic"),
                    title=f_dict.get("title", "Unknown"),
                    severity=f_dict.get("severity", "info"),
                    category=f_dict.get("category", "informational"),
                    affected_url=f_dict.get("affected_url", investigation.target),
                    evidence=f_dict.get("evidence", ""),
                    tags=f_dict.get("tags", [])
                )
                normalized_findings_objs.append(finding)

            # Save basic normalized findings to DB for TM layer usage (as requested by existing TM)
            if normalized_findings_objs:
                await self.finding_repo.create_many(normalized_findings_objs)

            # We can still extract TM category metrics from ti_findings to populate TM report
            stride_counts = {"Spoofing": 0, "Tampering": 0, "Repudiation": 0, "Information Disclosure": 0, "Denial of Service": 0, "Elevation of Privilege": 0}
            mitigation_roadmap = {}

            for ti in ti_findings:
                tm_category = ti.get("category", "Informational")
                title = ti.get("title", "Unknown")
                
                stride_cat = CATEGORY_TO_STRIDE.get(tm_category) or CATEGORY_TO_STRIDE.get(interpret_context(title, tm_category), "Information Disclosure")
                stride_counts[stride_cat] = stride_counts.get(stride_cat, 0) + 1
                
                mitigation = CATEGORY_TO_MITIGATION.get(tm_category) or CATEGORY_TO_MITIGATION.get(interpret_context(title, tm_category), "Remediate according to security guidelines.")
                mitigation_roadmap[tm_category] = mitigation

            # 3. Process and save Assets (technologies & domains)
            assets_to_save: List[Asset] = []
            
            # Save the primary target URL itself as an asset
            assets_to_save.append(
                Asset(
                    investigation_id=investigation.id,
                    asset_type="target",
                    url=investigation.target,
                    technology=None
                )
            )

            # Save technologies found
            for tech in detected_techs:
                assets_to_save.append(
                    Asset(
                        investigation_id=investigation.id,
                        asset_type="technology",
                        url=investigation.target,
                        technology=tech.get("name")
                    )
                )

            # Save detected sub-assets / assets
            for asset in detected_assets:
                assets_to_save.append(
                    Asset(
                        investigation_id=investigation.id,
                        asset_type=asset.get("type") or "sub-asset",
                        url=asset.get("url") or investigation.target,
                        technology=asset.get("technology")
                    )
                )

            self.session.add_all(assets_to_save)

            # 4. Conditionally generate and save Threat Intelligence (TI) report
            if include_ti:
                investigation.current_stage = "Threat Intelligence Enrichment"
                investigation.progress_percent = 75.0
                investigation.pipeline_state = {
                    "stage": "Threat Intelligence Enrichment",
                    "progress": 75.0,
                    "updated_at": datetime.utcnow().isoformat()
                }
                await self.investigation_repo.update(investigation)

                ti_report = TIReport(
                    investigation_id=investigation.id,
                    overall_risk=risk_score,
                    risk_summary=f"Analysis completed on {datetime.utcnow().strftime('%Y-%m-%d')}. "
                                 f"Discovered {len(ti_findings)} TI-validated findings across "
                                 f"{len(detected_techs)} technologies. Risk score: {risk_score}."
                )
                await self.report_repo.create_ti_report(ti_report)

            # 5. Generate and save Threat Modeling (TM) report
            investigation.current_stage = "Threat Modeling"
            investigation.progress_percent = 90.0
            investigation.pipeline_state = {
                "stage": "Threat Modeling",
                "progress": 90.0,
                "updated_at": datetime.utcnow().isoformat()
            }
            await self.investigation_repo.update(investigation)

            tm_report = TMReport(
                investigation_id=investigation.id,
                stride_summary=stride_counts,
                mitigations=mitigation_roadmap
            )
            await self.report_repo.create_tm_report(tm_report)

            # ──────────────────────────────────────────────────────────
            # Stages 4-6: Advanced Intelligence (Developer 2)
            # These stages extend the pipeline with correlation, STRIDE
            # modeling, and AI-powered reporting. Each stage is wrapped
            # in try/except so failures don't crash the pipeline.
            # ──────────────────────────────────────────────────────────

            # Prepare finding dicts for stages 4-6
            finding_dicts = []
            for f in normalized_findings:
                finding_dicts.append({
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "affected_url": f.affected_url,
                    "evidence": f.evidence,
                    "tags": f.tags or [],
                })

            # Initialize final_result with base data
            final_result_data = {
                "scan_id": investigation.scan_id,
                "target": investigation.target,
                "risk_score": risk_score,
                "findings_count": len(normalized_findings),
                "assets_count": len(assets_to_save),
                "ti_enriched": include_ti,
                "tm_mode": tm_mode,
            }

            # ── Stage 4: Threat Correlation Engine ─────────────────
            correlation_output = None
            try:
                from app.services.investigation.correlation_engine import ThreatCorrelationEngine

                investigation.current_stage = "Threat Correlation"
                investigation.progress_percent = 92.0
                investigation.pipeline_state = {
                    "stage": "Threat Correlation",
                    "progress": 92.0,
                    "updated_at": datetime.utcnow().isoformat()
                }
                await self.investigation_repo.update(investigation)

                correlation_engine = ThreatCorrelationEngine()
                correlation_output = await correlation_engine.correlate(
                    investigation_id=investigation.id,
                    findings=finding_dicts,
                    risk_score=risk_score,
                    stride_summary=stride_counts,
                    ti_reports=[],
                )
                final_result_data["correlation"] = correlation_output.model_dump(mode="json")
                print(f"[ORCHESTRATOR] Stage 4 (Correlation) completed: {correlation_output.unique_threats_identified} threats")
            except Exception as e:
                logger.warning(f"Stage 4 (Correlation) failed: {e}")
                print(f"[ORCHESTRATOR] Stage 4 (Correlation) failed: {e}")
                final_result_data["correlation"] = {"error": str(e)}

            # ── Stage 5: Automated STRIDE Threat Modeling ──────────
            stride_output = None
            try:
                from app.services.investigation.threat_modeler import AutomatedSTRIDEModeler

                investigation.current_stage = "STRIDE Modeling"
                investigation.progress_percent = 95.0
                investigation.pipeline_state = {
                    "stage": "STRIDE Modeling",
                    "progress": 95.0,
                    "updated_at": datetime.utcnow().isoformat()
                }
                await self.investigation_repo.update(investigation)

                stride_modeler = AutomatedSTRIDEModeler()
                corr_threats_dicts = []
                if correlation_output:
                    corr_threats_dicts = [
                        t.model_dump(mode="json") for t in correlation_output.correlated_threats
                    ]

                stride_output = await stride_modeler.model(
                    investigation_id=investigation.id,
                    findings=finding_dicts,
                    correlated_threats=corr_threats_dicts,
                )
                final_result_data["stride"] = stride_output.model_dump(mode="json")
                print(f"[ORCHESTRATOR] Stage 5 (STRIDE) completed: {len(stride_output.stride_threats)} threats")
            except Exception as e:
                logger.warning(f"Stage 5 (STRIDE) failed: {e}")
                print(f"[ORCHESTRATOR] Stage 5 (STRIDE) failed: {e}")
                final_result_data["stride"] = {"error": str(e)}

            # ── Stage 6: AI Security Reporter ──────────────────────
            try:
                from app.services.investigation.ai_reporter import AISecurityReporter

                investigation.current_stage = "AI Analysis"
                investigation.progress_percent = 97.0
                investigation.pipeline_state = {
                    "stage": "AI Analysis",
                    "progress": 97.0,
                    "updated_at": datetime.utcnow().isoformat()
                }
                await self.investigation_repo.update(investigation)

                ai_reporter = AISecurityReporter()
                corr_threats_for_report = []
                if correlation_output:
                    corr_threats_for_report = [
                        t.model_dump(mode="json") for t in correlation_output.correlated_threats
                    ]
                stride_threats_for_report = []
                stride_matrix_for_report = {}
                if stride_output:
                    stride_threats_for_report = [
                        t.model_dump(mode="json") for t in stride_output.stride_threats
                    ]
                    stride_matrix_for_report = stride_output.stride_matrix.model_dump()

                # Compute global risk from correlation or fallback to pentest risk
                global_risk = risk_score
                if correlation_output:
                    global_risk = correlation_output.global_risk_score

                reporter_output = await ai_reporter.generate_report(
                    investigation_id=investigation.id,
                    target=investigation.target,
                    risk_score=global_risk,
                    findings=finding_dicts,
                    correlated_threats=corr_threats_for_report,
                    stride_threats=stride_threats_for_report,
                    stride_matrix=stride_matrix_for_report,
                )
                final_result_data["reporter"] = reporter_output.model_dump(mode="json")
                print(f"[ORCHESTRATOR] Stage 6 (AI Reporter) completed")
            except Exception as e:
                logger.warning(f"Stage 6 (AI Reporter) failed: {e}")
                print(f"[ORCHESTRATOR] Stage 6 (AI Reporter) failed: {e}")
                final_result_data["reporter"] = {"error": str(e)}

            # ── Finalize investigation state ───────────────────────
            # Use the global risk from correlation if available
            final_risk = risk_score
            if correlation_output:
                final_risk = correlation_output.global_risk_score

            investigation.status = "completed"
            investigation.current_stage = "Completed"
            investigation.progress_percent = 100.0
            investigation.risk_score = final_risk
            investigation.completed_at = datetime.utcnow()
            investigation.pipeline_state = {
                "stage": "Completed",
                "progress": 100.0,
                "updated_at": investigation.completed_at.isoformat(),
                "raw_findings": raw_findings,
                "normalized_findings": normalized_findings,
                "ti_findings": ti_findings,
                "reputation_context": raw_output.get("shared_state", {}).get("reputation_context", {}),
                "risk_summary": raw_output.get("shared_state", {}).get("risk_summary", {})
            }
            final_result_data["status"] = "completed"
            final_result_data["risk_score"] = final_risk
            final_result_data["completed_at"] = investigation.completed_at.isoformat()
            investigation.final_result = final_result_data
            await self.investigation_repo.update(investigation)
            print(f"[ORCHESTRATOR] Investigation completed for {investigation.target} (risk={final_risk:.1f}).")

        except Exception as e:
            logger.exception(f"Pipeline execution failed for investigation {investigation_id}: {e}")
            investigation.status = "failed"
            investigation.current_stage = "Failed"
            investigation.completed_at = datetime.utcnow()
            await self.investigation_repo.update(investigation)
            print(f"[ORCHESTRATOR] Investigation failed for {investigation.target}. Error: {e}")
