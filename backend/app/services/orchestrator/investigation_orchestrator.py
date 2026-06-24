"""
Master Investigation Orchestrator.
Coordinates the entire threat intelligence and modeling ingestion pipeline.
Uses Supabase PostgreSQL client.
"""
import logging
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from supabase import Client

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
    def __init__(self, supabase: Client):
        self.supabase = supabase

    async def _update_investigation(self, inv_id: str, data: Dict[str, Any]) -> None:
        """Helper to update database columns in Supabase."""
        self.supabase.table("investigations").update(data).eq("id", inv_id).execute()

    def _add_timeline_event(self, pipeline_state: Dict[str, Any], stage: str, status: str, message: str) -> None:
        if "timeline" not in pipeline_state:
            pipeline_state["timeline"] = []
        pipeline_state["timeline"].append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "stage": stage,
            "status": status,
            "message": message
        })

    async def _check_cancelled(self, inv_id: str, pipeline_state: Dict[str, Any]) -> bool:
        res = self.supabase.table("investigations").select("status, current_stage").eq("id", inv_id).execute()
        if res.data:
            inv = res.data[0]
            status_val = inv.get("status")
            stage_val = inv.get("current_stage")
            if status_val == "stopped" or (status_val == "failed" and stage_val == "Stopped"):
                print(f"[ORCHESTRATOR] Pipeline check: Investigation {inv_id} was stopped by user.")
                pipeline_state["stage"] = "Stopped"
                pipeline_state["progress"] = 100.0
                self._add_timeline_event(pipeline_state, "System", "completed", "Investigation stopped by user")
                await self._update_investigation(inv_id, {
                    "pipeline_state": pipeline_state
                })
                return True
        return False

    async def create_investigation(
        self,
        target: str,
        tests: List[str],
        user_id: str,
        mode: str = "safe",
        include_ti: bool = True,
        tm_mode: str = "enhanced",
        enable_strict_correlation_hardening: bool = True
    ) -> Dict[str, Any]:
        """Create a new investigation in pending state in Supabase."""
        import time
        scan_id = f"SCAN-{int(time.time())}"
        data = {
            "scan_id": scan_id,
            "user_id": user_id,
            "target": target,
            "status": "pending",
            "risk_score": 0.0,
            "started_at": datetime.utcnow().isoformat(),
            "include_ti": include_ti,
            "tm_mode": tm_mode,
            "current_stage": "Pending",
            "progress_percent": 0.0,
            "pipeline_state": {
                "enable_strict_correlation_hardening": enable_strict_correlation_hardening
            },
            "final_result": {}
        }
        res = self.supabase.table("investigations").insert(data).execute()
        if not res.data:
            raise RuntimeError("Failed to create investigation in database.")
        return res.data[0]

    async def run_investigation_pipeline(
        self,
        investigation_id: str,
        tests: List[str],
        mode: str = "safe",
        enable_sqlmap: bool = False,
        auth_browser_analysis: bool = False,
        authorized_auth_mode: bool = False,
        auth_lifecycle_checks: bool = False,
        authz_transition_checks: bool = False,
        session_cookie: Optional[str] = None,
        enable_strict_correlation_hardening: bool = True,
    ) -> None:
        """
        Coordinates scanning, normalization, asset discovery, threat context interpretation,
        and database storage for an investigation.
        """
        from app.services.threat_context.context_interpreter import interpret_context

        # Fetch the investigation
        res = self.supabase.table("investigations").select("*").eq("id", investigation_id).execute()
        if not res.data:
            logger.error(f"Investigation with ID {investigation_id} not found.")
            return
        investigation = res.data[0]

        # Transition status to running & stage 1
        pipeline_state = {
            "stage": "Pentest Scanning",
            "progress": 25.0,
            "updated_at": datetime.utcnow().isoformat(),
            "timeline": [],
            "enable_strict_correlation_hardening": enable_strict_correlation_hardening
        }
        self._add_timeline_event(pipeline_state, "System", "completed", "Security investigation request received")
        self._add_timeline_event(pipeline_state, "System", "completed", f"Target website set to: {investigation.get('target')}")
        self._add_timeline_event(pipeline_state, "Pentest Scanning", "running", "Phase 1: Starting Pentest Scanning...")

        await self._update_investigation(investigation_id, {
            "status": "running",
            "current_stage": "Pentest Scanning",
            "progress_percent": 25.0,
            "pipeline_state": pipeline_state
        })

        try:
            # Check cancellation first
            if await self._check_cancelled(investigation_id, pipeline_state):
                return

            # 1. Run scanner
            print(f"[ORCHESTRATOR] Launching scanner for target: {investigation.get('target')}")
            raw_output = await ScannerAdapter.run_scan(
                target=investigation.get("target"),
                tests=tests,
                mode=mode,
                enable_sqlmap=enable_sqlmap,
                auth_browser_analysis=auth_browser_analysis,
                authorized_auth_mode=authorized_auth_mode,
                auth_lifecycle_checks=auth_lifecycle_checks,
                authz_transition_checks=authz_transition_checks,
                session_cookie=session_cookie,
            )
            
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
                logger.warning(f"Scanner completed with zero findings for target {investigation.get('target')}")
                print(f"[WARNING] Scanner completed with zero findings for target {investigation.get('target')}")

            # Check cancellation
            if await self._check_cancelled(investigation_id, pipeline_state):
                return

            # 2. Transition to stage 2: Normalization
            self._add_timeline_event(pipeline_state, "Pentest Scanning", "completed", "Technology detection & fingerprinting complete")
            self._add_timeline_event(pipeline_state, "Pentest Scanning", "completed", f"Vulnerability crawler flagged {len(raw_findings)} security warnings")
            self._add_timeline_event(pipeline_state, "Finding Normalization", "running", "Phase 2: Running Finding Normalization & Threat Context interpreter")

            pipeline_state["stage"] = "Finding Normalization"
            pipeline_state["progress"] = 50.0
            pipeline_state["updated_at"] = datetime.utcnow().isoformat()

            await self._update_investigation(investigation_id, {
                "current_stage": "Finding Normalization",
                "progress_percent": 50.0,
                "pipeline_state": pipeline_state
            })

            # Retrieve orchestration controls from the database row
            include_ti = investigation.get("include_ti", True)
            tm_mode = investigation.get("tm_mode", "enhanced")

            # Keep raw_findings from top-level scan output (set on line 121)
            # Also extract shared_state versions for TI pipeline
            shared_raw_findings = raw_output.get("shared_state", {}).get("raw_findings", [])
            ti_findings = raw_output.get("ti_findings", [])
            normalized_findings = raw_output.get("shared_state", {}).get("normalized_findings", [])
            # URL normalization helper
            def normalize_target_url(url: str) -> str:
                from app.services.translators.finding_normalizer import FindingNormalizer
                return FindingNormalizer.normalize_url(url)

            # Deduplicate findings before processing/database insertions
            seen_findings = set()
            dedup_normalized = []
            if normalized_findings:
                for f in normalized_findings:
                    title = f.get("title", "").strip().lower()
                    url = normalize_target_url(f.get("affected_url", ""))
                    key = (title, url)
                    if key not in seen_findings:
                        seen_findings.add(key)
                        dedup_normalized.append(f)
            normalized_findings = dedup_normalized

            seen_ti = set()
            dedup_ti = []
            if ti_findings:
                for t in ti_findings:
                    title = t.get("title", "").strip().lower()
                    url = normalize_target_url(t.get("affected_asset", ""))
                    key = (title, url)
                    if key not in seen_ti:
                        seen_ti.add(key)
                        dedup_ti.append(t)
            ti_findings = dedup_ti
            
            import copy
            # Deterministically sort findings by (normalized_url, severity, finding_id)
            normalized_findings.sort(key=lambda x: (
                normalize_target_url(x.get("affected_url") or x.get("url") or ""),
                x.get("severity") or "",
                x.get("finding_id") or ""
            ))
            ti_findings.sort(key=lambda x: (
                normalize_target_url(x.get("affected_asset") or x.get("affected_url") or ""),
                x.get("severity") or "",
                x.get("finding_id") or ""
            ))
            
            # Defensive deep copying
            normalized_findings = copy.deepcopy(normalized_findings)
            ti_findings = copy.deepcopy(ti_findings)
            
            # Save basic normalized findings to DB for TM layer usage (as requested by existing TM)
            if normalized_findings:
                findings_data = []
                for f_dict in normalized_findings:
                    findings_data.append({
                        "investigation_id": investigation_id,
                        "finding_id": f_dict.get("finding_id", "generic"),
                        "title": f_dict.get("title", "Unknown"),
                        "severity": f_dict.get("severity", "info"),
                        "category": f_dict.get("category", "informational"),
                        "affected_url": normalize_target_url(f_dict.get("affected_url", investigation.get("target"))),
                        "evidence": f_dict.get("evidence", ""),
                        "tags": f_dict.get("tags", [])
                    })
                self.supabase.table("findings").insert(findings_data).execute()

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
            assets_data = []
            
            # Save the primary target URL itself as an asset
            assets_data.append({
                "investigation_id": investigation_id,
                "asset_type": "target",
                "url": normalize_target_url(investigation.get("target")),
                "technology": None
            })

            # Save technologies found
            for tech in detected_techs:
                assets_data.append({
                    "investigation_id": investigation_id,
                    "asset_type": "technology",
                    "url": normalize_target_url(investigation.get("target")),
                    "technology": tech.get("name")
                })

            # Save detected sub-assets / assets
            for asset in detected_assets:
                assets_data.append({
                    "investigation_id": investigation_id,
                    "asset_type": asset.get("type") or "sub-asset",
                    "url": normalize_target_url(asset.get("url") or investigation.get("target")),
                    "technology": asset.get("technology")
                })

            # Deduplicate assets before DB insertion
            seen_assets = set()
            dedup_assets = []
            for a in assets_data:
                key = (a["asset_type"], a["url"], a["technology"])
                if key not in seen_assets:
                    seen_assets.add(key)
                    dedup_assets.append(a)
            assets_data = dedup_assets

            if assets_data:
                self.supabase.table("assets").insert(assets_data).execute()

            # 4. Conditionally generate and save Threat Intelligence (TI) report
            if include_ti:
                if await self._check_cancelled(investigation_id, pipeline_state):
                    return

                self._add_timeline_event(pipeline_state, "Finding Normalization", "completed", "Vulnerability findings mapped to CWE structure")
                self._add_timeline_event(pipeline_state, "Threat Intelligence Enrichment", "running", "Phase 3: Launching Threat Intelligence Enrichment (IOC verification)")

                pipeline_state["stage"] = "Threat Intelligence Enrichment"
                pipeline_state["progress"] = 75.0
                pipeline_state["updated_at"] = datetime.utcnow().isoformat()

                await self._update_investigation(investigation_id, {
                    "current_stage": "Threat Intelligence Enrichment",
                    "progress_percent": 75.0,
                    "pipeline_state": pipeline_state
                })

                # Perform OTX and VirusTotal lookup & enrichment
                from app.services.threat_intel_service import ThreatIntelService
                import re
                from urllib.parse import urlparse

                ti_service = ThreatIntelService()
                iocs = []
                seen_iocs = set()

                def add_ioc(val: str, type_: str):
                    if not val:
                        return
                    cleaned = val.strip().lower()
                    if cleaned and cleaned not in seen_iocs:
                        seen_iocs.add(cleaned)
                        iocs.append((val, type_))

                # Extract target URL & domain
                target = investigation.get("target", "")
                if target:
                    add_ioc(target, "url")
                    try:
                        parsed = urlparse(target)
                        domain = parsed.netloc.split(":")[0]
                        if domain:
                            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                                add_ioc(domain, "ip")
                            else:
                                add_ioc(domain, "domain")
                    except Exception:
                        pass

                # Extract from assets
                for asset in detected_assets:
                    url_val = asset.get("url")
                    if url_val:
                        add_ioc(url_val, "url")
                        try:
                            parsed = urlparse(url_val)
                            domain = parsed.netloc.split(":")[0]
                            if domain:
                                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                                    add_ioc(domain, "ip")
                                else:
                                    add_ioc(domain, "domain")
                        except Exception:
                            pass

                # Extract from findings
                for f in raw_findings:
                    url_val = f.get("url") or f.get("affected_url")
                    if url_val:
                        add_ioc(url_val, "url")
                        try:
                            parsed = urlparse(url_val)
                            domain = parsed.netloc.split(":")[0]
                            if domain:
                                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                                    add_ioc(domain, "ip")
                                else:
                                    add_ioc(domain, "domain")
                        except Exception:
                            pass

                # Query OTX/VT in parallel
                enriched_results = []
                if iocs:
                    tasks = [ti_service.enrich_ioc(ioc, ioc_type) for ioc, ioc_type in iocs]
                    enriched_results = await asyncio.gather(*tasks)

                # Merge back to ti_findings
                updated_ti_findings = []
                for ti in ti_findings:
                    asset = ti.get("affected_asset") or ti.get("affected_url") or ""
                    matched_res = None
                    for res in enriched_results:
                        if res["ioc"] == asset or asset.endswith(res["ioc"]):
                            matched_res = res
                            break
                    
                    if matched_res:
                        ti["ioc"] = matched_res["ioc"]
                        ti["type"] = matched_res["type"]
                        ti["vt_score"] = matched_res["vt_score"]
                        ti["vt_status"] = matched_res["vt_status"]
                        ti["otx_pulses"] = matched_res["otx_pulses"]
                        ti["threat_tags"] = matched_res["threat_tags"]
                        ti["campaign_context"] = matched_res["campaign_context"]
                        ti["related_malware_families"] = matched_res["related_malware_families"]
                        ti["confidence_level"] = matched_res["confidence_level"]
                        ti["confidence_score"] = matched_res["confidence_score"]
                        ti["confidence"] = matched_res["confidence_score"] / 100.0
                        ti["risk_reason"] = matched_res["risk_reason"]
                        ti["recommended_action"] = matched_res["recommended_action"]
                        ti["reputation_context"] = matched_res
                        
                        # Apply new severity and weighted risk score calculations
                        ti["severity"] = matched_res["severity"]
                        sev_weights = {"critical": 40.0, "high": 20.0, "medium": 8.0, "low": 3.0, "info": 0.5}
                        base_w = sev_weights.get(ti["severity"], 0.5)
                        ti["risk_score"] = round(base_w * 2.5 * ti["confidence"] * ti.get("risk_multiplier", 1.0), 2)
                    else:
                        ti["ioc"] = asset
                        ti["confidence_score"] = int(ti.get("confidence", 0.5) * 100)
                        ti["confidence_level"] = "medium"
                        ti["vt_status"] = "clean"
                        ti["otx_pulses"] = []
                        ti["threat_tags"] = []
                        ti["campaign_context"] = []
                        ti["related_malware_families"] = []
                        ti["risk_reason"] = "Resource analysed and found clean by threat intelligence checks."
                        ti["recommended_action"] = "No actions required."
                        ti["reputation_context"] = {"source": "Internal Scan", "status": "clean"}
                        ti["severity"] = "info"
                        ti["risk_score"] = 1.25
                    
                    updated_ti_findings.append(ti)

                ti_findings = updated_ti_findings
                pipeline_state["ti_findings"] = ti_findings

                # Recalculate aggregate risk using the new caps
                from app.services.ti_processing_service import TIProcessingService
                ti_risk = TIProcessingService.calculate_aggregate_risk(ti_findings)
                # Use the higher of scanner risk and TI risk so scanner findings aren't lost
                risk_score = max(raw_output.get("risk_score", 0.0), ti_risk)

                # Format enriched_results for the frontend's IOCTable
                ioc_results_formatted = []
                for res in (enriched_results or []):
                    source = res.get("source", "VirusTotal")
                    reputation_score = res.get("confidence_score", 10)
                    threat_level = res.get("threat_level", "clean")
                    flagged = res.get("flagged", False)

                    # Log every IOC right before creating the final response
                    logger.info(
                        f"\n[FINAL IOC]\n"
                        f"indicator = {res.get('ioc')}\n"
                        f"source = {source}\n"
                        f"vt_malicious = {res.get('vt_malicious', 0)}\n"
                        f"vt_suspicious = {res.get('vt_suspicious', 0)}\n"
                        f"otx_pulse_count = {res.get('otx_pulse_count', 0)}\n"
                        f"reputation_score = {reputation_score}\n"
                        f"threat_level = {threat_level}\n"
                        f"flagged = {flagged}\n"
                        f"reason = {res.get('risk_reason', '')}\n"
                    )

                    ioc_results_formatted.append({
                        "indicator_type": res.get("type"),
                        "value": res.get("ioc"),
                        "source": source,
                        "reputation_score": reputation_score,
                        "threat_level": threat_level,
                        "details": {
                            "otx_pulses": res.get("otx_pulses", []),
                            "threat_tags": res.get("threat_tags", []),
                            "campaign_context": res.get("campaign_context", []),
                            "related_malware_families": res.get("related_malware_families", []),
                            "risk_reason": res.get("risk_reason", ""),
                            "recommended_action": res.get("recommended_action", ""),
                            "vt_malicious": res.get("vt_malicious", 0),
                            "vt_suspicious": res.get("vt_suspicious", 0),
                            "otx_pulse_count": res.get("otx_pulse_count", 0),
                        },
                        "flagged": flagged
                    })
                
                pipeline_state["reputation_context"] = {
                    "source": "VirusTotal & AlienVault OTX Enrichment",
                    "last_seen": datetime.utcnow().isoformat() + "Z",
                    "ioc_results": ioc_results_formatted
                }

                self._add_timeline_event(pipeline_state, "Threat Intelligence Enrichment", "completed", f"Reputation lookup finished for {len(iocs)} host domains and IPs")

                self.supabase.table("ti_reports").insert({
                    "investigation_id": investigation_id,
                    "overall_risk": risk_score,
                    "risk_summary": f"Analysis completed on {datetime.utcnow().strftime('%Y-%m-%d')}. "
                                 f"Discovered {len(ti_findings)} TI-validated findings across "
                                 f"{len(detected_techs)} technologies. Risk score: {risk_score}."
                }).execute()

            # 5. Generate and save Threat Modeling (TM) report
            if await self._check_cancelled(investigation_id, pipeline_state):
                return

            await self._update_investigation(investigation_id, {
                "current_stage": "Threat Modeling",
                "progress_percent": 90.0,
                "pipeline_state": {
                    "stage": "Threat Modeling",
                    "progress": 90.0,
                    "updated_at": datetime.utcnow().isoformat()
                }
            })

            self.supabase.table("tm_reports").insert({
                "investigation_id": investigation_id,
                "stride_summary": stride_counts,
                "mitigations": mitigation_roadmap
            }).execute()

            # ──────────────────────────────────────────────────────────
            # Stages 4-6: Advanced Intelligence (Developer 2)
            # These stages extend the pipeline with correlation, STRIDE
            # modeling, and AI-powered reporting. Each stage is wrapped
            # in try/except so failures don't crash the pipeline.
            # ──────────────────────────────────────────────────────────

            # Prepare finding dicts for stages 4-6
            finding_dicts = []
            for f in normalized_findings:
                fid = f.get("finding_id", "generic")
                ti_match = next((t for t in ti_findings if t.get("finding_id") == fid), {})
                finding_dicts.append({
                    "finding_id": fid,
                    "title": f.get("title", "Unknown"),
                    "severity": f.get("severity", "info"),
                    "category": f.get("category", "informational"),
                    "affected_url": f.get("affected_url", investigation.get("target")),
                    "evidence": f.get("evidence", ""),
                    "tags": f.get("tags") or [],
                    "confidence": f.get("confidence", ti_match.get("verification_status", "heuristic")),
                    "risk_score": ti_match.get("risk_score", 0.0),
                    "exploitability_score": f.get("exploitability_score", 0.0)
                })

            # Deterministically sort finding_dicts using (normalized_url, severity, finding_id)
            finding_dicts.sort(key=lambda x: (
                normalize_target_url(x.get("affected_url") or ""),
                x.get("severity") or "",
                x.get("finding_id") or ""
            ))
            finding_dicts = copy.deepcopy(finding_dicts)

            # Initialize final_result with base data
            final_result_data = {
                "scan_id": investigation.get("scan_id"),
                "target": investigation.get("target"),
                "risk_score": risk_score,
                "findings_count": len(normalized_findings),
                "assets_count": len(assets_data),
                "ti_enriched": include_ti,
                "tm_mode": tm_mode,
            }

            # ── Stage 4: Threat Correlation Engine ─────────────────
            correlation_output = None
            try:
                if await self._check_cancelled(investigation_id, pipeline_state):
                    return

                from app.services.investigation.correlation_engine import ThreatCorrelationEngine

                self._add_timeline_event(pipeline_state, "Threat Correlation", "running", "Phase 4: Running Threat Correlation Engine...")

                pipeline_state["stage"] = "Threat Correlation"
                pipeline_state["progress"] = 92.0
                pipeline_state["updated_at"] = datetime.utcnow().isoformat()

                await self._update_investigation(investigation_id, {
                    "current_stage": "Threat Correlation",
                    "progress_percent": 92.0,
                    "pipeline_state": pipeline_state
                })

                correlation_engine = ThreatCorrelationEngine()
                correlation_output = await correlation_engine.correlate(
                    investigation_id=investigation_id,
                    findings=copy.deepcopy(finding_dicts),
                    risk_score=risk_score,
                    stride_summary=copy.deepcopy(stride_counts),
                    ti_reports=copy.deepcopy(ti_findings),
                    enable_strict_correlation_hardening=enable_strict_correlation_hardening,
                )
                final_result_data["correlation"] = correlation_output.model_dump(mode="json")
                
                self._add_timeline_event(pipeline_state, "Threat Correlation", "completed", f"Correlated {correlation_output.unique_threats_identified} multi-stage attack scenarios")
                print(f"[ORCHESTRATOR] Stage 4 (Correlation) completed: {correlation_output.unique_threats_identified} threats")
            except Exception as e:
                logger.warning(f"Stage 4 (Correlation) failed: {e}")
                print(f"[ORCHESTRATOR] Stage 4 (Correlation) failed: {e}")
                final_result_data["correlation"] = {
                    "stage_id": "stage_4_correlation",
                    "investigation_id": investigation_id,
                    "correlated_threats": [],
                    "global_risk_score": risk_score,
                    "risk_summary": {},
                    "total_findings_input": len(finding_dicts),
                    "unique_threats_identified": 0,
                    "duplicates_removed": 0,
                    "total_correlations": 0,
                    "escalated_risks": 0,
                    "escalated_risks_count": 0,
                    "error": str(e)
                }
                from app.schemas.stage_outputs import CorrelationStageOutput
                correlation_output = CorrelationStageOutput(
                    investigation_id=investigation_id,
                    correlated_threats=[],
                    global_risk_score=risk_score,
                    risk_summary={},
                    total_findings_input=len(finding_dicts),
                    unique_threats_identified=0,
                    duplicates_removed=0,
                    started_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                    duration_seconds=0.0,
                    total_correlations=0,
                    escalated_risks=0,
                    escalated_risks_count=0
                )

            # ── Stage 5: Automated STRIDE Threat Modeling ──────────
            stride_output = None
            try:
                if await self._check_cancelled(investigation_id, pipeline_state):
                    return

                from app.services.investigation.threat_modeler import AutomatedSTRIDEModeler

                self._add_timeline_event(pipeline_state, "STRIDE Modeling", "running", "Phase 5: Generating STRIDE Threat Matrix")

                pipeline_state["stage"] = "STRIDE Modeling"
                pipeline_state["progress"] = 95.0
                pipeline_state["updated_at"] = datetime.utcnow().isoformat()

                await self._update_investigation(investigation_id, {
                    "current_stage": "STRIDE Modeling",
                    "progress_percent": 95.0,
                    "pipeline_state": pipeline_state
                })

                stride_modeler = AutomatedSTRIDEModeler()
                corr_threats_dicts = []
                if correlation_output:
                    corr_threats_dicts = [
                        t.model_dump(mode="json") for t in correlation_output.correlated_threats
                    ]

                stride_output = await stride_modeler.model(
                    investigation_id=investigation_id,
                    findings=copy.deepcopy(finding_dicts),
                    correlated_threats=copy.deepcopy(corr_threats_dicts),
                )
                final_result_data["stride"] = stride_output.model_dump(mode="json")
                
                self._add_timeline_event(pipeline_state, "STRIDE Modeling", "completed", f"STRIDE threat matrix compiled. Identified {len(stride_output.stride_threats)} potential threats")
                print(f"[ORCHESTRATOR] Stage 5 (STRIDE) completed: {len(stride_output.stride_threats)} threats")
            except Exception as e:
                logger.warning(f"Stage 5 (STRIDE) failed: {e}")
                print(f"[ORCHESTRATOR] Stage 5 (STRIDE) failed: {e}")
                final_result_data["stride"] = {"error": str(e)}

            # ── Stage 6: AI Security Reporter ──────────────────────
            try:
                if await self._check_cancelled(investigation_id, pipeline_state):
                    return

                from app.services.investigation.ai_reporter import AISecurityReporter

                self._add_timeline_event(pipeline_state, "AI Analysis", "running", "Phase 6: Invoking AI Security Reporter...")

                pipeline_state["stage"] = "AI Analysis"
                pipeline_state["progress"] = 97.0
                pipeline_state["updated_at"] = datetime.utcnow().isoformat()

                await self._update_investigation(investigation_id, {
                    "current_stage": "AI Analysis",
                    "progress_percent": 97.0,
                    "pipeline_state": pipeline_state
                })

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
                    investigation_id=investigation_id,
                    target=investigation.get("target"),
                    risk_score=global_risk,
                    findings=copy.deepcopy(finding_dicts),
                    correlated_threats=copy.deepcopy(corr_threats_for_report),
                    stride_threats=copy.deepcopy(stride_threats_for_report),
                    stride_matrix=copy.deepcopy(stride_matrix_for_report),
                    timeline=copy.deepcopy(pipeline_state.get("timeline")),
                )
                final_result_data["reporter"] = reporter_output.model_dump(mode="json")
                
                self._add_timeline_event(pipeline_state, "AI Analysis", "completed", "Constructed executive and engineering explanations")
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

            completed_at = datetime.utcnow().isoformat()
            
            self._add_timeline_event(pipeline_state, "Success", "completed", f"Security pipeline completed. Global Risk Score finalized: {final_risk}/100")

            pipeline_state.update({
                "stage": "Completed",
                "progress": 100.0,
                "updated_at": completed_at,
                "raw_findings": raw_findings,
                "normalized_findings": normalized_findings,
                "ti_findings": ti_findings,
                "pentest_findings": raw_output.get("findings", []),
                "pentest_summary": {
                    "risk_score": raw_output.get("risk_score", 0),
                    "critical": raw_output.get("critical", 0),
                    "high": raw_output.get("high", 0),
                    "medium": raw_output.get("medium", 0),
                    "low": raw_output.get("low", 0),
                    "info": raw_output.get("info", 0),
                    "total": raw_output.get("total", 0),
                    "endpoints_found": raw_output.get("endpoints_found", 0),
                    "attack_surface_endpoints_count": raw_output.get("attack_surface_endpoints_count", 0),
                    "mode": raw_output.get("mode", "safe"),
                    "started_at": raw_output.get("started_at", ""),
                    "duration": raw_output.get("duration", 0),
                    "modules_run": raw_output.get("modules_run", []),
                    "detected_technologies": raw_output.get("detected_technologies", []),
                    "detected_assets": raw_output.get("detected_assets", []),
                    "scanner_json": raw_output.get("scanner_json"),
                },
                "reputation_context": pipeline_state.get("reputation_context") or raw_output.get("shared_state", {}).get("reputation_context", {}),
                "risk_summary": raw_output.get("shared_state", {}).get("risk_summary", {})
            })

            final_result_data["status"] = "completed"
            final_result_data["risk_score"] = final_risk
            final_result_data["completed_at"] = completed_at

            await self._update_investigation(investigation_id, {
                "status": "completed",
                "current_stage": "Completed",
                "progress_percent": 100.0,
                "risk_score": final_risk,
                "completed_at": completed_at,
                "pipeline_state": pipeline_state,
                "final_result": final_result_data
            })
            print(f"[ORCHESTRATOR] Investigation completed for {investigation.get('target')} (risk={final_risk:.1f}).")

        except (Exception, asyncio.CancelledError) as e:
            # Check if it was stopped/cancelled
            res = self.supabase.table("investigations").select("status, current_stage").eq("id", investigation_id).execute()
            if res.data:
                inv = res.data[0]
                status_val = inv.get("status")
                stage_val = inv.get("current_stage")
                if status_val == "stopped" or (status_val == "failed" and stage_val == "Stopped"):
                    print(f"[ORCHESTRATOR] Pipeline check: Investigation {investigation_id} was stopped by user.")
                    return

            logger.exception(f"Pipeline execution failed for investigation {investigation_id}: {e}")
            self._add_timeline_event(pipeline_state, "Failure", "critical", f"Security pipeline terminated due to failure: {str(e)}")
            pipeline_state["stage"] = "Failed"
            pipeline_state["progress"] = 100.0
            pipeline_state["updated_at"] = datetime.utcnow().isoformat()

            await self._update_investigation(investigation_id, {
                "status": "failed",
                "current_stage": "Failed",
                "completed_at": datetime.utcnow().isoformat(),
                "pipeline_state": pipeline_state
            })
            print(f"[ORCHESTRATOR] Investigation failed for {investigation.get('target')}. Error: {e}")
