"""
Threat Modeling – Service layer.

Handles persistence (Supabase) for threat model analyses.
Supports both legacy and enhanced threat modeling with comprehensive features.
"""
from __future__ import annotations

from typing import List, Optional
from supabase import Client
from datetime import datetime

from app.models.threat_modeling import (
    ThreatModelCreateRequest,
    ThreatModelAnalysisResponse,
    ThreatModelListItem,
    ThreatModelAnalysis,
    ExportFormat,
    ThreatModelScanHistoryItem,
    ThreatModelScanHistoryResponse,
    ThreatModelScanHistorySummary,
)
from app.services.threat_modeling_engine import analyze, analyze_comprehensive
from app.services.export_service import ExportService


class ThreatModelingService:
    TABLE = "threat_model_analyses"

    def __init__(self, supabase: Client):
        self.db = supabase
        self.export_service = ExportService()

    # ─── Create (Legacy) ───────────────────────────────────────────────

    async def create_analysis(
        self,
        req: ThreatModelCreateRequest,
        user_id: Optional[str] = None,
    ) -> ThreatModelAnalysisResponse:
        """
        Run the legacy threat engine and persist the results to Supabase.
        Returns the full stored analysis.
        Automatically records the scan in the history.
        """
        result = analyze(req)

        row = {
            "user_id":              user_id,
            "project_name":         req.project_name,
            "app_type":             req.app_type,
            "uses_auth":            req.uses_auth,
            "uses_database":        req.uses_database,
            "has_admin_panel":      req.has_admin_panel,
            "uses_external_apis":   req.uses_external_apis,
            "stores_sensitive_data": req.stores_sensitive_data,
            "frameworks":           req.frameworks,
            "languages":            req.languages,
            "deploy_envs":          req.deploy_envs,
            "deploy_types":         req.deploy_types,
            "databases":            req.databases,
            "protocols":            req.protocols,
            "risk_score":           result.risk_score,
            "risk_label":           result.risk_label,
            # Supabase expects JSON-serialisable value for JSONB columns
            "threats":              [t.model_dump() for t in result.threats],
            "analysis_type":        "legacy",
        }

        response = self.db.table(self.TABLE).insert(row).execute()

        if not response.data:
            raise RuntimeError("Failed to persist threat model analysis")

        analysis_data = response.data[0]
        analysis_response = self._row_to_response(analysis_data)

        # Record scan in history
        if user_id:
            try:
                await self.record_scan(
                    user_id=user_id,
                    analysis_id=analysis_data["id"],
                    project_name=req.project_name,
                    app_type=req.app_type,
                    risk_score=result.risk_score,
                    risk_label=result.risk_label,
                    threat_count=len(result.threats),
                    mitigation_count=0,
                    analysis_type="legacy",
                )
            except Exception as e:
                # Log but don't fail the analysis if scan history recording fails
                print(f"Warning: Failed to record scan history: {str(e)}")

        return analysis_response

    # ─── Create (Enhanced) ─────────────────────────────────────────────

    async def create_comprehensive_analysis(
        self,
        req: ThreatModelCreateRequest,
        user_id: Optional[str] = None,
        generate_heatmap: bool = True,
        include_summaries: bool = True,
    ) -> ThreatModelAnalysis:
        """
        Run the enhanced threat modeling engine with all features enabled.
        Persists the comprehensive analysis to Supabase.
        Automatically records the scan in the history.
        """
        # Generate comprehensive analysis
        analysis = analyze_comprehensive(req, generate_heatmap, include_summaries)

        # Prepare data for storage
        row = {
            "user_id": user_id,
            "project_name": req.project_name,
            "app_type": req.app_type,
            "uses_auth": req.uses_auth,
            "uses_database": req.uses_database,
            "has_admin_panel": req.has_admin_panel,
            "uses_external_apis": req.uses_external_apis,
            "stores_sensitive_data": req.stores_sensitive_data,
            "frameworks": req.frameworks,
            "languages": req.languages,
            "deploy_envs": req.deploy_envs,
            "deploy_types": req.deploy_types,
            "databases": req.databases,
            "protocols": req.protocols,
            # Enhanced fields
            "system_metadata": analysis.system_metadata,
            "architecture_diagram": analysis.architecture_diagram,
            "assets": analysis.assets,
            "entry_points": analysis.entry_points,
            "trust_boundaries": analysis.trust_boundaries,
            "auth_questions": getattr(analysis, 'auth_questions', None),
            "data_questions": getattr(analysis, 'data_questions', None),
            "control_questions": getattr(analysis, 'control_questions', None),
            "threats": [t.model_dump() for t in (analysis.threats or [])],
            "mitigations": [m.model_dump() for m in (analysis.mitigations or [])],
            "heatmap_data": analysis.heatmap_data.model_dump() if analysis.heatmap_data else None,
            "risk_score": self._calculate_overall_risk_score(analysis),
            "risk_label": self._calculate_overall_risk_label(analysis),
            "analysis_type": "comprehensive",
        }

        response = self.db.table(self.TABLE).insert(row).execute()

        if not response.data:
            raise RuntimeError("Failed to persist comprehensive threat model analysis")

        # Convert back to ThreatModelAnalysis
        stored_row = response.data[0]
        analysis_result = self._row_to_comprehensive_analysis(stored_row)

        # Record scan in history
        if user_id:
            try:
                await self.record_scan(
                    user_id=user_id,
                    analysis_id=stored_row["id"],
                    project_name=req.project_name,
                    app_type=req.app_type,
                    risk_score=row["risk_score"],
                    risk_label=row["risk_label"],
                    threat_count=len(analysis.threats or []),
                    mitigation_count=len(analysis.mitigations or []),
                    analysis_type="comprehensive",
                )
            except Exception as e:
                # Log but don't fail the analysis if scan history recording fails
                print(f"Warning: Failed to record scan history: {str(e)}")

        return analysis_result

    # ─── Export ───────────────────────────────────────────────────────

    async def export_analysis(
        self,
        analysis_id: str,
        format_type: ExportFormat,
        user_id: Optional[str] = None,
        include_heatmap: bool = True,
    ) -> Optional[bytes]:
        """
        Export a threat model analysis in the specified format.
        Returns the exported data as bytes.
        """
        # Get the analysis
        analysis = await self.get_comprehensive_analysis(analysis_id, user_id)
        if not analysis:
            return None

        # Generate export
        export_result = self.export_service.export_threat_model(
            analysis, format_type, include_heatmap
        )

        return export_result.content if isinstance(export_result.content, bytes) else export_result.content.encode('utf-8')

    # ─── Read (single) ────────────────────────────────────────────────

    async def get_analysis(
        self,
        analysis_id: str,
        user_id: Optional[str] = None,
    ) -> Optional[ThreatModelAnalysisResponse]:
        """
        Fetch a single legacy analysis by ID.
        Optionally filter by user_id to enforce ownership.
        """
        query = self.db.table(self.TABLE).select("*").eq("id", analysis_id)
        if user_id:
            query = query.eq("user_id", user_id)

        response = query.maybe_single().execute()

        if not response.data:
            return None

        return self._row_to_response(response.data)

    async def get_comprehensive_analysis(
        self,
        analysis_id: str,
        user_id: Optional[str] = None,
    ) -> Optional[ThreatModelAnalysis]:
        """
        Fetch a comprehensive analysis by ID.
        """
        query = self.db.table(self.TABLE).select("*").eq("id", analysis_id)
        if user_id:
            query = query.eq("user_id", user_id)

        response = query.maybe_single().execute()

        if not response.data:
            return None

        return self._row_to_comprehensive_analysis(response.data)

    # ─── Read (list) ──────────────────────────────────────────────────

    async def list_analyses(
        self,
        user_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        analysis_type: Optional[str] = None,
    ) -> List[ThreatModelListItem]:
        """
        List analyses (most recent first).
        If user_id is provided, only that user's rows are returned.
        analysis_type can be 'legacy' or 'comprehensive'.
        """
        query = (
            self.db.table(self.TABLE)
            .select("id, project_name, app_type, risk_score, risk_label, threats, created_at, analysis_type")
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
        )
        if user_id:
            query = query.eq("user_id", user_id)
        if analysis_type:
            query = query.eq("analysis_type", analysis_type)

        response = query.execute()

        items: List[ThreatModelListItem] = []
        for row in (response.data or []):
            threats = row.get("threats") or []
            items.append(ThreatModelListItem(
                id=row["id"],
                project_name=row["project_name"],
                app_type=row["app_type"],
                risk_score=row["risk_score"],
                risk_label=row["risk_label"],
                threat_count=len(threats),
                mitigation_count=0,
                created_at=row.get("created_at"),
            ))
        return items

    # ─── Delete ───────────────────────────────────────────────────────

    async def delete_analysis(
        self,
        analysis_id: str,
        user_id: Optional[str] = None,
    ) -> bool:
        """
        Delete an analysis.  Returns True if a row was deleted.
        """
        query = self.db.table(self.TABLE).delete().eq("id", analysis_id)
        if user_id:
            query = query.eq("user_id", user_id)

        response = query.execute()
        return bool(response.data)

    # ─── Scan History ─────────────────────────────────────────────────

    async def record_scan(
        self,
        user_id: str,
        analysis_id: str,
        project_name: str,
        app_type: str,
        risk_score: int,
        risk_label: str,
        threat_count: int,
        mitigation_count: int,
        analysis_type: str = "legacy",
        status: str = "completed",
        error_message: Optional[str] = None,
    ) -> ThreatModelScanHistoryItem:
        """
        Record a threat modeling scan in the history.
        Called automatically when a new analysis is created.
        """
        scan_data = {
            "user_id": user_id,
            "analysis_id": analysis_id,
            "project_name": project_name,
            "app_type": app_type,
            "risk_score": risk_score,
            "risk_label": risk_label,
            "threat_count": threat_count,
            "mitigation_count": mitigation_count,
            "analysis_type": analysis_type,
            "status": status,
            "error_message": error_message,
            "completed_at": datetime.utcnow().isoformat() if status == "completed" else None,
        }

        print(f"🔍 Recording scan: user={user_id}, analysis={analysis_id}, project={project_name}")
        response = self.db.table("threat_modeling_scan_history").insert(scan_data).execute()
        print(f"📝 Scan record response: {response}")

        if not response.data:
            print(f"❌ SCAN RECORD FAILED - No data in response: {response}")
            raise RuntimeError(f"Failed to record scan history: {response}")

        print(f"✅ Scan recorded successfully with ID: {response.data[0]['id']}")
        return self._row_to_scan_history_item(response.data[0])

    async def get_scan_history(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> ThreatModelScanHistoryResponse:
        """
        Retrieve scan history for a user with statistics.
        Returns list of scans and statistics about those scans.
        """
        # Get scan history
        response = (
            self.db.table("threat_modeling_scan_history")
            .select("*")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )

        scans: List[ThreatModelScanHistoryItem] = []
        for row in (response.data or []):
            scans.append(self._row_to_scan_history_item(row))

        # Calculate statistics
        all_scans_response = (
            self.db.table("threat_modeling_scan_history")
            .select("risk_score, risk_label, threat_count")
            .eq("user_id", user_id)
            .execute()
        )

        all_scans = all_scans_response.data or []
        high_risk_count = len([s for s in all_scans if s.get("risk_label") == "High"])
        medium_risk_count = len([s for s in all_scans if s.get("risk_label") == "Medium"])
        low_risk_count = len([s for s in all_scans if s.get("risk_label") == "Low"])

        avg_risk_score = None
        if all_scans:
            avg_risk_score = sum(s.get("risk_score", 0) for s in all_scans) / len(all_scans)

        return ThreatModelScanHistoryResponse(
            total_scans=len(all_scans),
            scans=scans,
            average_risk_score=avg_risk_score,
            high_risk_count=high_risk_count,
            medium_risk_count=medium_risk_count,
            low_risk_count=low_risk_count,
        )

    async def get_scan_history_summary(self, user_id: str) -> ThreatModelScanHistorySummary:
        """
        Get a summary of scan history statistics for a user.
        """
        response = (
            self.db.table("threat_modeling_scan_history")
            .select("*")
            .eq("user_id", user_id)
            .execute()
        )

        scans = response.data or []
        if not scans:
            return ThreatModelScanHistorySummary(
                total_scans=0,
                completed_scans=0,
                failed_scans=0,
                average_risk_score=0.0,
                high_risk_threats=0,
                medium_risk_threats=0,
                low_risk_threats=0,
                last_scan_date=None,
                most_common_threat=None,
            )

        completed_scans = len([s for s in scans if s.get("status") == "completed"])
        failed_scans = len([s for s in scans if s.get("status") == "failed"])
        high_risk = len([s for s in scans if s.get("risk_label") == "High"])
        medium_risk = len([s for s in scans if s.get("risk_label") == "Medium"])
        low_risk = len([s for s in scans if s.get("risk_label") == "Low"])

        avg_risk_score = sum(s.get("risk_score", 0) for s in scans) / len(scans)
        last_scan = max(scans, key=lambda s: s.get("created_at", ""), default=None)

        return ThreatModelScanHistorySummary(
            total_scans=len(scans),
            completed_scans=completed_scans,
            failed_scans=failed_scans,
            average_risk_score=round(avg_risk_score, 2),
            high_risk_threats=high_risk,
            medium_risk_threats=medium_risk,
            low_risk_threats=low_risk,
            last_scan_date=last_scan.get("created_at") if last_scan else None,
            most_common_threat=None,  # Can be enhanced to track common threat types
        )

    # ─── Internal ─────────────────────────────────────────────────────

    @staticmethod
    def _row_to_response(row: dict) -> ThreatModelAnalysisResponse:
        from app.models.threat_modeling import ThreatItem

        threats = [ThreatItem(**t) for t in (row.get("threats") or [])]

        return ThreatModelAnalysisResponse(
            id=row["id"],
            user_id=row.get("user_id"),
            project_name=row["project_name"],
            app_type=row["app_type"],
            uses_auth=row.get("uses_auth", False),
            uses_database=row.get("uses_database", False),
            has_admin_panel=row.get("has_admin_panel", False),
            uses_external_apis=row.get("uses_external_apis", False),
            stores_sensitive_data=row.get("stores_sensitive_data", False),
            frameworks=row.get("frameworks") or [],
            languages=row.get("languages") or [],
            deploy_envs=row.get("deploy_envs") or [],
            deploy_types=row.get("deploy_types") or [],
            databases=row.get("databases") or [],
            protocols=row.get("protocols") or [],
            risk_score=row["risk_score"],
            risk_label=row["risk_label"],
            threats=threats,
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    @staticmethod
    def _row_to_comprehensive_analysis(row: dict) -> ThreatModelAnalysis:
        from app.models.threat_modeling import ThreatItem, Mitigation, HeatmapData

        threats = [ThreatItem(**t) for t in (row.get("threats") or [])]
        mitigations = [Mitigation(**m) for m in (row.get("mitigations") or [])]
        heatmap_data = HeatmapData(**row["heatmap_data"]) if row.get("heatmap_data") else None

        return ThreatModelAnalysis(
            id=row["id"],
            title=row.get("project_name"),
            description=row.get("description"),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
            system_metadata=row.get("system_metadata"),
            architecture_diagram=row.get("architecture_diagram"),
            assets=row.get("assets"),
            entry_points=row.get("entry_points"),
            trust_boundaries=row.get("trust_boundaries"),
            auth_questions=row.get("auth_questions"),
            data_questions=row.get("data_questions"),
            control_questions=row.get("control_questions"),
            threats=threats,
            mitigations=mitigations,
            heatmap_data=heatmap_data,
        )

    @staticmethod
    def _calculate_overall_risk_score(analysis: ThreatModelAnalysis) -> int:
        """Calculate overall risk score from threats."""
        if not analysis.threats:
            return 0

        # Simple scoring based on threat severities
        score = 0
        for threat in analysis.threats:
            if threat.severity:
                if threat.severity.lower() == "critical":
                    score += 25
                elif threat.severity.lower() == "high":
                    score += 15
                elif threat.severity.lower() == "medium":
                    score += 8
                elif threat.severity.lower() == "low":
                    score += 3

        return min(score, 100)

    @staticmethod
    def _calculate_overall_risk_label(analysis: ThreatModelAnalysis) -> str:
        """Calculate overall risk label."""
        score = ThreatModelingService._calculate_overall_risk_score(analysis)

        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 35:
            return "Medium"
        else:
            return "Low"

    @staticmethod
    def _row_to_scan_history_item(row: dict) -> ThreatModelScanHistoryItem:
        """Convert a scan history database row to a ThreatModelScanHistoryItem."""
        return ThreatModelScanHistoryItem(
            id=row["id"],
            user_id=row["user_id"],
            analysis_id=row["analysis_id"],
            project_name=row["project_name"],
            app_type=row["app_type"],
            risk_score=row["risk_score"],
            risk_label=row["risk_label"],
            threat_count=row.get("threat_count", 0),
            mitigation_count=row.get("mitigation_count", 0),
            status=row.get("status", "completed"),
            error_message=row.get("error_message"),
            analysis_type=row.get("analysis_type", "legacy"),
            created_at=row.get("created_at"),
            completed_at=row.get("completed_at"),
        )
