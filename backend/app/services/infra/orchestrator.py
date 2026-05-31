"""
Infra Investigation Orchestrator – coordinates the full 8-stage pipeline.

Stages:
  1. Intake      – normalize target, detect IOC type
  2. Reputation  – AbuseIPDB, URLhaus, ThreatFox, OTX (parallel)
  3. Enrichment  – DNS, WHOIS, SSL, GeoIP (parallel)
  4. Passive DNS – OTX historical A records
  5. Indicators  – 15-check heuristic battery
  6. Correlation – 8-rule relationship analysis
  7. Risk        – weighted composite scoring
  8. AI Summary  – OpenRouter analyst narrative

After each stage the investigation row in Supabase is updated so the
frontend can poll GET /status for live progress.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from supabase import Client

from app.schemas.infra_investigation import InfraInvestigationResults
from app.services.infra.intake_service import IntakeService
from app.services.infra.reputation_service import ReputationService
from app.services.infra.dns_service import EnrichmentService
from app.services.infra.passive_dns_service import PassiveDNSService
from app.services.infra.indicator_service import IndicatorService
from app.services.infra.correlation_engine import CorrelationEngine
from app.services.infra.risk_engine import RiskEngine
from app.services.infra.ai_summary_service import AISummaryService
from app.services.infra.graph_builder import GraphBuilder

logger = logging.getLogger(__name__)

# Stage names and their progress checkpoints (0–100)
STAGES = [
    ("Intake",      10.0),
    ("Reputation",  25.0),
    ("Enrichment",  42.0),
    ("Passive DNS", 55.0),
    ("Indicators",  65.0),
    ("Correlation", 75.0),
    ("Risk Score",  85.0),
    ("AI Summary",  95.0),
    ("Complete",   100.0),
]


class InfraOrchestrator:
    """
    Drives the full Infra Intelligence pipeline for one investigation.
    Instantiate once per investigation run (not a singleton).
    """

    def __init__(self, supabase: Client) -> None:
        self.db = supabase
        self._reputation_svc = ReputationService()
        self._enrichment_svc = EnrichmentService()
        self._passive_dns_svc = PassiveDNSService()
        self._indicator_svc = IndicatorService()
        self._correlation_eng = CorrelationEngine()
        self._risk_eng = RiskEngine()
        self._graph_builder = GraphBuilder()

    # ── DB helpers ────────────────────────────────────────────────────────────

    def _update(self, inv_id: str, payload: Dict[str, Any]) -> None:
        """Synchronous Supabase update (called from async context via executor)."""
        self.db.table("infra_investigations").update(payload).eq("id", inv_id).execute()

    async def _aupdate(self, inv_id: str, payload: Dict[str, Any]) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._update, inv_id, payload)

    async def _advance_stage(
        self,
        inv_id: str,
        stage_name: str,
        progress: float,
    ) -> None:
        await self._aupdate(inv_id, {
            "current_stage": stage_name,
            "progress_percent": progress,
            "status": "running",
        })
        logger.info("[Infra:%s] → %s (%.0f%%)", inv_id[:8], stage_name, progress)

    async def _is_stopped(self, inv_id: str) -> bool:
        """Check if the user has requested a stop."""
        try:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: self.db.table("infra_investigations")
                    .select("status")
                    .eq("id", inv_id)
                    .single()
                    .execute()
            )
            return (resp.data or {}).get("status") == "stopped"
        except Exception:
            return False

    # ── Public API ────────────────────────────────────────────────────────────

    async def create(
        self,
        target: str,
        user_id: str,
        enable_passive_dns: bool = True,
        enable_ai_summary: bool = True,
    ) -> Dict[str, Any]:
        """
        Insert a new investigation row in 'pending' state and return it.
        """
        # Quick validation
        valid, err = IntakeService.validate(target)
        if not valid:
            raise ValueError(err)

        normalized, target_type = IntakeService.classify(target)
        now = datetime.now(timezone.utc).isoformat()

        data = {
            "user_id": user_id,
            "target": target,
            "target_type": target_type,
            "status": "pending",
            "current_stage": "Pending",
            "progress_percent": 0.0,
            "risk_score": 0.0,
            "started_at": now,
        }
        loop = asyncio.get_running_loop()
        resp = await loop.run_in_executor(
            None,
            lambda: self.db.table("infra_investigations").insert(data).execute()
        )
        if not resp.data:
            raise RuntimeError("Failed to create infra investigation in database.")
        return resp.data[0]

    async def run_pipeline(
        self,
        investigation_id: str,
        target: str,
        enable_passive_dns: bool = True,
        enable_ai_summary: bool = True,
    ) -> None:
        """
        Execute the full 8-stage pipeline for an existing investigation row.
        Called from a FastAPI BackgroundTask.
        """
        inv_id = investigation_id

        try:
            # ── Stage 1: Intake ───────────────────────────────────────────────
            await self._advance_stage(inv_id, "Intake", STAGES[0][1])
            normalized, target_type = IntakeService.classify(target)
            hostname = IntakeService.extract_hostname(normalized, target_type)

            if await self._is_stopped(inv_id):
                return

            # ── Stage 2: Reputation ───────────────────────────────────────────
            await self._advance_stage(inv_id, "Reputation", STAGES[1][1])
            reputation_obj = await self._reputation_svc.run(normalized, target_type, hostname)
            reputation_dict = reputation_obj.model_dump()

            if await self._is_stopped(inv_id):
                return

            # ── Stage 3: Enrichment ───────────────────────────────────────────
            await self._advance_stage(inv_id, "Enrichment", STAGES[2][1])
            enrichment_obj = await self._enrichment_svc.run(hostname, target_type)
            enrichment_dict = enrichment_obj.model_dump()

            if await self._is_stopped(inv_id):
                return

            # ── Stage 4: Passive DNS ──────────────────────────────────────────
            passive_dns_obj = None
            passive_dns_dict: Dict[str, Any] = {}
            if enable_passive_dns and target_type in ("domain", "url"):
                await self._advance_stage(inv_id, "Passive DNS", STAGES[3][1])
                passive_dns_obj = await self._passive_dns_svc.query(hostname, target_type)
                passive_dns_dict = passive_dns_obj.model_dump()
            else:
                await self._advance_stage(inv_id, "Passive DNS", STAGES[3][1])

            if await self._is_stopped(inv_id):
                return

            # ── Stage 5: Threat Indicators ────────────────────────────────────
            await self._advance_stage(inv_id, "Indicators", STAGES[4][1])
            ssl_dict = enrichment_dict.get("ssl") or {}
            whois_dict = enrichment_dict.get("whois") or {}
            indicators_obj = self._indicator_svc.run(
                target=target,
                target_type=target_type,
                hostname=hostname,
                whois=whois_dict,
                ssl_cert=ssl_dict,
                reputation=reputation_dict,
            )
            indicators_dict = indicators_obj.model_dump()

            if await self._is_stopped(inv_id):
                return

            # ── Stage 6: Correlation ──────────────────────────────────────────
            await self._advance_stage(inv_id, "Correlation", STAGES[5][1])
            correlation_obj = self._correlation_eng.run(
                reputation=reputation_dict,
                enrichment=enrichment_dict,
                passive_dns=passive_dns_dict,
                indicators=indicators_dict,
            )
            correlation_dict = correlation_obj.model_dump()

            if await self._is_stopped(inv_id):
                return

            # ── Stage 7: Risk Score ───────────────────────────────────────────
            await self._advance_stage(inv_id, "Risk Score", STAGES[6][1])
            risk_obj = self._risk_eng.run(
                reputation=reputation_dict,
                enrichment=enrichment_dict,
                passive_dns=passive_dns_dict,
                indicators=indicators_dict,
                correlation=correlation_dict,
            )
            risk_dict = risk_obj.model_dump()
            final_risk_score = risk_obj.weighted_total

            # ── Stage 8: AI Summary ───────────────────────────────────────────
            ai_dict: Dict[str, Any] = {}
            if enable_ai_summary:
                await self._advance_stage(inv_id, "AI Summary", STAGES[7][1])
                ai_obj = await AISummaryService.generate(
                    target=target,
                    target_type=target_type,
                    risk=risk_dict,
                    indicators=indicators_dict,
                    correlation=correlation_dict,
                    reputation=reputation_dict,
                    enrichment=enrichment_dict,
                )
                ai_dict = ai_obj.model_dump()

            if await self._is_stopped(inv_id):
                return

            # ── Build Graph ───────────────────────────────────────────────────
            graph_obj = self._graph_builder.build(
                target=target,
                target_type=target_type,
                risk_score=final_risk_score,
                enrichment=enrichment_dict,
                passive_dns=passive_dns_dict,
                reputation=reputation_dict,
            )

            # ── Assemble full results payload ─────────────────────────────────
            results = InfraInvestigationResults(
                target=target,
                target_type=target_type,
                normalized_target=normalized,
                reputation=reputation_obj,
                enrichment=enrichment_obj,
                passive_dns=passive_dns_obj,
                threat_indicators=indicators_obj,
                correlation=correlation_obj,
                risk=risk_obj,
                graph=graph_obj,
                ai_summary=ai_obj if enable_ai_summary else None,
            )

            # ── Persist final state ───────────────────────────────────────────
            await self._aupdate(inv_id, {
                "status": "completed",
                "current_stage": "Complete",
                "progress_percent": 100.0,
                "risk_score": round(final_risk_score, 1),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "results": results.model_dump(mode="json"),
                "error": None,
            })
            logger.info(
                "[Infra:%s] Pipeline complete. Risk=%.1f (%s)",
                inv_id[:8], final_risk_score, risk_obj.risk_label
            )

        except asyncio.CancelledError:
            # Task was cancelled externally
            await self._aupdate(inv_id, {
                "status": "stopped",
                "current_stage": "Stopped",
                "progress_percent": 100.0,
            })

        except Exception as exc:
            logger.exception("[Infra:%s] Pipeline failed: %s", inv_id[:8], exc)
            await self._aupdate(inv_id, {
                "status": "failed",
                "current_stage": "Failed",
                "progress_percent": 100.0,
                "error": str(exc),
            })
