"""
ProjectionService – writes pipeline results into the normalized relational tables.

Called once after run_pipeline() completes successfully.
The results JSONB column remains the canonical source of truth.
These tables are read-projections for analytics, search, and graph rendering.

Tables written:
  • infra_indicators       – per-IOC threat signals
  • infra_graph_nodes      – visualization graph nodes
  • infra_graph_edges      – visualization graph edges
  • infra_enrichment       – per-stage enrichment snapshots
  • infra_ai_reports       – structured AI threat report
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from supabase import Client

logger = logging.getLogger(__name__)


class ProjectionService:
    """
    Projects pipeline result objects into the normalized relational tables.
    All writes use upsert so the method is safe to call multiple times
    (e.g. backfill runs).
    """

    def __init__(self, supabase: Client) -> None:
        self.db = supabase

    # ── Internal sync helper ──────────────────────────────────────────────────

    def _upsert(self, table: str, rows: list[dict], conflict: str) -> None:
        if rows:
            self.db.table(table).upsert(rows, on_conflict=conflict).execute()

    async def _aupsert(self, table: str, rows: list[dict], conflict: str) -> None:
        if not rows:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._upsert, table, rows, conflict)

    # ── Public entry point ────────────────────────────────────────────────────

    async def project(
        self,
        inv_id: str,
        user_id: str,
        results: Dict[str, Any],
    ) -> None:
        """
        Extract structured data from the full results dict and write it to
        all normalized tables concurrently.
        """
        await asyncio.gather(
            self._project_indicators(inv_id, user_id, results),
            self._project_graph(inv_id, results),
            self._project_enrichment(inv_id, results),
            self._project_ai_report(inv_id, user_id, results),
            return_exceptions=True,   # one failure must not block the others
        )
        logger.info("[Projection:%s] Relational tables updated.", inv_id[:8])

    # ── Stage projections ─────────────────────────────────────────────────────

    async def _project_indicators(
        self,
        inv_id: str,
        user_id: str,
        results: Dict[str, Any],
    ) -> None:
        """
        Build infra_indicators rows from:
          • threat_indicators.checks   – heuristic battery signals
          • reputation.abuseipdb       – AbuseIPDB hit
          • reputation.urlhaus         – URLhaus blacklist
          • reputation.threatfox       – ThreatFox IOC feed
          • reputation.otx             – OTX pulse matches
        """
        rows: list[dict] = []
        target = results.get("target", "")
        target_type = results.get("target_type", "unknown")

        # — Heuristic indicator checks ————————————————————————————————————————
        threat_ind = results.get("threat_indicators") or {}
        for check in threat_ind.get("checks") or []:
            if not check.get("triggered"):
                continue
            rows.append({
                "investigation_id": inv_id,
                "user_id": user_id,
                "ioc_type": target_type,
                "ioc_value": target,
                "ioc_subtype": check.get("id"),
                "threat_category": check.get("name"),
                "confidence_score": _severity_to_confidence(check.get("severity", "info")),
                "severity": check.get("severity", "info"),
                "is_malicious": check.get("severity") in ("high", "critical"),
                "source_name": "heuristic",
                "metadata": {"description": check.get("description"), "detail": check.get("detail")},
            })

        # — AbuseIPDB ─────────────────────────────────────────────────────────
        abuse = (results.get("reputation") or {}).get("abuseipdb") or {}
        if abuse.get("total_reports", 0) > 0:
            score = abuse.get("abuse_confidence_score", 0)
            rows.append({
                "investigation_id": inv_id,
                "user_id": user_id,
                "ioc_type": "ip",
                "ioc_value": target,
                "threat_category": "abuse_reports",
                "confidence_score": float(score),
                "severity": _score_to_severity(score),
                "is_malicious": score >= 50,
                "source_name": "AbuseIPDB",
                "metadata": {
                    "total_reports": abuse.get("total_reports"),
                    "country_code": abuse.get("country_code"),
                    "isp": abuse.get("isp"),
                    "last_reported_at": abuse.get("last_reported_at"),
                },
            })

        # — URLhaus ───────────────────────────────────────────────────────────
        urlhaus = (results.get("reputation") or {}).get("urlhaus") or {}
        if urlhaus.get("query_status") == "is_host":
            rows.append({
                "investigation_id": inv_id,
                "user_id": user_id,
                "ioc_type": target_type,
                "ioc_value": target,
                "threat_category": "malware_distribution",
                "confidence_score": 85.0,
                "severity": "high",
                "is_malicious": True,
                "source_name": "URLhaus",
                "source_url": urlhaus.get("urlhaus_reference"),
                "metadata": {"blacklists": urlhaus.get("blacklists")},
            })

        # — ThreatFox ─────────────────────────────────────────────────────────
        threatfox = (results.get("reputation") or {}).get("threatfox") or {}
        for ioc in (threatfox.get("iocs") or []):
            rows.append({
                "investigation_id": inv_id,
                "user_id": user_id,
                "ioc_type": ioc.get("ioc_type", target_type),
                "ioc_value": ioc.get("ioc", target),
                "threat_category": ioc.get("malware_printable", "unknown"),
                "confidence_score": float(ioc.get("confidence_level", 50)),
                "severity": _confidence_to_severity(ioc.get("confidence_level", 50)),
                "is_malicious": True,
                "source_name": "ThreatFox",
                "first_seen": ioc.get("first_seen"),
                "last_seen": ioc.get("last_seen"),
                "metadata": {"malware_alias": ioc.get("malware_alias"), "tags": ioc.get("tags")},
            })

        # — OTX Pulses ────────────────────────────────────────────────────────
        otx = (results.get("reputation") or {}).get("otx") or {}
        if otx.get("pulse_count", 0) > 0:
            rows.append({
                "investigation_id": inv_id,
                "user_id": user_id,
                "ioc_type": target_type,
                "ioc_value": target,
                "threat_category": "threat_intel_feed",
                "confidence_score": min(float(otx["pulse_count"]) * 10, 100.0),
                "severity": "high" if otx["pulse_count"] >= 5 else "medium",
                "is_malicious": otx["pulse_count"] >= 3,
                "source_name": "OTX AlienVault",
                "metadata": {"pulse_count": otx["pulse_count"]},
            })

        await self._aupsert(
            "infra_indicators",
            rows,
            "investigation_id,ioc_type,ioc_value,source_name",
        )

    # ─────────────────────────────────────────────────────────────────────────

    async def _project_graph(self, inv_id: str, results: Dict[str, Any]) -> None:
        """Write graph nodes and edges from results.graph into relational tables."""
        graph = results.get("graph") or {}

        # Nodes
        node_rows = []
        for n in graph.get("nodes") or []:
            meta = n.get("metadata") or {}
            node_rows.append({
                "investigation_id": inv_id,
                "node_key": n["id"],
                "node_type": n.get("type", "unknown"),
                "label": n.get("label", n["id"]),
                "value": meta.get("value", n.get("label", n["id"])),
                "risk_score": _risk_level_to_score(n.get("risk_level", "clean")),
                "is_malicious": n.get("risk_level") in ("high", "critical"),
                "threat_tags": [],
                "group_name": n.get("type"),
                "metadata": meta,
            })

        # Edges
        edge_rows = []
        for e in graph.get("edges") or []:
            edge_rows.append({
                "investigation_id": inv_id,
                "source_key": e["source"],
                "target_key": e["target"],
                "relationship": e.get("relationship", "related_to"),
                "weight": _confidence_str_to_weight(e.get("confidence", "medium")),
                "bidirectional": False,
                "metadata": {"confidence": e.get("confidence")},
            })

        await asyncio.gather(
            self._aupsert("infra_graph_nodes", node_rows, "investigation_id,node_key"),
            self._aupsert("infra_graph_edges", edge_rows,
                          "investigation_id,source_key,target_key,relationship"),
        )

    # ─────────────────────────────────────────────────────────────────────────

    async def _project_enrichment(self, inv_id: str, results: Dict[str, Any]) -> None:
        """Snapshot each enrichment stage into infra_enrichment."""
        enrichment = results.get("enrichment") or {}
        passive = results.get("passive_dns") or {}
        reputation = results.get("reputation") or {}

        rows: list[dict] = []
        now = datetime.now(timezone.utc).isoformat()

        stage_map = [
            ("dns",         "dnspython",    enrichment.get("dns")),
            ("whois",       "RDAP/whois",   enrichment.get("whois")),
            ("ssl",         "ssl_socket",   enrichment.get("ssl")),
            ("geoip",       "ip-api.com",   enrichment.get("geoip")),
            ("passive_dns", "OTX",          passive if passive.get("passive_dns") else None),
            ("reputation",  "AbuseIPDB",    reputation.get("abuseipdb")),
            ("reputation",  "URLhaus",      reputation.get("urlhaus")),
            ("reputation",  "ThreatFox",    reputation.get("threatfox")),
            ("reputation",  "OTX",          reputation.get("otx")),
        ]

        for stage, source, data in stage_map:
            if data is None:
                continue
            rows.append({
                "investigation_id": inv_id,
                "stage": stage,
                "source": source,
                "status": "failed" if data.get("error") else "success",
                "data": data,
                "fetched_at": now,
            })

        await self._aupsert(
            "infra_enrichment",
            rows,
            "investigation_id,stage,source",
        )

    # ─────────────────────────────────────────────────────────────────────────

    async def _project_ai_report(
        self,
        inv_id: str,
        user_id: str,
        results: Dict[str, Any],
    ) -> None:
        """Write the AI summary into infra_ai_reports."""
        ai = results.get("ai_summary")
        if not ai:
            return

        risk = results.get("risk") or {}
        label = risk.get("risk_label", "unknown").lower()
        threat_level = label if label in ("critical", "high", "medium", "low", "clean") else "unknown"

        row = {
            "investigation_id": inv_id,
            "user_id": user_id,
            "threat_level": threat_level,
            "threat_category": ai.get("threat_classification") or None,
            "summary": ai.get("executive_summary", ""),
            "recommendations": ai.get("recommended_actions") or [],
            "mitre_techniques": [],   # extend when AI produces MITRE output
            "cve_references": [],
            "model_name": "openrouter",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        await self._aupsert("infra_ai_reports", [row], "investigation_id")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _severity_to_confidence(severity: str) -> float:
    return {"info": 10.0, "low": 30.0, "medium": 55.0, "high": 80.0, "critical": 95.0}.get(severity, 10.0)


def _score_to_severity(score: int) -> str:
    if score >= 75: return "critical"
    if score >= 50: return "high"
    if score >= 25: return "medium"
    if score > 0:   return "low"
    return "info"


def _confidence_to_severity(confidence: int) -> str:
    if confidence >= 75: return "critical"
    if confidence >= 50: return "high"
    if confidence >= 25: return "medium"
    return "low"


def _risk_level_to_score(risk_level: str) -> float:
    return {"clean": 0.0, "low": 25.0, "medium": 50.0, "high": 75.0, "critical": 95.0}.get(risk_level, 0.0)


def _confidence_str_to_weight(confidence: str) -> float:
    return {"low": 0.3, "medium": 0.6, "high": 1.0}.get(confidence, 0.5)
