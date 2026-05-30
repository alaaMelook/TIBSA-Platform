"""
Stage 4 — Threat Correlation Engine.

Analyzes cross-stage outputs (findings, context, IOC data) to identify
compound threats, build attack chains, and compute a global risk score.

Integrated into the investigation orchestrator pipeline.
"""
from __future__ import annotations

import logging
import uuid
import re
import copy
import inspect
from datetime import datetime
from typing import List, Dict, Any, Optional

from app.config import settings
from app.schemas.stage_outputs import (
    CorrelationStageOutput,
    CorrelatedThreat,
    AttackChainStep,
    ThreatSeverity,
)

logger = logging.getLogger(__name__)

ENABLE_STRICT_CORRELATION_HARDENING = getattr(settings, "enable_strict_correlation_hardening", True)


class ThreatCorrelationEngine:
    """
    Rule-based correlation engine that cross-references pentest findings,
    threat context categories, and normalized data to identify compound threats.
    """

    def __init__(self):
        self._rules = self._build_rules()

    @staticmethod
    def _get_confidence_str(finding: Dict[str, Any]) -> str:
        conf = finding.get("confidence")
        if conf is None:
            sev = (finding.get("severity") or "info").lower()
            if sev in ["medium", "high", "critical"]:
                return "probable"
            return "heuristic"
        if isinstance(conf, (int, float)):
            if conf >= 0.9:
                return "confirmed"
            elif conf >= 0.7:
                return "probable"
            elif conf >= 0.4:
                return "heuristic"
            else:
                return "informational"
        return str(conf).lower().strip()

    @staticmethod
    def _parse_url_host_and_path(url: str):
        if not url:
            return "", ""
        from urllib.parse import urlparse
        try:
            p = urlparse(url)
            host = p.netloc.lower().split(":")[0]
            path = p.path
            if (not path or path == "/") and p.fragment:
                path = p.fragment
            path = path.strip().lower()
            if path.endswith("/"):
                path = path[:-1]
            if not path.startswith("/"):
                path = "/" + path
            return host, path
        except Exception:
            return "", ""

    @staticmethod
    def _paths_overlap(path1: str, path2: str) -> bool:
        if not path1 or path1 == "/" or not path2 or path2 == "/":
            return True
        if path1 == path2:
            return True
        p1 = path1 + "/"
        p2 = path2 + "/"
        if p1.startswith(p2) or p2.startswith(p1):
            return True
        return False

    def _has_host_overlap(self, findings: List[Dict], keywords_A: List[str], keywords_B: List[str]) -> bool:
        findings_A = self._get_findings(findings, keywords_A)
        findings_B = self._get_findings(findings, keywords_B)
        if not findings_A or not findings_B:
            return False
            
        for fA in findings_A:
            urlA = fA.get("affected_url") or fA.get("url") or fA.get("affected_asset") or ""
            hostA, _ = self._parse_url_host_and_path(urlA)
            if not hostA:
                continue
                
            for fB in findings_B:
                if (fA.get("finding_id") or fA.get("id")) == (fB.get("finding_id") or fB.get("id")):
                    continue
                urlB = fB.get("affected_url") or fB.get("url") or fB.get("affected_asset") or ""
                hostB, _ = self._parse_url_host_and_path(urlB)
                if hostA == hostB:
                    return True
        return False

    def _has_endpoint_overlap(self, findings: List[Dict], keywords_A: List[str], keywords_B: List[str]) -> bool:
        findings_A = self._get_findings(findings, keywords_A)
        findings_B = self._get_findings(findings, keywords_B)
        if not findings_A or not findings_B:
            return False
            
        for fA in findings_A:
            urlA = fA.get("affected_url") or fA.get("url") or fA.get("affected_asset") or ""
            hostA, pathA = self._parse_url_host_and_path(urlA)
            if not hostA:
                continue
                
            for fB in findings_B:
                if (fA.get("finding_id") or fA.get("id")) == (fB.get("finding_id") or fB.get("id")):
                    continue
                urlB = fB.get("affected_url") or fB.get("url") or fB.get("affected_asset") or ""
                hostB, pathB = self._parse_url_host_and_path(urlB)
                if hostA == hostB and self._paths_overlap(pathA, pathB):
                    return True
        return False

    def _has_multiple_high_severity_on_same_host(self, findings: List[Dict]) -> bool:
        host_counts = {}
        for f in findings:
            sev = (f.get("severity") or "").lower()
            if sev in ["critical", "high"]:
                url = f.get("affected_url") or f.get("url") or f.get("affected_asset") or ""
                host, _ = self._parse_url_host_and_path(url)
                if host:
                    host_counts[host] = host_counts.get(host, 0) + 1
        return any(count >= 3 for count in host_counts.values())

    def _has_cascading_misconfigs_on_same_host(self, findings: List[Dict]) -> bool:
        host_counts = {}
        for f in findings:
            cat = (f.get("category") or "").lower()
            title = (f.get("title") or "").lower()
            if any(kw in cat or kw in title for kw in ["header", "misconfig", "hardening", "missing"]):
                url = f.get("affected_url") or f.get("url") or f.get("affected_asset") or ""
                host, _ = self._parse_url_host_and_path(url)
                if host:
                    host_counts[host] = host_counts.get(host, 0) + 1
        return any(count >= 4 for count in host_counts.values())

    async def correlate(
        self,
        investigation_id: str,
        findings: List[Dict[str, Any]],
        risk_score: float,
        stride_summary: Dict[str, int],
        ti_reports: List[Dict[str, Any]],
        enable_strict_correlation_hardening: Optional[bool] = None,
    ) -> CorrelationStageOutput:
        """
        Main correlation entry point.
        """
        if enable_strict_correlation_hardening is None:
            enable_strict_correlation_hardening = ENABLE_STRICT_CORRELATION_HARDENING
        self.enable_strict_correlation_hardening = enable_strict_correlation_hardening

        started_at = datetime.utcnow()
        logger.info(
            "[CORRELATION] Starting correlation for investigation %s with %d findings",
            investigation_id, len(findings)
        )

        try:
            # 1. Rule Isolation & Immutability: Deepcopy inputs so rules can never mutate originals
            findings_copy = copy.deepcopy(findings)
            for f in findings_copy:
                url_val = f.get("affected_url") or f.get("url") or f.get("affected_asset") or ""
                f["affected_url"] = url_val
                f["url"] = url_val
            ti_reports_copy = copy.deepcopy(ti_reports)
            stride_summary_copy = copy.deepcopy(stride_summary)

            # 2. Skip/Short-circuit correlation entirely for hardened targets or if there's no exploit capability
            if self.enable_strict_correlation_hardening:
                from app.services.translators.finding_normalizer import FindingNormalizer
                all_passive = True
                has_exploit_capable = False
                for f in findings_copy:
                    title_lower = (f.get("title") or "").lower()
                    url_val = f.get("affected_url") or f.get("url") or ""
                    is_passive = FindingNormalizer.is_passive_finding(title_lower, url_val)
                    if not is_passive and (f.get("severity") or "info").lower() != "info":
                        all_passive = False
                    
                    sev_lower = (f.get("severity") or "info").lower()
                    exp_score = float(f.get("exploitability_score") or (4.0 if sev_lower == "medium" else 7.0 if sev_lower == "high" else 9.0 if sev_lower == "critical" else 0.0))
                    if sev_lower in ["medium", "high", "critical"] and exp_score >= 3.0:
                        has_exploit_capable = True
                        
                if all_passive or not has_exploit_capable:
                    logger.debug("[CORRELATION] Skipping correlation engine: all passive or no exploit-capable findings.")
                    completed_at = datetime.utcnow()
                    duration = (completed_at - started_at).total_seconds()
                    return CorrelationStageOutput(
                        investigation_id=investigation_id,
                        correlated_threats=[],
                        global_risk_score=risk_score,
                        risk_summary=self._build_risk_summary([], risk_score),
                        total_findings_input=len(findings),
                        unique_threats_identified=0,
                        duplicates_removed=0,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_seconds=round(duration, 2),
                        total_correlations=0,
                        escalated_risks=0,
                        escalated_risks_count=0
                    )

            correlated_threats: List[CorrelatedThreat] = []
            seen_rule_ids: set = set()

            # Run each correlation rule against the copied findings
            for rule in self._rules:
                rule_id = rule["id"]
                try:
                    if rule["condition"](findings_copy, stride_summary_copy, ti_reports_copy):
                        if rule_id not in seen_rule_ids:
                            sig = inspect.signature(rule["generate"])
                            if len(sig.parameters) == 3:
                                threat = rule["generate"](findings_copy, investigation_id, ti_reports_copy)
                            else:
                                threat = rule["generate"](findings_copy, investigation_id)
                            
                            # Normalize, cap, and sanitize the threat dynamically
                            threat = self._normalize_correlated_threat(threat, findings_copy, ti_reports_copy)
                            if threat is not None:
                                correlated_threats.append(threat)
                                seen_rule_ids.add(rule_id)
                                logger.info("[CORRELATION] Rule %s fired: %s", rule_id, threat.title)
                except Exception as e:
                    logger.warning("[CORRELATION] Rule %s failed: %s", rule_id, str(e))
                    continue

            # Deduplicate threats by title similarity
            correlated_threats = self._deduplicate(correlated_threats)

            # Sort correlated threats and attack chain steps deterministically
            severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            def threat_sort_key(t: CorrelatedThreat):
                risk_val = t.combined_risk or (t.severity.value if hasattr(t.severity, "value") else str(t.severity)) or "info"
                risk_int = severity_map.get(risk_val.lower(), 0)
                conf_val = float(t.confidence_score or 0.0)
                primary_affected_asset = t.affected_endpoints[0] if t.affected_endpoints else ""
                tid_val = t.threat_id or ""
                return (-risk_int, -conf_val, primary_affected_asset, tid_val)
                
            correlated_threats = sorted(correlated_threats, key=threat_sort_key)

            for t in correlated_threats:
                if t.attack_chain:
                    t.attack_chain = sorted(
                        t.attack_chain,
                        key=lambda s: (s.order, s.affected_endpoint or "")
                    )

            # Compute global risk score
            global_risk = self._compute_global_risk(risk_score, 0.0, correlated_threats, findings_copy)

            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()

            output = CorrelationStageOutput(
                investigation_id=investigation_id,
                correlated_threats=correlated_threats,
                global_risk_score=global_risk,
                risk_summary=self._build_risk_summary(correlated_threats, global_risk),
                total_findings_input=len(findings),
                unique_threats_identified=len(correlated_threats),
                duplicates_removed=0,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=round(duration, 2),
                total_correlations=len(correlated_threats),
                escalated_risks=sum(1 for t in correlated_threats if t.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]),
                escalated_risks_count=sum(1 for t in correlated_threats if t.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL])
            )

            logger.info(
                "[CORRELATION] Completed: %d correlated threats, global risk=%.1f",
                len(correlated_threats), global_risk
            )
            return output

        except Exception as e:
            import traceback
            logger.warning("[CORRELATION] Correlation engine failed internally: %s\n%s", str(e), traceback.format_exc())
            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()
            return CorrelationStageOutput(
                investigation_id=investigation_id,
                correlated_threats=[],
                global_risk_score=risk_score,
                risk_summary=self._build_risk_summary([], risk_score),
                total_findings_input=len(findings),
                unique_threats_identified=0,
                duplicates_removed=0,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=round(duration, 2),
                total_correlations=0,
                escalated_risks=0,
                escalated_risks_count=0
            )

    # ── Risk score computation ──────────────────────────────────────

    def _compute_global_risk(self, pentest_risk: float, escalation_bonus: float, correlated_threats: List[CorrelatedThreat] = None, findings: List[Dict] = None) -> float:
        """
        Compute global risk score. Correlation must NEVER mutate or overwrite the base risk score.
        """
        return round(pentest_risk, 1)

    def _build_risk_summary(
        self, threats: List[CorrelatedThreat], global_risk: float
    ) -> Dict[str, Any]:
        """Build a summary breakdown of risk categories."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for t in threats:
            sev = t.combined_risk or (t.severity.value if isinstance(t.severity, ThreatSeverity) else str(t.severity))
            severity_counts[sev.lower()] = severity_counts.get(sev.lower(), 0) + 1

        return {
            "global_risk_score": global_risk,
            "total_correlated_threats": len(threats),
            "severity_distribution": severity_counts,
            "risk_label": self._score_to_label(global_risk),
        }

    @staticmethod
    def _score_to_label(score: float) -> str:
        """Convert a 0-100 score to a risk label."""
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        return "Low"

    # ── Deduplication ──────────────────────────────────────────────

    @staticmethod
    def _deduplicate(threats: List[CorrelatedThreat]) -> List[CorrelatedThreat]:
        """Remove duplicate threats by title (case-insensitive)."""
        seen_titles: set = set()
        unique: List[CorrelatedThreat] = []
        for t in threats:
            key = t.title.lower().strip()
            if key not in seen_titles:
                seen_titles.add(key)
                unique.append(t)
        return unique

    # ── Helper: find findings by category/classification ────────────

    @staticmethod
    def _has_finding(findings: List[Dict], category_keywords: List[str]) -> bool:
        """Check if any finding matches one of the category keywords."""
        for f in findings:
            cat = (f.get("category") or "").lower()
            title = (f.get("title") or "").lower()
            for kw in category_keywords:
                if kw in cat or kw in title:
                    return True
        return False

    @staticmethod
    def _get_findings(findings: List[Dict], category_keywords: List[str]) -> List[Dict]:
        """Get all findings matching category keywords."""
        result = []
        for f in findings:
            cat = (f.get("category") or "").lower()
            title = (f.get("title") or "").lower()
            for kw in category_keywords:
                if kw in cat or kw in title:
                    result.append(f)
                    break
        return result

    @staticmethod
    def _get_finding_ids(findings: List[Dict], category_keywords: List[str]) -> List[str]:
        """Get IDs of findings matching category keywords."""
        ids = []
        for f in findings:
            cat = (f.get("category") or "").lower()
            title = (f.get("title") or "").lower()
            for kw in category_keywords:
                if kw in cat or kw in title:
                    ids.append(f.get("finding_id") or f.get("id") or "unknown")
                    break
        return ids

    @staticmethod
    def _count_severity(findings: List[Dict], severities: List[str]) -> int:
        """Count findings matching given severities."""
        return sum(
            1 for f in findings
            if (f.get("severity") or "").lower() in severities
        )

    @staticmethod
    def _make_threat_id() -> str:
        return f"CT-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _is_passive_or_header(finding: Dict[str, Any]) -> bool:
        """
        Classifies a finding as passive/header-only based on confidence,
        verification status, title, or category.
        """
        title_lower = (finding.get("title") or "").lower()
        conf = str(finding.get("confidence") or "").lower()
        ver = str(finding.get("verification_status") or finding.get("verification") or "").lower()
        
        if any(kw in title_lower for kw in ["potential", "candidate", "heuristic", "mapped"]):
            return True
            
        if conf in ["heuristic", "informational"] or ver in ["heuristic", "informational", "unverified"]:
            return True
            
        from app.services.translators.finding_normalizer import FindingNormalizer
        url_val = finding.get("affected_url") or finding.get("url") or ""
        return FindingNormalizer.is_passive_finding(title_lower, url_val)

    def _has_exploit_capable_finding(self, findings: List[Dict], source_finding_ids: List[str]) -> bool:
        """Verify if the threat contains at least one exploit-capable finding."""
        for f in findings:
            fid = f.get("finding_id") or f.get("id")
            if fid not in source_finding_ids:
                continue

            title_lower = (f.get("title") or "").lower()
            severity = (f.get("severity") or "info").lower()
            conf = self._get_confidence_str(f)
            exp_score = float(f.get("exploitability_score") or 0.0)
            
            if severity == "info":
                continue
                
            if self._is_passive_or_header(f):
                continue
                
            if ENABLE_STRICT_CORRELATION_HARDENING:
                cat_lower = (f.get("category") or "").lower()
                is_hardening = cat_lower in ["hardening", "informational"]
                if is_hardening:
                    continue
                if conf == "informational":
                    continue
                if exp_score >= 5.0:
                    return True
                if severity in ["high", "critical"] and conf in ["confirmed", "probable"]:
                    return True
                if severity == "medium" and exp_score >= 3.0:
                    return True
            else:
                is_exploit_type = any(kw in title_lower for kw in ["sqli", "sql injection", "xss", "cross-site scripting", "injection", "auth", "login", "idor", "bac", "access control", "command execution"])
                if is_exploit_type:
                    if severity in ["high", "critical"] or conf in ["confirmed", "probable"]:
                        return True
                if severity == "medium" and exp_score >= 3.0:
                    return True
        return False

    def _is_finding_verified(self, f: Dict[str, Any]) -> bool:
        if f.get("verified") is True:
            return True
        conf = str(f.get("confidence") or "").lower().strip()
        if conf in ("verified", "confirmed"):
            return True
        ver_status = str(f.get("verification_status") or f.get("verification") or "").lower().strip()
        if ver_status in ("verified", "confirmed"):
            return True
        return False

    def _normalize_correlated_threat(
        self, threat: CorrelatedThreat, findings: List[Dict], ti_reports: List[Dict]
    ) -> Optional[CorrelatedThreat]:
        """
        Applies Dynamic Correlation Severity caps, exploitability checks, confidence scaling, and STRIDE text sanitization.
        """
        source_ids = set(threat.source_findings)
        supporting = [f for f in findings if (f.get("finding_id") or f.get("id")) in source_ids]
        
        if not supporting:
            return None

        # Filter threat source findings to only valid ones
        valid_source_ids = [f.get("finding_id") or f.get("id") for f in supporting if (f.get("finding_id") or f.get("id"))]
        threat.source_findings = list(sorted(set(valid_source_ids)))

        # Rule: A correlated threat must contain at least one logical relationship (requires at least 2 findings)
        if len(supporting) < 2:
            logger.debug("[CORRELATION] Suppressing chain %s: does not contain at least one logical relationship between findings.", threat.title)
            return None

        # Rule 6: Correlation Evidence Gate (must contain at least one verified finding)
        verified_supporting = [f for f in supporting if self._is_finding_verified(f)]
        if self.enable_strict_correlation_hardening:
            if not verified_supporting:
                logger.debug("[CORRELATION] Suppressing chain %s: contains no verified findings.", threat.title)
                return None

            # Suppress disallowed chains
            all_headers = all(
                any(kw in (f.get("title") or "").lower() or kw in (f.get("category") or "").lower()
                    for kw in ["header", "hsts", "csp", "x-frame", "content-security-policy", "x-content-type", "referrer-policy"])
                for f in supporting
            )
            if all_headers:
                logger.debug("[CORRELATION] Suppressing chain %s: missing headers only.", threat.title)
                return None

            all_directory = all(
                any(kw in (f.get("title") or "").lower() or kw in (f.get("category") or "").lower()
                    for kw in ["directory listing", "dir_listing", "index of", "exposed directory"])
                for f in supporting
            )
            if all_directory:
                logger.debug("[CORRELATION] Suppressing chain %s: directory mapping only.", threat.title)
                return None

            all_asset = all(
                any(kw in (f.get("title") or "").lower() or kw in (f.get("category") or "").lower()
                    for kw in ["asset", "discovery", "endpoint mapping", "attack surface", "potential upload endpoint"])
                for f in supporting
            )
            if all_asset:
                logger.debug("[CORRELATION] Suppressing chain %s: asset discovery only.", threat.title)
                return None

            all_heuristic = all(
                str(f.get("confidence") or "").lower() in ["heuristic", "informational"]
                for f in supporting
            )
            if all_heuristic:
                logger.debug("[CORRELATION] Suppressing chain %s: heuristic observations only.", threat.title)
                return None

            all_informational = all(
                (f.get("severity") or "info").lower() == "info" or str(f.get("confidence") or "").lower() == "informational"
                for f in supporting
            )
            if all_informational:
                logger.debug("[CORRELATION] Suppressing chain %s: informational findings only.", threat.title)
                return None
            
        sev_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        inv_sev_map = {0: ThreatSeverity.INFO, 1: ThreatSeverity.LOW, 2: ThreatSeverity.MEDIUM, 3: ThreatSeverity.HIGH, 4: ThreatSeverity.CRITICAL}
        
        max_sev_val = 0
        max_conf_str = "heuristic"
        max_conf_order = 1
        
        for f in supporting:
            sev_str = f.get("severity", "info").lower()
            max_sev_val = max(max_sev_val, sev_map.get(sev_str, 0))
            
            conf_str = self._get_confidence_str(f)
            conf_order = {"informational": 0, "heuristic": 1, "probable": 2, "confirmed": 3}
            curr_conf_order = conf_order.get(conf_str, 1)
            if curr_conf_order > max_conf_order:
                max_conf_order = curr_conf_order
                max_conf_str = conf_str
                
        limit_sev_val = max_sev_val
        
        conf_limits = {"informational": 0, "heuristic": 2, "probable": 3, "confirmed": 4}
        limit_sev_val = min(limit_sev_val, conf_limits.get(max_conf_str, 2))
        
        if limit_sev_val >= 3:
            if not self._has_exploit_capable_finding(findings, threat.source_findings):
                limit_sev_val = min(limit_sev_val, 2)
                
        # Apply Correlation Severity Limiter cap
        if self.enable_strict_correlation_hardening and verified_supporting:
            max_verified_sev_val = max(sev_map.get(f.get("severity", "info").lower(), 0) for f in verified_supporting)
            limit_sev_val = min(limit_sev_val, max_verified_sev_val)

        threat.severity = inv_sev_map[limit_sev_val]
        
        sev_caps = {0: 15.0, 1: 35.0, 2: 65.0, 3: 85.0, 4: 98.0}
        max_allowed_score = sev_caps.get(limit_sev_val, 65.0)
        
        threat.risk_score = min(threat.risk_score, max_allowed_score)
        if threat.global_chain_risk is not None:
            threat.global_chain_risk = min(threat.global_chain_risk, max_allowed_score)
            
        # Calculate dynamic confidence score from supporting findings
        finding_scores = []
        for f in supporting:
            c_str = self._get_confidence_str(f)
            c_score = {"informational": 0.20, "heuristic": 0.50, "probable": 0.80, "confirmed": 0.95}.get(c_str, 0.50)
            finding_scores.append(c_score)
        
        if finding_scores:
            avg_conf = sum(finding_scores) / len(finding_scores)
            threat.confidence_score = round((threat.confidence_score * 0.3) + (avg_conf * 0.7), 2)

        conf_float_map = {"informational": 0.2, "heuristic": 0.5, "probable": 0.8, "confirmed": 1.0}
        max_conf_val = conf_float_map.get(max_conf_str, 0.5)
        
        threat.confidence_score = min(threat.confidence_score, max_conf_val)
        if threat.chain_confidence is not None:
            threat.chain_confidence = min(threat.chain_confidence, max_conf_val * 100.0)
            
        MIN_CHAIN_CONFIDENCE = 0.65
        if self.enable_strict_correlation_hardening and threat.confidence_score < MIN_CHAIN_CONFIDENCE:
            logger.debug("[CORRELATION] Suppressing threat %s due to low confidence: %s < %s", threat.title, threat.confidence_score, MIN_CHAIN_CONFIDENCE)
            return None

        if limit_sev_val < 3 or max_conf_str == "heuristic":
            replacements = {
                "credential theft": "potential unauthorized interaction",
                "full compromise": "possible client-side manipulation",
                "admin takeover": "increased exposure risk",
                "system breach": "increased exposure risk",
                "full database exposure": "limited information disclosure",
                "unauthorized administrative access": "unauthorized restricted path access"
            }
            for pattern, repl in replacements.items():
                if threat.title:
                    threat.title = re.sub(pattern, repl, threat.title, flags=re.IGNORECASE)
                if threat.description:
                    threat.description = re.sub(pattern, repl, threat.description, flags=re.IGNORECASE)
                if threat.impact:
                    threat.impact = re.sub(pattern, repl, threat.impact, flags=re.IGNORECASE)
                if threat.exploitation_scenario:
                    threat.exploitation_scenario = re.sub(pattern, repl, threat.exploitation_scenario, flags=re.IGNORECASE)

        threat.title = threat.title or ""
        threat.description = threat.description or ""
        threat.impact = threat.impact or f"Potential impact of {threat.title} vulnerability."
        threat.exploitation_scenario = threat.exploitation_scenario or f"Attacker exploits {threat.title}."
        threat.recommended_mitigation = threat.recommended_mitigation or "Remediate findings."
        threat.global_chain_risk = threat.global_chain_risk or threat.risk_score
        threat.chain_confidence = threat.chain_confidence or (threat.confidence_score * 100.0)
        threat.attack_complexity = threat.attack_complexity or "medium"
        threat.sources = threat.sources or self._get_sources_for_findings(threat.source_findings, ti_reports)
        threat.affected_endpoints = [ep for ep in (threat.affected_endpoints or []) if ep]
        threat.tags = [tag for tag in (threat.tags or []) if tag]

        threat.id = threat.threat_id
        threat.combined_risk = threat.severity.value if isinstance(threat.severity, ThreatSeverity) else str(threat.severity)
        threat.confidence = threat.confidence_score
        threat.contributing_finding_ids = threat.source_findings
        threat.contributing_ioc_values = []
        threat.risk_label = self._score_to_label(threat.risk_score)
        
        if threat.attack_chain is None:
            threat.attack_chain = []
        else:
            for step in threat.attack_chain:
                if step.evidence_source is None:
                    step.evidence_source = "pentest"
                if step.finding_ids is None:
                    step.finding_ids = []
                if step.description is None:
                    step.description = ""
                if not getattr(step, "affected_endpoint", None):
                    step.affected_endpoint = ""
                    
            threat.attack_chain.sort(key=lambda s: (s.order, s.affected_endpoint or ""))
                    
        return threat

    def _get_sources_for_findings(self, source_finding_ids: List[str], ti_reports: List[Dict]) -> List[str]:
        sources = ["Pentest Engine"]
        if ti_reports:
            for r in ti_reports:
                if r.get("finding_id") in source_finding_ids:
                    sources.append("Threat Intel Engine")
                    break
        return list(set(sources))

    @staticmethod
    def _count_misconfigs(findings: List[Dict]) -> int:
        """Count misconfiguration-related findings."""
        count = 0
        for f in findings:
            cat = (f.get("category") or "").lower()
            title = (f.get("title") or "").lower()
            if any(kw in cat or kw in title
                   for kw in ["header", "misconfig", "hardening", "missing"]):
                count += 1
        return count

    # ── Correlation Rules ──────────────────────────────────────────

    def _build_rules(self) -> List[Dict[str, Any]]:
        """
        Build the list of correlation rules.
        """
        return [
            # ─── Rule CR-001: XSS + Missing CSP Header ─────────────────
            {
                "id": "CR-001",
                "name": "Unprotected XSS Exploitation",
                "condition": lambda findings, stride, ti: (
                    self._has_host_overlap(findings, ["xss", "cross-site scripting"], ["csp", "content-security-policy", "content security policy"])
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="XSS Exploitation Amplified by Missing CSP",
                    description=(
                        "Cross-Site Scripting vulnerability found with no Content-Security-Policy header. "
                        "Attackers can inject and execute arbitrary scripts in victim browsers without "
                        "any CSP restrictions, enabling session hijacking and credential theft."
                    ),
                    source_findings=(
                        self._get_finding_ids(findings, ["xss", "cross-site scripting"]) +
                        self._get_finding_ids(findings, ["csp", "content-security-policy"])
                    ),
                    correlation_rule="CR-001",
                    confidence_score=0.9,
                    severity=ThreatSeverity.CRITICAL,
                    risk_score=92.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Attacker identifies XSS injection point in the application",
                            finding_ids=self._get_finding_ids(findings, ["xss", "cross-site scripting"]),
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=2,
                            description="No CSP header present to block inline script execution",
                            finding_ids=self._get_finding_ids(findings, ["csp", "content-security-policy"]),
                            severity=ThreatSeverity.MEDIUM,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Malicious script executes unrestricted in victim's browser",
                            finding_ids=[],
                            severity=ThreatSeverity.CRITICAL,
                        ),
                        AttackChainStep(
                            order=4,
                            description="Session cookies or credentials stolen via injected payload",
                            finding_ids=[],
                            severity=ThreatSeverity.CRITICAL,
                        ),
                    ],
                    affected_endpoints=[
                        f.get("affected_url", "") for f in self._get_findings(findings, ["xss"])
                    ],
                    tags=["xss", "csp", "session-hijacking", "credential-theft"],
                ),
            },

            # ─── Rule CR-002: SQLi + Sensitive Endpoint Exposure ────────
            {
                "id": "CR-002",
                "name": "Database Compromise via SQLi + Exposed Endpoints",
                "condition": lambda findings, stride, ti: (
                    self._has_host_overlap(findings, ["sql injection", "sqli", "injection vulnerability"], ["directory", "exposed", "information disclosure"])
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Database Compromise Risk — SQLi with Exposed Endpoints",
                    description=(
                        "SQL injection vulnerability combined with exposed directory listings or "
                        "information disclosure. Attackers can map application structure through "
                        "exposed paths and exploit SQL injection to extract or modify database contents."
                    ),
                    source_findings=(
                        self._get_finding_ids(findings, ["sql injection", "sqli", "injection"]) +
                        self._get_finding_ids(findings, ["directory", "exposed", "information disclosure"])
                    ),
                    correlation_rule="CR-002",
                    confidence_score=0.85,
                    severity=ThreatSeverity.CRITICAL,
                    risk_score=90.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Attacker discovers exposed directories revealing application structure",
                            finding_ids=self._get_finding_ids(findings, ["directory", "exposed"]),
                            severity=ThreatSeverity.MEDIUM,
                        ),
                        AttackChainStep(
                            order=2,
                            description="SQL injection point identified on sensitive endpoint",
                            finding_ids=self._get_finding_ids(findings, ["sql injection", "sqli"]),
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Database contents extracted via crafted SQL payloads",
                            finding_ids=[],
                            severity=ThreatSeverity.CRITICAL,
                        ),
                    ],
                    affected_endpoints=[
                        f.get("affected_url", "") for f in self._get_findings(
                            findings, ["sql injection", "sqli"]
                        )
                    ],
                    tags=["sqli", "data-exfiltration", "database-compromise"],
                ),
            },

            # ─── Rule CR-003: Weak Cookies + Missing HSTS ──────────────
            {
                "id": "CR-003",
                "name": "Session Hijacking via Insecure Transport",
                "condition": lambda findings, stride, ti: (
                    self._has_host_overlap(findings, ["cookie", "session security"], ["hsts", "strict-transport"])
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Session Hijacking via Insecure Cookies + Missing HSTS",
                    description=(
                        "Insecure cookie flags combined with missing HSTS header. "
                        "Attackers on the same network can intercept session cookies via "
                        "protocol downgrade attacks, hijacking authenticated sessions."
                    ),
                    source_findings=(
                        self._get_finding_ids(findings, ["cookie", "session"]) +
                        self._get_finding_ids(findings, ["hsts", "strict-transport"])
                    ),
                    correlation_rule="CR-003",
                    confidence_score=0.8,
                    severity=ThreatSeverity.HIGH,
                    risk_score=78.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Missing HSTS allows HTTP downgrade on first visit",
                            finding_ids=self._get_finding_ids(findings, ["hsts"]),
                            severity=ThreatSeverity.MEDIUM,
                        ),
                        AttackChainStep(
                            order=2,
                            description="Cookies lack Secure/HttpOnly/SameSite flags",
                            finding_ids=self._get_finding_ids(findings, ["cookie"]),
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Attacker intercepts session cookie via MITM on HTTP",
                            finding_ids=[],
                            severity=ThreatSeverity.HIGH,
                        ),
                    ],
                    affected_endpoints=[
                        f.get("affected_url", "") for f in self._get_findings(findings, ["cookie"])
                    ],
                    tags=["session-hijacking", "mitm", "cookie", "hsts"],
                ),
            },

            # ─── Rule CR-004: CORS Misconfiguration + External Domains ──
            {
                "id": "CR-004",
                "name": "Cross-Origin Data Theft via CORS Misconfiguration",
                "condition": lambda findings, stride, ti: (
                    self._has_finding(findings, ["cors", "cross-origin", "api security"])
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Cross-Origin Data Theft via CORS Misconfiguration",
                    description=(
                        "CORS policy is misconfigured (e.g., wildcard or overly permissive origin). "
                        "Malicious websites can make authenticated cross-origin requests to steal "
                        "user data, tokens, or perform actions on behalf of the user."
                    ),
                    source_findings=self._get_finding_ids(findings, ["cors", "cross-origin", "api"]),
                    correlation_rule="CR-004",
                    confidence_score=0.75,
                    severity=ThreatSeverity.HIGH,
                    risk_score=72.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Attacker hosts malicious page with cross-origin fetch",
                            finding_ids=[],
                            severity=ThreatSeverity.LOW,
                        ),
                        AttackChainStep(
                            order=2,
                            description="Permissive CORS allows the request with credentials",
                            finding_ids=self._get_finding_ids(findings, ["cors"]),
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=3,
                            description="User data or auth tokens exfiltrated cross-origin",
                            finding_ids=[],
                            severity=ThreatSeverity.HIGH,
                        ),
                    ],
                    affected_endpoints=[
                        f.get("affected_url", "") for f in self._get_findings(findings, ["cors"])
                    ],
                    tags=["cors", "token-theft", "cross-origin"],
                ),
            },

            # ─── Rule CR-005: Auth Weakness + Directory Exposure ────────
            {
                "id": "CR-005",
                "name": "Unauthorized Access via Weak Auth + Exposed Paths",
                "condition": lambda findings, stride, ti: (
                    self._has_endpoint_overlap(findings, ["auth", "password", "login", "brute", "authentication"], ["directory", "exposed", "admin"])
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Unauthorized Admin Access — Weak Auth + Exposed Paths",
                    description=(
                        "Authentication weaknesses (weak passwords, no rate limiting, no MFA) "
                        "combined with exposed directory listings or admin paths. "
                        "Attackers can discover admin panels and brute-force credentials."
                    ),
                    source_findings=(
                        self._get_finding_ids(findings, ["auth", "password", "login", "brute"]) +
                        self._get_finding_ids(findings, ["directory", "exposed", "admin"])
                    ),
                    correlation_rule="CR-005",
                    confidence_score=0.8,
                    severity=ThreatSeverity.HIGH,
                    risk_score=80.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Exposed directories reveal admin panel or login paths",
                            finding_ids=self._get_finding_ids(findings, ["directory", "admin"]),
                            severity=ThreatSeverity.MEDIUM,
                        ),
                        AttackChainStep(
                            order=2,
                            description="Authentication weakness enables brute-force or bypass",
                            finding_ids=self._get_finding_ids(findings, ["auth", "password"]),
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Attacker gains unauthorized admin-level access",
                            finding_ids=[],
                            severity=ThreatSeverity.CRITICAL,
                        ),
                    ],
                    affected_endpoints=[
                        f.get("affected_url", "") for f in self._get_findings(
                            findings, ["auth", "login", "admin", "directory"]
                        )
                    ],
                    tags=["auth-bypass", "admin-access", "brute-force"],
                ),
            },

            # ─── Rule CR-006: Multiple High-Severity Findings (≥3) ──────
            {
                "id": "CR-006",
                "name": "Critical Attack Surface — Multiple High-Severity Vulnerabilities",
                "condition": lambda findings, stride, ti: (
                    self._has_multiple_high_severity_on_same_host(findings)
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Critical Attack Surface — Multiple High-Severity Vulnerabilities",
                    description=(
                        f"Detected {self._count_severity(findings, ['critical', 'high'])} "
                        f"high or critical severity findings. The combination of multiple severe "
                        f"vulnerabilities creates a broad attack surface where attackers can "
                        f"chain exploits for maximum impact."
                    ),
                    source_findings=[
                        f.get("finding_id") or f.get("id") or "unknown"
                        for f in findings
                        if (f.get("severity") or "").lower() in ("critical", "high")
                    ],
                    correlation_rule="CR-006",
                    confidence_score=0.85,
                    severity=ThreatSeverity.CRITICAL,
                    risk_score=88.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Attacker surveys broad attack surface with multiple high-severity entry points",
                            finding_ids=[],
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=2,
                            description="Exploit chain constructed by combining multiple vulnerabilities",
                            finding_ids=[],
                            severity=ThreatSeverity.CRITICAL,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Full system compromise achieved through chained exploitation",
                            finding_ids=[],
                            severity=ThreatSeverity.CRITICAL,
                        ),
                    ],
                    affected_endpoints=list(set(
                        f.get("affected_url", "") for f in findings
                        if (f.get("severity") or "").lower() in ("critical", "high")
                    )),
                    tags=["multi-vuln", "attack-surface", "exploit-chain"],
                ),
            },

            # ─── Rule CR-007: Clickjacking + Session Weakness ──────────
            {
                "id": "CR-007",
                "name": "Clickjacking-Enabled Session Theft",
                "condition": lambda findings, stride, ti: (
                    self._has_host_overlap(findings, ["x-frame", "clickjack", "frame"], ["cookie", "session"])
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Clickjacking-Enabled Session Theft",
                    description=(
                        "Missing X-Frame-Options header allows the application to be embedded "
                        "in iframes. Combined with insecure session cookies, attackers can trick "
                        "users into performing actions that expose their sessions."
                    ),
                    source_findings=(
                        self._get_finding_ids(findings, ["x-frame", "clickjack"]) +
                        self._get_finding_ids(findings, ["cookie", "session"])
                    ),
                    correlation_rule="CR-007",
                    confidence_score=0.7,
                    severity=ThreatSeverity.MEDIUM,
                    risk_score=58.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Application can be framed due to missing X-Frame-Options",
                            finding_ids=self._get_finding_ids(findings, ["x-frame"]),
                            severity=ThreatSeverity.MEDIUM,
                        ),
                        AttackChainStep(
                            order=2,
                            description="Attacker creates page embedding the target in hidden iframe",
                            finding_ids=[],
                            severity=ThreatSeverity.MEDIUM,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Victim clicks UI elements, unknowingly performing actions",
                            finding_ids=[],
                            severity=ThreatSeverity.HIGH,
                        ),
                    ],
                    affected_endpoints=[
                        f.get("affected_url", "") for f in self._get_findings(findings, ["x-frame"])
                    ],
                    tags=["clickjacking", "session-theft", "ui-redressing"],
                ),
            },

            # ─── Rule CR-008: Injection + Privilege Escalation Context ──
            {
                "id": "CR-008",
                "name": "Privilege Escalation via Injection Vulnerability",
                "condition": lambda findings, stride, ti: (
                    self._has_finding(findings, ["injection", "sqli", "sql injection"]) and
                    stride.get("Elevation of Privilege", 0) > 0
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Privilege Escalation via Injection Vulnerability",
                    description=(
                        "Injection vulnerability detected alongside elevation-of-privilege "
                        "threat indicators. Attackers can use SQL or command injection to "
                        "escalate privileges, access admin functionality, or execute OS commands."
                    ),
                    source_findings=self._get_finding_ids(
                        findings, ["injection", "sqli", "sql injection"]
                    ),
                    correlation_rule="CR-008",
                    confidence_score=0.8,
                    severity=ThreatSeverity.CRITICAL,
                    risk_score=85.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Injection point identified in application input",
                            finding_ids=self._get_finding_ids(findings, ["injection", "sqli"]),
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=2,
                            description="Crafted payload exploits injection to access privileged operations",
                            finding_ids=[],
                            severity=ThreatSeverity.CRITICAL,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Attacker gains elevated privileges or admin access",
                            finding_ids=[],
                            severity=ThreatSeverity.CRITICAL,
                        ),
                    ],
                    affected_endpoints=[
                        f.get("affected_url", "") for f in self._get_findings(
                            findings, ["injection", "sqli"]
                        )
                    ],
                    tags=["privilege-escalation", "injection", "admin-takeover"],
                ),
            },

            # ─── Rule CR-009: Access Control + Cookie Weakness ──────────
            {
                "id": "CR-009",
                "name": "Privilege Escalation via Session + Access Control Weakness",
                "condition": lambda findings, stride, ti: (
                    self._has_host_overlap(findings, ["access control", "authorization", "idor", "bac"], ["cookie", "session"])
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Privilege Escalation via Session + Access Control Weakness",
                    description=(
                        "Broken access control combined with insecure session management. "
                        "Attackers can manipulate session cookies or tokens to access "
                        "resources belonging to other users or escalate to admin roles."
                    ),
                    source_findings=(
                        self._get_finding_ids(findings, ["access control", "authorization", "idor"]) +
                        self._get_finding_ids(findings, ["cookie", "session"])
                    ),
                    correlation_rule="CR-009",
                    confidence_score=0.75,
                    severity=ThreatSeverity.HIGH,
                    risk_score=76.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Insecure cookie configuration allows session manipulation",
                            finding_ids=self._get_finding_ids(findings, ["cookie"]),
                            severity=ThreatSeverity.MEDIUM,
                        ),
                        AttackChainStep(
                            order=2,
                            description="Broken access controls fail to validate user permissions",
                            finding_ids=self._get_finding_ids(findings, ["access control", "idor"]),
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Attacker accesses other users' data or admin resources",
                            finding_ids=[],
                            severity=ThreatSeverity.HIGH,
                        ),
                    ],
                    affected_endpoints=[
                        f.get("affected_url", "") for f in self._get_findings(
                            findings, ["access control", "idor", "bac"]
                        )
                    ],
                    tags=["access-control", "privilege-escalation"],
                ),
            },

            # ─── Rule CR-010: Cascading Misconfigurations (≥4) ──────────
            {
                "id": "CR-010",
                "name": "Defense-in-Depth Failure - Cascading Misconfigurations",
                "condition": lambda findings, stride, ti: (
                    self._has_cascading_misconfigs_on_same_host(findings)
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Defense-in-Depth Failure - Cascading Security Misconfigurations",
                    description=(
                        f"Detected security misconfigurations "
                        f"or missing header findings. This systemic lack of hardening indicates "
                        f"a defense-in-depth failure."
                    ),
                    source_findings=[
                        f.get("finding_id") or f.get("id") or "unknown"
                        for f in findings
                        if any(kw in (f.get("category") or "").lower() or kw in (f.get("title") or "").lower()
                               for kw in ["header", "misconfig", "hardening", "missing"])
                    ],
                    correlation_rule="CR-010",
                    confidence_score=0.85,
                    severity=ThreatSeverity.HIGH,
                    risk_score=70.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="Multiple security headers and configurations are missing",
                            finding_ids=[],
                            severity=ThreatSeverity.MEDIUM,
                        ),
                    ],
                    affected_endpoints=list(set(
                        f.get("affected_url", "") for f in findings
                        if any(kw in (f.get("category") or "").lower()
                               for kw in ["header", "misconfig", "hardening"])
                    )),
                    tags=["misconfiguration", "hardening", "defense-in-depth"],
                ),
            },

            # ─── Rule CR-011: Client-Side Compromise Chain ──
            {
                "id": "CR-011",
                "name": "Client-Side Compromise Chain",
                "condition": lambda findings, stride, ti: (
                    self._has_host_overlap(findings, ["xss", "cross-site scripting"], ["csp", "content-security-policy"]) and
                    any(t.get("vt_status") == "malicious" for t in (ti or []))
                ),
                "generate": lambda findings, inv_id, ti: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Client-Side Compromise Chain (Malicious JS + XSS + Missing CSP)",
                    description=(
                        "A critical threat chain identified where XSS vulnerabilities are exposed "
                        "with no Content-Security-Policy restrictions, while external resources "
                        "or domains loaded by the application are actively flagged by threat "
                        "intelligence as malicious."
                    ),
                    source_findings=(
                        self._get_finding_ids(findings, ["xss", "cross-site scripting"]) +
                        self._get_finding_ids(findings, ["csp", "content-security-policy"]) +
                        [t.get("finding_id") for t in (ti or []) if t.get("finding_id") and t.get("vt_status") == "malicious"]
                    ),
                    correlation_rule="CR-011",
                    confidence_score=0.95,
                    severity=ThreatSeverity.CRITICAL,
                    risk_score=98.0,
                    attack_chain=[
                        AttackChainStep(
                            order=1,
                            description="External domain or script loaded by the application is flagged as malicious by Threat Intelligence",
                            finding_ids=[t.get("finding_id") for t in (ti or []) if t.get("finding_id") and t.get("vt_status") == "malicious"],
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=2,
                            description="Lack of Content-Security-Policy (CSP) allows browser to load and run scripts from unauthorized external origins",
                            finding_ids=self._get_finding_ids(findings, ["csp"]),
                            severity=ThreatSeverity.MEDIUM,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Attacker chains with XSS vulnerability to execute high-privilege scripts",
                            finding_ids=self._get_finding_ids(findings, ["xss"]),
                            severity=ThreatSeverity.HIGH,
                        ),
                    ],
                    affected_endpoints=list(set(
                        [f.get("affected_url", "") for f in self._get_findings(findings, ["xss"])] +
                        [t.get("ioc") for t in (ti or []) if t.get("ioc") and t.get("vt_status") == "malicious"]
                    )),
                    tags=["client-side-compromise", "xss", "csp-bypass", "threat-intel"],
                ),
            },
        ]
