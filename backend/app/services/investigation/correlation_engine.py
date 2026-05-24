"""
Stage 4 — Threat Correlation Engine.

Analyzes cross-stage outputs (findings, context, IOC data) to identify
compound threats, build attack chains, and compute a global risk score.

Integrated into the investigation orchestrator pipeline.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from app.schemas.stage_outputs import (
    CorrelationStageOutput,
    CorrelatedThreat,
    AttackChainStep,
    ThreatSeverity,
)

logger = logging.getLogger(__name__)


class ThreatCorrelationEngine:
    """
    Rule-based correlation engine that cross-references pentest findings,
    threat context categories, and normalized data to identify compound threats.
    """

    def __init__(self):
        self._rules = self._build_rules()

    async def correlate(
        self,
        investigation_id: str,
        findings: List[Dict[str, Any]],
        risk_score: float,
        stride_summary: Dict[str, int],
        ti_reports: List[Dict[str, Any]],
    ) -> CorrelationStageOutput:
        """
        Main correlation entry point.

        Args:
            investigation_id: The investigation ID.
            findings: List of normalized finding dicts from the DB.
            risk_score: The pentest risk score.
            stride_summary: STRIDE category counts from TM report.
            ti_reports: Threat intelligence reports.

        Returns:
            CorrelationStageOutput with correlated threats and global risk.
        """
        started_at = datetime.utcnow()
        logger.info(
            "[CORRELATION] Starting correlation for investigation %s with %d findings",
            investigation_id, len(findings)
        )

        correlated_threats: List[CorrelatedThreat] = []
        seen_rule_ids: set = set()

        # Run each correlation rule against the findings
        for rule in self._rules:
            rule_id = rule["id"]
            try:
                if rule["condition"](findings, stride_summary, ti_reports):
                    if rule_id not in seen_rule_ids:
                        threat = rule["generate"](findings, investigation_id)
                        correlated_threats.append(threat)
                        seen_rule_ids.add(rule_id)
                        logger.info("[CORRELATION] Rule %s fired: %s", rule_id, threat.title)
            except Exception as e:
                logger.warning("[CORRELATION] Rule %s failed: %s", rule_id, str(e))
                continue

        # Deduplicate threats by title similarity
        correlated_threats = self._deduplicate(correlated_threats)

        # Compute global risk score
        escalation_bonus = min(100.0, len(correlated_threats) * 12.0)
        global_risk = self._compute_global_risk(risk_score, escalation_bonus)

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
        )

        logger.info(
            "[CORRELATION] Completed: %d correlated threats, global risk=%.1f",
            len(correlated_threats), global_risk
        )
        return output

    # ── Risk score computation ──────────────────────────────────────

    def _compute_global_risk(self, pentest_risk: float, escalation_bonus: float) -> float:
        """
        Compute global risk score. The correlation engine can only ESCALATE
        risk, never reduce it below the original pentest score.
        - Base = pentest risk score (always preserved)
        - Bonus = escalation from correlated threats (additive, capped at 100)
        """
        escalated = pentest_risk + (escalation_bonus * 0.40)
        return min(100.0, round(escalated, 1))

    def _build_risk_summary(
        self, threats: List[CorrelatedThreat], global_risk: float
    ) -> Dict[str, Any]:
        """Build a summary breakdown of risk categories."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for t in threats:
            sev = t.severity.value if isinstance(t.severity, ThreatSeverity) else str(t.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

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

    # ── Correlation Rules ──────────────────────────────────────────

    def _build_rules(self) -> List[Dict[str, Any]]:
        """
        Build the list of correlation rules. Each rule has:
        - id: unique rule identifier
        - name: human-readable name
        - condition: function(findings, stride, ti_reports) -> bool
        - generate: function(findings, investigation_id) -> CorrelatedThreat
        """
        return [
            # ─── Rule CR-001: XSS + Missing CSP Header ─────────────────
            # When XSS is found AND CSP header is missing, scripts can execute
            # without restriction, amplifying the XSS risk to critical.
            {
                "id": "CR-001",
                "name": "Unprotected XSS Exploitation",
                "condition": lambda findings, stride, ti: (
                    self._has_finding(findings, ["xss", "cross-site scripting"]) and
                    self._has_finding(findings, ["csp", "content-security-policy", "content security policy"])
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
            # SQL injection combined with exposed sensitive endpoints
            # (directory exposure, admin paths) enables database compromise.
            {
                "id": "CR-002",
                "name": "Database Compromise via SQLi + Exposed Endpoints",
                "condition": lambda findings, stride, ti: (
                    self._has_finding(findings, ["sql injection", "sqli", "injection vulnerability"]) and
                    self._has_finding(findings, ["directory", "exposed", "information disclosure"])
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
            # Insecure cookies combined with no HSTS allows session hijacking
            # via man-in-the-middle attacks on downgraded HTTP connections.
            {
                "id": "CR-003",
                "name": "Session Hijacking via Insecure Transport",
                "condition": lambda findings, stride, ti: (
                    self._has_finding(findings, ["cookie", "session security"]) and
                    self._has_finding(findings, ["hsts", "strict-transport"])
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
            # Open CORS combined with numerous external domains enables
            # cross-origin data theft from untrusted origins.
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
            # Weak authentication combined with exposed admin/sensitive paths
            # enables unauthorized access to privileged resources.
            {
                "id": "CR-005",
                "name": "Unauthorized Access via Weak Auth + Exposed Paths",
                "condition": lambda findings, stride, ti: (
                    self._has_finding(findings, ["auth", "password", "login", "brute", "authentication"]) and
                    self._has_finding(findings, ["directory", "exposed", "admin"])
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
            # Three or more critical/high findings indicate a broad attack
            # surface requiring immediate attention.
            {
                "id": "CR-006",
                "name": "Critical Attack Surface — Multiple High-Severity Vulnerabilities",
                "condition": lambda findings, stride, ti: (
                    self._count_severity(findings, ["critical", "high"]) >= 3
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
            # Missing X-Frame-Options combined with session cookie issues
            # enables clickjacking attacks that steal sessions.
            {
                "id": "CR-007",
                "name": "Clickjacking-Enabled Session Theft",
                "condition": lambda findings, stride, ti: (
                    self._has_finding(findings, ["x-frame", "clickjack", "frame"]) and
                    self._has_finding(findings, ["cookie", "session"])
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
            # Any injection vulnerability combined with STRIDE elevation indicators
            # suggests privilege escalation risk.
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
            # Broken access control combined with insecure cookies enables
            # session fixation or privilege escalation attacks.
            {
                "id": "CR-009",
                "name": "Privilege Escalation via Session + Access Control Weakness",
                "condition": lambda findings, stride, ti: (
                    self._has_finding(findings, ["access control", "authorization", "idor", "bac"]) and
                    self._has_finding(findings, ["cookie", "session"])
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
                    tags=["access-control", "session-fixation", "privilege-escalation"],
                ),
            },

            # ─── Rule CR-010: Cascading Misconfigurations (≥5) ──────────
            # Five or more misconfiguration/header findings indicate a systemic
            # failure in security hardening (defense-in-depth breakdown).
            {
                "id": "CR-010",
                "name": "Defense-in-Depth Failure — Cascading Misconfigurations",
                "condition": lambda findings, stride, ti: (
                    self._count_misconfigs(findings) >= 5
                ),
                "generate": lambda findings, inv_id: CorrelatedThreat(
                    threat_id=self._make_threat_id(),
                    title="Defense-in-Depth Failure — Cascading Security Misconfigurations",
                    description=(
                        f"Detected {self._count_misconfigs(findings)} security misconfiguration "
                        f"or missing header findings. This systemic lack of hardening indicates "
                        f"a defense-in-depth failure where no single control compensates for "
                        f"missing protections, creating cumulative risk."
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
                        AttackChainStep(
                            order=2,
                            description="No defense-in-depth: each missing control amplifies others",
                            finding_ids=[],
                            severity=ThreatSeverity.HIGH,
                        ),
                        AttackChainStep(
                            order=3,
                            description="Attacker exploits weakest link in unhardened stack",
                            finding_ids=[],
                            severity=ThreatSeverity.HIGH,
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
        ]

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
