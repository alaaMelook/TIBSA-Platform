"""
Stage 5 — Automated STRIDE Threat Modeler.

Automatically generates STRIDE threat models from investigation findings,
context categories, and correlated threats. Maps each finding to one or
more STRIDE categories with attack scenarios and mitigations.

Integrated into the investigation orchestrator pipeline.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

from app.schemas.stage_outputs import (
    STRIDEStageOutput,
    STRIDEThreat,
    STRIDEMatrix,
    STRIDEType,
    ThreatSeverity,
)

logger = logging.getLogger(__name__)


# ── Finding-to-STRIDE Mapping Table ──────────────────────────────────────────
# Each entry maps a keyword (found in finding category/title) to one or more
# STRIDE categories, along with a template attack scenario and mitigations.

STRIDE_MAPPINGS: List[Dict[str, Any]] = [
    # XSS → Tampering + Information Disclosure
    {
        "keywords": ["xss", "cross-site scripting", "client-side security"],
        "categories": [STRIDEType.TAMPERING, STRIDEType.INFORMATION_DISCLOSURE],
        "scenario_template": (
            "Attacker injects malicious scripts via {asset}. "
            "Tampering: page content and behavior are modified client-side. "
            "Information Disclosure: session tokens, cookies, or user data are exfiltrated."
        ),
        "mitigations": [
            "Implement Content-Security-Policy (CSP) header with strict directives",
            "Apply context-aware output encoding on all user-controlled data",
            "Use HttpOnly and Secure flags on session cookies",
            "Sanitize all user input on both client and server side",
        ],
        "severity": ThreatSeverity.HIGH,
        "likelihood": ThreatSeverity.HIGH,
    },
    # SQLi → Tampering + Elevation of Privilege
    {
        "keywords": ["sqli", "sql injection", "injection vulnerability"],
        "categories": [STRIDEType.TAMPERING, STRIDEType.ELEVATION_OF_PRIVILEGE],
        "scenario_template": (
            "Attacker exploits SQL injection on {asset} to read, modify, or delete "
            "database records. Tampering: data integrity compromised. "
            "Elevation of Privilege: attacker may gain admin-level database access."
        ),
        "mitigations": [
            "Use parameterized queries or ORM frameworks exclusively",
            "Implement input validation with strict allowlisting",
            "Apply least-privilege database user permissions",
            "Enable SQL query logging and anomaly detection",
        ],
        "severity": ThreatSeverity.CRITICAL,
        "likelihood": ThreatSeverity.HIGH,
    },
    # Weak Authentication → Spoofing
    {
        "keywords": ["auth", "password", "login", "brute", "authentication security"],
        "categories": [STRIDEType.SPOOFING],
        "scenario_template": (
            "Attacker exploits weak authentication on {asset} to impersonate "
            "legitimate users. Spoofing: identity verification is bypassed through "
            "credential stuffing, brute force, or default credentials."
        ),
        "mitigations": [
            "Implement multi-factor authentication (MFA)",
            "Enforce strong password policies with complexity requirements",
            "Add rate limiting and account lockout on login endpoints",
            "Use CAPTCHA to prevent automated attacks",
        ],
        "severity": ThreatSeverity.HIGH,
        "likelihood": ThreatSeverity.MEDIUM,
    },
    # Missing Security Headers → Information Disclosure
    {
        "keywords": ["header", "hsts", "x-frame", "csp", "hardening"],
        "categories": [STRIDEType.INFORMATION_DISCLOSURE],
        "scenario_template": (
            "Missing security headers on {asset} expose the application to various "
            "attacks. Information Disclosure: internal server details, technology stack, "
            "or sensitive data may leak through unprotected responses."
        ),
        "mitigations": [
            "Configure all recommended security headers (CSP, HSTS, X-Frame-Options, etc.)",
            "Remove server version and technology disclosure headers",
            "Implement X-Content-Type-Options: nosniff",
            "Enable Referrer-Policy to prevent information leakage",
        ],
        "severity": ThreatSeverity.MEDIUM,
        "likelihood": ThreatSeverity.HIGH,
    },
    # Cookie Issues → Spoofing + Information Disclosure
    {
        "keywords": ["cookie", "session security"],
        "categories": [STRIDEType.SPOOFING, STRIDEType.INFORMATION_DISCLOSURE],
        "scenario_template": (
            "Insecure cookie configuration on {asset} enables session theft. "
            "Spoofing: stolen session cookies allow identity impersonation. "
            "Information Disclosure: cookie values transmitted in clear text."
        ),
        "mitigations": [
            "Set Secure flag on all cookies to prevent HTTP transmission",
            "Set HttpOnly flag to prevent JavaScript access",
            "Set SameSite=Strict or Lax to mitigate CSRF",
            "Implement session rotation on authentication state changes",
        ],
        "severity": ThreatSeverity.MEDIUM,
        "likelihood": ThreatSeverity.MEDIUM,
    },
    # CORS → Information Disclosure + Tampering
    {
        "keywords": ["cors", "cross-origin", "api security"],
        "categories": [STRIDEType.INFORMATION_DISCLOSURE, STRIDEType.TAMPERING],
        "scenario_template": (
            "CORS misconfiguration on {asset} allows unauthorized cross-origin access. "
            "Information Disclosure: sensitive API data leaked to attacker domains. "
            "Tampering: unauthorized cross-origin requests modify server state."
        ),
        "mitigations": [
            "Restrict Access-Control-Allow-Origin to specific trusted domains",
            "Never use wildcard (*) with credentials",
            "Validate Origin header server-side",
            "Implement CSRF tokens for state-changing operations",
        ],
        "severity": ThreatSeverity.HIGH,
        "likelihood": ThreatSeverity.MEDIUM,
    },
    # Directory Exposure → Information Disclosure
    {
        "keywords": ["directory", "exposed", "path traversal"],
        "categories": [STRIDEType.INFORMATION_DISCLOSURE],
        "scenario_template": (
            "Exposed directories or path traversal on {asset} reveals internal "
            "application structure, source code, configuration files, or backup data "
            "to unauthorized users."
        ),
        "mitigations": [
            "Disable directory listing on the web server",
            "Remove backup files and development artifacts from production",
            "Implement proper access controls on all directories",
            "Use a web application firewall (WAF) to block path traversal",
        ],
        "severity": ThreatSeverity.MEDIUM,
        "likelihood": ThreatSeverity.HIGH,
    },
    # Misconfiguration → Information Disclosure + Denial of Service
    {
        "keywords": ["misconfig", "misconfiguration"],
        "categories": [STRIDEType.INFORMATION_DISCLOSURE, STRIDEType.DENIAL_OF_SERVICE],
        "scenario_template": (
            "Server misconfiguration on {asset} exposes internal details and may "
            "create denial-of-service vectors. Information Disclosure: verbose error "
            "messages reveal stack traces. DoS: misconfigs may allow resource exhaustion."
        ),
        "mitigations": [
            "Disable verbose error pages in production",
            "Follow security hardening benchmarks (CIS, OWASP)",
            "Implement resource limits and rate limiting",
            "Conduct regular configuration audits",
        ],
        "severity": ThreatSeverity.MEDIUM,
        "likelihood": ThreatSeverity.MEDIUM,
    },
    # Access Control → Elevation of Privilege + Repudiation
    {
        "keywords": ["access control", "authorization", "idor", "bac", "privilege"],
        "categories": [STRIDEType.ELEVATION_OF_PRIVILEGE, STRIDEType.REPUDIATION],
        "scenario_template": (
            "Broken access control on {asset} allows users to access resources "
            "beyond their authorization. Elevation: normal users access admin functions. "
            "Repudiation: lack of audit trails makes actions unattributable."
        ),
        "mitigations": [
            "Implement role-based access control (RBAC) with least privilege",
            "Validate authorization server-side for every request",
            "Implement comprehensive audit logging",
            "Use indirect object references instead of direct IDs",
        ],
        "severity": ThreatSeverity.HIGH,
        "likelihood": ThreatSeverity.HIGH,
    },
]


class AutomatedSTRIDEModeler:
    """
    Automated STRIDE threat modeler that generates structured threat models
    from investigation findings.
    """

    def __init__(self):
        self._mappings = STRIDE_MAPPINGS

    async def model(
        self,
        investigation_id: str,
        findings: List[Dict[str, Any]],
        correlated_threats: List[Dict[str, Any]],
    ) -> STRIDEStageOutput:
        """
        Generate STRIDE threat model from investigation findings.

        Args:
            investigation_id: The investigation ID.
            findings: List of normalized finding dicts from the DB.
            correlated_threats: List of correlated threat dicts from Stage 4.

        Returns:
            STRIDEStageOutput with STRIDE threats and matrix.
        """
        started_at = datetime.utcnow()
        logger.info(
            "[STRIDE] Starting threat modeling for investigation %s with %d findings",
            investigation_id, len(findings)
        )

        stride_threats: List[STRIDEThreat] = []
        processed_findings: set = set()

        # Generate STRIDE threats from each finding
        for finding in findings:
            finding_id = finding.get("finding_id") or finding.get("id") or "unknown"

            # Skip if already processed (dedup)
            if finding_id in processed_findings:
                continue
            processed_findings.add(finding_id)

            # Match finding against STRIDE mappings
            matched_mappings = self._match_finding(finding)

            for mapping in matched_mappings:
                for stride_category in mapping["categories"]:
                    threat = self._create_stride_threat(
                        finding=finding,
                        category=stride_category,
                        mapping=mapping,
                    )
                    stride_threats.append(threat)

        # Add threats from correlated threat analysis
        for corr in correlated_threats:
            stride_threats.extend(self._threats_from_correlation(corr))

        # Remove duplicate STRIDE threats (same category + same asset)
        stride_threats = self._deduplicate_stride(stride_threats)

        # Build the STRIDE matrix summary
        matrix = self._build_matrix(stride_threats)

        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()

        output = STRIDEStageOutput(
            investigation_id=investigation_id,
            stride_threats=stride_threats,
            stride_matrix=matrix,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=round(duration, 2),
        )

        logger.info(
            "[STRIDE] Completed: %d threats, matrix total=%d",
            len(stride_threats), matrix.total_threats()
        )
        return output

    # ── Finding-to-STRIDE matching ─────────────────────────────────

    def _match_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find all STRIDE mappings that match a given finding."""
        cat = (finding.get("category") or "").lower()
        title = (finding.get("title") or "").lower()
        matched = []

        for mapping in self._mappings:
            for keyword in mapping["keywords"]:
                if keyword in cat or keyword in title:
                    matched.append(mapping)
                    break  # Don't double-match same mapping

        # If no specific mapping matched, assign a default Information Disclosure
        if not matched:
            matched.append({
                "keywords": [],
                "categories": [STRIDEType.INFORMATION_DISCLOSURE],
                "scenario_template": (
                    "Security finding on {asset} may lead to information disclosure. "
                    "Review and apply appropriate security controls."
                ),
                "mitigations": [
                    "Review and remediate according to security best practices",
                    "Conduct a detailed manual security assessment",
                ],
                "severity": ThreatSeverity.LOW,
                "likelihood": ThreatSeverity.LOW,
            })

        return matched

    def _create_stride_threat(
        self,
        finding: Dict[str, Any],
        category: STRIDEType,
        mapping: Dict[str, Any],
    ) -> STRIDEThreat:
        """Create a single STRIDEThreat from a finding and mapping."""
        asset = finding.get("affected_url") or finding.get("url") or "the target application"
        finding_title = finding.get("title") or "Unknown Finding"
        finding_id = finding.get("finding_id") or finding.get("id") or "unknown"
        finding_severity = (finding.get("severity") or "medium").lower()

        # Determine severity — use the higher of finding severity and mapping severity
        severity = self._resolve_severity(finding_severity, mapping["severity"])
        likelihood = mapping.get("likelihood", ThreatSeverity.MEDIUM)

        return STRIDEThreat(
            stride_id=f"ST-{uuid.uuid4().hex[:8]}",
            category=category,
            affected_asset=asset,
            attack_scenario=mapping["scenario_template"].format(asset=asset),
            severity=severity,
            likelihood=likelihood,
            mitigations=mapping["mitigations"],
            related_findings=[finding_id],
        )

    # ── Correlation-based STRIDE threats ───────────────────────────

    def _threats_from_correlation(self, correlated: Dict[str, Any]) -> List[STRIDEThreat]:
        """Generate additional STRIDE threats from correlated threat data."""
        threats = []
        rule_id = correlated.get("correlation_rule", "")
        title = correlated.get("title", "")
        severity_str = correlated.get("severity", "high")

        # Map correlation rules to STRIDE categories
        corr_stride_map = {
            "CR-001": [STRIDEType.TAMPERING, STRIDEType.INFORMATION_DISCLOSURE],  # XSS+CSP
            "CR-002": [STRIDEType.TAMPERING, STRIDEType.ELEVATION_OF_PRIVILEGE],  # SQLi+exposure
            "CR-003": [STRIDEType.SPOOFING, STRIDEType.INFORMATION_DISCLOSURE],  # Cookie+HSTS
            "CR-004": [STRIDEType.INFORMATION_DISCLOSURE, STRIDEType.TAMPERING],  # CORS
            "CR-005": [STRIDEType.SPOOFING, STRIDEType.ELEVATION_OF_PRIVILEGE],  # Auth+directory
            "CR-006": [STRIDEType.TAMPERING],  # Multi high-severity
            "CR-007": [STRIDEType.TAMPERING, STRIDEType.SPOOFING],  # Clickjacking
            "CR-008": [STRIDEType.ELEVATION_OF_PRIVILEGE],  # Injection+privesc
            "CR-009": [STRIDEType.ELEVATION_OF_PRIVILEGE, STRIDEType.REPUDIATION],  # Access control
            "CR-010": [STRIDEType.INFORMATION_DISCLOSURE, STRIDEType.DENIAL_OF_SERVICE],  # Misconfig
        }

        categories = corr_stride_map.get(rule_id, [STRIDEType.INFORMATION_DISCLOSURE])
        severity = self._str_to_severity(severity_str)

        for category in categories:
            threats.append(STRIDEThreat(
                stride_id=f"ST-{uuid.uuid4().hex[:8]}",
                category=category,
                affected_asset="Multiple correlated endpoints",
                attack_scenario=f"Correlated threat: {title}. "
                                f"Cross-stage analysis identified compound risk affecting "
                                f"multiple assets under the {category.value} STRIDE category.",
                severity=severity,
                likelihood=ThreatSeverity.MEDIUM,
                mitigations=[
                    f"Address all findings contributing to: {title}",
                    "Implement defense-in-depth controls across affected components",
                    "Conduct focused penetration testing on correlated attack paths",
                ],
                related_findings=correlated.get("source_findings", []),
            ))

        return threats

    # ── Matrix building ────────────────────────────────────────────

    @staticmethod
    def _build_matrix(threats: List[STRIDEThreat]) -> STRIDEMatrix:
        """Count threats per STRIDE category into a matrix."""
        counts = {
            STRIDEType.SPOOFING: 0,
            STRIDEType.TAMPERING: 0,
            STRIDEType.REPUDIATION: 0,
            STRIDEType.INFORMATION_DISCLOSURE: 0,
            STRIDEType.DENIAL_OF_SERVICE: 0,
            STRIDEType.ELEVATION_OF_PRIVILEGE: 0,
        }
        for t in threats:
            if t.category in counts:
                counts[t.category] += 1

        return STRIDEMatrix(
            spoofing_count=counts[STRIDEType.SPOOFING],
            tampering_count=counts[STRIDEType.TAMPERING],
            repudiation_count=counts[STRIDEType.REPUDIATION],
            information_disclosure_count=counts[STRIDEType.INFORMATION_DISCLOSURE],
            denial_of_service_count=counts[STRIDEType.DENIAL_OF_SERVICE],
            elevation_of_privilege_count=counts[STRIDEType.ELEVATION_OF_PRIVILEGE],
        )

    # ── Deduplication ──────────────────────────────────────────────

    @staticmethod
    def _deduplicate_stride(threats: List[STRIDEThreat]) -> List[STRIDEThreat]:
        """Remove duplicate STRIDE threats (same category + same asset)."""
        seen: set = set()
        unique: List[STRIDEThreat] = []
        for t in threats:
            key = f"{t.category.value}|{t.affected_asset}"
            if key not in seen:
                seen.add(key)
                unique.append(t)
        return unique

    # ── Severity helpers ───────────────────────────────────────────

    @staticmethod
    def _resolve_severity(finding_sev: str, mapping_sev: ThreatSeverity) -> ThreatSeverity:
        """Return the higher severity between finding and mapping."""
        order = {
            ThreatSeverity.INFO: 0,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4,
        }
        finding_enum = AutomatedSTRIDEModeler._str_to_severity(finding_sev)
        if order.get(finding_enum, 0) > order.get(mapping_sev, 0):
            return finding_enum
        return mapping_sev

    @staticmethod
    def _str_to_severity(s: str) -> ThreatSeverity:
        """Convert a string severity to ThreatSeverity enum."""
        mapping = {
            "critical": ThreatSeverity.CRITICAL,
            "high": ThreatSeverity.HIGH,
            "medium": ThreatSeverity.MEDIUM,
            "low": ThreatSeverity.LOW,
            "info": ThreatSeverity.INFO,
        }
        return mapping.get(s.lower().strip(), ThreatSeverity.MEDIUM)
