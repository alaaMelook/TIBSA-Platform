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
import re
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
        "attack_prerequisites": "Application must accept and output user input without proper escaping or have lax CSP configuration.",
        "business_impact": "Session hijacking, credential theft, unauthorized client actions, and defacement of the application.",
        "detection_recommendations": [
            "Monitor for script tags in query strings or post payloads",
            "Implement Web Application Firewall (WAF) rule filters"
        ]
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
        "attack_prerequisites": "Application accepts database parameters in queries without parameterization or escaping.",
        "business_impact": "Full disclosure of database tables, unauthorized modifications, potential administrative bypass, and data leakage.",
        "detection_recommendations": [
            "Enable query sanitization logs",
            "Audit database access logs for high-frequency queries",
            "Use WAF rules for SQL syntax keywords"
        ]
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
        "attack_prerequisites": "Login endpoints permit brute-force attempts without rate limiting, or enforce weak password policies.",
        "business_impact": "Account takeover, unauthorized access to user accounts, and credentials abuse.",
        "detection_recommendations": [
            "Monitor for high-frequency login failures from single IP or user account",
            "Alert on logins from unusual locations"
        ]
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
        "attack_prerequisites": "Missing security control configurations in server or proxy response configurations.",
        "business_impact": "Enables secondary attacks like MITM, Clickjacking, MIME sniffing, and browser-based exploits.",
        "detection_recommendations": [
            "Automate security header configuration checks in deployment pipelines"
        ]
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
        "attack_prerequisites": "Session cookies are transmitted over plaintext HTTP or do not restrict client-side scripting access.",
        "business_impact": "Intercepted session tokens, session takeover, and cross-site request forgery attacks.",
        "detection_recommendations": [
            "Audit cookie flags in backend HTTP response headers",
            "Alert on cookie usage from multiple IPs in short timeframes"
        ]
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
        "attack_prerequisites": "CORS configuration permits wildcard or dynamic reflecting of untrusted origins with credentials enabled.",
        "business_impact": "Unauthorized reading of private user API data by malicious third-party origins.",
        "detection_recommendations": [
            "Monitor CORS Access-Control-Allow-Origin configurations in router rules",
            "Log and flag mismatching origins"
        ]
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
        "attack_prerequisites": "Directory listing enabled on the server or backup files/artifacts left in the web root.",
        "business_impact": "Exposure of server configuration, source files, database credentials, and path mappings.",
        "detection_recommendations": [
            "Scan web root for leftover backup extensions (.bak, .old, .zip)",
            "Monitor directory enumeration attempts"
        ]
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
        "attack_prerequisites": "Unnecessary system features enabled, default configurations used, or verbose error logging in production.",
        "business_impact": "Unintended system behavior, resource leakages, stack trace leaks revealing code structure.",
        "detection_recommendations": [
            "Audit container configuration files",
            "Monitor server response codes and logs for excessive 5xx errors"
        ]
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
        "attack_prerequisites": "Endpoints fail to validate relationship between session and object ID, or lack permission checks.",
        "business_impact": "Privilege escalation, unauthorized data viewing or deletion, and business logic bypass.",
        "detection_recommendations": [
            "Trace object ID access logs for anomalies",
            "Implement regression tests for privilege boundary checks"
        ]
    },
]


class AutomatedSTRIDEModeler:
    """
    Automated STRIDE threat modeler that generates structured threat models
    from investigation findings.
    """

    def __init__(self):
        self._mappings = STRIDE_MAPPINGS

    def _get_allowed_stride_categories(self, finding: Dict[str, Any]) -> List[STRIDEType]:
        title_lower = (finding.get("title") or "").lower()
        cat_lower = (finding.get("category") or "").lower()
        
        # 1. SQL Injection / Injection
        if "sqli" in title_lower or "sql injection" in title_lower or "injection" in title_lower or "injection" in cat_lower:
            return [STRIDEType.TAMPERING, STRIDEType.ELEVATION_OF_PRIVILEGE, STRIDEType.INFORMATION_DISCLOSURE]

        # 2. XSS Findings
        if "xss" in title_lower or "cross-site scripting" in title_lower:
            return [STRIDEType.TAMPERING, STRIDEType.INFORMATION_DISCLOSURE]

        # 3. SSRF Findings
        if "ssrf" in title_lower or "server-side request forgery" in title_lower:
            return [STRIDEType.INFORMATION_DISCLOSURE, STRIDEType.ELEVATION_OF_PRIVILEGE]

        # 4. CSRF Findings
        if "csrf" in title_lower or "cross-site request forgery" in title_lower:
            return [STRIDEType.TAMPERING]

        # 5. CORS Findings
        if "cors" in title_lower or "cors" in cat_lower:
            return [STRIDEType.INFORMATION_DISCLOSURE, STRIDEType.TAMPERING]

        # 6. Upload Exposure
        if "upload" in title_lower or "upload" in cat_lower:
            return [STRIDEType.INFORMATION_DISCLOSURE, STRIDEType.ELEVATION_OF_PRIVILEGE]

        # 7. Directory Listing
        if "directory listing" in title_lower or "dir_listing" in title_lower or "index of" in title_lower:
            return [STRIDEType.INFORMATION_DISCLOSURE]

        # 8. Robots.txt
        if "robots.txt" in title_lower:
            return [STRIDEType.INFORMATION_DISCLOSURE]

        # 9. CSP Findings
        if "csp" in title_lower or "content-security-policy" in title_lower or "content security policy" in title_lower:
            return [STRIDEType.TAMPERING, STRIDEType.INFORMATION_DISCLOSURE]

        # 10. Clickjacking
        if "clickjacking" in title_lower or "x-frame-options" in title_lower or "frame-ancestors" in title_lower:
            return [STRIDEType.SPOOFING, STRIDEType.TAMPERING]

        # 11. Missing HSTS
        if "hsts" in title_lower or "strict-transport-security" in title_lower or "strict transport security" in title_lower:
            return [STRIDEType.INFORMATION_DISCLOSURE]

        # 12. Cookie Findings
        if "cookie" in title_lower or "cookie" in cat_lower:
            return [STRIDEType.SPOOFING, STRIDEType.INFORMATION_DISCLOSURE]

        # 13. Authorization / Access Control / IDOR
        if any(kw in title_lower or kw in cat_lower for kw in ["authorization", "authz", "privilege", "idor", "bac", "access control"]):
            return [STRIDEType.ELEVATION_OF_PRIVILEGE]

        # 14. Authentication Weakness
        if any(kw in title_lower or kw in cat_lower for kw in ["auth", "login", "password", "brute", "mfa", "authentication"]):
            return [STRIDEType.SPOOFING]

        # 15. General Headers / Hardening
        if "header" in title_lower or "header" in cat_lower or "hardening" in title_lower or "hardening" in cat_lower:
            return [STRIDEType.INFORMATION_DISCLOSURE]

        # 16. Exposed Configuration Files
        if any(kw in title_lower or kw in cat_lower for kw in ["exposed file", "configuration file", ".env", ".git", "config.php", "phpinfo", "dump.sql"]):
            return [STRIDEType.INFORMATION_DISCLOSURE]
            
        return []

    async def model(
        self,
        investigation_id: str,
        findings: List[Dict[str, Any]],
        correlated_threats: List[Dict[str, Any]],
    ) -> STRIDEStageOutput:
        """
        Generate STRIDE threat model from investigation findings.
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
                allowed_cats = self._get_allowed_stride_categories(finding)
                target_cats = [c for c in mapping["categories"] if c in allowed_cats]

                for stride_category in target_cats:
                    threat = self._create_stride_threat(
                        finding=finding,
                        category=stride_category,
                        mapping=mapping,
                    )
                    # Sanitize exaggerated claims dynamically
                    threat = self._sanitize_stride_threat(threat, findings)
                    stride_threats.append(threat)

        # Add threats from correlated threat analysis
        for corr in correlated_threats:
            corr_threats = self._threats_from_correlation(corr, findings)
            for t in corr_threats:
                t = self._sanitize_stride_threat(t, findings)
                stride_threats.append(t)

        # Remove duplicate STRIDE threats (same category + same asset) and merge them
        stride_threats = self._deduplicate_stride(stride_threats, findings)

        # Sort threats deterministically by (category.value, affected_asset, severity)
        stride_threats = sorted(
            stride_threats,
            key=lambda x: (
                x.category.value if hasattr(x.category, "value") else str(x.category),
                x.affected_asset or "",
                x.severity.value if hasattr(x.severity, "value") else str(x.severity),
                x.stride_id or ""
            )
        )

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
                "attack_prerequisites": "Standard system operation with lack of protective configuration.",
                "business_impact": "Exposure of passive application parameters or environment metadata.",
                "detection_recommendations": ["Conduct automated baseline scanning daily."]
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
        finding_id = finding.get("finding_id") or finding.get("id") or "unknown"
        finding_severity = (finding.get("severity") or "medium").lower()

        # Determine severity — use the higher of finding severity and mapping severity
        severity = self._resolve_severity(finding_severity, mapping["severity"])
        likelihood = mapping.get("likelihood", ThreatSeverity.MEDIUM)

        # Dynamic priority based on severity
        priority_map = {
            ThreatSeverity.CRITICAL: "Critical",
            ThreatSeverity.HIGH: "High",
            ThreatSeverity.MEDIUM: "Medium",
            ThreatSeverity.LOW: "Low",
            ThreatSeverity.INFO: "Low"
        }
        priority = priority_map.get(severity, "Medium")

        finding_cat = finding.get("category") or "Unknown"
        finding_ev = finding.get("evidence") or "No direct evidence provided"

        scenario = mapping["scenario_template"].format(asset=asset)
        scenario += f"\n\n[Evidence Tracing]\n- Supporting Finding ID: {finding_id}\n- Supporting Category: {finding_cat}\n- Supporting Evidence: {finding_ev}"

        return STRIDEThreat(
            stride_id=f"ST-{uuid.uuid4().hex[:8]}",
            category=category,
            affected_asset=asset,
            attack_scenario=scenario,
            severity=severity,
            likelihood=likelihood,
            mitigations=mapping["mitigations"],
            related_findings=[finding_id],
            attack_prerequisites=mapping.get("attack_prerequisites"),
            business_impact=mapping.get("business_impact"),
            mitigation_priority=priority,
            detection_recommendations=mapping.get("detection_recommendations", []),
            sources=["Pentest Engine"]
        )

    # ── Correlation-based STRIDE threats ───────────────────────────

    def _threats_from_correlation(self, correlated: Dict[str, Any], findings: List[Dict]) -> List[STRIDEThreat]:
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
            "CR-011": [STRIDEType.TAMPERING, STRIDEType.INFORMATION_DISCLOSURE, STRIDEType.SPOOFING], # Client-Side Compromise Chain
        }

        categories = corr_stride_map.get(rule_id, [STRIDEType.INFORMATION_DISCLOSURE])

        # Filter categories based on source findings
        source_ids = set(correlated.get("source_findings", []))
        supporting_findings = [f for f in findings if (f.get("finding_id") or f.get("id")) in source_ids]
        
        if not supporting_findings:
            return []

        filtered_categories = []
        for cat in categories:
            allowed_by_at_least_one = False
            for f in supporting_findings:
                allowed_cats = self._get_allowed_stride_categories(f)
                if allowed_cats and cat in allowed_cats:
                    allowed_by_at_least_one = True
                    break
            if allowed_by_at_least_one:
                filtered_categories.append(cat)
        categories = filtered_categories
        severity = self._str_to_severity(severity_str)

        # Dynamic priority based on severity
        priority_map = {
            ThreatSeverity.CRITICAL: "Critical",
            ThreatSeverity.HIGH: "High",
            ThreatSeverity.MEDIUM: "Medium",
            ThreatSeverity.LOW: "Low",
            ThreatSeverity.INFO: "Low"
        }
        priority = priority_map.get(severity, "Medium")

        # Build supporting trace details
        trace_parts = ["[Evidence Tracing]"]
        for f in supporting_findings:
            f_id = f.get("finding_id") or f.get("id") or "unknown"
            f_cat = f.get("category") or "Unknown"
            f_ev = f.get("evidence") or "No direct evidence provided"
            trace_parts.append(f"- Finding ID: {f_id} | Category: {f_cat} | Evidence: {f_ev}")
        trace_text = "\n".join(trace_parts)

        for category in categories:
            threats.append(STRIDEThreat(
                stride_id=f"ST-{uuid.uuid4().hex[:8]}",
                category=category,
                affected_asset="Multiple correlated endpoints",
                attack_scenario=f"Correlated threat: {title}. "
                                f"Cross-stage analysis identified compound risk affecting "
                                f"multiple assets under the {category.value} STRIDE category.\n\n"
                                f"{trace_text}",
                severity=severity,
                likelihood=ThreatSeverity.MEDIUM,
                mitigations=[
                    f"Address all findings contributing to: {title}",
                    "Implement defense-in-depth controls across affected components",
                    "Conduct focused penetration testing on correlated attack paths",
                ],
                related_findings=correlated.get("source_findings", []),
                attack_prerequisites=f"Requires exploitation chain of vulnerabilities: {', '.join(correlated.get('source_findings', []))}",
                business_impact=correlated.get("impact") or "Elevated compound risk targeting system components.",
                mitigation_priority=priority,
                detection_recommendations=[
                    "Correlate events for the affected endpoints in SIEM logs.",
                    "Define rule alerts for sequential visits to the involved assets."
                ],
                sources=correlated.get("sources", ["Pentest Engine"])
            ))

        return threats

    # ── STRIDE Sanitization Helper ──────────────────────────────────

    def _sanitize_stride_threat(self, threat: STRIDEThreat, findings: List[Dict]) -> STRIDEThreat:
        """
        Replaces exaggerated terminology with neutral wording if finding severity is not high/critical or is heuristic.
        Caps passive threat severity and likelihood to Low/Info and updates narrative to hardening focus.
        """
        from app.services.translators.finding_normalizer import FindingNormalizer

        target_ids = set(threat.related_findings)
        supporting = [f for f in findings if (f.get("finding_id") or f.get("id")) in target_ids]
        
        # Check if all related findings are passive/heuristic
        is_passive_threat = False
        if supporting:
            is_passive_threat = all(
                FindingNormalizer.is_passive_finding((f.get("title") or "").lower(), f.get("affected_url") or f.get("url") or "")
                or str(f.get("confidence") or "").lower() == "heuristic"
                for f in supporting
            )
        else:
            # If no supporting findings (e.g., threat from correlation), check if correlation itself has passive findings
            if "correlated" in str(threat.attack_scenario).lower() or not threat.related_findings:
                is_passive_threat = all(
                    FindingNormalizer.is_passive_finding((f.get("title") or "").lower(), f.get("affected_url") or f.get("url") or "")
                    or str(f.get("confidence") or "").lower() == "heuristic"
                    for f in findings
                )

        # Determine if active exploitability is confirmed
        exploit_confirmed = False
        for f in supporting:
            exploit_score = f.get("exploitability_score")
            if exploit_score is None:
                title_lower = (f.get("title") or "").lower()
                sev = (f.get("severity") or "info").lower()
                is_pass = FindingNormalizer.is_passive_finding(title_lower, f.get("affected_url") or f.get("url") or "")
                if is_pass:
                    exploit_score = 0.1
                elif any(kw in title_lower for kw in ["cookie", "cache", "session"]):
                    exploit_score = 2.0
                elif "xss" in title_lower:
                    exploit_score = 8.0
                elif any(kw in title_lower for kw in ["sqli", "sql injection", "injection", "auth bypass", "rce"]):
                    exploit_score = 10.0
                else:
                    exploit_score = 9.0 if sev == "critical" else 7.0 if sev == "high" else 4.0 if sev == "medium" else 1.0 if sev == "low" else 0.1

            conf = str(f.get("confidence") or "").lower()
            if exploit_score >= 8.0 and conf in ["confirmed", "probable"]:
                title_lower = (f.get("title") or "").lower()
                url = f.get("affected_url") or f.get("url") or ""
                if not FindingNormalizer.is_passive_finding(title_lower, url):
                    exploit_confirmed = True
                    break

        # If it is passive, downgrade severity and likelihood
        if is_passive_threat:
            if supporting:
                lowest_sev_str = "info"
                finding_sevs = [str(f.get("severity") or "info").lower() for f in supporting]
                if "low" in finding_sevs:
                    lowest_sev_str = "low"
                elif "info" in finding_sevs:
                    lowest_sev_str = "info"
                else:
                    lowest_sev_str = "low"
                threat.severity = self._str_to_severity(lowest_sev_str)
            else:
                threat.severity = ThreatSeverity.LOW
                
            threat.likelihood = ThreatSeverity.LOW
            threat.mitigation_priority = "Low"

        # Apply replacements for exaggerated terms
        if not exploit_confirmed:
            replacements = [
                (re.compile(r"\bsession theft\b", re.IGNORECASE), "potential session exposure"),
                (re.compile(r"\bsystem compromise\b", re.IGNORECASE), "potential security risks"),
                (re.compile(r"\bcredential stuffing\b", re.IGNORECASE), "automated authentication attempts"),
                (re.compile(r"\btampering\b", re.IGNORECASE), "unauthorized modification risk"),
                (re.compile(r"\bpath traversal\b", re.IGNORECASE), "potential path exposure"),
                (re.compile(r"\bdata exfiltration\b", re.IGNORECASE), "information disclosure risk"),
                (re.compile(r"\bcompromise\b", re.IGNORECASE), "exposure risk"),
                (re.compile(r"\bcompromised\b", re.IGNORECASE), "affected"),
                (re.compile(r"\badmin takeover\b", re.IGNORECASE), "restricted path exposure"),
                (re.compile(r"\bsystem breach\b", re.IGNORECASE), "security hardening recommendation"),
                (re.compile(r"\bfull database exposure\b", re.IGNORECASE), "limited information disclosure"),
                (re.compile(r"\bunauthorized administrative access\b", re.IGNORECASE), "unauthorized restricted path access"),
            ]
            for pattern, repl in replacements:
                if threat.attack_scenario:
                    threat.attack_scenario = pattern.sub(repl, threat.attack_scenario)
                if threat.business_impact:
                    threat.business_impact = pattern.sub(repl, threat.business_impact)
                if threat.attack_prerequisites:
                    threat.attack_prerequisites = pattern.sub(repl, threat.attack_prerequisites)

        # Passive findings must produce informational/hardening narratives only.
        # Do not claim successful exploitation without validated evidence.
        if is_passive_threat or not exploit_confirmed:
            exploitation_claims = [
                (re.compile(r"Attacker exploits", re.IGNORECASE), "Incomplete configuration on"),
                (re.compile(r"exploits the application to", re.IGNORECASE), "could lead to"),
                (re.compile(r"exploits \w+ to", re.IGNORECASE), "could lead to"),
                (re.compile(r"to impersonate legitimate users", re.IGNORECASE), "to identify potential configuration gaps"),
                (re.compile(r"identity verification is bypassed", re.IGNORECASE), "configuration does not enforce latest hardening guidelines"),
            ]
            for pattern, repl in exploitation_claims:
                if threat.attack_scenario:
                    threat.attack_scenario = pattern.sub(repl, threat.attack_scenario)

            if threat.attack_scenario and "hardening" not in threat.attack_scenario.lower():
                threat.attack_scenario += " Hardening recommendation: Review server configurations and follow security best practices."

        return threat

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
    def _deduplicate_stride(threats: List[STRIDEThreat], findings: List[Dict] = None) -> List[STRIDEThreat]:
        """Remove duplicate STRIDE threats (same category + same root cause template) and merge details."""
        unique_map: Dict[tuple, STRIDEThreat] = {}
        original_assets: Dict[tuple, str] = {}
        
        for t in threats:
            # Extract normalized template key
            norm_scenario = t.attack_scenario or ""
            if "[Evidence Tracing]" in norm_scenario:
                norm_scenario = norm_scenario.split("[Evidence Tracing]")[0]
            if t.affected_asset:
                norm_scenario = norm_scenario.replace(t.affected_asset, "{asset}")
            # Normalize spaces
            norm_scenario = " ".join(norm_scenario.split()).lower()
            
            key = (t.category, norm_scenario)
            
            if key not in unique_map:
                unique_map[key] = t
                original_assets[key] = t.affected_asset or ""
            else:
                existing = unique_map[key]
                # Merge findings, mitigations, sources
                existing.related_findings = list(sorted(set(existing.related_findings + t.related_findings)))
                existing.mitigations = list(sorted(set(existing.mitigations + t.mitigations)))
                existing.sources = list(sorted(set(existing.sources + t.sources)))
                if hasattr(existing, 'detection_recommendations') and hasattr(t, 'detection_recommendations'):
                    existing.detection_recommendations = list(sorted(set((existing.detection_recommendations or []) + (t.detection_recommendations or []))))
                
                # Merge assets
                orig_asset = original_assets[key]
                new_asset = t.affected_asset or ""
                
                if new_asset and orig_asset:
                    if orig_asset == "Multiple correlated endpoints" or new_asset == "Multiple correlated endpoints":
                        existing.affected_asset = "Multiple correlated endpoints"
                    else:
                        # Extract individual assets
                        assets = []
                        for a in [orig_asset, new_asset]:
                            for part in a.split(","):
                                part = part.strip()
                                if part and part not in assets:
                                    assets.append(part)
                        if len(assets) > 3:
                            existing.affected_asset = f"{assets[0]}, {assets[1]} and {len(assets)-2} other endpoints"
                        else:
                            existing.affected_asset = ", ".join(assets)
                elif new_asset:
                    existing.affected_asset = new_asset
                
                # Resolve severity to highest
                order = {
                    ThreatSeverity.INFO: 0,
                    ThreatSeverity.LOW: 1,
                    ThreatSeverity.MEDIUM: 2,
                    ThreatSeverity.HIGH: 3,
                    ThreatSeverity.CRITICAL: 4,
                }
                if order.get(t.severity, 0) > order.get(existing.severity, 0):
                    existing.severity = t.severity
                    existing.likelihood = t.likelihood
                    existing.mitigation_priority = t.mitigation_priority

        # After grouping, update the attack scenario text for any merged threats
        for key, t in unique_map.items():
            orig_asset = original_assets[key]
            if orig_asset and t.affected_asset and orig_asset != t.affected_asset:
                if t.attack_scenario:
                    base_sc = t.attack_scenario.split("[Evidence Tracing]")[0].strip()
                    t.attack_scenario = base_sc.replace(orig_asset, t.affected_asset)
            
            # Rebuild evidence tracing block to include all merged findings
            if findings and t.related_findings:
                base_sc = t.attack_scenario.split("[Evidence Tracing]")[0].strip()
                trace_lines = ["[Evidence Tracing]"]
                for fid in t.related_findings:
                    f = next((x for x in findings if (x.get("finding_id") or x.get("id")) == fid), None)
                    if f:
                        f_cat = f.get("category") or "Unknown"
                        f_ev = f.get("evidence") or "No direct evidence provided"
                        trace_lines.append(f"- Supporting Finding ID: {fid}\n  Category: {f_cat}\n  Evidence: {f_ev}")
                t.attack_scenario = base_sc + "\n\n" + "\n".join(trace_lines)

        return list(unique_map.values())

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
