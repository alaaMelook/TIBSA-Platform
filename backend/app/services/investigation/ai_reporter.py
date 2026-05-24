"""
Stage 6 — AI Security Reporter.

Generates human-readable security summaries using OpenRouter AI with
a deterministic rule-based fallback when the AI service is unavailable.

Reuses the existing OpenRouter client from app.services.ai.openrouter_client.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from app.schemas.stage_outputs import (
    ReporterStageOutput,
    AISummary,
    RemediationStep,
    ExportMetadata,
)

logger = logging.getLogger(__name__)


class AISecurityReporter:
    """
    AI-powered security report generator with rule-based fallback.
    Uses OpenRouter for natural-language summaries and falls back to
    deterministic generation if the AI service fails.
    """

    def __init__(self):
        pass

    async def generate_report(
        self,
        investigation_id: str,
        target: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        correlated_threats: List[Dict[str, Any]],
        stride_threats: List[Dict[str, Any]],
        stride_matrix: Dict[str, int],
    ) -> ReporterStageOutput:
        """
        Generate a complete security report with AI summaries.

        Falls back to rule-based summaries if OpenRouter fails.
        """
        started_at = datetime.utcnow()
        logger.info(
            "[AI-REPORTER] Starting report generation for investigation %s",
            investigation_id
        )

        # Try AI-powered summary first, fall back if it fails
        try:
            ai_summary = await self._generate_ai_summary(
                target=target,
                risk_score=risk_score,
                findings=findings,
                correlated_threats=correlated_threats,
                stride_threats=stride_threats,
                stride_matrix=stride_matrix,
            )
            logger.info("[AI-REPORTER] AI summary generated successfully")
        except Exception as e:
            logger.warning(
                "[AI-REPORTER] AI generation failed (%s), using fallback", str(e)
            )
            ai_summary = self._generate_fallback_summary(
                target=target,
                risk_score=risk_score,
                findings=findings,
                correlated_threats=correlated_threats,
                stride_matrix=stride_matrix,
            )

        # Build export metadata
        export_metadata = ExportMetadata(
            investigation_id=investigation_id,
            target=target,
            scan_date=started_at,
            global_risk_score=risk_score,
            total_findings=len(findings),
            total_threats=len(correlated_threats),
        )

        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()

        output = ReporterStageOutput(
            investigation_id=investigation_id,
            ai_summary=ai_summary,
            export_metadata=export_metadata,
            export_status="completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=round(duration, 2),
        )

        logger.info("[AI-REPORTER] Report generation completed in %.2fs", duration)
        return output

    # ── AI-Powered Summary Generation ───────────────────────────────

    async def _generate_ai_summary(
        self,
        target: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        correlated_threats: List[Dict[str, Any]],
        stride_threats: List[Dict[str, Any]],
        stride_matrix: Dict[str, int],
    ) -> AISummary:
        """Generate summaries using OpenRouter AI."""
        from app.services.ai.openrouter_client import call_openrouter

        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(
            target=target,
            risk_score=risk_score,
            findings=findings,
            correlated_threats=correlated_threats,
            stride_matrix=stride_matrix,
        )

        # Call OpenRouter — may raise ValueError or RuntimeError
        raw_response = await call_openrouter(system_prompt, user_prompt)

        return self._parse_ai_response(raw_response, findings)

    def _build_system_prompt(self) -> str:
        """Build the system prompt for the AI security reporter."""
        return """You are an expert cybersecurity analyst writing a security investigation report.

Your task is to generate a structured JSON response with the following fields:
- "executive_summary": A 3-5 sentence summary for non-technical executives explaining the overall security posture, key risks found, and business impact. Use clear, non-technical language.
- "technical_summary": A detailed technical summary for engineers explaining the specific vulnerabilities found, their exploitation potential, and technical risk factors. Include CVE references where applicable.
- "risk_explanation": A plain-language paragraph explaining what the overall risk score means and why it was assigned.
- "remediation_steps": An array of objects, each with:
  - "priority": integer 1-5 (1=highest)
  - "title": short action title
  - "description": detailed description of what to do
  - "estimated_effort": "Low", "Medium", or "High"

IMPORTANT:
- Be specific and actionable, not generic
- Prioritize remediations by actual risk impact
- Never include API keys, tokens, or internal paths
- Never include stack traces or raw error messages
- Keep the response under 2000 tokens
- Respond ONLY with valid JSON, no markdown formatting"""

    def _build_user_prompt(
        self,
        target: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        correlated_threats: List[Dict[str, Any]],
        stride_matrix: Dict[str, int],
    ) -> str:
        """Build the user prompt with sanitized investigation data."""
        # Sanitize and limit findings data for the prompt
        sanitized_findings = []
        for f in findings[:15]:  # Limit to 15 findings
            sanitized_findings.append({
                "title": str(f.get("title", ""))[:150],
                "severity": str(f.get("severity", ""))[:20],
                "category": str(f.get("category", ""))[:50],
                "url": str(f.get("affected_url", ""))[:200],
            })

        sanitized_threats = []
        for t in correlated_threats[:10]:  # Limit to 10 correlated threats
            sanitized_threats.append({
                "title": str(t.get("title", ""))[:150],
                "severity": str(t.get("severity", ""))[:20],
                "confidence": t.get("confidence_score", 0),
            })

        prompt_data = {
            "target": target,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "findings": sanitized_findings,
            "correlated_threats": sanitized_threats,
            "stride_matrix": stride_matrix,
        }

        return (
            f"Generate a security investigation report for the target: {target}\n\n"
            f"Investigation Data:\n{json.dumps(prompt_data, indent=2, default=str)}"
        )

    def _parse_ai_response(
        self, raw: Dict[str, Any], findings: List[Dict[str, Any]]
    ) -> AISummary:
        """Parse and validate the AI response into an AISummary."""
        # Parse remediation steps
        remediation_steps = []
        raw_steps = raw.get("remediation_steps", [])
        if isinstance(raw_steps, list):
            for i, step in enumerate(raw_steps[:10], start=1):
                if isinstance(step, dict):
                    remediation_steps.append(RemediationStep(
                        priority=min(5, max(1, int(step.get("priority", i)))),
                        title=str(step.get("title", f"Remediation Step {i}"))[:200],
                        description=str(step.get("description", ""))[:500],
                        estimated_effort=str(step.get("estimated_effort", "Medium"))[:20],
                    ))

        # If AI didn't provide enough remediation steps, add defaults
        if len(remediation_steps) < 3:
            remediation_steps.extend(self._default_remediation_steps(findings))
            remediation_steps = remediation_steps[:10]

        return AISummary(
            executive_summary=str(raw.get(
                "executive_summary",
                "Security analysis completed. Review the findings for details."
            ))[:2000],
            technical_summary=str(raw.get(
                "technical_summary",
                "Technical assessment completed. See individual findings."
            ))[:3000],
            remediation_plan=remediation_steps,
            risk_explanation=str(raw.get(
                "risk_explanation",
                "Risk score reflects the combined impact of all identified vulnerabilities."
            ))[:1000],
        )

    # ── Rule-Based Fallback Summary ─────────────────────────────────

    def _generate_fallback_summary(
        self,
        target: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        correlated_threats: List[Dict[str, Any]],
        stride_matrix: Dict[str, int],
    ) -> AISummary:
        """
        Generate deterministic rule-based summaries when AI is unavailable.
        Never crashes — always produces a valid AISummary.
        """
        logger.info("[AI-REPORTER] Generating fallback rule-based summary")

        executive_summary = self._generate_executive_fallback(
            target, risk_score, findings, correlated_threats
        )
        technical_summary = self._generate_technical_fallback(
            target, risk_score, findings, stride_matrix
        )
        risk_explanation = self._generate_risk_explanation(risk_score, findings)
        remediation_steps = self._generate_remediation_fallback(findings)

        return AISummary(
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            remediation_plan=remediation_steps,
            risk_explanation=risk_explanation,
        )

    def _generate_executive_fallback(
        self,
        target: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        correlated_threats: List[Dict[str, Any]],
    ) -> str:
        """Generate executive summary for non-technical stakeholders."""
        risk_label = self._score_to_label(risk_score)
        severity_counts = self._count_severities(findings)
        critical_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)

        summary_parts = [
            f"A comprehensive security assessment of {target} has been completed.",
            f"The overall risk level is {risk_label} (score: {risk_score:.0f}/100).",
        ]

        if critical_high > 0:
            summary_parts.append(
                f"{critical_high} critical or high-severity vulnerabilities were identified "
                f"that require immediate attention to protect sensitive data and user accounts."
            )
        elif len(findings) > 0:
            summary_parts.append(
                f"{len(findings)} security findings were identified. "
                f"While no critical threats were found, recommended improvements "
                f"should be implemented to strengthen the security posture."
            )
        else:
            summary_parts.append(
                "No significant vulnerabilities were detected in this assessment. "
                "Continue monitoring and maintaining security best practices."
            )

        if correlated_threats:
            summary_parts.append(
                f"Additionally, {len(correlated_threats)} compound threat scenarios "
                f"were identified where multiple vulnerabilities could be chained together."
            )

        return " ".join(summary_parts)

    def _generate_technical_fallback(
        self,
        target: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        stride_matrix: Dict[str, int],
    ) -> str:
        """Generate technical summary for engineers."""
        severity_counts = self._count_severities(findings)
        categories = self._count_categories(findings)

        parts = [
            f"Security scan of {target} completed.",
            f"Risk Score: {risk_score:.1f}/100.",
            f"Total Findings: {len(findings)}.",
        ]

        # Severity breakdown
        sev_items = [f"{v} {k}" for k, v in severity_counts.items() if v > 0]
        if sev_items:
            parts.append(f"Severity breakdown: {', '.join(sev_items)}.")

        # Category breakdown
        if categories:
            cat_items = [f"{k} ({v})" for k, v in sorted(
                categories.items(), key=lambda x: -x[1]
            )[:5]]
            parts.append(f"Top categories: {', '.join(cat_items)}.")

        # STRIDE summary
        stride_items = [f"{k}: {v}" for k, v in stride_matrix.items() if v > 0]
        if stride_items:
            parts.append(f"STRIDE distribution: {', '.join(stride_items)}.")

        return " ".join(parts)

    def _generate_risk_explanation(
        self, risk_score: float, findings: List[Dict[str, Any]]
    ) -> str:
        """Generate a plain-language risk explanation."""
        label = self._score_to_label(risk_score)
        severity_counts = self._count_severities(findings)

        if risk_score >= 75:
            return (
                f"The risk score of {risk_score:.0f}/100 ({label}) reflects severe security "
                f"deficiencies. With {severity_counts.get('critical', 0)} critical and "
                f"{severity_counts.get('high', 0)} high-severity findings, the application "
                f"faces significant risk of exploitation. Immediate remediation is required."
            )
        elif risk_score >= 50:
            return (
                f"The risk score of {risk_score:.0f}/100 ({label}) indicates substantial "
                f"security concerns. Multiple vulnerabilities were identified that could "
                f"be exploited individually or in combination. Prioritized remediation "
                f"is strongly recommended."
            )
        elif risk_score >= 25:
            return (
                f"The risk score of {risk_score:.0f}/100 ({label}) reflects moderate "
                f"security findings. While no immediately critical threats were found, "
                f"the identified issues should be addressed to prevent future escalation."
            )
        else:
            return (
                f"The risk score of {risk_score:.0f}/100 ({label}) indicates a relatively "
                f"strong security posture. Minor findings should still be addressed as "
                f"part of ongoing security maintenance."
            )

    def _generate_remediation_fallback(
        self, findings: List[Dict[str, Any]]
    ) -> List[RemediationStep]:
        """Generate prioritized remediation steps from findings."""
        steps = self._default_remediation_steps(findings)
        return steps[:10]

    def _default_remediation_steps(
        self, findings: List[Dict[str, Any]]
    ) -> List[RemediationStep]:
        """Build default remediation steps based on finding categories."""
        steps: List[RemediationStep] = []
        seen_categories: set = set()

        # Remediation templates by category keyword
        remediation_templates = {
            "xss": RemediationStep(
                priority=1, title="Fix Cross-Site Scripting Vulnerabilities",
                description="Implement input validation and output encoding on all user inputs. Deploy Content-Security-Policy headers to restrict inline script execution.",
                estimated_effort="Medium",
            ),
            "sqli": RemediationStep(
                priority=1, title="Eliminate SQL Injection Vectors",
                description="Replace all dynamic SQL queries with parameterized queries or ORM methods. Validate and sanitize all user inputs server-side.",
                estimated_effort="Medium",
            ),
            "injection": RemediationStep(
                priority=1, title="Eliminate Injection Vulnerabilities",
                description="Use parameterized queries and prepared statements. Apply strict input validation with allowlisting.",
                estimated_effort="Medium",
            ),
            "auth": RemediationStep(
                priority=1, title="Strengthen Authentication Controls",
                description="Implement multi-factor authentication, enforce strong password policies, add rate limiting to login endpoints, and use CAPTCHA.",
                estimated_effort="High",
            ),
            "cookie": RemediationStep(
                priority=2, title="Secure Session Cookie Configuration",
                description="Set Secure, HttpOnly, and SameSite flags on all session cookies. Implement session rotation on login/logout.",
                estimated_effort="Low",
            ),
            "header": RemediationStep(
                priority=2, title="Deploy Security Headers",
                description="Configure Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers.",
                estimated_effort="Low",
            ),
            "hardening": RemediationStep(
                priority=2, title="Apply Security Hardening",
                description="Follow OWASP security hardening guidelines. Configure all recommended security headers and disable verbose error messages.",
                estimated_effort="Low",
            ),
            "cors": RemediationStep(
                priority=2, title="Fix CORS Configuration",
                description="Restrict Access-Control-Allow-Origin to specific trusted domains. Remove wildcard origins and validate Origin headers server-side.",
                estimated_effort="Low",
            ),
            "directory": RemediationStep(
                priority=3, title="Remediate Information Disclosure",
                description="Disable directory listing, remove backup files from production, restrict access to sensitive paths, and configure proper access controls.",
                estimated_effort="Low",
            ),
            "misconfig": RemediationStep(
                priority=3, title="Fix Server Misconfigurations",
                description="Review server configuration against security benchmarks. Disable debug modes, remove default pages, and restrict unnecessary services.",
                estimated_effort="Medium",
            ),
        }

        # Match findings to remediation templates
        for finding in findings:
            cat = (finding.get("category") or "").lower()
            title_lower = (finding.get("title") or "").lower()

            for keyword, step in remediation_templates.items():
                if keyword not in seen_categories and (keyword in cat or keyword in title_lower):
                    steps.append(step)
                    seen_categories.add(keyword)
                    break

        # Sort by priority
        steps.sort(key=lambda s: s.priority)
        return steps

    # ── Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _score_to_label(score: float) -> str:
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        return "Low"

    @staticmethod
    def _count_severities(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _count_categories(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in findings:
            cat = f.get("category") or "Unknown"
            counts[cat] = counts.get(cat, 0) + 1
        return counts
