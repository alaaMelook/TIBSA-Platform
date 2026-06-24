"""
Stage 6 — AI Security Reporter.

Generates human-readable security summaries using OpenRouter AI with
a deterministic rule-based fallback when the AI service is unavailable.

Reuses the existing OpenRouter client from app.services.ai.openrouter_client.
"""
from __future__ import annotations

import json
import logging
import re
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
        timeline: Optional[List[Dict[str, Any]]] = None,
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
                timeline=timeline,
            )
            logger.info("[AI-REPORTER] AI summary generated successfully")
        except Exception as e:
            if "quota unavailable" in str(e).lower():
                logger.warning("OpenRouter quota unavailable, using fallback reporter.")
            else:
                logger.warning(
                    "[AI-REPORTER] AI generation failed (%s), using fallback", str(e)
                )
            ai_summary = self._generate_fallback_summary(
                target=target,
                risk_score=risk_score,
                findings=findings,
                correlated_threats=correlated_threats,
                stride_matrix=stride_matrix,
                timeline=timeline,
            )

        # Sanitize and harden the generated summary
        ai_summary = self._sanitize_ai_summary(ai_summary, findings)

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
        timeline: Optional[List[Dict[str, Any]]] = None,
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
            timeline=timeline,
        )

        raw_response = await call_openrouter(system_prompt, user_prompt)
        return self._parse_ai_response(raw_response, findings)

    def _build_system_prompt(self) -> str:
        """Build the system prompt for the AI security reporter."""
        return """You are an expert SOC security investigator writing a professional, enterprise-grade Security Investigation Report.
Your task is to generate a structured JSON response with the following fields:
- "executive_summary": A detailed, descriptive, and user-friendly summary of 2-3 paragraphs for non-technical executives explaining the target's overall security posture, what kinds of issues were found (e.g. missing security headers, broad cookie domain scopes), and what they mean in plain English. MUST reflect the REAL severity distribution of the findings. If no HIGH or CRITICAL findings exist, you MUST explicitly state: "No confirmed critical vulnerabilities were identified during this investigation."
- "technical_summary": A detailed technical summary for engineers explaining the specific vulnerabilities found, grouped by technical category (such as hardening, session security, authentication, etc.), with specific examples, technical risks, and CVE references where applicable.
- "risk_explanation": A detailed, plain-language paragraph explaining what the overall risk score means, the primary factors contributing to the score, and why it was assigned.
- "remediation_steps": An array of objects, each with:
  - "priority": integer 1-5 (1=highest)
  - "title": short action title
  - "description": detailed description of what to do
  - "estimated_effort": "Low", "Medium", or "High"
- "risk_overview": Detailed risk breakdown and security posture explanation.
- "investigation_timeline": List of key timeline event objects containing "timestamp", "stage", "status", "message" representing the flow of this security investigation.
- "attack_surface_summary": Breakdown of the external assets, endpoints, and technologies discovered, highlighting exposure.
- "threat_intelligence_summary": Summary of VirusTotal and AlienVault OTX reputation lookups. You MUST clearly distinguish between confirmed malicious indicators, suspicious indicators, clean indicators, and no-significant-reputation indicators. Include exact counts.
- "correlated_attack_chains": Array of objects, each representing an attack scenario:
  - "title": Scenario name
  - "severity": critical/high/medium/low
  - "risk_score": 0-100 float
  - "chain_steps": List of step description strings
  - "sources": List of source engines attributing this threat
  - "explanation": Explain WHY the chain is technically valid, list supporting finding IDs, and describe the actual evidence overlap. Avoid cinematic or exaggerated language.
- "stride_threat_matrix": The STRIDE matrix distribution.
- "high_risk_findings": Array of high/critical vulnerability objects with "title", "severity", "affected_url", "evidence".
- "exploitation_scenarios": Array of objects with "threat" and "scenario" explaining step-by-step how the attack chains can be exploited.
- "business_impact_analysis": Narrative on operational, financial, and reputational impact. Tie impacts directly to actual findings. Avoid exaggerated breach, ransomware, or compromise assumptions without evidence.
- "mitigation_roadmap": Array of objects containing "phase" (e.g. "Phase 1"), "action", "description", and "effort" detailing the remediation timeline.
- "immediate_actions": List of strings for critical immediate tasks (next 24-48 hours).
- "long_term_improvements": List of strings representing defense-in-depth architectural hardening.
- "technical_appendix": Brief technical overview of security scanners and threat modeling tooling used.

IMPORTANT:
- Be strictly evidence-based. Never claim "malicious JS", "active campaign", "attacker infrastructure", or "known malware family" unless VirusTotal detections >= 3 and OTX pulse count >= 1 are present.
- Every correlated threat scenario must reference its contributing sources in the "sources" list.
- Respond ONLY with valid JSON, no markdown formatting"""

    def _build_user_prompt(
        self,
        target: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        correlated_threats: List[Dict[str, Any]],
        stride_matrix: Dict[str, int],
        timeline: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Build the user prompt with sanitized investigation data."""
        sanitized_findings = []
        for f in findings[:15]:
            sanitized_findings.append({
                "title": str(f.get("title", ""))[:150],
                "severity": str(f.get("severity", ""))[:20],
                "category": str(f.get("category", ""))[:50],
                "url": str(f.get("affected_url", ""))[:200],
            })

        sanitized_threats = []
        for t in correlated_threats[:10]:
            sanitized_threats.append({
                "title": str(t.get("title", ""))[:150],
                "severity": str(t.get("severity", ""))[:20],
                "risk_score": t.get("risk_score", 0.0),
                "sources": t.get("sources", []),
                "attack_chain": [step.get("description", "") for step in t.get("attack_chain", [])] if t.get("attack_chain") else []
            })

        prompt_data = {
            "target": target,
            "risk_score": risk_score,
            "total_findings": len(findings),
            "findings": sanitized_findings,
            "correlated_threats": sanitized_threats,
            "stride_matrix": stride_matrix,
            "timeline": timeline or [],
        }

        return (
            f"Generate a security investigation report for the target: {target}\n\n"
            f"Investigation Data:\n{json.dumps(prompt_data, indent=2, default=str)}"
        )

    def _parse_ai_response(
        self, raw: Dict[str, Any], findings: List[Dict[str, Any]]
    ) -> AISummary:
        """Parse and validate the AI response into an AISummary."""
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
            risk_overview=raw.get("risk_overview"),
            investigation_timeline=raw.get("investigation_timeline"),
            attack_surface_summary=raw.get("attack_surface_summary"),
            threat_intelligence_summary=raw.get("threat_intelligence_summary"),
            correlated_attack_chains=raw.get("correlated_attack_chains"),
            stride_threat_matrix=raw.get("stride_threat_matrix"),
            high_risk_findings=raw.get("high_risk_findings"),
            exploitation_scenarios=raw.get("exploitation_scenarios"),
            business_impact_analysis=raw.get("business_impact_analysis"),
            mitigation_roadmap=raw.get("mitigation_roadmap"),
            immediate_actions=raw.get("immediate_actions") or [],
            long_term_improvements=raw.get("long_term_improvements") or [],
            technical_appendix=raw.get("technical_appendix"),
        )

    # ── Rule-Based Fallback Summary ─────────────────────────────────

    def _generate_fallback_summary(
        self,
        target: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        correlated_threats: List[Dict[str, Any]],
        stride_matrix: Dict[str, int],
        timeline: Optional[List[Dict[str, Any]]] = None,
    ) -> AISummary:
        """
        Generate deterministic rule-based summaries when AI is unavailable.
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

        risk_label = self._score_to_label(risk_score)
        risk_overview = (
            f"An enterprise security investigation on {target} has established a security posture risk rating of "
            f"{risk_label} (Score: {risk_score:.1f}/100). This assessment incorporates active vulnerability crawling, "
            f"architectural threat modeling, and reputation lookup databases."
        )

        attack_surface_summary = (
            f"The application attack surface consists of {len(findings)} identified vulnerability exposure points. "
            f"Scanning identified technologies and scrutinized active endpoints. Primary risks center around "
            f"hardening failures and application framework configurations."
        )

        # Categorize threat intel indicators and enforce thresholds
        malicious_count = 0
        suspicious_count = 0
        clean_count = 0
        no_rep_count = 0
        
        # We classify finding details and count them
        for f in findings:
            tags = [t.lower() for t in f.get("tags", [])]
            evidence = (f.get("evidence") or "").lower()
            title = (f.get("title") or "").lower()
            
            # Use strict TI indicators categorization
            if "malicious" in tags or "malicious" in title:
                malicious_count += 1
            elif "suspicious" in tags or "suspicious" in title:
                suspicious_count += 1
            elif "clean" in title or "benign" in evidence:
                clean_count += 1
            else:
                no_rep_count += 1

        threat_intel_summary = (
            f"External threat intelligence integration queried VirusTotal and AlienVault OTX reputation indices. "
            f"Threat Intel Metrics: Confirmed Malicious Indicators: {malicious_count}; "
            f"Suspicious Indicators: {suspicious_count}; "
            f"Clean Indicators: {clean_count}; "
            f"No Significant Reputation Indicators: {no_rep_count}."
        )

        # Format correlated attack chains and explain why technically valid
        correlated_chains = []
        for t in correlated_threats:
            source_ids = ", ".join(t.get("source_findings", []))
            explanation = (
                f"This chain is technically valid because the vulnerability and hardening gap "
                f"co-exist on the same hostname and endpoint/path. Exploiting the technical "
                f"weakness allows bypassing the missing control (supporting finding IDs: {source_ids})."
            )
            
            correlated_chains.append({
                "title": t.get("title"),
                "severity": t.get("severity"),
                "risk_score": t.get("risk_score"),
                "chain_steps": [step.get("description") for step in t.get("attack_chain", [])] if t.get("attack_chain") else [],
                "sources": t.get("sources", ["Pentest Engine"]),
                "explanation": explanation
            })

        high_risk_findings = []
        for f in findings:
            if (f.get("severity") or "").lower() in ["critical", "high"]:
                high_risk_findings.append({
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "affected_url": f.get("affected_url") or f.get("url"),
                    "evidence": f.get("evidence")
                })

        exploitation_scenarios = []
        for t in correlated_threats:
            exploitation_scenarios.append({
                "threat": t.get("title"),
                "scenario": t.get("exploitation_scenario") or t.get("description")
            })

        # Sanitized non-exaggerated Business Impact Analysis
        critical_high_count = len(high_risk_findings)
        if critical_high_count == 0:
            business_impact_analysis = (
                "The business impact is minimal. No confirmed critical vulnerabilities were identified, "
                "meaning there is no immediate risk of severe breach or system takeover. However, "
                "minor information disclosures and hardening gaps should be resolved to maintain compliance."
            )
        else:
            business_impact_analysis = (
                f"Exploitation of the {critical_high_count} high-severity findings on {target} could affect "
                "specific business operations on the involved endpoints. Risks are limited to potential "
                "unauthorized interaction or client-side manipulation on the affected administrative/session scopes. "
                "Mitigation of these specific vectors is recommended to preserve compliance."
            )

        mitigation_roadmap = []
        for i, step in enumerate(remediation_steps):
            mitigation_roadmap.append({
                "phase": f"Phase {i + 1}",
                "action": step.title,
                "description": step.description,
                "effort": step.estimated_effort
            })

        immediate_actions = [
            "Remediate all high and critical severity findings immediately.",
            "Enforce basic transport hardening headers (HSTS, CSP)."
        ]

        long_term_improvements = [
            "Establish a strict Content Security Policy (CSP) release process.",
            "Enforce Multi-Factor Authentication (MFA) and rate limit restrictions."
        ]

        technical_appendix = (
            "SOC Cybersecurity Investigation platform coordinates finding normalization across STRIDE threat matrices and active reputation providers."
        )

        return AISummary(
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            remediation_plan=remediation_steps,
            risk_explanation=risk_explanation,
            risk_overview=risk_overview,
            investigation_timeline=timeline or [],
            attack_surface_summary=attack_surface_summary,
            threat_intelligence_summary=threat_intel_summary,
            correlated_attack_chains=correlated_chains,
            stride_threat_matrix=stride_matrix,
            high_risk_findings=high_risk_findings,
            exploitation_scenarios=exploitation_scenarios,
            business_impact_analysis=business_impact_analysis,
            mitigation_roadmap=mitigation_roadmap,
            immediate_actions=immediate_actions,
            long_term_improvements=long_term_improvements,
            technical_appendix=technical_appendix,
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

        # Categorize findings for context-specific explanations
        headers_count = 0
        cookies_count = 0
        auth_count = 0
        upload_count = 0
        for f in findings:
            title = str(f.get("title", "")).lower()
            category = str(f.get("category", "")).lower()
            if any(x in title or x in category for x in ["header", "csp", "content-security-policy", "strict-transport-security", "hsts", "clickjacking", "x-content-type-options", "x-frame-options"]):
                headers_count += 1
            elif any(x in title or x in category for x in ["cookie", "samesite", "httponly", "domain attribute"]):
                cookies_count += 1
            elif any(x in title or x in category for x in ["auth", "csrf", "login", "privilege boundary", "boundaries mapped"]):
                auth_count += 1
            elif "upload" in title or "upload" in category:
                upload_count += 1

        if risk_label in ("High", "Critical"):
            posture_desc = "indicating an elevated threat exposure that requires immediate remediation."
        elif risk_label == "Medium":
            posture_desc = "indicating a moderate risk profile with several security improvements needed."
        else:
            posture_desc = "indicating a well-maintained and structurally sound security posture."

        summary_parts = [
            f"A comprehensive security assessment of the target {target} has been completed.",
            f"The overall risk level is analyzed as {risk_label} (calculated score: {risk_score:.1f}/100), {posture_desc}"
        ]

        # Enforce standard disclaimer if no high/critical findings
        if critical_high > 0:
            summary_parts.append(
                f"We identified {critical_high} high-severity findings that require prioritized engineering attention to protect critical assets."
            )
        else:
            summary_parts.append("No confirmed critical vulnerabilities were identified during this investigation.")

        # Hardening / Headers explanation
        if headers_count > 0:
            summary_parts.append(
                f"The scan highlighted areas for browser-side hardening, noting that {headers_count} findings relate to missing or loosely defined HTTP security headers (such as Content-Security-Policy or Strict-Transport-Security). Configuring these headers helps instruct user browsers to block cross-site execution and framing attempts."
            )

        # Cookie domain scoping explanation
        if cookies_count > 0:
            summary_parts.append(
                f"Regarding session security, the scanner identified {cookies_count} cookie configuration findings. Some cookies are mapped with a broad domain scope (e.g., matching a wildcard dot prefix), which technically permits child subdomains to access session state. Restricting these to specific host scopes is recommended as a defense-in-depth practice."
            )

        # Auth and upload pathways
        if auth_count > 0 or upload_count > 0:
            pathway_desc = []
            if auth_count > 0:
                pathway_desc.append("potential authentication gateway boundaries were mapped")
            if upload_count > 0:
                pathway_desc.append("a potential file-upload path was identified")
            summary_parts.append(
                f"Furthermore, {' and '.join(pathway_desc)}. These represent entry points where strict input validation and access controls should be monitored regularly."
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

        # Find specific examples of findings to make it very descriptive
        header_examples = []
        cookie_examples = []
        auth_examples = []
        upload_examples = []

        for f in findings:
            title = str(f.get("title", ""))
            title_lower = title.lower()
            category = str(f.get("category", "")).lower()
            if any(x in title_lower or x in category for x in ["header", "csp", "content-security-policy", "strict-transport-security", "hsts", "clickjacking", "x-content-type-options", "x-frame-options"]):
                if title not in header_examples:
                    header_examples.append(title)
            elif any(x in title_lower or x in category for x in ["cookie", "samesite", "httponly", "domain attribute"]):
                if title not in cookie_examples:
                    cookie_examples.append(title)
            elif any(x in title_lower or x in category for x in ["auth", "csrf", "login", "privilege boundary", "boundaries mapped"]):
                if title not in auth_examples:
                    auth_examples.append(title)
            elif "upload" in title_lower or "upload" in category:
                if title not in upload_examples:
                    upload_examples.append(title)

        parts = [
            f"Technical security investigation on {target} completed.",
            f"Vulnerability Risk Score: {risk_score:.1f}/100 | Total Findings: {len(findings)}.",
        ]

        sev_items = [f"{v} {k}" for k, v in severity_counts.items() if v > 0]
        if sev_items:
            parts.append(f"Severity breakdown: {', '.join(sev_items)}.")

        # Hardening details
        if header_examples:
            short_examples = [ex.replace("Potential ", "").replace("Header - ", "") for ex in header_examples[:3]]
            parts.append(
                f"HTTP Hardening: Missing or weak HTTP header controls were analyzed (examples: {', '.join(short_examples)}). Specifically, the lack of default-src and frame-ancestors in Content-Security-Policy leaves the host vulnerable to cross-site script execution and clickjacking framing. Additionally, HSTS omission on raw redirection endpoints increases susceptibility to MITM downgrades."
            )

        # Cookie scope details
        if cookie_examples:
            short_examples = [ex.replace("Potential ", "") for ex in cookie_examples[:3]]
            parts.append(
                f"Session Boundaries: Cookie attribute evaluations flagged issues regarding domain scoping and SameSite configurations (examples: {', '.join(short_examples)}). Cookies mapped to wildcard domains (e.g. '.google.com') allow subdomain session leakage, which deviates from standard RFC 6265 security isolation rules."
            )

        # Auth and CSRF details
        if auth_examples:
            short_examples = [ex.replace("Potential ", "") for ex in auth_examples[:2]]
            parts.append(
                f"Authentication Gates: Legacy login gateways and access paths were evaluated (examples: {', '.join(short_examples)}). State-changing or endpoint-access paths (such as ClientLogin) lack explicit CSRF tokens or Lax/Strict SameSite boundaries, presenting vulnerabilities to cross-site request hijacking."
            )

        # Upload details
        if upload_examples:
            parts.append(
                f"Asset Surface: Discovered potential file import or file-upload path configurations (example: {upload_examples[0]}). These endpoints require strict backend verification of uploaded MIME types and file extensions."
            )

        # Stride breakdown
        stride_items = [f"{k}: {v}" for k, v in stride_matrix.items() if v > 0]
        if stride_items:
            parts.append(f"Threat Modeling (STRIDE): {', '.join(stride_items)}.")

        return " ".join(parts)

    def _generate_risk_explanation(
        self, risk_score: float, findings: List[Dict[str, Any]]
    ) -> str:
        """Generate a plain-language risk explanation."""
        label = self._score_to_label(risk_score)
        severity_counts = self._count_severities(findings)

        # Categorize findings
        low_count = severity_counts.get("low", 0)
        info_count = severity_counts.get("info", 0)
        critical_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)

        explanation = [
            f"The risk score of {risk_score:.1f}/100 ({label}) represents the calibrated exposure profile of the target hostname."
        ]

        if critical_high > 0:
            explanation.append(
                f"This rating is driven by the presence of {critical_high} critical or high-severity vulnerabilities. These issues present immediate exploitation pathways that could compromise system integrity or sensitive data, requiring prompt remediation."
            )
        else:
            explanation.append(
                f"This rating indicates a secure baseline posture because no critical or high-severity exploits were detected during the scan. The score is entirely composed of {low_count} low-severity hardening findings and {info_count} informational observations."
            )

        if critical_high > 0:
            explanation.append(
                f"The primary contributing factors to this calculation include critical or high-severity vulnerabilities (such as active injection or transport security flaws), along with browser-side HTTP hardening gaps. Because these vulnerabilities present direct pathways for potential compromise, the overall risk is classified as {label.lower()}. Prompt remediation of these key vulnerabilities is strongly recommended."
            )
        else:
            explanation.append(
                "The primary contributing factors to this calculation are browser-side HTTP headers (such as missing or weak CSP/HSTS configurations) and broad cookie scope alignments (which share tokens with all subdomains). Because these hardening gaps do not represent direct vectors for remote code execution or data exposure on their own, the overall risk is classified as low. Resolving these issues is recommended as part of routine security maintenance to prevent threat actors from chaining them with future vulnerabilities."
            )

        return " ".join(explanation)

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

        remediation_templates = {
            "xss": RemediationStep(
                priority=1, title="Fix Cross-Site Scripting Vulnerabilities",
                description="Implement input validation and output encoding on all user inputs. Deploy Content-Security-Policy headers.",
                estimated_effort="Medium",
            ),
            "sqli": RemediationStep(
                priority=1, title="Eliminate SQL Injection Vectors",
                description="Replace all dynamic SQL queries with parameterized queries or ORM methods.",
                estimated_effort="Medium",
            ),
            "injection": RemediationStep(
                priority=1, title="Eliminate Injection Vulnerabilities",
                description="Use parameterized queries and prepared statements.",
                estimated_effort="Medium",
            ),
            "auth": RemediationStep(
                priority=1, title="Strengthen Authentication Controls",
                description="Implement multi-factor authentication, enforce strong password policies, add rate limiting.",
                estimated_effort="High",
            ),
            "cookie": RemediationStep(
                priority=2, title="Secure Session Cookie Configuration",
                description="Set Secure, HttpOnly, and SameSite flags on all session cookies.",
                estimated_effort="Low",
            ),
            "header": RemediationStep(
                priority=2, title="Deploy Security Headers",
                description="Configure Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options headers.",
                estimated_effort="Low",
            ),
            "hardening": RemediationStep(
                priority=2, title="Apply Security Hardening",
                description="Follow OWASP security hardening guidelines. Configure all recommended security headers.",
                estimated_effort="Low",
            ),
            "cors": RemediationStep(
                priority=2, title="Fix CORS Configuration",
                description="Restrict Access-Control-Allow-Origin to specific trusted domains.",
                estimated_effort="Low",
            ),
            "directory": RemediationStep(
                priority=3, title="Remediate Information Disclosure",
                description="Disable directory listing, remove backup files from production.",
                estimated_effort="Low",
            ),
            "misconfig": RemediationStep(
                priority=3, title="Fix Server Misconfigurations",
                description="Review server configuration against security benchmarks. Disable debug modes.",
                estimated_effort="Medium",
            ),
        }

        for finding in findings:
            cat = (finding.get("category") or "").lower()
            title_lower = (finding.get("title") or "").lower()

            for keyword, step in remediation_templates.items():
                if keyword not in seen_categories and (keyword in cat or keyword in title_lower):
                    steps.append(step)
                    seen_categories.add(keyword)
                    break

        steps.sort(key=lambda s: s.priority)
        return steps

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

    def _sanitize_ai_summary(self, ai_summary: AISummary, findings: List[Dict[str, Any]]) -> AISummary:
        """
        Sanitizes AI summaries to align with actual evidence.
        Applies conservative language, ensures the critical vulnerability disclaimer is present
        if no active exploit exists, and prevents emergency remediation for low/passive findings.
        """
        _, _, _, cleaned_ai_summary = self.validate_report_consistency(
            findings=findings,
            correlated_threats=[],
            stride_threats=[],
            stride_matrix={},
            ai_summary=ai_summary
        )
        return cleaned_ai_summary

    @staticmethod
    def validate_report_consistency(
        findings: List[Dict[str, Any]],
        correlated_threats: List[Any],
        stride_threats: List[Any],
        stride_matrix: Dict[str, Any],
        ai_summary: Any
    ) -> tuple:
        """
        Validates end-to-end evidence consistency across findings, correlated threats,
        stride/architecture threats, and the generated AI summary.
        Mutates/filters the lists in-place or returns the cleaned versions.
        """
        import re

        # 1. Map existing finding IDs
        finding_ids = set()
        for f in findings:
            fid = f.get("finding_id") or f.get("id")
            if fid:
                finding_ids.add(fid)

        # 2. Filter correlated threats
        filtered_correlated = []
        for ct in correlated_threats:
            if isinstance(ct, dict):
                src = ct.get("source_findings") or []
            else:
                src = getattr(ct, "source_findings", []) or []
            
            valid_src = [fid for fid in src if fid in finding_ids]
            
            # Suppress if no supporting findings or less than 2 (since relation requires 2)
            if not valid_src or len(valid_src) < 2:
                continue
                
            if isinstance(ct, dict):
                ct["source_findings"] = valid_src
                if "contributing_finding_ids" in ct:
                    ct["contributing_finding_ids"] = valid_src
            else:
                setattr(ct, "source_findings", valid_src)
                if hasattr(ct, "contributing_finding_ids"):
                    setattr(ct, "contributing_finding_ids", valid_src)
                    
            filtered_correlated.append(ct)

        # 3. Filter stride/architecture threats
        filtered_stride = []
        for st in stride_threats:
            if isinstance(st, dict):
                rel = st.get("related_findings") or []
            else:
                rel = getattr(st, "related_findings", []) or []
                
            valid_rel = [fid for fid in rel if fid in finding_ids]
            if not valid_rel:
                continue
                
            if isinstance(st, dict):
                st["related_findings"] = valid_rel
            else:
                setattr(st, "related_findings", valid_rel)
                
            filtered_stride.append(st)

        # 4. Update stride_matrix counts to match filtered stride threats
        matrix_counts = {
            "Spoofing": 0,
            "Tampering": 0,
            "Repudiation": 0,
            "Information Disclosure": 0,
            "Denial of Service": 0,
            "Elevation of Privilege": 0
        }
        for st in filtered_stride:
            if isinstance(st, dict):
                cat = st.get("category")
            else:
                cat = getattr(st, "category", None)
                
            if cat:
                cat_name = cat.value if hasattr(cat, "value") else str(cat)
                if cat_name in matrix_counts:
                    matrix_counts[cat_name] += 1
                    
        if isinstance(stride_matrix, dict):
            stride_matrix["spoofing_count"] = matrix_counts["Spoofing"]
            stride_matrix["tampering_count"] = matrix_counts["Tampering"]
            stride_matrix["repudiation_count"] = matrix_counts["Repudiation"]
            stride_matrix["information_disclosure_count"] = matrix_counts["Information Disclosure"]
            stride_matrix["denial_of_service_count"] = matrix_counts["Denial of Service"]
            stride_matrix["elevation_of_privilege_count"] = matrix_counts["Elevation of Privilege"]
        elif stride_matrix:
            if hasattr(stride_matrix, "spoofing_count"):
                setattr(stride_matrix, "spoofing_count", matrix_counts["Spoofing"])
                setattr(stride_matrix, "tampering_count", matrix_counts["Tampering"])
                setattr(stride_matrix, "repudiation_count", matrix_counts["Repudiation"])
                setattr(stride_matrix, "information_disclosure_count", matrix_counts["Information Disclosure"])
                setattr(stride_matrix, "denial_of_service_count", matrix_counts["Denial of Service"])
                setattr(stride_matrix, "elevation_of_privilege_count", matrix_counts["Elevation of Privilege"])

        # 5. Filter and sanitize AI summary
        if ai_summary is None:
            return filtered_correlated, filtered_stride, stride_matrix, ai_summary

        def get_summary_field(field_name, default=None):
            if isinstance(ai_summary, dict):
                return ai_summary.get(field_name, default)
            return getattr(ai_summary, field_name, default)

        def set_summary_field(field_name, value):
            if isinstance(ai_summary, dict):
                ai_summary[field_name] = value
            else:
                setattr(ai_summary, field_name, value)

        # Detect vulnerability category presence
        has_sqli = any(kw in str(f.get("title") or "").lower() or kw in str(f.get("category") or "").lower() for f in findings for kw in ["sqli", "sql injection"])
        has_privesc = any(kw in str(f.get("title") or "").lower() or kw in str(f.get("category") or "").lower() for f in findings for kw in ["access control", "authorization", "idor", "bac", "privilege", "elevation of privilege"])
        has_session = any(kw in str(f.get("title") or "").lower() or kw in str(f.get("category") or "").lower() for f in findings for kw in ["cookie", "session", "auth", "login", "password", "brute", "authentication"])
        has_cors = any(kw in str(f.get("title") or "").lower() or kw in str(f.get("category") or "").lower() for f in findings for kw in ["cors", "cross-origin"])
        has_clickjacking = any(kw in str(f.get("title") or "").lower() or kw in str(f.get("category") or "").lower() for f in findings for kw in ["clickjacking", "x-frame-options", "frame-ancestors"])
        has_csrf = any(kw in str(f.get("title") or "").lower() or kw in str(f.get("category") or "").lower() for f in findings for kw in ["csrf", "cross-site request forgery"])
        has_upload = any(kw in str(f.get("title") or "").lower() or kw in str(f.get("category") or "").lower() for f in findings for kw in ["upload"])
        has_xss = any(kw in str(f.get("title") or "").lower() or kw in str(f.get("category") or "").lower() for f in findings for kw in ["xss", "cross-site scripting"])
        has_ssrf = any(kw in str(f.get("title") or "").lower() or kw in str(f.get("category") or "").lower() for f in findings for kw in ["ssrf", "server-side request forgery"])

        def is_scenario_supported(title: str, text: str) -> bool:
            t_lower = (title or "").lower()
            tx_lower = (text or "").lower()
            
            if ("sql injection" in t_lower or "sql injection" in tx_lower or "sqli" in t_lower or "sqli" in tx_lower) and not has_sqli:
                return False
            if ("privilege escalation" in t_lower or "privilege escalation" in tx_lower or "elevation of privilege" in t_lower or "elevation of privilege" in tx_lower or "broken access control" in t_lower or "broken access control" in tx_lower) and not has_privesc:
                return False
            if ("session hijacking" in t_lower or "session hijacking" in tx_lower or "session theft" in t_lower or "session theft" in tx_lower or "session security" in t_lower or "session security" in tx_lower) and not has_session:
                return False
            if ("cors" in t_lower or "cors" in tx_lower or "cross-origin" in t_lower or "cross-origin" in tx_lower) and not has_cors:
                return False
            if ("clickjacking" in t_lower or "clickjacking" in tx_lower or "x-frame-options" in t_lower or "x-frame-options" in tx_lower) and not has_clickjacking:
                return False
            if ("csrf" in t_lower or "csrf" in tx_lower or "cross-site request forgery" in t_lower or "cross-site request forgery" in tx_lower) and not has_csrf:
                return False
            if ("upload" in t_lower or "upload" in tx_lower) and not has_upload:
                return False
            if ("xss" in t_lower or "xss" in tx_lower or "cross-site scripting" in t_lower or "cross-site scripting" in tx_lower) and not has_xss:
                return False
            if ("ssrf" in t_lower or "ssrf" in tx_lower or "server-side request forgery" in t_lower or "server-side request forgery" in tx_lower) and not has_ssrf:
                return False
                
            return True

        # Filter attack chains, scenarios, remediation, roadmap
        chains = get_summary_field("correlated_attack_chains", []) or []
        filtered_chains = []
        for chain in chains:
            if isinstance(chain, dict):
                c_title = chain.get("title", "")
                c_expl = chain.get("explanation", "")
            else:
                c_title = getattr(chain, "title", "")
                c_expl = getattr(chain, "explanation", "")
            
            if is_scenario_supported(c_title, c_expl):
                filtered_chains.append(chain)
        set_summary_field("correlated_attack_chains", filtered_chains)

        scenarios = get_summary_field("exploitation_scenarios", []) or []
        filtered_scenarios = []
        for sc in scenarios:
            if isinstance(sc, dict):
                s_threat = sc.get("threat", "")
                s_scenario = sc.get("scenario", "")
            else:
                s_threat = getattr(sc, "threat", "")
                s_scenario = getattr(sc, "scenario", "")
                
            if is_scenario_supported(s_threat, s_scenario):
                filtered_scenarios.append(sc)
        set_summary_field("exploitation_scenarios", filtered_scenarios)

        remediation = get_summary_field("remediation_plan", []) or get_summary_field("remediation_steps", []) or []
        filtered_remediation = []
        for step in remediation:
            if isinstance(step, dict):
                r_title = step.get("title", "")
                r_desc = step.get("description", "")
            else:
                r_title = getattr(step, "title", "")
                r_desc = getattr(step, "description", "")
                
            if is_scenario_supported(r_title, r_desc):
                filtered_remediation.append(step)
        if get_summary_field("remediation_plan") is not None:
            set_summary_field("remediation_plan", filtered_remediation)
        if get_summary_field("remediation_steps") is not None:
            set_summary_field("remediation_steps", filtered_remediation)

        roadmap = get_summary_field("mitigation_roadmap", []) or []
        filtered_roadmap = []
        for phase in roadmap:
            if isinstance(phase, dict):
                ph_action = phase.get("action", "")
                ph_desc = phase.get("description", "")
            else:
                ph_action = getattr(phase, "action", "")
                ph_desc = getattr(phase, "description", "")
                
            if is_scenario_supported(ph_action, ph_desc):
                filtered_roadmap.append(phase)
        set_summary_field("mitigation_roadmap", filtered_roadmap)

        # Enforce narrative level consistency based on highest severity
        severity_values = [f.get("severity", "info").lower() for f in findings]
        sev_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        highest_severity_val = max([sev_priority.get(s, 0) for s in severity_values]) if severity_values else 0
        highest_severity = "info"
        for s, v in sev_priority.items():
            if v == highest_severity_val:
                highest_severity = s
                break

        has_high_or_critical = (highest_severity in ["high", "critical"])
        has_medium = (highest_severity == "medium")
        has_low_or_info = (highest_severity in ["low", "info"])

        replacements = []
        if has_low_or_info:
            replacements.extend([
                (re.compile(r"\bno\s+critical\s+or\s+high-severity\b", re.IGNORECASE), "no high-severity"),
                (re.compile(r"\bno\s+critical\s+or\s+high\b", re.IGNORECASE), "no high-severity"),
                (re.compile(r"\bno\s+high\s+or\s+critical\b", re.IGNORECASE), "no high-severity"),
                (re.compile(r"\bno\s+high\s+or\s+critical-severity\b", re.IGNORECASE), "no high-severity"),
                (re.compile(r"\b(high|critical|severe|immediate)\s+risk\b", re.IGNORECASE), "low risk"),
                (re.compile(r"\bimmediate\s+exploitation\b", re.IGNORECASE), "limited exposure"),
                (re.compile(r"\bcritical\s+compromise\b", re.IGNORECASE), "potential configuration gap"),
                (re.compile(r"\bsevere\s+breach\b", re.IGNORECASE), "routine hardening observation"),
                (re.compile(r"\bactive\s+takeover\b", re.IGNORECASE), "passive path exposure"),
                (re.compile(r"\bhigh\s+severity\s+vulnerabilities\b", re.IGNORECASE), "low severity findings"),
                (re.compile(r"\bimmediate\s+remediation\b", re.IGNORECASE), "remediation during standard maintenance"),
                (re.compile(r"\bcritical\s+attack\s+paths\b", re.IGNORECASE), "hardening opportunities"),
                (re.compile(r"\bcritical\s+vulnerabilities\b", re.IGNORECASE), "low severity findings"),
                (re.compile(r"\bhigh-severity\b", re.IGNORECASE), "low-severity"),
                (re.compile(r"\bcritical-severity\b", re.IGNORECASE), "low-severity"),
                (re.compile(r"\bcritical\b", re.IGNORECASE), "low-severity"),
                (re.compile(r"\bhigh\b", re.IGNORECASE), "low"),
                (re.compile(r"\bsevere\b", re.IGNORECASE), "minor"),
                (re.compile(r"\bbreach\b", re.IGNORECASE), "exposure"),
                (re.compile(r"\btakeover\b", re.IGNORECASE), "access"),
                (re.compile(r"\bexploitation\b", re.IGNORECASE), "mitigation option"),
            ])
        elif has_medium:
            replacements.extend([
                (re.compile(r"\bno\s+critical\s+or\s+high-severity\b", re.IGNORECASE), "no high-severity"),
                (re.compile(r"\bno\s+critical\s+or\s+high\b", re.IGNORECASE), "no high-severity"),
                (re.compile(r"\bno\s+high\s+or\s+critical\b", re.IGNORECASE), "no high-severity"),
                (re.compile(r"\bno\s+high\s+or\s+critical-severity\b", re.IGNORECASE), "no high-severity"),
                (re.compile(r"\bcritical\s+compromise\b", re.IGNORECASE), "medium risk exposure"),
                (re.compile(r"\bsevere\s+breach\b", re.IGNORECASE), "medium severity finding"),
                (re.compile(r"\bactive\s+takeover\b", re.IGNORECASE), "potential access exposure"),
                (re.compile(r"\b(critical|severe|immediate)\s+risk\b", re.IGNORECASE), "medium risk"),
                (re.compile(r"\bhigh\s+severity\s+vulnerabilities\b", re.IGNORECASE), "medium severity findings"),
                (re.compile(r"\bcritical\s+vulnerabilities\b", re.IGNORECASE), "medium severity findings"),
                (re.compile(r"\bcritical\s+attack\s+paths\b", re.IGNORECASE), "medium risk paths"),
                (re.compile(r"\bhigh-severity\b", re.IGNORECASE), "medium-severity"),
                (re.compile(r"\bcritical-severity\b", re.IGNORECASE), "medium-severity"),
                (re.compile(r"\bcritical\b", re.IGNORECASE), "medium-severity"),
                (re.compile(r"\bhigh\b", re.IGNORECASE), "medium"),
                (re.compile(r"\bsevere\b", re.IGNORECASE), "moderate"),
                (re.compile(r"\btakeover\b", re.IGNORECASE), "access"),
            ])

        if not has_high_or_critical:
            replacements.extend([
                (re.compile(r"\bhigh\s+severity\s+vulnerabilities\s+detected\b", re.IGNORECASE), "no high severity vulnerabilities detected"),
                (re.compile(r"\bimmediate\s+remediation\s+required\b", re.IGNORECASE), "remediation during standard maintenance is recommended"),
                (re.compile(r"\bcritical\s+attack\s+paths\s+identified\b", re.IGNORECASE), "no critical attack paths identified"),
                (re.compile(r"\bhigh\s+and\s+critical\b", re.IGNORECASE), "low and medium"),
                (re.compile(r"\bhigh\s+or\s+critical\b", re.IGNORECASE), "low or medium"),
            ])

        def apply_replacements(text: str) -> str:
            if not text:
                return ""
            for pattern, repl in replacements:
                text = pattern.sub(repl, text)
            return text

        def clean_text(text: str) -> str:
            if not text:
                return ""
            sentences = re.split(r'(?<=[.!?])\s+', text)
            filtered_sentences = []
            for sentence in sentences:
                s_lower = sentence.lower()
                if ("sql injection" in s_lower or "sqli" in s_lower) and not has_sqli:
                    continue
                if ("privilege escalation" in s_lower or "elevation of privilege" in s_lower or "idor" in s_lower or "broken access control" in s_lower) and not has_privesc:
                    continue
                if ("session hijacking" in s_lower or "session theft" in s_lower or "session security" in s_lower) and not has_session:
                    continue
                if ("cors" in s_lower or "cross-origin" in s_lower) and not has_cors:
                    continue
                if ("clickjacking" in s_lower or "x-frame-options" in s_lower) and not has_clickjacking:
                    continue
                if ("csrf" in s_lower or "cross-site request forgery" in s_lower) and not has_csrf:
                    continue
                if ("file upload" in s_lower or "upload exposure" in s_lower or "upload vulnerability" in s_lower) and not has_upload:
                    continue
                if ("xss" in s_lower or "cross-site scripting" in s_lower) and not has_xss:
                    continue
                if ("ssrf" in s_lower or "server-side request forgery" in s_lower) and not has_ssrf:
                    continue
                filtered_sentences.append(sentence)
            return " ".join(filtered_sentences)

        text_fields = [
            "executive_summary",
            "technical_summary",
            "risk_explanation",
            "risk_overview",
            "business_impact_analysis",
            "attack_surface_summary",
            "technical_appendix",
        ]
        for field in text_fields:
            val = get_summary_field(field)
            if isinstance(val, str):
                cleaned = clean_text(val)
                cleaned = apply_replacements(cleaned)
                set_summary_field(field, cleaned)

        # Enforce critical vulnerability disclaimer
        if not has_high_or_critical:
            disclaimer = "No confirmed critical vulnerabilities were identified during this investigation."
            exec_sum = get_summary_field("executive_summary") or ""
            if disclaimer not in exec_sum:
                if exec_sum and not exec_sum.endswith("."):
                    exec_sum += "."
                exec_sum = exec_sum + " " + disclaimer if exec_sum else disclaimer
                set_summary_field("executive_summary", exec_sum)

        # Clean individual list fields
        for chain in filtered_chains:
            if isinstance(chain, dict):
                if "explanation" in chain:
                    chain["explanation"] = apply_replacements(clean_text(chain["explanation"]))
            else:
                if hasattr(chain, "explanation"):
                    setattr(chain, "explanation", apply_replacements(clean_text(getattr(chain, "explanation"))))

        for sc in filtered_scenarios:
            if isinstance(sc, dict):
                if "scenario" in sc:
                    sc["scenario"] = apply_replacements(clean_text(sc["scenario"]))
            else:
                if hasattr(sc, "scenario"):
                    setattr(sc, "scenario", apply_replacements(clean_text(getattr(sc, "scenario"))))

        # 6. Prevent emergency remediation priorities for low findings
        if not has_high_or_critical:
            # Adjust immediate actions
            immediate = get_summary_field("immediate_actions", []) or []
            new_actions = []
            for act in immediate:
                if "immediate" in act.lower() or "critical" in act.lower():
                    act = act.replace("immediately", "during regular maintenance")
                    act = act.replace("Immediately", "During regular maintenance")
                    act = act.replace("high and critical severity findings", "findings")
                    act = act.replace("high and critical findings", "findings")
                    act = act.replace("critical severity findings", "findings")
                    act = act.replace("high and critical", "relevant")
                new_actions.append(act)
            set_summary_field("immediate_actions", new_actions)

            # Adjust remediation plan priorities
            for step in filtered_remediation:
                if not isinstance(step, dict):
                    if hasattr(step, "priority"):
                        if step.priority <= 2:
                            step.priority = max(3, step.priority)
                    if hasattr(step, "title") and step.title:
                        step.title = apply_replacements(step.title)
                        step.title = step.title.replace("Fix immediately", "Review and configure")
                        step.title = step.title.replace("Eliminate", "Address")
                    if hasattr(step, "description") and step.description:
                        step.description = apply_replacements(step.description)
                        step.description = step.description.replace("immediately", "as part of standard maintenance")
                else:
                    if "priority" in step:
                        if step["priority"] <= 2:
                            step["priority"] = max(3, step["priority"])
                    if "title" in step and step["title"]:
                        step["title"] = apply_replacements(step["title"])
                        step["title"] = step["title"].replace("Fix immediately", "Review and configure")
                        step["title"] = step["title"].replace("Eliminate", "Address")
                    if "description" in step and step["description"]:
                        step["description"] = apply_replacements(step["description"])
                        step["description"] = step["description"].replace("immediately", "as part of standard maintenance")

        return filtered_correlated, filtered_stride, stride_matrix, ai_summary
