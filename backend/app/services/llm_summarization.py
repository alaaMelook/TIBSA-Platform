"""
Threat Modeling – LLM Summarization Service.

Uses Large Language Models to provide natural language summaries,
explanations, and recommendations for threats and mitigations.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from app.models.threat_modeling import ThreatItem, Mitigation, STRIDECategory


@dataclass
class LLMSummary:
    """Represents an LLM-generated summary."""
    threat_description: str
    impact_explanation: str
    mitigation_recommendations: List[str]
    risk_assessment: str
    confidence_score: float  # 0.0 to 1.0


class LLMSummarizationService:
    """Service for generating LLM-powered summaries and recommendations."""

    def __init__(self):
        # In production, this would initialize an LLM client (OpenAI, Anthropic, etc.)
        self.llm_client = None

    def generate_threat_summary(self, threat: ThreatItem) -> LLMSummary:
        """
        Generate a comprehensive summary for a threat using LLM.

        In production, this would call an actual LLM API.
        For now, we'll use rule-based generation with some intelligence.
        """
        # Build context for the LLM prompt
        context = self._build_threat_context(threat)

        # Generate summary using rule-based approach (would be LLM call in production)
        summary = self._generate_rule_based_summary(threat, context)

        return summary

    def _build_threat_context(self, threat: ThreatItem) -> Dict[str, Any]:
        """Build context information for the threat."""
        context = {
            "threat_id": threat.id,
            "title": threat.title,
            "description": threat.description,
            "stride_category": threat.stride_category.value if threat.stride_category else None,
            "severity": threat.severity,
            "likelihood": threat.likelihood,
            "impact": threat.impact,
            "status": threat.status.value if threat.status else None,
            "capec_id": threat.capec_id,
            "capec_description": threat.capec_description,
            "asvs_controls": threat.asvs_controls or [],
            "affected_assets": threat.affected_assets or [],
            "entry_points": threat.entry_points or [],
            "trust_boundaries": threat.trust_boundaries or [],
        }

        return context

    def _generate_rule_based_summary(self, threat: ThreatItem, context: Dict[str, Any]) -> LLMSummary:
        """Generate a summary using rule-based logic (placeholder for LLM)."""

        # Generate threat description
        threat_desc = self._generate_threat_description(threat, context)

        # Generate impact explanation
        impact_exp = self._generate_impact_explanation(threat, context)

        # Generate mitigation recommendations
        mitigations = self._generate_mitigation_recommendations(threat, context)

        # Generate risk assessment
        risk_assessment = self._generate_risk_assessment(threat, context)

        # Calculate confidence score based on available information
        confidence = self._calculate_confidence_score(context)

        return LLMSummary(
            threat_description=threat_desc,
            impact_explanation=impact_exp,
            mitigation_recommendations=mitigations,
            risk_assessment=risk_assessment,
            confidence_score=confidence
        )

    def _generate_threat_description(self, threat: ThreatItem, context: Dict[str, Any]) -> str:
        """Generate a natural language description of the threat."""
        base_desc = f"The threat '{threat.title}' "

        if threat.stride_category == STRIDECategory.SPOOFING:
            base_desc += "involves an attacker impersonating a legitimate user, system, or service to gain unauthorized access."
        elif threat.stride_category == STRIDECategory.TAMPERING:
            base_desc += "involves unauthorized modification of data or systems, potentially compromising integrity."
        elif threat.stride_category == STRIDECategory.REPUDIATION:
            base_desc += "involves the ability of an attacker to deny having performed an action, compromising accountability."
        elif threat.stride_category == STRIDECategory.INFORMATION_DISCLOSURE:
            base_desc += "involves unauthorized access to sensitive information, potentially leading to privacy breaches."
        elif threat.stride_category == STRIDECategory.DENIAL_OF_SERVICE:
            base_desc += "involves disrupting service availability, preventing legitimate users from accessing resources."
        elif threat.stride_category == STRIDECategory.ELEVATION_OF_PRIVILEGE:
            base_desc += "involves gaining higher access privileges than authorized, potentially leading to system compromise."

        if threat.capec_description:
            base_desc += f" This threat follows the attack pattern described as: {threat.capec_description[:200]}..."

        if threat.affected_assets:
            assets_str = ", ".join(threat.affected_assets[:3])
            base_desc += f" The threat affects assets including: {assets_str}."

        return base_desc

    def _generate_impact_explanation(self, threat: ThreatItem, context: Dict[str, Any]) -> str:
        """Generate an explanation of the threat's potential impact."""
        impact_parts = []

        if threat.impact:
            impact_parts.append(f"The impact is rated as {threat.impact}, indicating ")

            if threat.impact.lower() in ["high", "critical"]:
                impact_parts.append("severe consequences for the organization including financial loss, reputational damage, and operational disruption.")
            elif threat.impact.lower() == "medium":
                impact_parts.append("moderate consequences that could affect business operations and require remediation efforts.")
            elif threat.impact.lower() in ["low", "info"]:
                impact_parts.append("limited consequences with minimal impact on operations.")

        if threat.affected_assets:
            impact_parts.append(f"This threat could compromise {len(threat.affected_assets)} asset(s), potentially affecting confidentiality, integrity, and availability of critical systems.")

        if threat.stride_category == STRIDECategory.INFORMATION_DISCLOSURE:
            impact_parts.append("Data breaches could result in regulatory fines, loss of customer trust, and legal consequences.")
        elif threat.stride_category == STRIDECategory.DENIAL_OF_SERVICE:
            impact_parts.append("Service disruption could lead to lost revenue, customer dissatisfaction, and emergency response costs.")
        elif threat.stride_category == STRIDECategory.ELEVATION_OF_PRIVILEGE:
            impact_parts.append("Privilege escalation could enable further attacks and complete system compromise.")

        return " ".join(impact_parts) if impact_parts else "The impact of this threat requires further assessment."

    def _generate_mitigation_recommendations(self, threat: ThreatItem, context: Dict[str, Any]) -> List[str]:
        """Generate specific mitigation recommendations."""
        recommendations = []

        # Add ASVS-based recommendations
        if threat.asvs_controls:
            recommendations.extend([
                f"Implement ASVS control: {control}" for control in threat.asvs_controls[:2]
            ])

        # Add STRIDE-specific recommendations
        stride_recs = self._get_stride_recommendations(threat.stride_category)
        recommendations.extend(stride_recs)

        # Add general recommendations based on threat characteristics
        if threat.entry_points:
            recommendations.append(f"Secure entry points: {', '.join(threat.entry_points[:2])}")

        if threat.trust_boundaries:
            recommendations.append(f"Strengthen trust boundaries: {', '.join(threat.trust_boundaries[:2])}")

        # Add risk-based recommendations
        if threat.likelihood and threat.likelihood.lower() in ["high", "critical"]:
            recommendations.append("Implement immediate monitoring and alerting for this high-likelihood threat.")

        if threat.severity and threat.severity.lower() in ["high", "critical"]:
            recommendations.append("Consider implementing compensating controls and regular security assessments.")

        return recommendations[:5]  # Limit to 5 recommendations

    def _get_stride_recommendations(self, stride_category: Optional[STRIDECategory]) -> List[str]:
        """Get STRIDE-specific mitigation recommendations."""
        if not stride_category:
            return []

        recommendations = {
            STRIDECategory.SPOOFING: [
                "Implement multi-factor authentication",
                "Use strong password policies and credential management",
                "Validate user identities through multiple channels"
            ],
            STRIDECategory.TAMPERING: [
                "Implement input validation and sanitization",
                "Use integrity checks and digital signatures",
                "Implement access controls and audit logging"
            ],
            STRIDECategory.REPUDIATION: [
                "Implement comprehensive audit logging",
                "Use digital signatures for critical transactions",
                "Implement non-repudiation mechanisms"
            ],
            STRIDECategory.INFORMATION_DISCLOSURE: [
                "Implement encryption for data at rest and in transit",
                "Use access controls and data classification",
                "Implement secure communication protocols"
            ],
            STRIDECategory.DENIAL_OF_SERVICE: [
                "Implement rate limiting and throttling",
                "Use redundant systems and load balancing",
                "Implement monitoring and automated response"
            ],
            STRIDECategory.ELEVATION_OF_PRIVILEGE: [
                "Implement principle of least privilege",
                "Use role-based access control (RBAC)",
                "Regular privilege reviews and access audits"
            ]
        }

        return recommendations.get(stride_category, [])

    def _generate_risk_assessment(self, threat: ThreatItem, context: Dict[str, Any]) -> str:
        """Generate a risk assessment summary."""
        risk_factors = []

        if threat.likelihood:
            risk_factors.append(f"likelihood: {threat.likelihood}")

        if threat.impact:
            risk_factors.append(f"impact: {threat.impact}")

        if threat.severity:
            risk_factors.append(f"severity: {threat.severity}")

        risk_level = "Unknown"
        if threat.likelihood and threat.impact:
            # Simple risk calculation
            likelihood_score = self._score_level(threat.likelihood)
            impact_score = self._score_level(threat.impact)
            overall_score = (likelihood_score + impact_score) / 2

            if overall_score >= 4:
                risk_level = "Critical"
            elif overall_score >= 3:
                risk_level = "High"
            elif overall_score >= 2:
                risk_level = "Medium"
            else:
                risk_level = "Low"

        assessment = f"Overall risk level: {risk_level}."

        if risk_factors:
            assessment += f" Based on {', '.join(risk_factors)}."

        if threat.stride_category:
            assessment += f" This is a {threat.stride_category.value} threat, which typically requires specific security controls."

        return assessment

    def _score_level(self, level: str) -> int:
        """Convert severity level to numeric score."""
        level_map = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "moderate": 3,
            "low": 2,
            "info": 1,
            "informational": 1
        }
        return level_map.get(level.lower(), 3)

    def _calculate_confidence_score(self, context: Dict[str, Any]) -> float:
        """Calculate confidence score based on available information."""
        score = 0.5  # Base confidence

        # Increase confidence based on available data
        if context.get("stride_category"):
            score += 0.1
        if context.get("capec_id"):
            score += 0.1
        if context.get("asvs_controls"):
            score += 0.1
        if context.get("affected_assets"):
            score += 0.1
        if context.get("entry_points"):
            score += 0.1
        if context.get("severity") and context.get("likelihood"):
            score += 0.1

        return min(score, 1.0)

    def generate_mitigation_summary(self, mitigation: Mitigation) -> str:
        """Generate a summary for a mitigation strategy."""
        summary_parts = []

        if mitigation.title:
            summary_parts.append(f"Mitigation: {mitigation.title}")

        if mitigation.description:
            summary_parts.append(mitigation.description)

        if mitigation.implementation_steps:
            steps = mitigation.implementation_steps[:3]  # Limit to first 3 steps
            summary_parts.append(f"Implementation steps: {'; '.join(steps)}")

        if mitigation.cost:
            summary_parts.append(f"Estimated cost: {mitigation.cost}")

        if mitigation.effectiveness:
            summary_parts.append(f"Expected effectiveness: {mitigation.effectiveness}")

        return ". ".join(summary_parts)

    def generate_overall_assessment(self, threats: List[ThreatItem]) -> str:
        """Generate an overall assessment of the threat model."""
        if not threats:
            return "No threats identified in the current threat model."

        total_threats = len(threats)
        high_severity = sum(1 for t in threats if t.severity and t.severity.lower() in ["high", "critical"])
        high_likelihood = sum(1 for t in threats if t.likelihood and t.likelihood.lower() in ["high", "critical"])

        assessment = f"Threat model contains {total_threats} identified threats. "

        if high_severity > 0:
            assessment += f"{high_severity} threats are rated as high or critical severity. "

        if high_likelihood > 0:
            assessment += f"{high_likelihood} threats have high or critical likelihood. "

        # Analyze STRIDE distribution
        stride_counts = {}
        for threat in threats:
            if threat.stride_category:
                stride_counts[threat.stride_category.value] = stride_counts.get(threat.stride_category.value, 0) + 1

        if stride_counts:
            top_stride = max(stride_counts.items(), key=lambda x: x[1])
            assessment += f"The most common threat type is {top_stride[0]} ({top_stride[1]} threats). "

        assessment += "Recommendations: Focus on implementing the highest priority mitigations first, particularly for high-risk threats."

        return assessment
