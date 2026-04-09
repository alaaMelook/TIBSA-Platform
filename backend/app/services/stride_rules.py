"""
Threat Modeling – STRIDE Rules Engine.

Implements STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service, Elevation of Privilege) threat categorization and rules.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from app.models.threat_modeling import STRIDECategory, ThreatItem, RiskLevel
from app.services.normalized_schema import (
    NormalizedArchitecture, NormalizedAsset, NormalizedEntryPoint,
    NormalizedTrustBoundary, NormalizedDataFlow
)


@dataclass
class STRIDERule:
    """Represents a STRIDE rule for threat generation."""
    category: STRIDECategory
    name: str
    condition: str
    threat_template: str
    mitigation_template: str
    risk_level: RiskLevel
    base_score: int

    def evaluate(self, architecture: NormalizedArchitecture,
                 system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Evaluate rule against architecture and generate threats."""
        threats = []

        # Evaluate based on category
        if self.category == STRIDECategory.SPOOFING:
            threats.extend(self._evaluate_spoofing(architecture, system_metadata))
        elif self.category == STRIDECategory.TAMPERING:
            threats.extend(self._evaluate_tampering(architecture, system_metadata))
        elif self.category == STRIDECategory.REPUDIATION:
            threats.extend(self._evaluate_repudiation(architecture, system_metadata))
        elif self.category == STRIDECategory.INFORMATION_DISCLOSURE:
            threats.extend(self._evaluate_information_disclosure(architecture, system_metadata))
        elif self.category == STRIDECategory.DENIAL_OF_SERVICE:
            threats.extend(self._evaluate_denial_of_service(architecture, system_metadata))
        elif self.category == STRIDECategory.ELEVATION_OF_PRIVILEGE:
            threats.extend(self._evaluate_elevation_of_privilege(architecture, system_metadata))

        return threats

    def _evaluate_spoofing(self, architecture: NormalizedArchitecture,
                          system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Evaluate spoofing threats."""
        threats = []

        # Check entry points without authentication
        for ep in architecture.entry_points:
            if not ep.authentication_required and ep.exposed_to_internet:
                threat = ThreatItem(
                    id=f"spoof-{ep.id}",
                    title=f"Spoofing via {ep.name}",
                    risk=self.risk_level,
                    category="Authentication",
                    description=(
                        f"An attacker could spoof legitimate users or systems through the "
                        f"{ep.name} entry point, which lacks authentication and is exposed to the internet."
                    ),
                    mitigation=(
                        f"Implement strong authentication mechanisms for {ep.name}, "
                        f"such as OAuth 2.0, API keys, or mutual TLS."
                    ),
                    stride_category=STRIDECategory.SPOOFING,
                    affected_assets=[ep.id],
                    entry_points=[ep.id],
                    priority_score=self.base_score + 10  # Higher for internet-exposed
                )
                threats.append(threat)

        return threats

    def _evaluate_tampering(self, architecture: NormalizedArchitecture,
                           system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Evaluate tampering threats."""
        threats = []

        # Check data flows without encryption
        for df in architecture.data_flows:
            if not df.encryption and df.sensitivity in ["High", "Confidential"]:
                source_asset = architecture.get_asset_by_id(df.source_asset_id)
                dest_asset = architecture.get_asset_by_id(df.destination_asset_id)

                if source_asset and dest_asset:
                    threat = ThreatItem(
                        id=f"tamper-{df.id}",
                        title=f"Data Tampering in {df.name}",
                        risk=self.risk_level,
                        category="Data Security",
                        description=(
                            f"Sensitive data flowing from {source_asset.name} to {dest_asset.name} "
                            f"is not encrypted and could be tampered with in transit."
                        ),
                        mitigation=(
                            f"Implement end-to-end encryption for the {df.name} data flow, "
                            f"such as TLS 1.3 or application-level encryption."
                        ),
                        stride_category=STRIDECategory.TAMPERING,
                        affected_assets=[df.source_asset_id, df.destination_asset_id],
                        priority_score=self.base_score + 15
                    )
                    threats.append(threat)

        return threats

    def _evaluate_repudiation(self, architecture: NormalizedArchitecture,
                             system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Evaluate repudiation threats."""
        threats = []

        # Check for lack of audit logging
        audit_enabled = system_metadata.get("audit_logging", False)
        if not audit_enabled:
            threat = ThreatItem(
                id="repudiation-no-audit",
                title="Lack of Audit Logging",
                risk="Medium",
                category="Audit",
                description=(
                    "The system does not implement comprehensive audit logging, "
                    "making it impossible to track user actions and detect security incidents."
                ),
                mitigation=(
                    "Implement centralized audit logging for all security-relevant events, "
                    "user actions, and system changes with tamper-proof storage."
                ),
                stride_category=STRIDECategory.REPUDIATION,
                priority_score=self.base_score
            )
            threats.append(threat)

        return threats

    def _evaluate_information_disclosure(self, architecture: NormalizedArchitecture,
                                        system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Evaluate information disclosure threats."""
        threats = []

        # Check for sensitive data handling
        for asset in architecture.assets:
            if asset.data_classification in ["Confidential", "Restricted"]:
                # Check if asset is exposed through entry points
                exposed_eps = [
                    ep for ep in architecture.entry_points
                    if ep.exposed_to_internet and asset.id in ep.connected_assets
                ]

                for ep in exposed_eps:
                    threat = ThreatItem(
                        id=f"disclosure-{asset.id}-{ep.id}",
                        title=f"Information Disclosure of {asset.name}",
                        risk="High",
                        category="Data Security",
                        description=(
                            f"Confidential data in {asset.name} could be disclosed through "
                            f"the internet-exposed {ep.name} entry point."
                        ),
                        mitigation=(
                            f"Implement proper access controls, data masking, and encryption "
                            f"for {asset.name} when accessed via {ep.name}."
                        ),
                        stride_category=STRIDECategory.INFORMATION_DISCLOSURE,
                        affected_assets=[asset.id],
                        entry_points=[ep.id],
                        priority_score=self.base_score + 20
                    )
                    threats.append(threat)

        return threats

    def _evaluate_denial_of_service(self, architecture: NormalizedArchitecture,
                                   system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Evaluate denial of service threats."""
        threats = []

        # Check internet-exposed entry points
        for ep in architecture.entry_points:
            if ep.exposed_to_internet:
                threat = ThreatItem(
                    id=f"dos-{ep.id}",
                    title=f"Denial of Service via {ep.name}",
                    risk="Medium",
                    category="Availability",
                    description=(
                        f"The {ep.name} entry point is exposed to the internet and could be "
                        f"targeted for denial of service attacks, making the system unavailable."
                    ),
                    mitigation=(
                        f"Implement rate limiting, DDoS protection, and resource quotas "
                        f"for {ep.name}. Consider using a CDN or load balancer with DoS protection."
                    ),
                    stride_category=STRIDECategory.DENIAL_OF_SERVICE,
                    entry_points=[ep.id],
                    priority_score=self.base_score + 5
                )
                threats.append(threat)

        return threats

    def _evaluate_elevation_of_privilege(self, architecture: NormalizedArchitecture,
                                        system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Evaluate elevation of privilege threats."""
        threats = []

        # Check trust boundaries
        for tb in architecture.trust_boundaries:
            if tb.risk_level == "High":
                threat = ThreatItem(
                    id=f"elevation-{tb.id}",
                    title=f"Privilege Elevation across {tb.name}",
                    risk="High",
                    category="Authorization",
                    description=(
                        f"The {tb.name} trust boundary could be exploited to elevate privileges "
                        f"from {tb.source_zone} to {tb.target_zone}."
                    ),
                    mitigation=(
                        f"Implement strict access controls and privilege separation across "
                        f"the {tb.name} boundary. Use principle of least privilege."
                    ),
                    stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                    trust_boundaries=[tb.id],
                    priority_score=self.base_score + 15
                )
                threats.append(threat)

        return threats


class STRIDEEngine:
    """STRIDE-based threat generation engine."""

    def __init__(self):
        self.rules = self._initialize_rules()

    def _initialize_rules(self) -> List[STRIDERule]:
        """Initialize STRIDE rules."""
        return [
            STRIDERule(
                category=STRIDECategory.SPOOFING,
                name="Authentication Bypass",
                condition="Entry points without authentication",
                threat_template="Spoofing through unauthenticated entry points",
                mitigation_template="Implement authentication",
                risk_level="High",
                base_score=15
            ),
            STRIDERule(
                category=STRIDECategory.TAMPERING,
                name="Data Integrity Violation",
                condition="Unencrypted sensitive data flows",
                threat_template="Data tampering in transit",
                mitigation_template="Implement encryption",
                risk_level="High",
                base_score=18
            ),
            STRIDERule(
                category=STRIDECategory.REPUDIATION,
                name="Audit Logging Absence",
                condition="No audit logging",
                threat_template="Actions cannot be tracked",
                mitigation_template="Implement audit logging",
                risk_level="Medium",
                base_score=10
            ),
            STRIDERule(
                category=STRIDECategory.INFORMATION_DISCLOSURE,
                name="Data Exposure",
                condition="Sensitive data accessible via internet",
                threat_template="Confidential data disclosure",
                mitigation_template="Implement access controls",
                risk_level="High",
                base_score=20
            ),
            STRIDERule(
                category=STRIDECategory.DENIAL_OF_SERVICE,
                name="Service Unavailability",
                condition="Internet-exposed entry points",
                threat_template="Denial of service attacks",
                mitigation_template="Implement DoS protection",
                risk_level="Medium",
                base_score=12
            ),
            STRIDERule(
                category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                name="Privilege Escalation",
                condition="Weak trust boundaries",
                threat_template="Unauthorized privilege elevation",
                mitigation_template="Implement access controls",
                risk_level="High",
                base_score=18
            ),
        ]

    def generate_threats(self, architecture: NormalizedArchitecture,
                        system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Generate threats using STRIDE methodology."""
        all_threats = []

        for rule in self.rules:
            threats = rule.evaluate(architecture, system_metadata)
            all_threats.extend(threats)

        # Remove duplicates based on ID
        unique_threats = []
        seen_ids = set()
        for threat in all_threats:
            if threat.id not in seen_ids:
                unique_threats.append(threat)
                seen_ids.add(threat.id)

        return unique_threats
