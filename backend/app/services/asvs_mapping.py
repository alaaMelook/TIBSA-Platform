"""
Threat Modeling – ASVS Control Mapping.

Maps threats to Application Security Verification Standard (ASVS) controls
for comprehensive security control recommendations.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from app.models.threat_modeling import STRIDECategory, ThreatItem


@dataclass
class ASVSControl:
    """Represents an ASVS control."""
    id: str
    category: str
    description: str
    level: str  # "L1", "L2", "L3"
    requirement: str
    stride_categories: List[STRIDECategory]

    def matches_threat(self, threat: ThreatItem) -> bool:
        """Check if this ASVS control matches the given threat."""
        # Check if the control's STRIDE categories match the threat's category
        return threat.stride_category in self.stride_categories


class ASVSControlDatabase:
    """Database of ASVS controls."""

    def __init__(self):
        self.controls = self._load_controls()

    def _load_controls(self) -> Dict[str, ASVSControl]:
        """Load ASVS controls. In production, this would load from a database or API."""
        return {
            # Authentication
            "V2.1.1": ASVSControl(
                id="V2.1.1",
                category="Authentication",
                description="Verify that user set passwords are at least 12 characters in length.",
                level="L2",
                requirement="2.1.1",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.1.2": ASVSControl(
                id="V2.1.2",
                category="Authentication",
                description="Verify that passwords of at least 64 characters are permitted.",
                level="L1",
                requirement="2.1.2",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.1.3": ASVSControl(
                id="V2.1.3",
                category="Authentication",
                description="Verify that passwords are stored with sufficient entropy.",
                level="L2",
                requirement="2.1.3",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.1.4": ASVSControl(
                id="V2.1.4",
                category="Authentication",
                description="Verify that Unicode characters are permitted in passwords.",
                level="L1",
                requirement="2.1.4",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.1.5": ASVSControl(
                id="V2.1.5",
                category="Authentication",
                description="Verify that users can change their password.",
                level="L1",
                requirement="2.1.5",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.1.6": ASVSControl(
                id="V2.1.6",
                category="Authentication",
                description="Verify that password change functionality requires current password.",
                level="L1",
                requirement="2.1.6",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.1.7": ASVSControl(
                id="V2.1.7",
                category="Authentication",
                description="Verify that passwords submitted during account registration are checked against a set of breached passwords.",
                level="L2",
                requirement="2.1.7",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.1.8": ASVSControl(
                id="V2.1.8",
                category="Authentication",
                description="Verify that a password strength meter is provided.",
                level="L1",
                requirement="2.1.8",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.1.9": ASVSControl(
                id="V2.1.9",
                category="Authentication",
                description="Verify that there are no password composition rules limiting the type of characters permitted.",
                level="L1",
                requirement="2.1.9",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.2.1": ASVSControl(
                id="V2.2.1",
                category="Authentication",
                description="Verify that anti-automation controls are effective at mitigating breached credential testing.",
                level="L1",
                requirement="2.2.1",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.2.2": ASVSControl(
                id="V2.2.2",
                category="Authentication",
                description="Verify that the use of weak authenticators is limited.",
                level="L1",
                requirement="2.2.2",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.2.3": ASVSControl(
                id="V2.2.3",
                category="Authentication",
                description="Verify that secure notifications are sent to users when new devices log in.",
                level="L2",
                requirement="2.2.3",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.2.4": ASVSControl(
                id="V2.2.4",
                category="Authentication",
                description="Verify that proper multi-factor authentication is implemented.",
                level="L2",
                requirement="2.2.4",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V2.3.1": ASVSControl(
                id="V2.3.1",
                category="Authentication",
                description="Verify that the principle of least privilege exists.",
                level="L1",
                requirement="2.3.1",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "V2.3.2": ASVSControl(
                id="V2.3.2",
                category="Authentication",
                description="Verify that users can only view data they are authorized to view.",
                level="L1",
                requirement="2.3.2",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "V2.3.3": ASVSControl(
                id="V2.3.3",
                category="Authentication",
                description="Verify that users can only modify data they are authorized to modify.",
                level="L1",
                requirement="2.3.3",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),

            # Session Management
            "V3.1.1": ASVSControl(
                id="V3.1.1",
                category="Session Management",
                description="Verify that the application never reveals session tokens in URL parameters.",
                level="L1",
                requirement="3.1.1",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V3.2.1": ASVSControl(
                id="V3.2.1",
                category="Session Management",
                description="Verify that all pages and resources validate the session.",
                level="L1",
                requirement="3.2.1",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V3.2.2": ASVSControl(
                id="V3.2.2",
                category="Session Management",
                description="Verify that sessions are invalidated when the user logs out.",
                level="L1",
                requirement="3.2.2",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V3.2.3": ASVSControl(
                id="V3.2.3",
                category="Session Management",
                description="Verify that sessions timeout after a specified period of inactivity.",
                level="L1",
                requirement="3.2.3",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V3.3.1": ASVSControl(
                id="V3.3.1",
                category="Session Management",
                description="Verify that the application generates strong session tokens.",
                level="L1",
                requirement="3.3.1",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V3.3.2": ASVSControl(
                id="V3.3.2",
                category="Session Management",
                description="Verify that the application generates strong session tokens using approved cryptographic algorithms.",
                level="L2",
                requirement="3.3.2",
                stride_categories=[STRIDECategory.SPOOFING]
            ),

            # Access Control
            "V4.1.1": ASVSControl(
                id="V4.1.1",
                category="Access Control",
                description="Verify that the application enforces access control rules on a trusted service layer.",
                level="L1",
                requirement="4.1.1",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "V4.1.2": ASVSControl(
                id="V4.1.2",
                category="Access Control",
                description="Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users.",
                level="L1",
                requirement="4.1.2",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V4.1.3": ASVSControl(
                id="V4.1.3",
                category="Access Control",
                description="Verify that the principle of least privilege exists.",
                level="L1",
                requirement="4.1.3",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "V4.1.4": ASVSControl(
                id="V4.1.4",
                category="Access Control",
                description="Verify that access control decisions are made at the server side.",
                level="L1",
                requirement="4.1.4",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "V4.1.5": ASVSControl(
                id="V4.1.5",
                category="Access Control",
                description="Verify that access controls fail securely.",
                level="L1",
                requirement="4.1.5",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),

            # Input Validation
            "V5.1.1": ASVSControl(
                id="V5.1.1",
                category="Input Validation",
                description="Verify that the application has defenses against HTTP parameter pollution attacks.",
                level="L1",
                requirement="5.1.1",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V5.1.2": ASVSControl(
                id="V5.1.2",
                category="Input Validation",
                description="Verify that frameworks protect against mass parameter assignment attacks.",
                level="L2",
                requirement="5.1.2",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V5.1.3": ASVSControl(
                id="V5.1.3",
                category="Input Validation",
                description="Verify that all input is validated using positive validation patterns.",
                level="L1",
                requirement="5.1.3",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V5.1.4": ASVSControl(
                id="V5.1.4",
                category="Input Validation",
                description="Verify that structured data is strongly typed and validated against a defined schema.",
                level="L1",
                requirement="5.1.4",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V5.1.5": ASVSControl(
                id="V5.1.5",
                category="Input Validation",
                description="Verify that redirects and forwards are validated against an allowlist.",
                level="L1",
                requirement="5.1.5",
                stride_categories=[STRIDECategory.TAMPERING]
            ),

            # Output Encoding/Escaping
            "V6.1.1": ASVSControl(
                id="V6.1.1",
                category="Output Encoding/Escaping",
                description="Verify that the application sets the Content-Type header appropriately.",
                level="L1",
                requirement="6.1.1",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V6.1.2": ASVSControl(
                id="V6.1.2",
                category="Output Encoding/Escaping",
                description="Verify that all untrusted data that is output to HTML is properly escaped.",
                level="L1",
                requirement="6.1.2",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V6.1.3": ASVSControl(
                id="V6.1.3",
                category="Output Encoding/Escaping",
                description="Verify that untrusted data is properly escaped before being included in HTTP response headers.",
                level="L1",
                requirement="6.1.3",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V6.1.4": ASVSControl(
                id="V6.1.4",
                category="Output Encoding/Escaping",
                description="Verify that untrusted data is properly escaped before being included in SQL queries.",
                level="L1",
                requirement="6.1.4",
                stride_categories=[STRIDECategory.TAMPERING]
            ),

            # Cryptography
            "V7.1.1": ASVSControl(
                id="V7.1.1",
                category="Cryptography",
                description="Verify that the application does not use insecure or deprecated cryptographic algorithms.",
                level="L1",
                requirement="7.1.1",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V7.1.2": ASVSControl(
                id="V7.1.2",
                category="Cryptography",
                description="Verify that the application uses strong encryption algorithms.",
                level="L2",
                requirement="7.1.2",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V7.1.3": ASVSControl(
                id="V7.1.3",
                category="Cryptography",
                description="Verify that the application uses proper key management.",
                level="L2",
                requirement="7.1.3",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),

            # Error Handling and Logging
            "V8.1.1": ASVSControl(
                id="V8.1.1",
                category="Error Handling and Logging",
                description="Verify that the application does not log sensitive data.",
                level="L1",
                requirement="8.1.1",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V8.1.2": ASVSControl(
                id="V8.1.2",
                category="Error Handling and Logging",
                description="Verify that the application logs security-relevant events.",
                level="L1",
                requirement="8.1.2",
                stride_categories=[STRIDECategory.REPUDIATION]
            ),
            "V8.1.3": ASVSControl(
                id="V8.1.3",
                category="Error Handling and Logging",
                description="Verify that the application properly handles errors.",
                level="L1",
                requirement="8.1.3",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),

            # Data Protection
            "V9.1.1": ASVSControl(
                id="V9.1.1",
                category="Data Protection",
                description="Verify that sensitive data is not stored in the browser.",
                level="L1",
                requirement="9.1.1",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V9.1.2": ASVSControl(
                id="V9.1.2",
                category="Data Protection",
                description="Verify that sensitive data is not logged.",
                level="L1",
                requirement="9.1.2",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V9.1.3": ASVSControl(
                id="V9.1.3",
                category="Data Protection",
                description="Verify that sensitive data is properly encrypted at rest.",
                level="L2",
                requirement="9.1.3",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),

            # Communications
            "V10.1.1": ASVSControl(
                id="V10.1.1",
                category="Communications",
                description="Verify that TLS is used for all client-server communications.",
                level="L1",
                requirement="10.1.1",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V10.1.2": ASVSControl(
                id="V10.1.2",
                category="Communications",
                description="Verify that only strong TLS configurations are used.",
                level="L2",
                requirement="10.1.2",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V10.1.3": ASVSControl(
                id="V10.1.3",
                category="Communications",
                description="Verify that server certificates are properly validated.",
                level="L1",
                requirement="10.1.3",
                stride_categories=[STRIDECategory.SPOOFING]
            ),

            # HTTP Security Headers
            "V11.1.1": ASVSControl(
                id="V11.1.1",
                category="HTTP Security Headers",
                description="Verify that the application sets appropriate security headers.",
                level="L1",
                requirement="11.1.1",
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V11.1.2": ASVSControl(
                id="V11.1.2",
                category="HTTP Security Headers",
                description="Verify that the application sets the X-Frame-Options header.",
                level="L1",
                requirement="11.1.2",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V11.1.3": ASVSControl(
                id="V11.1.3",
                category="HTTP Security Headers",
                description="Verify that the application sets the X-Content-Type-Options header.",
                level="L1",
                requirement="11.1.3",
                stride_categories=[STRIDECategory.TAMPERING]
            ),

            # Files and Resources
            "V12.1.1": ASVSControl(
                id="V12.1.1",
                category="Files and Resources",
                description="Verify that file uploads are properly validated.",
                level="L1",
                requirement="12.1.1",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V12.1.2": ASVSControl(
                id="V12.1.2",
                category="Files and Resources",
                description="Verify that uploaded files are stored outside the web root.",
                level="L1",
                requirement="12.1.2",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V12.1.3": ASVSControl(
                id="V12.1.3",
                category="Files and Resources",
                description="Verify that user-submitted filenames are validated.",
                level="L1",
                requirement="12.1.3",
                stride_categories=[STRIDECategory.TAMPERING]
            ),

            # API and Web Service
            "V13.1.1": ASVSControl(
                id="V13.1.1",
                category="API and Web Service",
                description="Verify that API endpoints have proper access controls.",
                level="L1",
                requirement="13.1.1",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "V13.1.2": ASVSControl(
                id="V13.1.2",
                category="API and Web Service",
                description="Verify that API rate limiting is implemented.",
                level="L1",
                requirement="13.1.2",
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "V13.1.3": ASVSControl(
                id="V13.1.3",
                category="API and Web Service",
                description="Verify that API responses do not include sensitive information.",
                level="L1",
                requirement="13.1.3",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),

            # Configuration
            "V14.1.1": ASVSControl(
                id="V14.1.1",
                category="Configuration",
                description="Verify that the application does not have default credentials.",
                level="L1",
                requirement="14.1.1",
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "V14.1.2": ASVSControl(
                id="V14.1.2",
                category="Configuration",
                description="Verify that the application does not expose configuration information.",
                level="L1",
                requirement="14.1.2",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V14.1.3": ASVSControl(
                id="V14.1.3",
                category="Configuration",
                description="Verify that the application has a secure configuration management process.",
                level="L2",
                requirement="14.1.3",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
        }

    def get_controls_for_threat(self, threat: ThreatItem) -> List[ASVSControl]:
        """Get ASVS controls that match the given threat."""
        matching_controls = []
        for control in self.controls.values():
            if control.matches_threat(threat):
                matching_controls.append(control)

        return matching_controls

    def enrich_threat(self, threat: ThreatItem) -> ThreatItem:
        """Enrich a threat with ASVS control information."""
        matching_controls = self.get_controls_for_threat(threat)

        if not matching_controls:
            return threat

        # Add control descriptions to the threat's ASVS controls
        control_descriptions = [control.description for control in matching_controls[:3]]  # Limit to 3

        if threat.asvs_controls:
            threat.asvs_controls.extend(control_descriptions)
        else:
            threat.asvs_controls = control_descriptions

        return threat
