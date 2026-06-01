# MODIFIED: FIX 5 | Mapped each STRIDE category to correct ASVS chapters (Spoofing→V2+V3, Tampering→V6+V12, Repudiation→V7, InfoDisc→V8+V9, DoS→V11+V12, PrivElev→V4+V13); added missing ASVSControl entries with level/requirement_text/verification_method
"""
Threat Modeling – ASVS Control Mapping.

Maps threats to Application Security Verification Standard (ASVS) controls
for comprehensive security control recommendations.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from app.models.threat_modeling import STRIDECategory, ThreatItem


# ─── STRIDE → ASVS Control ID Mapping (FIX 5) ─────────────────────────────
# Maps each STRIDE category to the correct ASVS chapters per spec:
#   Spoofing       → V2 (Authentication) + V3 (Session Management)
#   Tampering      → V6 (Cryptography)  + V12 (Files & Resources)
#   Repudiation    → V7 (Error Handling & Logging)
#   Info Disclosure→ V8 (Data Protection) + V9 (Communications)
#   DoS            → V11 (Business Logic) + V12 (Files & Resources)
#   Priv Elevation → V4 (Access Control) + V13 (API & Web Services)
STRIDE_TO_ASVS_IDS: Dict[STRIDECategory, List[str]] = {
    STRIDECategory.SPOOFING:               ["V2.1.1", "V2.2.4", "V3.2.2"],
    STRIDECategory.TAMPERING:              ["V6.2.1", "V6.2.2", "V12.1.1"],
    STRIDECategory.REPUDIATION:            ["V7.1.1", "V7.1.2", "V7.2.1"],
    STRIDECategory.INFORMATION_DISCLOSURE: ["V8.1.1", "V8.2.1", "V9.1.1"],
    STRIDECategory.DENIAL_OF_SERVICE:      ["V11.1.1", "V11.1.2", "V12.1.1"],
    STRIDECategory.ELEVATION_OF_PRIVILEGE: ["V4.1.1", "V4.1.3", "V13.1.1"],
}


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

            # ─────────────────────────────────────────────────────────────────
            # FIX 5: Missing ASVS chapters required by the updated STRIDE_TO_ASVS_IDS.
            # V6 = Cryptography (Tampering), V7 = Error Handling & Logging (Repudiation),
            # V8 = Data Protection (Info Disclosure), V9 = Communications (Info Disclosure),
            # V11 = Business Logic (DoS), V13 = API & Web Services (Priv Elevation)
            # ─────────────────────────────────────────────────────────────────

            # V6 – Cryptography (maps to Tampering per FIX 5)
            "V6.2.1": ASVSControl(
                id="V6.2.1",
                category="Cryptography",
                description="Verify that all cryptographic modules fail securely and errors are handled in a way that does not enable Padding Oracle attacks.",
                level="L1",
                requirement="6.2.1",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V6.2.2": ASVSControl(
                id="V6.2.2",
                category="Cryptography",
                description="Verify that industry proven or government approved cryptographic algorithms, modes, and libraries are used, instead of custom coded cryptography.",
                level="L2",
                requirement="6.2.2",
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V6.2.3": ASVSControl(
                id="V6.2.3",
                category="Cryptography",
                description="Verify that encryption initialization vector, cipher configuration, and block modes are configured securely using the latest advice.",
                level="L2",
                requirement="6.2.3",
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "V6.2.5": ASVSControl(
                id="V6.2.5",
                category="Cryptography",
                description="Verify that known insecure block modes (i.e. ECB, etc.), padding modes (i.e. PKCS#1 v1.5, etc.), ciphers with small block sizes (i.e. Triple-DES, Blowfish, etc.), and weak hashing algorithms (i.e. MD5, SHA1, etc.) are not used unless required for backwards compatibility.",
                level="L1",
                requirement="6.2.5",
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),

            # V7 – Error Handling & Logging (maps to Repudiation per FIX 5)
            "V7.1.1": ASVSControl(
                id="V7.1.1",
                category="Error Handling and Logging",
                description="Verify that the application does not log credentials or payment details. Session tokens should only be stored in logs in an irreversible, hashed form.",
                level="L1",
                requirement="7.1.1",
                stride_categories=[STRIDECategory.REPUDIATION, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V7.1.2": ASVSControl(
                id="V7.1.2",
                category="Error Handling and Logging",
                description="Verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy.",
                level="L1",
                requirement="7.1.2",
                stride_categories=[STRIDECategory.REPUDIATION, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V7.2.1": ASVSControl(
                id="V7.2.1",
                category="Error Handling and Logging",
                description="Verify that all authentication decisions are logged, without storing sensitive session tokens or passwords. This should include requests with relevant metadata needed for security investigations.",
                level="L2",
                requirement="7.2.1",
                stride_categories=[STRIDECategory.REPUDIATION]
            ),
            "V7.2.2": ASVSControl(
                id="V7.2.2",
                category="Error Handling and Logging",
                description="Verify that all access control decisions can be logged and all failed decisions are logged. This should include requests with relevant metadata needed for security investigations.",
                level="L2",
                requirement="7.2.2",
                stride_categories=[STRIDECategory.REPUDIATION, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "V7.3.1": ASVSControl(
                id="V7.3.1",
                category="Error Handling and Logging",
                description="Verify that the logging system has controls to prevent unauthorized access and cannot be manipulated to erase or tamper with existing records.",
                level="L2",
                requirement="7.3.1",
                stride_categories=[STRIDECategory.REPUDIATION, STRIDECategory.TAMPERING]
            ),

            # V8 – Data Protection (maps to Information Disclosure per FIX 5)
            "V8.1.1": ASVSControl(
                id="V8.1.1",
                category="Data Protection",
                description="Verify that the application protects sensitive data from being cached in server components such as load balancers and application caches.",
                level="L2",
                requirement="8.1.1",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V8.1.2": ASVSControl(
                id="V8.1.2",
                category="Data Protection",
                description="Verify that all cached or temporary copies of sensitive data stored on the server are protected from unauthorized access or purged/invalidated after the authorized user accesses the sensitive data.",
                level="L2",
                requirement="8.1.2",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V8.2.1": ASVSControl(
                id="V8.2.1",
                category="Data Protection",
                description="Verify that the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers.",
                level="L1",
                requirement="8.2.1",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V8.2.2": ASVSControl(
                id="V8.2.2",
                category="Data Protection",
                description="Verify that data stored in client side storage (such as HTML5 local storage, session storage, IndexedDB, regular cookies or Flash cookies) does not contain sensitive data or PII.",
                level="L1",
                requirement="8.2.2",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V8.3.1": ASVSControl(
                id="V8.3.1",
                category="Data Protection",
                description="Verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP verb do not contain sensitive data.",
                level="L1",
                requirement="8.3.1",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),

            # V9 – Communications (maps to Information Disclosure per FIX 5)
            "V9.1.1": ASVSControl(
                id="V9.1.1",
                category="Communications",
                description="Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted communications.",
                level="L1",
                requirement="9.1.1",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING]
            ),
            "V9.1.2": ASVSControl(
                id="V9.1.2",
                category="Communications",
                description="Verify using up to date TLS testing tools that only strong cipher suites are enabled, with the strongest cipher suites set as preferred.",
                level="L1",
                requirement="9.1.2",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V9.1.3": ASVSControl(
                id="V9.1.3",
                category="Communications",
                description="Verify that old versions of SSL and TLS protocols, algorithms, ciphers, and configuration are disabled, such as SSLv2, SSLv3, or TLS 1.0 and 1.1. The latest version of TLS should be the preferred cipher suite.",
                level="L1",
                requirement="9.1.3",
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),

            # V11 – Business Logic (maps to Denial of Service per FIX 5)
            "V11.1.1": ASVSControl(
                id="V11.1.1",
                category="Business Logic",
                description="Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps.",
                level="L1",
                requirement="11.1.1",
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "V11.1.2": ASVSControl(
                id="V11.1.2",
                category="Business Logic",
                description="Verify that the application will only process business logic flows with all steps being processed in realistic human time, i.e. transactions are not submitted too quickly.",
                level="L1",
                requirement="11.1.2",
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "V11.1.4": ASVSControl(
                id="V11.1.4",
                category="Business Logic",
                description="Verify that the application has anti-automation controls to protect against excessive calls such as mass data exfiltration, business logic requests, file uploads or denial of service attacks.",
                level="L1",
                requirement="11.1.4",
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "V11.1.6": ASVSControl(
                id="V11.1.6",
                category="Business Logic",
                description="Verify that the application does not suffer from \"Time Of Check to Time Of Use\" (TOCTOU) issues or other race conditions for sensitive operations.",
                level="L2",
                requirement="11.1.6",
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE, STRIDECategory.TAMPERING]
            ),

            # V13 – API & Web Services (maps to Priv Elevation per FIX 5)
            "V13.1.1": ASVSControl(
                id="V13.1.1",
                category="API and Web Service",
                description="Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file parsing behavior that could be used in SSRF and RFI attacks.",
                level="L1",
                requirement="13.1.1",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING]
            ),
            "V13.1.2": ASVSControl(
                id="V13.1.2",
                category="API and Web Service",
                description="Verify that API URLs do not expose sensitive information, such as the API key, session tokens etc.",
                level="L1",
                requirement="13.1.2",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "V13.1.3": ASVSControl(
                id="V13.1.3",
                category="API and Web Service",
                description="Verify that API endpoints are protected by access controls, including HTTP methods and verb tampering protection.",
                level="L1",
                requirement="13.1.3",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "V13.2.1": ASVSControl(
                id="V13.2.1",
                category="API and Web Service",
                description="Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such that normal users cannot use DELETE or PUT on protected API or resources.",
                level="L1",
                requirement="13.2.1",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING]
            ),
            "V13.2.3": ASVSControl(
                id="V13.2.3",
                category="API and Web Service",
                description="Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: double submit cookie pattern, CSRF nonces, or Origin request header checks.",
                level="L1",
                requirement="13.2.3",
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING]
            ),
        }

    def get_asvs_ids_for_stride(self, stride_category: STRIDECategory) -> List[str]:
        """
        Return the canonical ASVS control IDs for a STRIDE category.
        Uses the deterministic STRIDE_TO_ASVS_IDS lookup table.
        """
        return STRIDE_TO_ASVS_IDS.get(stride_category, [])

    def get_controls_for_threat(self, threat: ThreatItem) -> List[ASVSControl]:
        """Get ASVS controls that match the given threat."""
        matching_controls = []
        for control in self.controls.values():
            if control.matches_threat(threat):
                matching_controls.append(control)

        return matching_controls

    def enrich_threat(self, threat: ThreatItem) -> ThreatItem:
        """
        Enrich a threat with ASVS control IDs.

        Uses the STRIDE category to look up the canonical ASVS control IDs
        (e.g. 'V2.1.1') and appends them to threat.asvs_controls.
        Falls back to STRIDE-matched controls from the full database if the
        category is unknown.
        """
        if threat.stride_category:
            # Deterministic path: direct STRIDE → ASVS ID lookup
            ids = self.get_asvs_ids_for_stride(threat.stride_category)
            if ids:
                # Merge with any existing controls (avoid duplicates)
                existing = set(threat.asvs_controls or [])
                for cid in ids:
                    if cid not in existing:
                        threat.asvs_controls.append(cid)
                return threat

        # Fallback: match by STRIDE category across full controls database
        matching_controls = self.get_controls_for_threat(threat)
        if not matching_controls:
            return threat

        # Store control IDs (not descriptions)
        existing = set(threat.asvs_controls or [])
        for control in matching_controls[:3]:
            if control.id not in existing:
                threat.asvs_controls.append(control.id)

        return threat
