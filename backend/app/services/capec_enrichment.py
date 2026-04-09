"""
Threat Modeling – CAPEC Attack Pattern Enrichment.

Enriches threats with Common Attack Pattern Enumeration and Classification (CAPEC)
patterns for more detailed attack descriptions and mitigations.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from app.models.threat_modeling import STRIDECategory, ThreatItem


@dataclass
class CAPECPattern:
    """Represents a CAPEC attack pattern."""
    id: str
    name: str
    description: str
    likelihood: str  # "High", "Medium", "Low"
    severity: str    # "High", "Medium", "Low"
    prerequisites: List[str]
    skills_required: str  # "High", "Medium", "Low"
    resources_required: List[str]
    mitigations: List[str]
    related_weaknesses: List[str]
    stride_categories: List[STRIDECategory]

    def matches_threat(self, threat: ThreatItem) -> bool:
        """Check if this CAPEC pattern matches the given threat."""
        # Simple keyword matching - could be enhanced with ML
        threat_text = f"{threat.title} {threat.description}".lower()

        pattern_text = f"{self.name} {self.description}".lower()

        # Check for common keywords
        keywords = [
            "injection", "sql", "xss", "csrf", "authentication", "authorization",
            "encryption", "session", "cookie", "api", "database", "file",
            "upload", "download", "privilege", "escalation", "spoofing",
            "tampering", "repudiation", "disclosure", "denial", "dos"
        ]

        threat_keywords = [kw for kw in keywords if kw in threat_text]
        pattern_keywords = [kw for kw in keywords if kw in pattern_text]

        return len(set(threat_keywords) & set(pattern_keywords)) > 0


class CAPECEnrichmentService:
    """Database of CAPEC patterns."""

    def __init__(self):
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, CAPECPattern]:
        """Load CAPEC patterns. In production, this would load from a database or API."""
        return {
            "CAPEC-1": CAPECPattern(
                id="CAPEC-1",
                name="Accessing Functionality Not Properly Constrained by ACLs",
                description="An attacker attempts to access functionality that is not properly constrained by access control lists.",
                likelihood="High",
                severity="High",
                prerequisites=["The application must be navigable to the attacker"],
                skills_required="Low",
                resources_required=["Ability to navigate to the target application"],
                mitigations=[
                    "Implement proper access controls",
                    "Use role-based access control (RBAC)",
                    "Validate user permissions on every request"
                ],
                related_weaknesses=["CWE-284", "CWE-285", "CWE-287"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-7": CAPECPattern(
                id="CAPEC-7",
                name="Blind SQL Injection",
                description="An attacker attempts to inject SQL code into a vulnerable SQL query.",
                likelihood="High",
                severity="High",
                prerequisites=["SQL queries must be used", "User-controllable input must be incorporated into SQL queries"],
                skills_required="Medium",
                resources_required=["Ability to send HTTP requests"],
                mitigations=[
                    "Use parameterized queries",
                    "Input validation and sanitization",
                    "Use ORM with proper escaping"
                ],
                related_weaknesses=["CWE-89"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-8": CAPECPattern(
                id="CAPEC-8",
                name="Buffer Overflow via Parameter Expansion",
                description="An attacker exploits a buffer overflow condition by causing the target to expand a small parameter into a larger one.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Target must be vulnerable to buffer overflow"],
                skills_required="High",
                resources_required=["Ability to send crafted input"],
                mitigations=[
                    "Input validation",
                    "Use safe string functions",
                    "Address space layout randomization (ASLR)"
                ],
                related_weaknesses=["CWE-119", "CWE-120"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-10": CAPECPattern(
                id="CAPEC-10",
                name="Buffer Overflow via Environment Variables",
                description="An attacker exploits a buffer overflow condition via environment variables.",
                likelihood="Low",
                severity="High",
                prerequisites=["Application uses environment variables unsafely"],
                skills_required="High",
                resources_required=["Ability to set environment variables"],
                mitigations=[
                    "Validate environment variable input",
                    "Use safe string handling functions"
                ],
                related_weaknesses=["CWE-119"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-13": CAPECPattern(
                id="CAPEC-13",
                name="Subverting Environment Variable Values",
                description="An attacker subverts environment variable values to cause the target to use a different path or configuration.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Application relies on environment variables"],
                skills_required="Medium",
                resources_required=["Ability to modify environment variables"],
                mitigations=[
                    "Validate environment variable values",
                    "Use absolute paths",
                    "Restrict environment variable modification"
                ],
                related_weaknesses=["CWE-426", "CWE-427"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-14": CAPECPattern(
                id="CAPEC-14",
                name="Client-side Injection-induced Buffer Overflow",
                description="An attacker exploits a buffer overflow on the client side.",
                likelihood="Low",
                severity="High",
                prerequisites=["Client-side buffer overflow vulnerability"],
                skills_required="High",
                resources_required=["Malicious web content"],
                mitigations=[
                    "Client-side input validation",
                    "Safe memory management"
                ],
                related_weaknesses=["CWE-119"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-15": CAPECPattern(
                id="CAPEC-15",
                name="Command Injection",
                description="An attacker attempts to inject command syntax into a vulnerable application.",
                likelihood="High",
                severity="High",
                prerequisites=["Application executes system commands"],
                skills_required="Medium",
                resources_required=["Ability to send crafted input"],
                mitigations=[
                    "Input validation and sanitization",
                    "Use safe APIs",
                    "Avoid shell execution when possible"
                ],
                related_weaknesses=["CWE-77", "CWE-78"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-16": CAPECPattern(
                id="CAPEC-16",
                name="Dictionary-based Password Attack",
                description="An attacker attempts to guess passwords using a dictionary of common passwords.",
                likelihood="High",
                severity="High",
                prerequisites=["Password-based authentication"],
                skills_required="Low",
                resources_required=["Password dictionary"],
                mitigations=[
                    "Strong password policies",
                    "Account lockout mechanisms",
                    "Multi-factor authentication"
                ],
                related_weaknesses=["CWE-521"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-17": CAPECPattern(
                id="CAPEC-17",
                name="Using Malicious Files",
                description="An attacker uses malicious files to exploit vulnerabilities.",
                likelihood="High",
                severity="High",
                prerequisites=["Application processes files"],
                skills_required="Medium",
                resources_required=["Malicious file"],
                mitigations=[
                    "File type validation",
                    "Content scanning",
                    "Sandboxing"
                ],
                related_weaknesses=["CWE-434"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-19": CAPECPattern(
                id="CAPEC-19",
                name="Embedding Scripts within Scripts",
                description="An attacker embeds scripts within other scripts to execute malicious code.",
                likelihood="High",
                severity="High",
                prerequisites=["Application processes scripts"],
                skills_required="Medium",
                resources_required=["Scripting capability"],
                mitigations=[
                    "Input validation",
                    "Output encoding",
                    "Content Security Policy"
                ],
                related_weaknesses=["CWE-79", "CWE-80"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-22": CAPECPattern(
                id="CAPEC-22",
                name="Exploiting Trust in Client",
                description="An attacker exploits trust relationships between clients and servers.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Trust relationship exists"],
                skills_required="Medium",
                resources_required=["Access to client"],
                mitigations=[
                    "Validate client certificates",
                    "Use mutual TLS",
                    "Server-side validation"
                ],
                related_weaknesses=["CWE-290"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-31": CAPECPattern(
                id="CAPEC-31",
                name="Accessing/Intercepting/Modifying HTTP Cookies",
                description="An attacker accesses, intercepts, or modifies HTTP cookies.",
                likelihood="High",
                severity="Medium",
                prerequisites=["Application uses cookies"],
                skills_required="Low",
                resources_required=["Network access"],
                mitigations=[
                    "Use HttpOnly cookies",
                    "Use Secure cookies",
                    "Implement cookie encryption"
                ],
                related_weaknesses=["CWE-565", "CWE-614"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-33": CAPECPattern(
                id="CAPEC-33",
                name="HTTP Request Smuggling",
                description="An attacker smuggles HTTP requests to bypass security controls.",
                likelihood="Medium",
                severity="High",
                prerequisites=["HTTP proxy or load balancer"],
                skills_required="High",
                resources_required=["Crafted HTTP requests"],
                mitigations=[
                    "Proper HTTP parsing",
                    "Use latest HTTP libraries",
                    "Web Application Firewall (WAF)"
                ],
                related_weaknesses=["CWE-436"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-34": CAPECPattern(
                id="CAPEC-34",
                name="HTTP Response Splitting",
                description="An attacker splits HTTP responses to inject malicious content.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Application reflects user input in HTTP headers"],
                skills_required="Medium",
                resources_required=["Crafted input"],
                mitigations=[
                    "Input validation",
                    "Output encoding",
                    "Use safe HTTP libraries"
                ],
                related_weaknesses=["CWE-113"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-42": CAPECPattern(
                id="CAPEC-42",
                name="MIME Conversion",
                description="An attacker exploits MIME type conversion vulnerabilities.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["MIME type processing"],
                skills_required="Medium",
                resources_required=["Crafted MIME content"],
                mitigations=[
                    "Validate MIME types",
                    "Content validation",
                    "Safe MIME processing"
                ],
                related_weaknesses=["CWE-430"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-43": CAPECPattern(
                id="CAPEC-43",
                name="Exploiting Multiple Input Interpretation Layers",
                description="An attacker exploits differences in input interpretation across layers.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Multiple interpretation layers"],
                skills_required="High",
                resources_required=["Crafted input"],
                mitigations=[
                    "Canonicalize input",
                    "Validate at each layer",
                    "Consistent interpretation"
                ],
                related_weaknesses=["CWE-179"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-59": CAPECPattern(
                id="CAPEC-59",
                name="Session Credential Falsification through Prediction",
                description="An attacker predicts session credentials.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Predictable session IDs"],
                skills_required="Medium",
                resources_required=["Session observation"],
                mitigations=[
                    "Cryptographically secure random session IDs",
                    "Short session timeouts",
                    "Session invalidation on logout"
                ],
                related_weaknesses=["CWE-384"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-60": CAPECPattern(
                id="CAPEC-60",
                name="Session Credential Falsification through Forging",
                description="An attacker forges session credentials.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Weak session management"],
                skills_required="Medium",
                resources_required=["Session capture"],
                mitigations=[
                    "Use secure session management",
                    "Implement session fixation protection",
                    "Use HttpOnly and Secure flags"
                ],
                related_weaknesses=["CWE-384"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-62": CAPECPattern(
                id="CAPEC-62",
                name="Cross Site Request Forgery",
                description="An attacker tricks a user into performing unwanted actions.",
                likelihood="High",
                severity="Medium",
                prerequisites=["State-changing operations"],
                skills_required="Medium",
                resources_required=["Malicious website"],
                mitigations=[
                    "CSRF tokens",
                    "SameSite cookies",
                    "Referer validation"
                ],
                related_weaknesses=["CWE-352"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-63": CAPECPattern(
                id="CAPEC-63",
                name="Simple Script Injection",
                description="An attacker injects scripts into web pages.",
                likelihood="High",
                severity="High",
                prerequisites=["Reflected user input"],
                skills_required="Low",
                resources_required=["Script injection payload"],
                mitigations=[
                    "Input validation",
                    "Output encoding",
                    "Content Security Policy"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-64": CAPECPattern(
                id="CAPEC-64",
                name="Using Slashes and URL Encoding Combined to Bypass Validation Logic",
                description="An attacker uses encoding to bypass input validation.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Input validation"],
                skills_required="Medium",
                resources_required=["URL encoding knowledge"],
                mitigations=[
                    "Decode before validation",
                    "Canonicalize input",
                    "Use whitelist validation"
                ],
                related_weaknesses=["CWE-180"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-66": CAPECPattern(
                id="CAPEC-66",
                name="SQL Injection",
                description="An attacker injects SQL code into queries.",
                likelihood="High",
                severity="High",
                prerequisites=["SQL queries with user input"],
                skills_required="Medium",
                resources_required=["SQL knowledge"],
                mitigations=[
                    "Parameterized queries",
                    "Input validation",
                    "Use ORM"
                ],
                related_weaknesses=["CWE-89"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-67": CAPECPattern(
                id="CAPEC-67",
                name="String Format Overflow in syslog()",
                description="An attacker exploits format string vulnerabilities in syslog.",
                likelihood="Low",
                severity="High",
                prerequisites=["syslog usage"],
                skills_required="High",
                resources_required=["Format string knowledge"],
                mitigations=[
                    "Safe format functions",
                    "Input validation"
                ],
                related_weaknesses=["CWE-134"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-78": CAPECPattern(
                id="CAPEC-78",
                name="Using GET to Bypass Access Control",
                description="An attacker uses GET instead of POST to bypass controls.",
                likelihood="Low",
                severity="Low",
                prerequisites=["Method-based access control"],
                skills_required="Low",
                resources_required=["HTTP client"],
                mitigations=[
                    "Method-independent authorization",
                    "Proper access controls"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-79": CAPECPattern(
                id="CAPEC-79",
                name="Using XSS to Hijack the Session",
                description="An attacker uses XSS to steal session cookies.",
                likelihood="High",
                severity="High",
                prerequisites=["XSS vulnerability"],
                skills_required="Medium",
                resources_required=["XSS payload"],
                mitigations=[
                    "Input validation",
                    "Output encoding",
                    "HttpOnly cookies"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.SPOOFING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-80": CAPECPattern(
                id="CAPEC-80",
                name="Using Script to Compromise the Client",
                description="An attacker uses scripts to compromise client systems.",
                likelihood="High",
                severity="High",
                prerequisites=["Client-side scripting"],
                skills_required="Medium",
                resources_required=["Malicious script"],
                mitigations=[
                    "Input validation",
                    "Content Security Policy",
                    "Safe JavaScript practices"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-81": CAPECPattern(
                id="CAPEC-81",
                name="Web Logs Tampering",
                description="An attacker tampers with web server logs.",
                likelihood="Low",
                severity="Low",
                prerequisites=["Log file access"],
                skills_required="Medium",
                resources_required=["File system access"],
                mitigations=[
                    "Log integrity protection",
                    "Secure log storage",
                    "Log monitoring"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.REPUDIATION]
            ),
            "CAPEC-83": CAPECPattern(
                id="CAPEC-83",
                name="XPath Injection",
                description="An attacker injects XPath expressions.",
                likelihood="Medium",
                severity="High",
                prerequisites=["XPath queries"],
                skills_required="Medium",
                resources_required=["XPath knowledge"],
                mitigations=[
                    "Parameterized XPath",
                    "Input validation"
                ],
                related_weaknesses=["CWE-643"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-84": CAPECPattern(
                id="CAPEC-84",
                name="XQuery Injection",
                description="An attacker injects XQuery expressions.",
                likelihood="Low",
                severity="High",
                prerequisites=["XQuery usage"],
                skills_required="Medium",
                resources_required=["XQuery knowledge"],
                mitigations=[
                    "Parameterized queries",
                    "Input validation"
                ],
                related_weaknesses=["CWE-643"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-85": CAPECPattern(
                id="CAPEC-85",
                name="AJAX Footprinting",
                description="An attacker enumerates AJAX endpoints.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["AJAX usage"],
                skills_required="Low",
                resources_required=["Web browser"],
                mitigations=[
                    "Minimize exposed endpoints",
                    "Authentication for sensitive endpoints"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-86": CAPECPattern(
                id="CAPEC-86",
                name="Embedding NULL Bytes",
                description="An attacker embeds NULL bytes to bypass validation.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["String processing"],
                skills_required="Medium",
                resources_required=["NULL byte knowledge"],
                mitigations=[
                    "Proper string handling",
                    "Validate all input"
                ],
                related_weaknesses=["CWE-626"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-87": CAPECPattern(
                id="CAPEC-87",
                name="Forceful Browsing",
                description="An attacker browses to unauthorized pages.",
                likelihood="High",
                severity="Medium",
                prerequisites=["Hidden URLs"],
                skills_required="Low",
                resources_required=["Web browser"],
                mitigations=[
                    "Proper authorization",
                    "URL randomization",
                    "Access control"
                ],
                related_weaknesses=["CWE-425"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-88": CAPECPattern(
                id="CAPEC-88",
                name="OS Command Injection",
                description="An attacker injects OS commands.",
                likelihood="High",
                severity="High",
                prerequisites=["OS command execution"],
                skills_required="Medium",
                resources_required=["Command injection payload"],
                mitigations=[
                    "Avoid shell execution",
                    "Input validation",
                    "Use safe APIs"
                ],
                related_weaknesses=["CWE-78"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-89": CAPECPattern(
                id="CAPEC-89",
                name="Phishing",
                description="An attacker tricks users into revealing credentials.",
                likelihood="High",
                severity="High",
                prerequisites=["User interaction"],
                skills_required="Medium",
                resources_required=["Phishing website"],
                mitigations=[
                    "User education",
                    "Multi-factor authentication",
                    "Anti-phishing tools"
                ],
                related_weaknesses=["CWE-352"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-90": CAPECPattern(
                id="CAPEC-90",
                name="Reflection Injection",
                description="An attacker injects reflection-based attacks.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Reflection usage"],
                skills_required="High",
                resources_required=["Reflection knowledge"],
                mitigations=[
                    "Avoid runtime reflection",
                    "Input validation"
                ],
                related_weaknesses=["CWE-470"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-92": CAPECPattern(
                id="CAPEC-92",
                name="Forced Integer Overflow",
                description="An attacker forces integer overflow conditions.",
                likelihood="Low",
                severity="High",
                prerequisites=["Integer arithmetic"],
                skills_required="High",
                resources_required=["Integer overflow knowledge"],
                mitigations=[
                    "Safe integer operations",
                    "Bounds checking"
                ],
                related_weaknesses=["CWE-190"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-93": CAPECPattern(
                id="CAPEC-93",
                name="Log Injection-Tampering-Forging",
                description="An attacker injects malicious content into logs.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Log processing"],
                skills_required="Medium",
                resources_required=["Log injection payload"],
                mitigations=[
                    "Log sanitization",
                    "Safe logging functions"
                ],
                related_weaknesses=["CWE-117"],
                stride_categories=[STRIDECategory.REPUDIATION, STRIDECategory.TAMPERING]
            ),
            "CAPEC-94": CAPECPattern(
                id="CAPEC-94",
                name="Man in the Middle Attack",
                description="An attacker intercepts communications.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Network communication"],
                skills_required="Medium",
                resources_required=["Network position"],
                mitigations=[
                    "Encryption (TLS)",
                    "Certificate pinning",
                    "Mutual authentication"
                ],
                related_weaknesses=["CWE-300"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-95": CAPECPattern(
                id="CAPEC-95",
                name="WSDL Scanning",
                description="An attacker scans WSDL files for information.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["SOAP web services"],
                skills_required="Low",
                resources_required=["Web browser"],
                mitigations=[
                    "Restrict WSDL access",
                    "Use authentication"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-96": CAPECPattern(
                id="CAPEC-96",
                name="Block Access to Libraries",
                description="An attacker blocks access to required libraries.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["External library dependencies"],
                skills_required="Medium",
                resources_required=["Network control"],
                mitigations=[
                    "Local library caching",
                    "Alternative sources"
                ],
                related_weaknesses=["CWE-350"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-97": CAPECPattern(
                id="CAPEC-97",
                name="Cryptanalysis of Encrypted Data",
                description="An attacker cryptanalyzes encrypted data.",
                likelihood="Low",
                severity="High",
                prerequisites=["Weak encryption"],
                skills_required="High",
                resources_required=["Cryptanalysis tools"],
                mitigations=[
                    "Strong encryption algorithms",
                    "Proper key management"
                ],
                related_weaknesses=["CWE-326"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-98": CAPECPattern(
                id="CAPEC-98",
                name="Phishing via Shortened URLs",
                description="An attacker uses URL shortening for phishing.",
                likelihood="High",
                severity="High",
                prerequisites=["URL shortening services"],
                skills_required="Low",
                resources_required=["URL shortener"],
                mitigations=[
                    "URL validation",
                    "User education",
                    "Link preview"
                ],
                related_weaknesses=["CWE-451"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-99": CAPECPattern(
                id="CAPEC-99",
                name="XML Parser Attack",
                description="An attacker exploits XML parser vulnerabilities.",
                likelihood="Medium",
                severity="High",
                prerequisites=["XML processing"],
                skills_required="Medium",
                resources_required=["XML payload"],
                mitigations=[
                    "Safe XML parsing",
                    "Disable external entities",
                    "Input validation"
                ],
                related_weaknesses=["CWE-611"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-100": CAPECPattern(
                id="CAPEC-100",
                name="Overflow Binary Resource File",
                description="An attacker overflows binary resource files.",
                likelihood="Low",
                severity="High",
                prerequisites=["Binary file processing"],
                skills_required="High",
                resources_required=["Malicious binary file"],
                mitigations=[
                    "File validation",
                    "Safe parsing libraries"
                ],
                related_weaknesses=["CWE-119"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-101": CAPECPattern(
                id="CAPEC-101",
                name="Server Side Include (SSI) Injection",
                description="An attacker injects SSI directives.",
                likelihood="Medium",
                severity="High",
                prerequisites=["SSI processing"],
                skills_required="Medium",
                resources_required=["SSI payload"],
                mitigations=[
                    "Disable SSI",
                    "Input validation"
                ],
                related_weaknesses=["CWE-97"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-102": CAPECPattern(
                id="CAPEC-102",
                name="Session Sidejacking",
                description="An attacker steals session cookies.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Cookie-based sessions"],
                skills_required="Medium",
                resources_required=["Network access"],
                mitigations=[
                    "Use HTTPS",
                    "HttpOnly cookies",
                    "Session timeout"
                ],
                related_weaknesses=["CWE-614"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-103": CAPECPattern(
                id="CAPEC-103",
                name="Clickjacking",
                description="An attacker tricks users into clicking hidden elements.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Interactive web content"],
                skills_required="Medium",
                resources_required=["HTML/CSS knowledge"],
                mitigations=[
                    "X-Frame-Options header",
                    "Content Security Policy",
                    "Frame busting code"
                ],
                related_weaknesses=["CWE-693"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-104": CAPECPattern(
                id="CAPEC-104",
                name="Cross Zone Scripting",
                description="An attacker exploits cross-zone scripting vulnerabilities.",
                likelihood="Low",
                severity="High",
                prerequisites=["Zone-based security"],
                skills_required="High",
                resources_required=["Scripting knowledge"],
                mitigations=[
                    "Zone isolation",
                    "Input validation"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-105": CAPECPattern(
                id="CAPEC-105",
                name="HTTP Request Splitting",
                description="An attacker splits HTTP requests.",
                likelihood="Medium",
                severity="High",
                prerequisites=["HTTP header processing"],
                skills_required="High",
                resources_required=["HTTP knowledge"],
                mitigations=[
                    "Safe HTTP libraries",
                    "Input validation"
                ],
                related_weaknesses=["CWE-113"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-106": CAPECPattern(
                id="CAPEC-106",
                name="Cross Site Scripting through Log Files",
                description="An attacker injects XSS through log files.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Log file viewing"],
                skills_required="Medium",
                resources_required=["XSS payload"],
                mitigations=[
                    "Log sanitization",
                    "Safe log viewing"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-107": CAPECPattern(
                id="CAPEC-107",
                name="Cross Site Tracing",
                description="An attacker uses TRACE method for XSS.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["TRACE method enabled"],
                skills_required="Low",
                resources_required=["HTTP client"],
                mitigations=[
                    "Disable TRACE method",
                    "Web Application Firewall"
                ],
                related_weaknesses=["CWE-693"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-108": CAPECPattern(
                id="CAPEC-108",
                name="Command Line Execution through SQL Injection",
                description="An attacker executes commands through SQL injection.",
                likelihood="Low",
                severity="High",
                prerequisites=["SQL injection + command execution"],
                skills_required="High",
                resources_required=["SQL and command knowledge"],
                mitigations=[
                    "Parameterized queries",
                    "Disable command execution in DB"
                ],
                related_weaknesses=["CWE-89"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-109": CAPECPattern(
                id="CAPEC-109",
                name="Object Relational Mapping Injection",
                description="An attacker exploits ORM injection vulnerabilities.",
                likelihood="Medium",
                severity="High",
                prerequisites=["ORM usage"],
                skills_required="Medium",
                resources_required=["ORM knowledge"],
                mitigations=[
                    "Safe ORM usage",
                    "Input validation"
                ],
                related_weaknesses=["CWE-89"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-110": CAPECPattern(
                id="CAPEC-110",
                name="SQL Injection through SOAP Parameter Tampering",
                description="An attacker injects SQL through SOAP parameters.",
                likelihood="Medium",
                severity="High",
                prerequisites=["SOAP web services"],
                skills_required="Medium",
                resources_required=["SOAP and SQL knowledge"],
                mitigations=[
                    "SOAP validation",
                    "Parameterized queries"
                ],
                related_weaknesses=["CWE-89"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-111": CAPECPattern(
                id="CAPEC-111",
                name="JSON Hijacking (aka JavaScript Hijacking)",
                description="An attacker steals JSON data through script tags.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["JSON endpoints"],
                skills_required="Medium",
                resources_required=["Script tag"],
                mitigations=[
                    "Content-Type validation",
                    "CSRF protection",
                    "Authentication required"
                ],
                related_weaknesses=["CWE-352"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-112": CAPECPattern(
                id="CAPEC-112",
                name="Brute Force",
                description="An attacker attempts brute force attacks.",
                likelihood="High",
                severity="High",
                prerequisites=["Authentication system"],
                skills_required="Low",
                resources_required=["Automated tools"],
                mitigations=[
                    "Account lockout",
                    "Rate limiting",
                    "Multi-factor authentication"
                ],
                related_weaknesses=["CWE-307"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-113": CAPECPattern(
                id="CAPEC-113",
                name="API Manipulation",
                description="An attacker manipulates API calls.",
                likelihood="Medium",
                severity="High",
                prerequisites=["API usage"],
                skills_required="Medium",
                resources_required=["API knowledge"],
                mitigations=[
                    "API authentication",
                    "Input validation",
                    "Rate limiting"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-114": CAPECPattern(
                id="CAPEC-114",
                name="Authentication Bypass via SNMP Community String",
                description="An attacker bypasses authentication using SNMP.",
                likelihood="Low",
                severity="High",
                prerequisites=["SNMP usage"],
                skills_required="Medium",
                resources_required=["SNMP tools"],
                mitigations=[
                    "Strong community strings",
                    "SNMP v3",
                    "Network segmentation"
                ],
                related_weaknesses=["CWE-798"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-115": CAPECPattern(
                id="CAPEC-115",
                name="Authentication Bypass via SNMP Community String",
                description="An attacker bypasses authentication using SNMP.",
                likelihood="Low",
                severity="High",
                prerequisites=["SNMP usage"],
                skills_required="Medium",
                resources_required=["SNMP tools"],
                mitigations=[
                    "Strong community strings",
                    "SNMP v3",
                    "Network segmentation"
                ],
                related_weaknesses=["CWE-798"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-116": CAPECPattern(
                id="CAPEC-116",
                name="Excavation",
                description="An attacker excavates information from responses.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Verbose error messages"],
                skills_required="Low",
                resources_required=["Web browser"],
                mitigations=[
                    "Generic error messages",
                    "Disable debugging in production"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-117": CAPECPattern(
                id="CAPEC-117",
                name="Interception",
                description="An attacker intercepts communications.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Unencrypted communication"],
                skills_required="Medium",
                resources_required=["Network access"],
                mitigations=[
                    "Encryption",
                    "Secure protocols"
                ],
                related_weaknesses=["CWE-319"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-118": CAPECPattern(
                id="CAPEC-118",
                name="Caching",
                description="An attacker exploits caching mechanisms.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Caching enabled"],
                skills_required="Medium",
                resources_required=["Cache knowledge"],
                mitigations=[
                    "Cache validation",
                    "Secure cache keys"
                ],
                related_weaknesses=["CWE-524"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-119": CAPECPattern(
                id="CAPEC-119",
                name="Data Encoding",
                description="An attacker exploits data encoding weaknesses.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Data encoding"],
                skills_required="Medium",
                resources_required=["Encoding knowledge"],
                mitigations=[
                    "Canonicalize input",
                    "Validate encoding"
                ],
                related_weaknesses=["CWE-179"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-120": CAPECPattern(
                id="CAPEC-120",
                name="Double Encoding",
                description="An attacker uses double encoding to bypass filters.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Input filtering"],
                skills_required="Medium",
                resources_required=["Encoding knowledge"],
                mitigations=[
                    "Decode multiple times",
                    "Canonicalize input"
                ],
                related_weaknesses=["CWE-179"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-121": CAPECPattern(
                id="CAPEC-121",
                name="Lockout Mechanism Bypass",
                description="An attacker bypasses account lockout mechanisms.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Account lockout"],
                skills_required="Medium",
                resources_required=["Multiple accounts"],
                mitigations=[
                    "IP-based lockout",
                    "Progressive delays",
                    "CAPTCHA"
                ],
                related_weaknesses=["CWE-307"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-122": CAPECPattern(
                id="CAPEC-122",
                name="Privilege Abuse",
                description="An attacker abuses legitimate privileges.",
                likelihood="High",
                severity="High",
                prerequisites=["User privileges"],
                skills_required="Low",
                resources_required=["Valid account"],
                mitigations=[
                    "Principle of least privilege",
                    "Privilege separation",
                    "Audit logging"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-123": CAPECPattern(
                id="CAPEC-123",
                name="Session Replay",
                description="An attacker replays captured session data.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Session-based auth"],
                skills_required="Medium",
                resources_required=["Session capture"],
                mitigations=[
                    "Session expiration",
                    "One-time tokens",
                    "Mutual authentication"
                ],
                related_weaknesses=["CWE-294"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-124": CAPECPattern(
                id="CAPEC-124",
                name="Shared Resource Manipulation",
                description="An attacker manipulates shared resources.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Shared resources"],
                skills_required="Medium",
                resources_required=["Resource access"],
                mitigations=[
                    "Resource locking",
                    "Synchronization",
                    "Input validation"
                ],
                related_weaknesses=["CWE-362"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-125": CAPECPattern(
                id="CAPEC-125",
                name="Flooding",
                description="An attacker floods the system with requests.",
                likelihood="High",
                severity="High",
                prerequisites=["Network service"],
                skills_required="Low",
                resources_required=["Automated tools"],
                mitigations=[
                    "Rate limiting",
                    "Traffic filtering",
                    "Load balancing"
                ],
                related_weaknesses=["CWE-400"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-126": CAPECPattern(
                id="CAPEC-126",
                name="Path Traversal",
                description="An attacker traverses file system paths.",
                likelihood="High",
                severity="High",
                prerequisites=["File system access"],
                skills_required="Low",
                resources_required=["Path traversal payload"],
                mitigations=[
                    "Input validation",
                    "Path canonicalization",
                    "Chroot jails"
                ],
                related_weaknesses=["CWE-22"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING]
            ),
            "CAPEC-127": CAPECPattern(
                id="CAPEC-127",
                name="Directory Indexing",
                description="An attacker exploits directory indexing.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Directory listing enabled"],
                skills_required="Low",
                resources_required=["Web browser"],
                mitigations=[
                    "Disable directory indexing",
                    "Access controls"
                ],
                related_weaknesses=["CWE-548"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-128": CAPECPattern(
                id="CAPEC-128",
                name="Integer Attacks",
                description="An attacker exploits integer vulnerabilities.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Integer operations"],
                skills_required="High",
                resources_required=["Integer overflow knowledge"],
                mitigations=[
                    "Safe integer operations",
                    "Bounds checking"
                ],
                related_weaknesses=["CWE-190"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-129": CAPECPattern(
                id="CAPEC-129",
                name="Pointer Manipulation",
                description="An attacker manipulates pointers.",
                likelihood="Low",
                severity="High",
                prerequisites=["Pointer usage"],
                skills_required="High",
                resources_required=["Memory knowledge"],
                mitigations=[
                    "Safe pointer operations",
                    "Memory-safe languages"
                ],
                related_weaknesses=["CWE-119"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-130": CAPECPattern(
                id="CAPEC-130",
                name="Excessive Allocation",
                description="An attacker causes excessive resource allocation.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Dynamic allocation"],
                skills_required="Medium",
                resources_required=["Large input"],
                mitigations=[
                    "Resource limits",
                    "Input validation"
                ],
                related_weaknesses=["CWE-400"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-131": CAPECPattern(
                id="CAPEC-131",
                name="Resource Leak Exposure",
                description="An attacker exploits resource leaks.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Resource management"],
                skills_required="Medium",
                resources_required=["Repeated requests"],
                mitigations=[
                    "Proper resource cleanup",
                    "Resource monitoring"
                ],
                related_weaknesses=["CWE-404"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-132": CAPECPattern(
                id="CAPEC-132",
                name="Symlink Attack",
                description="An attacker uses symbolic links maliciously.",
                likelihood="Low",
                severity="High",
                prerequisites=["File system access"],
                skills_required="Medium",
                resources_required=["Symlink creation"],
                mitigations=[
                    "Validate paths",
                    "Use safe APIs"
                ],
                related_weaknesses=["CWE-59"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-133": CAPECPattern(
                id="CAPEC-133",
                name="Try All Common Switches",
                description="An attacker tries common configuration switches.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Configuration options"],
                skills_required="Low",
                resources_required=["Common switch knowledge"],
                mitigations=[
                    "Hide configuration",
                    "Access controls"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-134": CAPECPattern(
                id="CAPEC-134",
                name="Email Injection",
                description="An attacker injects malicious email content.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Email functionality"],
                skills_required="Medium",
                resources_required=["Email injection payload"],
                mitigations=[
                    "Email validation",
                    "Safe email libraries"
                ],
                related_weaknesses=["CWE-150"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-135": CAPECPattern(
                id="CAPEC-135",
                name="Format String Injection",
                description="An attacker injects format strings.",
                likelihood="Low",
                severity="High",
                prerequisites=["Format functions"],
                skills_required="High",
                resources_required=["Format string knowledge"],
                mitigations=[
                    "Safe format functions",
                    "Input validation"
                ],
                related_weaknesses=["CWE-134"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-136": CAPECPattern(
                id="CAPEC-136",
                name="LDAP Injection",
                description="An attacker injects LDAP queries.",
                likelihood="Medium",
                severity="High",
                prerequisites=["LDAP usage"],
                skills_required="Medium",
                resources_required=["LDAP knowledge"],
                mitigations=[
                    "LDAP encoding",
                    "Input validation"
                ],
                related_weaknesses=["CWE-90"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-137": CAPECPattern(
                id="CAPEC-137",
                name="Parameter Injection",
                description="An attacker injects parameters.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Parameter processing"],
                skills_required="Medium",
                resources_required=["Parameter knowledge"],
                mitigations=[
                    "Parameter validation",
                    "Safe parameter handling"
                ],
                related_weaknesses=["CWE-88"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-138": CAPECPattern(
                id="CAPEC-138",
                name="Reflection Injection",
                description="An attacker injects reflection-based attacks.",
                likelihood="Low",
                severity="High",
                prerequisites=["Reflection usage"],
                skills_required="High",
                resources_required=["Reflection knowledge"],
                mitigations=[
                    "Avoid runtime reflection",
                    "Input validation"
                ],
                related_weaknesses=["CWE-470"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-139": CAPECPattern(
                id="CAPEC-139",
                name="Relative Path Traversal",
                description="An attacker uses relative paths to traverse directories.",
                likelihood="Medium",
                severity="High",
                prerequisites=["File access"],
                skills_required="Low",
                resources_required=["Path traversal payload"],
                mitigations=[
                    "Path validation",
                    "Canonicalize paths"
                ],
                related_weaknesses=["CWE-23"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING]
            ),
            "CAPEC-140": CAPECPattern(
                id="CAPEC-140",
                name="Genetic Algorithm Attacks",
                description="An attacker uses genetic algorithms to crack systems.",
                likelihood="Low",
                severity="High",
                prerequisites=["Weak authentication"],
                skills_required="High",
                resources_required=["Genetic algorithm tools"],
                mitigations=[
                    "Strong passwords",
                    "Multi-factor authentication"
                ],
                related_weaknesses=["CWE-521"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-141": CAPECPattern(
                id="CAPEC-141",
                name="Cache Poisoning",
                description="An attacker poisons cache entries.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Caching"],
                skills_required="Medium",
                resources_required=["Cache knowledge"],
                mitigations=[
                    "Cache validation",
                    "Secure cache keys"
                ],
                related_weaknesses=["CWE-524"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-142": CAPECPattern(
                id="CAPEC-142",
                name="DNS Cache Poisoning",
                description="An attacker poisons DNS cache.",
                likelihood="Low",
                severity="High",
                prerequisites=["DNS caching"],
                skills_required="High",
                resources_required=["DNS spoofing tools"],
                mitigations=[
                    "DNSSEC",
                    "Secure DNS resolvers"
                ],
                related_weaknesses=["CWE-350"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-143": CAPECPattern(
                id="CAPEC-143",
                name="Detecting Target Using Port Scanning",
                description="An attacker scans for open ports.",
                likelihood="High",
                severity="Low",
                prerequisites=["Network service"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-144": CAPECPattern(
                id="CAPEC-144",
                name="Detecting Target Using Packet Sniffing",
                description="An attacker sniffs network packets.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Network traffic"],
                skills_required="Medium",
                resources_required=["Packet sniffer"],
                mitigations=[
                    "Encryption",
                    "Network segmentation"
                ],
                related_weaknesses=["CWE-319"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-145": CAPECPattern(
                id="CAPEC-145",
                name="Checksum Spoofing",
                description="An attacker spoofs checksums.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Checksum validation"],
                skills_required="High",
                resources_required=["Checksum knowledge"],
                mitigations=[
                    "Cryptographic hashes",
                    "Secure checksums"
                ],
                related_weaknesses=["CWE-353"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-146": CAPECPattern(
                id="CAPEC-146",
                name="IP Address Spoofing",
                description="An attacker spoofs IP addresses.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["IP-based authentication"],
                skills_required="Medium",
                resources_required=["IP spoofing tools"],
                mitigations=[
                    "Mutual authentication",
                    "Avoid IP-based auth"
                ],
                related_weaknesses=["CWE-290"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-147": CAPECPattern(
                id="CAPEC-147",
                name="XML Ping of the Death",
                description="An attacker sends malicious XML to cause DoS.",
                likelihood="Low",
                severity="High",
                prerequisites=["XML processing"],
                skills_required="Medium",
                resources_required=["Large XML"],
                mitigations=[
                    "XML size limits",
                    "Safe XML parsers"
                ],
                related_weaknesses=["CWE-400"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-148": CAPECPattern(
                id="CAPEC-148",
                name="Content Spoofing",
                description="An attacker spoofs content.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Content display"],
                skills_required="Low",
                resources_required=["HTML knowledge"],
                mitigations=[
                    "Content validation",
                    "Output encoding"
                ],
                related_weaknesses=["CWE-451"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-149": CAPECPattern(
                id="CAPEC-149",
                name="EMBED Tag Manipulation",
                description="An attacker manipulates EMBED tags.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["EMBED tag usage"],
                skills_required="Medium",
                resources_required=["HTML knowledge"],
                mitigations=[
                    "Validate EMBED sources",
                    "Content Security Policy"
                ],
                related_weaknesses=["CWE-451"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-150": CAPECPattern(
                id="CAPEC-150",
                name="OBJECT Tag Manipulation",
                description="An attacker manipulates OBJECT tags.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["OBJECT tag usage"],
                skills_required="Medium",
                resources_required=["HTML knowledge"],
                mitigations=[
                    "Validate OBJECT sources",
                    "Content Security Policy"
                ],
                related_weaknesses=["CWE-451"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-151": CAPECPattern(
                id="CAPEC-151",
                name="Identity Spoofing via Wireless Access Point Name",
                description="An attacker spoofs wireless access points.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Wireless network"],
                skills_required="Medium",
                resources_required=["Wireless tools"],
                mitigations=[
                    "WPA3",
                    "Certificate validation"
                ],
                related_weaknesses=["CWE-290"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-152": CAPECPattern(
                id="CAPEC-152",
                name="Remote Deployment of Malicious Software",
                description="An attacker deploys malicious software remotely.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Remote deployment capability"],
                skills_required="Medium",
                resources_required=["Malicious software"],
                mitigations=[
                    "Code signing",
                    "Secure deployment channels"
                ],
                related_weaknesses=["CWE-506"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-153": CAPECPattern(
                id="CAPEC-153",
                name="Input Data Manipulation",
                description="An attacker manipulates input data.",
                likelihood="High",
                severity="High",
                prerequisites=["Data processing"],
                skills_required="Medium",
                resources_required=["Input manipulation"],
                mitigations=[
                    "Input validation",
                    "Data integrity checks"
                ],
                related_weaknesses=["CWE-20"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-154": CAPECPattern(
                id="CAPEC-154",
                name="Resource Location Spoofing",
                description="An attacker spoofs resource locations.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Resource loading"],
                skills_required="Medium",
                resources_required=["URL manipulation"],
                mitigations=[
                    "URL validation",
                    "Content Security Policy"
                ],
                related_weaknesses=["CWE-451"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-155": CAPECPattern(
                id="CAPEC-155",
                name="Screen Temporary Files for Sensitive Information",
                description="An attacker screens temp files for sensitive data.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Temp file usage"],
                skills_required="Low",
                resources_required=["File system access"],
                mitigations=[
                    "Secure temp files",
                    "Clean up temp files"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-156": CAPECPattern(
                id="CAPEC-156",
                name="Using Malicious Files",
                description="An attacker uses malicious files.",
                likelihood="High",
                severity="High",
                prerequisites=["File processing"],
                skills_required="Medium",
                resources_required=["Malicious file"],
                mitigations=[
                    "File validation",
                    "Content scanning"
                ],
                related_weaknesses=["CWE-434"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-157": CAPECPattern(
                id="CAPEC-157",
                name="Sniffing Attacks",
                description="An attacker sniffs network traffic.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Network traffic"],
                skills_required="Medium",
                resources_required=["Sniffer tools"],
                mitigations=[
                    "Encryption",
                    "Secure protocols"
                ],
                related_weaknesses=["CWE-319"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-158": CAPECPattern(
                id="CAPEC-158",
                name="Sniffing Network Traffic",
                description="An attacker sniffs network traffic.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Network traffic"],
                skills_required="Medium",
                resources_required=["Sniffer tools"],
                mitigations=[
                    "Encryption",
                    "Secure protocols"
                ],
                related_weaknesses=["CWE-319"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-159": CAPECPattern(
                id="CAPEC-159",
                name="Redirect Access to Libraries",
                description="An attacker redirects library access.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Library loading"],
                skills_required="Medium",
                resources_required=["Library manipulation"],
                mitigations=[
                    "Secure library paths",
                    "Code signing"
                ],
                related_weaknesses=["CWE-426"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-160": CAPECPattern(
                id="CAPEC-160",
                name="Exploit Script-Based APIs",
                description="An attacker exploits script-based APIs.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Script APIs"],
                skills_required="Medium",
                resources_required=["Script knowledge"],
                mitigations=[
                    "API validation",
                    "Secure scripting"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-161": CAPECPattern(
                id="CAPEC-161",
                name="Infrastructure Manipulation",
                description="An attacker manipulates infrastructure.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Infrastructure access"],
                skills_required="High",
                resources_required=["Infrastructure knowledge"],
                mitigations=[
                    "Infrastructure security",
                    "Access controls"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-162": CAPECPattern(
                id="CAPEC-162",
                name="Manipulating Hidden Fields",
                description="An attacker manipulates hidden form fields.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Web forms"],
                skills_required="Low",
                resources_required=["Browser dev tools"],
                mitigations=[
                    "Server-side validation",
                    "Cryptographic signatures"
                ],
                related_weaknesses=["CWE-472"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-163": CAPECPattern(
                id="CAPEC-163",
                name="Spear Phishing",
                description="An attacker uses targeted phishing.",
                likelihood="High",
                severity="High",
                prerequisites=["Email communication"],
                skills_required="Medium",
                resources_required=["Target research"],
                mitigations=[
                    "User training",
                    "Email filtering",
                    "Multi-factor authentication"
                ],
                related_weaknesses=["CWE-352"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-164": CAPECPattern(
                id="CAPEC-164",
                name="XML Schema Poisoning",
                description="An attacker poisons XML schemas.",
                likelihood="Low",
                severity="High",
                prerequisites=["XML schema usage"],
                skills_required="High",
                resources_required=["XML knowledge"],
                mitigations=[
                    "Schema validation",
                    "Secure schema storage"
                ],
                related_weaknesses=["CWE-611"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-165": CAPECPattern(
                id="CAPEC-165",
                name="File Manipulation",
                description="An attacker manipulates files.",
                likelihood="Medium",
                severity="High",
                prerequisites=["File access"],
                skills_required="Medium",
                resources_required=["File system access"],
                mitigations=[
                    "File permissions",
                    "Integrity checks"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-166": CAPECPattern(
                id="CAPEC-166",
                name="Force Use of Corrupted Files",
                description="An attacker forces use of corrupted files.",
                likelihood="Low",
                severity="High",
                prerequisites=["File processing"],
                skills_required="High",
                resources_required=["File corruption"],
                mitigations=[
                    "File integrity checks",
                    "Backup validation"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-167": CAPECPattern(
                id="CAPEC-167",
                name="White Box Reverse Engineering",
                description="An attacker reverse engineers the system.",
                likelihood="Low",
                severity="High",
                prerequisites=["Access to binaries"],
                skills_required="High",
                resources_required=["Reverse engineering tools"],
                mitigations=[
                    "Code obfuscation",
                    "Anti-debugging",
                    "Legal protections"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-168": CAPECPattern(
                id="CAPEC-168",
                name="Windows ::DATA Alternate Data Stream",
                description="An attacker uses alternate data streams.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Windows NTFS"],
                skills_required="Medium",
                resources_required=["ADS knowledge"],
                mitigations=[
                    "ADS scanning",
                    "File system monitoring"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-169": CAPECPattern(
                id="CAPEC-169",
                name="Footprinting",
                description="An attacker gathers system information.",
                likelihood="High",
                severity="Low",
                prerequisites=["Public information"],
                skills_required="Low",
                resources_required=["Search engines"],
                mitigations=[
                    "Minimize information disclosure",
                    "Security through obscurity"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-170": CAPECPattern(
                id="CAPEC-170",
                name="Web Application Fingerprinting",
                description="An attacker fingerprints web applications.",
                likelihood="High",
                severity="Low",
                prerequisites=["Web application"],
                skills_required="Low",
                resources_required=["Web browser"],
                mitigations=[
                    "Generic responses",
                    "Web Application Firewall"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-171": CAPECPattern(
                id="CAPEC-171",
                name="Distributed Denial of Service",
                description="An attacker performs DDoS attacks.",
                likelihood="High",
                severity="High",
                prerequisites=["Network service"],
                skills_required="Medium",
                resources_required=["Botnet"],
                mitigations=[
                    "DDoS protection",
                    "Traffic filtering",
                    "Load balancing"
                ],
                related_weaknesses=["CWE-400"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-172": CAPECPattern(
                id="CAPEC-172",
                name="Blended Attack",
                description="An attacker combines multiple attack vectors.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Multiple vulnerabilities"],
                skills_required="High",
                resources_required=["Multiple tools"],
                mitigations=[
                    "Defense in depth",
                    "Comprehensive security"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-173": CAPECPattern(
                id="CAPEC-173",
                name="Action Spoofing",
                description="An attacker spoofs user actions.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["User interface"],
                skills_required="Medium",
                resources_required=["UI manipulation"],
                mitigations=[
                    "Action verification",
                    "Secure UI design"
                ],
                related_weaknesses=["CWE-451"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-174": CAPECPattern(
                id="CAPEC-174",
                name="Flash Parameter Injection",
                description="An attacker injects Flash parameters.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Flash content"],
                skills_required="Medium",
                resources_required=["Flash knowledge"],
                mitigations=[
                    "Parameter validation",
                    "Secure Flash configuration"
                ],
                related_weaknesses=["CWE-20"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-175": CAPECPattern(
                id="CAPEC-175",
                name="Code Inclusion",
                description="An attacker includes malicious code.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Dynamic includes"],
                skills_required="Medium",
                resources_required=["Code inclusion payload"],
                mitigations=[
                    "Whitelist includes",
                    "Input validation"
                ],
                related_weaknesses=["CWE-98"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-176": CAPECPattern(
                id="CAPEC-176",
                name="Configuration Override",
                description="An attacker overrides configuration.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Configuration files"],
                skills_required="Medium",
                resources_required=["Config access"],
                mitigations=[
                    "Secure config files",
                    "Configuration validation"
                ],
                related_weaknesses=["CWE-15"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-177": CAPECPattern(
                id="CAPEC-177",
                name="Create files with the same name as library files",
                description="An attacker creates malicious library files.",
                likelihood="Low",
                severity="High",
                prerequisites=["Library loading"],
                skills_required="Medium",
                resources_required=["Library path knowledge"],
                mitigations=[
                    "Secure library paths",
                    "File integrity checks"
                ],
                related_weaknesses=["CWE-426"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-178": CAPECPattern(
                id="CAPEC-178",
                name="Cross-Site Flashing",
                description="An attacker exploits Flash vulnerabilities.",
                likelihood="Low",
                severity="High",
                prerequisites=["Flash content"],
                skills_required="High",
                resources_required=["Flash exploit"],
                mitigations=[
                    "Update Flash",
                    "Disable Flash"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-179": CAPECPattern(
                id="CAPEC-179",
                name="Calling Micro-Services Directly",
                description="An attacker bypasses API gateways.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Microservices"],
                skills_required="Medium",
                resources_required=["Service discovery"],
                mitigations=[
                    "API gateway",
                    "Service mesh security"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-180": CAPECPattern(
                id="CAPEC-180",
                name="Exploiting Incorrectly Configured Access Control Security Levels",
                description="An attacker exploits misconfigured access controls.",
                likelihood="High",
                severity="High",
                prerequisites=["Access controls"],
                skills_required="Medium",
                resources_required=["Access control knowledge"],
                mitigations=[
                    "Proper configuration",
                    "Access control testing"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-181": CAPECPattern(
                id="CAPEC-181",
                name="Flash File Overlay",
                description="An attacker overlays Flash files.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Flash files"],
                skills_required="Medium",
                resources_required=["Flash tools"],
                mitigations=[
                    "File integrity checks",
                    "Secure file storage"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-182": CAPECPattern(
                id="CAPEC-182",
                name="Flash Parameter Injection",
                description="An attacker injects Flash parameters.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Flash parameters"],
                skills_required="Medium",
                resources_required=["Flash knowledge"],
                mitigations=[
                    "Parameter validation",
                    "Secure Flash apps"
                ],
                related_weaknesses=["CWE-20"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-183": CAPECPattern(
                id="CAPEC-183",
                name="IMAP/SMTP Command Injection",
                description="An attacker injects IMAP/SMTP commands.",
                likelihood="Low",
                severity="High",
                prerequisites=["Email protocols"],
                skills_required="Medium",
                resources_required=["Protocol knowledge"],
                mitigations=[
                    "Command validation",
                    "Safe protocol handling"
                ],
                related_weaknesses=["CWE-77"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-184": CAPECPattern(
                id="CAPEC-184",
                name="Software Integrity Attack",
                description="An attacker compromises software integrity.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Software updates"],
                skills_required="High",
                resources_required=["Code signing compromise"],
                mitigations=[
                    "Code signing",
                    "Secure update channels"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-185": CAPECPattern(
                id="CAPEC-185",
                name="Malicious Software Update",
                description="An attacker distributes malicious updates.",
                likelihood="Low",
                severity="High",
                prerequisites=["Software updates"],
                skills_required="High",
                resources_required=["Update compromise"],
                mitigations=[
                    "Secure update channels",
                    "Update verification"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-186": CAPECPattern(
                id="CAPEC-186",
                name="Cloud Service Discovery",
                description="An attacker discovers cloud services.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Cloud services"],
                skills_required="Low",
                resources_required=["Cloud tools"],
                mitigations=[
                    "Service minimization",
                    "Access controls"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-187": CAPECPattern(
                id="CAPEC-187",
                name="Malicious Automated Software Update",
                description="An attacker uses automated updates maliciously.",
                likelihood="Low",
                severity="High",
                prerequisites=["Auto-updates"],
                skills_required="High",
                resources_required=["Update system compromise"],
                mitigations=[
                    "Update verification",
                    "Manual update approval"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-188": CAPECPattern(
                id="CAPEC-188",
                name="Reverse Engineering",
                description="An attacker reverse engineers software.",
                likelihood="Low",
                severity="High",
                prerequisites=["Access to binaries"],
                skills_required="High",
                resources_required=["Reverse engineering tools"],
                mitigations=[
                    "Code obfuscation",
                    "Legal protections"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-189": CAPECPattern(
                id="CAPEC-189",
                name="Black Box Reverse Engineering",
                description="An attacker performs black box reverse engineering.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Running software"],
                skills_required="High",
                resources_required=["Testing tools"],
                mitigations=[
                    "Minimize information leakage",
                    "Rate limiting"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-190": CAPECPattern(
                id="CAPEC-190",
                name="IP Address Blocking",
                description="An attacker blocks IP addresses.",
                likelihood="Low",
                severity="Low",
                prerequisites=["IP filtering"],
                skills_required="Low",
                resources_required=["IP knowledge"],
                mitigations=[
                    "IP rotation",
                    "VPN usage"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-191": CAPECPattern(
                id="CAPEC-191",
                name="Read Sensitive Strings Within an Executable",
                description="An attacker reads sensitive strings in executables.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Compiled software"],
                skills_required="Low",
                resources_required=["String tools"],
                mitigations=[
                    "String encryption",
                    "Code obfuscation"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-192": CAPECPattern(
                id="CAPEC-192",
                name="Protocol Analysis",
                description="An attacker analyzes protocols.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Network protocols"],
                skills_required="Medium",
                resources_required=["Protocol analyzer"],
                mitigations=[
                    "Protocol obfuscation",
                    "Encryption"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-193": CAPECPattern(
                id="CAPEC-193",
                name="PHP Remote File Inclusion",
                description="An attacker includes remote PHP files.",
                likelihood="Medium",
                severity="High",
                prerequisites=["PHP includes"],
                skills_required="Medium",
                resources_required=["PHP knowledge"],
                mitigations=[
                    "Disable remote includes",
                    "Whitelist includes"
                ],
                related_weaknesses=["CWE-98"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-194": CAPECPattern(
                id="CAPEC-194",
                name="Fake the Source of Data",
                description="An attacker fakes data sources.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Data processing"],
                skills_required="Medium",
                resources_required=["Data manipulation"],
                mitigations=[
                    "Data validation",
                    "Source verification"
                ],
                related_weaknesses=["CWE-20"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-195": CAPECPattern(
                id="CAPEC-195",
                name="Principal Spoofing",
                description="An attacker spoofs principals.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Authentication"],
                skills_required="Medium",
                resources_required=["Identity knowledge"],
                mitigations=[
                    "Strong authentication",
                    "Identity verification"
                ],
                related_weaknesses=["CWE-290"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-196": CAPECPattern(
                id="CAPEC-196",
                name="Session Credential Falsification through Forging",
                description="An attacker forges session credentials.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Session management"],
                skills_required="Medium",
                resources_required=["Session knowledge"],
                mitigations=[
                    "Secure session management",
                    "Session fixation protection"
                ],
                related_weaknesses=["CWE-384"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-197": CAPECPattern(
                id="CAPEC-197",
                name="Exponential Backoff",
                description="An attacker uses exponential backoff for timing attacks.",
                likelihood="Low",
                severity="Low",
                prerequisites=["Timing dependencies"],
                skills_required="High",
                resources_required=["Timing analysis"],
                mitigations=[
                    "Constant time operations",
                    "Random delays"
                ],
                related_weaknesses=["CWE-208"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-198": CAPECPattern(
                id="CAPEC-198",
                name="XSS Targeting Error Pages",
                description="An attacker targets error pages with XSS.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Error pages"],
                skills_required="Medium",
                resources_required=["XSS payload"],
                mitigations=[
                    "Safe error pages",
                    "Input validation"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-199": CAPECPattern(
                id="CAPEC-199",
                name="XSS Using Alternate Syntax",
                description="An attacker uses alternate XSS syntax.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["XSS vulnerability"],
                skills_required="Medium",
                resources_required=["XSS knowledge"],
                mitigations=[
                    "Input validation",
                    "Output encoding"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-200": CAPECPattern(
                id="CAPEC-200",
                name="Removal of filters",
                description="An attacker removes input filters.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Input filtering"],
                skills_required="Medium",
                resources_required=["Filter knowledge"],
                mitigations=[
                    "Server-side validation",
                    "Multiple validation layers"
                ],
                related_weaknesses=["CWE-20"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-201": CAPECPattern(
                id="CAPEC-201",
                name="JSON Hijacking (aka JavaScript Hijacking)",
                description="An attacker hijacks JSON data.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["JSON endpoints"],
                skills_required="Medium",
                resources_required=["Script tag"],
                mitigations=[
                    "Content-Type validation",
                    "CSRF protection"
                ],
                related_weaknesses=["CWE-352"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-202": CAPECPattern(
                id="CAPEC-202",
                name="Create Malicious Client",
                description="An attacker creates malicious clients.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Client-server architecture"],
                skills_required="High",
                resources_required=["Client development"],
                mitigations=[
                    "Client validation",
                    "Mutual authentication"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-203": CAPECPattern(
                id="CAPEC-203",
                name="Manipulate Registry Information",
                description="An attacker manipulates registry information.",
                likelihood="Low",
                severity="High",
                prerequisites=["Registry usage"],
                skills_required="Medium",
                resources_required=["Registry access"],
                mitigations=[
                    "Registry protection",
                    "Integrity monitoring"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-204": CAPECPattern(
                id="CAPEC-204",
                name="Query System for Information",
                description="An attacker queries system for information.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Information leakage"],
                skills_required="Low",
                resources_required=["Query tools"],
                mitigations=[
                    "Minimize information disclosure",
                    "Access controls"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-205": CAPECPattern(
                id="CAPEC-205",
                name="Remove Dependent Critical Components",
                description="An attacker removes critical components.",
                likelihood="Low",
                severity="High",
                prerequisites=["Component dependencies"],
                skills_required="Medium",
                resources_required=["System knowledge"],
                mitigations=[
                    "Component protection",
                    "Redundancy"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-206": CAPECPattern(
                id="CAPEC-206",
                name="Signature Spoofing by Key Recreation",
                description="An attacker spoofs signatures by recreating keys.",
                likelihood="Low",
                severity="High",
                prerequisites=["Digital signatures"],
                skills_required="High",
                resources_required=["Cryptography knowledge"],
                mitigations=[
                    "Strong key protection",
                    "Key rotation"
                ],
                related_weaknesses=["CWE-347"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-207": CAPECPattern(
                id="CAPEC-207",
                name="Removing Important Client Functionality",
                description="An attacker removes client functionality.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Client software"],
                skills_required="Medium",
                resources_required=["Client modification"],
                mitigations=[
                    "Code integrity checks",
                    "Tamper detection"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-208": CAPECPattern(
                id="CAPEC-208",
                name="Setting Manipulation",
                description="An attacker manipulates settings.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Configuration settings"],
                skills_required="Medium",
                resources_required=["Settings access"],
                mitigations=[
                    "Settings validation",
                    "Secure storage"
                ],
                related_weaknesses=["CWE-15"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-209": CAPECPattern(
                id="CAPEC-209",
                name="XSS Using Meta Characters",
                description="An attacker uses meta characters for XSS.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["XSS vulnerability"],
                skills_required="Medium",
                resources_required=["Meta character knowledge"],
                mitigations=[
                    "Input validation",
                    "Output encoding"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-210": CAPECPattern(
                id="CAPEC-210",
                name="XSS Using Unicode Encoding",
                description="An attacker uses Unicode encoding for XSS.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["XSS vulnerability"],
                skills_required="Medium",
                resources_required=["Unicode knowledge"],
                mitigations=[
                    "Input validation",
                    "Output encoding"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-211": CAPECPattern(
                id="CAPEC-211",
                name="XSS Using Script Element",
                description="An attacker uses script elements for XSS.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["XSS vulnerability"],
                skills_required="Medium",
                resources_required=["Script knowledge"],
                mitigations=[
                    "Input validation",
                    "Output encoding"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-212": CAPECPattern(
                id="CAPEC-212",
                name="Functionality Misuse",
                description="An attacker misuses functionality.",
                likelihood="High",
                severity="High",
                prerequisites=["Application functionality"],
                skills_required="Low",
                resources_required=["Application knowledge"],
                mitigations=[
                    "Access controls",
                    "Input validation"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-213": CAPECPattern(
                id="CAPEC-213",
                name="Directory Traversal",
                description="An attacker traverses directories.",
                likelihood="High",
                severity="High",
                prerequisites=["File system access"],
                skills_required="Low",
                resources_required=["Path traversal payload"],
                mitigations=[
                    "Path validation",
                    "Canonicalization"
                ],
                related_weaknesses=["CWE-22"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING]
            ),
            "CAPEC-214": CAPECPattern(
                id="CAPEC-214",
                name="Session Credential Falsification through Prediction",
                description="An attacker predicts session credentials.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Predictable sessions"],
                skills_required="Medium",
                resources_required=["Session observation"],
                mitigations=[
                    "Cryptographically secure sessions",
                    "Short timeouts"
                ],
                related_weaknesses=["CWE-384"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-215": CAPECPattern(
                id="CAPEC-215",
                name="Fuzzing and observing application log data",
                description="An attacker fuzzes and observes logs.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Application logging"],
                skills_required="Medium",
                resources_required=["Fuzzer"],
                mitigations=[
                    "Generic error messages",
                    "Log sanitization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-216": CAPECPattern(
                id="CAPEC-216",
                name="Communication Channel Manipulation",
                description="An attacker manipulates communication channels.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Communication channels"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Channel security",
                    "Encryption"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-217": CAPECPattern(
                id="CAPEC-217",
                name="Exploitation of Session Variables, Resource IDs and other Trusted Credentials",
                description="An attacker exploits session variables.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Session management"],
                skills_required="Medium",
                resources_required=["Session knowledge"],
                mitigations=[
                    "Secure session handling",
                    "Input validation"
                ],
                related_weaknesses=["CWE-384"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-218": CAPECPattern(
                id="CAPEC-218",
                name="Spoofing of UDDI/ebXML Messages",
                description="An attacker spoofs UDDI/ebXML messages.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["UDDI/ebXML"],
                skills_required="Medium",
                resources_required=["XML knowledge"],
                mitigations=[
                    "Message authentication",
                    "Digital signatures"
                ],
                related_weaknesses=["CWE-290"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-219": CAPECPattern(
                id="CAPEC-219",
                name="XML Routing Detour Attacks",
                description="An attacker detours XML routing.",
                likelihood="Low",
                severity="High",
                prerequisites=["XML routing"],
                skills_required="High",
                resources_required=["XML knowledge"],
                mitigations=[
                    "Routing validation",
                    "Secure routing"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-220": CAPECPattern(
                id="CAPEC-220",
                name="Client-Server Protocol Manipulation",
                description="An attacker manipulates client-server protocols.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Client-server communication"],
                skills_required="Medium",
                resources_required=["Protocol knowledge"],
                mitigations=[
                    "Protocol validation",
                    "Secure communication"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-221": CAPECPattern(
                id="CAPEC-221",
                name="Data Serialization External Entities Blowup",
                description="An attacker causes serialization entity blowup.",
                likelihood="Low",
                severity="High",
                prerequisites=["XML serialization"],
                skills_required="Medium",
                resources_required=["XML entity knowledge"],
                mitigations=[
                    "Disable external entities",
                    "Entity limits"
                ],
                related_weaknesses=["CWE-611"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-222": CAPECPattern(
                id="CAPEC-222",
                name="iFrame Overlay",
                description="An attacker overlays iframes.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Web content"],
                skills_required="Medium",
                resources_required=["HTML/CSS knowledge"],
                mitigations=[
                    "X-Frame-Options",
                    "Content Security Policy"
                ],
                related_weaknesses=["CWE-693"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-223": CAPECPattern(
                id="CAPEC-223",
                name="Omit Critical Step in Authentication",
                description="An attacker omits authentication steps.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Multi-step authentication"],
                skills_required="Low",
                resources_required=["Authentication knowledge"],
                mitigations=[
                    "Enforce all steps",
                    "State validation"
                ],
                related_weaknesses=["CWE-287"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-224": CAPECPattern(
                id="CAPEC-224",
                name="Fingerprinting",
                description="An attacker fingerprints systems.",
                likelihood="High",
                severity="Low",
                prerequisites=["System exposure"],
                skills_required="Low",
                resources_required=["Fingerprinting tools"],
                mitigations=[
                    "Minimize information leakage",
                    "Generic responses"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-225": CAPECPattern(
                id="CAPEC-225",
                name="XPath Injection",
                description="An attacker injects XPath expressions.",
                likelihood="Medium",
                severity="High",
                prerequisites=["XPath queries"],
                skills_required="Medium",
                resources_required=["XPath knowledge"],
                mitigations=[
                    "Parameterized XPath",
                    "Input validation"
                ],
                related_weaknesses=["CWE-643"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-226": CAPECPattern(
                id="CAPEC-226",
                name="Session Credential Falsification through Manipulation",
                description="An attacker manipulates session credentials.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Session management"],
                skills_required="Medium",
                resources_required=["Session capture"],
                mitigations=[
                    "Secure session handling",
                    "Session validation"
                ],
                related_weaknesses=["CWE-384"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-227": CAPECPattern(
                id="CAPEC-227",
                name="Sustaining a DoS Attack",
                description="An attacker sustains DoS attacks.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Network service"],
                skills_required="Medium",
                resources_required=["DoS tools"],
                mitigations=[
                    "Rate limiting",
                    "Traffic filtering"
                ],
                related_weaknesses=["CWE-400"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-228": CAPECPattern(
                id="CAPEC-228",
                name="DTD Injection",
                description="An attacker injects DTDs.",
                likelihood="Low",
                severity="High",
                prerequisites=["XML processing"],
                skills_required="High",
                resources_required=["DTD knowledge"],
                mitigations=[
                    "Disable DTD processing",
                    "Input validation"
                ],
                related_weaknesses=["CWE-611"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-229": CAPECPattern(
                id="CAPEC-229",
                name="XML Attribute Blowup",
                description="An attacker causes XML attribute blowup.",
                likelihood="Low",
                severity="High",
                prerequisites=["XML processing"],
                skills_required="Medium",
                resources_required=["XML knowledge"],
                mitigations=[
                    "Attribute limits",
                    "Safe XML parsers"
                ],
                related_weaknesses=["CWE-400"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-230": CAPECPattern(
                id="CAPEC-230",
                name="Serialized Data with Nested Payloads",
                description="An attacker uses nested serialized payloads.",
                likelihood="Low",
                severity="High",
                prerequisites=["Serialization"],
                skills_required="High",
                resources_required=["Serialization knowledge"],
                mitigations=[
                    "Safe deserialization",
                    "Input validation"
                ],
                related_weaknesses=["CWE-502"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-231": CAPECPattern(
                id="CAPEC-231",
                name="Inappropriate Encoding for LDAP Query",
                description="An attacker uses inappropriate encoding for LDAP.",
                likelihood="Medium",
                severity="High",
                prerequisites=["LDAP queries"],
                skills_required="Medium",
                resources_required=["LDAP knowledge"],
                mitigations=[
                    "LDAP encoding",
                    "Input validation"
                ],
                related_weaknesses=["CWE-90"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-232": CAPECPattern(
                id="CAPEC-232",
                name="Parameter Injection",
                description="An attacker injects parameters.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Parameter processing"],
                skills_required="Medium",
                resources_required=["Parameter knowledge"],
                mitigations=[
                    "Parameter validation",
                    "Safe parameter handling"
                ],
                related_weaknesses=["CWE-88"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-233": CAPECPattern(
                id="CAPEC-233",
                name="Privilege Escalation",
                description="An attacker escalates privileges.",
                likelihood="High",
                severity="High",
                prerequisites=["Privilege system"],
                skills_required="Medium",
                resources_required=["Privilege knowledge"],
                mitigations=[
                    "Principle of least privilege",
                    "Access controls"
                ],
                related_weaknesses=["CWE-264"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-234": CAPECPattern(
                id="CAPEC-234",
                name="LOADLIB and CDLL Injection",
                description="An attacker injects LOADLIB/CDLL.",
                likelihood="Low",
                severity="High",
                prerequisites=["Library loading"],
                skills_required="High",
                resources_required=["Library knowledge"],
                mitigations=[
                    "Secure library paths",
                    "Library validation"
                ],
                related_weaknesses=["CWE-426"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-235": CAPECPattern(
                id="CAPEC-235",
                name="Incubated Vulnerability in Software",
                description="An attacker exploits incubated vulnerabilities.",
                likelihood="Low",
                severity="High",
                prerequisites=["Software vulnerabilities"],
                skills_required="High",
                resources_required=["Vulnerability knowledge"],
                mitigations=[
                    "Regular updates",
                    "Vulnerability scanning"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-236": CAPECPattern(
                id="CAPEC-236",
                name="Data Encoding",
                description="An attacker exploits data encoding.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Data encoding"],
                skills_required="Medium",
                resources_required=["Encoding knowledge"],
                mitigations=[
                    "Canonicalize input",
                    "Validate encoding"
                ],
                related_weaknesses=["CWE-179"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-237": CAPECPattern(
                id="CAPEC-237",
                name="Parameter Manipulation",
                description="An attacker manipulates parameters.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Parameter processing"],
                skills_required="Low",
                resources_required=["Parameter knowledge"],
                mitigations=[
                    "Parameter validation",
                    "Server-side validation"
                ],
                related_weaknesses=["CWE-20"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-238": CAPECPattern(
                id="CAPEC-238",
                name="Forced Deadlock",
                description="An attacker forces deadlocks.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Concurrent processing"],
                skills_required="High",
                resources_required=["Concurrency knowledge"],
                mitigations=[
                    "Deadlock prevention",
                    "Timeout handling"
                ],
                related_weaknesses=["CWE-400"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-239": CAPECPattern(
                id="CAPEC-239",
                name="Phishing",
                description="An attacker performs phishing.",
                likelihood="High",
                severity="High",
                prerequisites=["User interaction"],
                skills_required="Medium",
                resources_required=["Phishing tools"],
                mitigations=[
                    "User training",
                    "Anti-phishing tools"
                ],
                related_weaknesses=["CWE-352"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-240": CAPECPattern(
                id="CAPEC-240",
                name="Resource Injection",
                description="An attacker injects resources.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Resource handling"],
                skills_required="Medium",
                resources_required=["Resource knowledge"],
                mitigations=[
                    "Resource validation",
                    "Safe resource handling"
                ],
                related_weaknesses=["CWE-99"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-241": CAPECPattern(
                id="CAPEC-241",
                name="Code Injection",
                description="An attacker injects code.",
                likelihood="High",
                severity="High",
                prerequisites=["Code execution"],
                skills_required="Medium",
                resources_required=["Code injection payload"],
                mitigations=[
                    "Input validation",
                    "Safe code execution"
                ],
                related_weaknesses=["CWE-94"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-242": CAPECPattern(
                id="CAPEC-242",
                name="Code Injection",
                description="An attacker injects code.",
                likelihood="High",
                severity="High",
                prerequisites=["Code execution"],
                skills_required="Medium",
                resources_required=["Code injection payload"],
                mitigations=[
                    "Input validation",
                    "Safe code execution"
                ],
                related_weaknesses=["CWE-94"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-243": CAPECPattern(
                id="CAPEC-243",
                name="Cross-Site Scripting in Attributes",
                description="An attacker uses XSS in attributes.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["XSS vulnerability"],
                skills_required="Medium",
                resources_required=["XSS knowledge"],
                mitigations=[
                    "Attribute encoding",
                    "Input validation"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-244": CAPECPattern(
                id="CAPEC-244",
                name="Cross-Site Scripting in HTTP Headers",
                description="An attacker uses XSS in HTTP headers.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Header reflection"],
                skills_required="Medium",
                resources_required=["XSS payload"],
                mitigations=[
                    "Header validation",
                    "Safe header handling"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-245": CAPECPattern(
                id="CAPEC-245",
                name="Cross-Site Scripting Using Doubled Characters",
                description="An attacker uses doubled characters for XSS.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["XSS vulnerability"],
                skills_required="Medium",
                resources_required=["XSS knowledge"],
                mitigations=[
                    "Input validation",
                    "Output encoding"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-246": CAPECPattern(
                id="CAPEC-246",
                name="Cross-Site Scripting Using Flash",
                description="An attacker uses Flash for XSS.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Flash content"],
                skills_required="Medium",
                resources_required=["Flash knowledge"],
                mitigations=[
                    "Flash security",
                    "Input validation"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-247": CAPECPattern(
                id="CAPEC-247",
                name="Cross-Site Scripting with Timing Differences",
                description="An attacker uses timing for XSS.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["Timing-dependent XSS"],
                skills_required="High",
                resources_required=["Timing analysis"],
                mitigations=[
                    "Constant time operations",
                    "Input validation"
                ],
                related_weaknesses=["CWE-79"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-248": CAPECPattern(
                id="CAPEC-248",
                name="Command Injection",
                description="An attacker injects commands.",
                likelihood="High",
                severity="High",
                prerequisites=["Command execution"],
                skills_required="Medium",
                resources_required=["Command injection payload"],
                mitigations=[
                    "Input validation",
                    "Safe command execution"
                ],
                related_weaknesses=["CWE-77"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-249": CAPECPattern(
                id="CAPEC-249",
                name="Command Injection",
                description="An attacker injects commands.",
                likelihood="High",
                severity="High",
                prerequisites=["Command execution"],
                skills_required="Medium",
                resources_required=["Command injection payload"],
                mitigations=[
                    "Input validation",
                    "Safe command execution"
                ],
                related_weaknesses=["CWE-77"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-250": CAPECPattern(
                id="CAPEC-250",
                name="XML Injection",
                description="An attacker injects XML.",
                likelihood="Medium",
                severity="High",
                prerequisites=["XML processing"],
                skills_required="Medium",
                resources_required=["XML knowledge"],
                mitigations=[
                    "XML validation",
                    "Safe XML processing"
                ],
                related_weaknesses=["CWE-91"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-251": CAPECPattern(
                id="CAPEC-251",
                name="Local Code Inclusion",
                description="An attacker includes local code.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Code inclusion"],
                skills_required="Medium",
                resources_required=["Path traversal"],
                mitigations=[
                    "Path validation",
                    "Whitelist includes"
                ],
                related_weaknesses=["CWE-98"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-252": CAPECPattern(
                id="CAPEC-252",
                name="PHP Local File Inclusion",
                description="An attacker includes local PHP files.",
                likelihood="Medium",
                severity="High",
                prerequisites=["PHP includes"],
                skills_required="Medium",
                resources_required=["Path traversal"],
                mitigations=[
                    "Path validation",
                    "Disable dangerous includes"
                ],
                related_weaknesses=["CWE-98"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-253": CAPECPattern(
                id="CAPEC-253",
                name="Remote Code Inclusion",
                description="An attacker includes remote code.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Remote includes"],
                skills_required="Medium",
                resources_required=["Remote URL"],
                mitigations=[
                    "Disable remote includes",
                    "Whitelist includes"
                ],
                related_weaknesses=["CWE-98"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-254": CAPECPattern(
                id="CAPEC-254",
                name="LDAP Injection",
                description="An attacker injects LDAP queries.",
                likelihood="Medium",
                severity="High",
                prerequisites=["LDAP queries"],
                skills_required="Medium",
                resources_required=["LDAP knowledge"],
                mitigations=[
                    "LDAP encoding",
                    "Input validation"
                ],
                related_weaknesses=["CWE-90"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-255": CAPECPattern(
                id="CAPEC-255",
                name="Manipulating Writeable Configuration Files",
                description="An attacker manipulates configuration files.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Writable configs"],
                skills_required="Medium",
                resources_required=["Config access"],
                mitigations=[
                    "Config protection",
                    "Integrity checks"
                ],
                related_weaknesses=["CWE-15"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-256": CAPECPattern(
                id="CAPEC-256",
                name="SOAP Array Overflow",
                description="An attacker overflows SOAP arrays.",
                likelihood="Low",
                severity="High",
                prerequisites=["SOAP processing"],
                skills_required="Medium",
                resources_required=["SOAP knowledge"],
                mitigations=[
                    "Array bounds checking",
                    "Safe SOAP processing"
                ],
                related_weaknesses=["CWE-119"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-257": CAPECPattern(
                id="CAPEC-257",
                name="SOAP Array Overflow",
                description="An attacker overflows SOAP arrays.",
                likelihood="Low",
                severity="High",
                prerequisites=["SOAP processing"],
                skills_required="Medium",
                resources_required=["SOAP knowledge"],
                mitigations=[
                    "Array bounds checking",
                    "Safe SOAP processing"
                ],
                related_weaknesses=["CWE-119"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-258": CAPECPattern(
                id="CAPEC-258",
                name="Passwd File Manipulation",
                description="An attacker manipulates passwd files.",
                likelihood="Low",
                severity="High",
                prerequisites=["Passwd file access"],
                skills_required="Medium",
                resources_required=["System knowledge"],
                mitigations=[
                    "File protection",
                    "Shadow passwords"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-259": CAPECPattern(
                id="CAPEC-259",
                name="Passwd File Manipulation",
                description="An attacker manipulates passwd files.",
                likelihood="Low",
                severity="High",
                prerequisites=["Passwd file access"],
                skills_required="Medium",
                resources_required=["System knowledge"],
                mitigations=[
                    "File protection",
                    "Shadow passwords"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-260": CAPECPattern(
                id="CAPEC-260",
                name="Password Recovery Exploitation",
                description="An attacker exploits password recovery.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Password recovery"],
                skills_required="Medium",
                resources_required=["Recovery knowledge"],
                mitigations=[
                    "Secure recovery process",
                    "Rate limiting"
                ],
                related_weaknesses=["CWE-640"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-261": CAPECPattern(
                id="CAPEC-261",
                name="Fraudulent Resource Acquisition",
                description="An attacker acquires resources fraudulently.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Resource allocation"],
                skills_required="Medium",
                resources_required=["Resource knowledge"],
                mitigations=[
                    "Resource validation",
                    "Fraud detection"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-262": CAPECPattern(
                id="CAPEC-262",
                name="Restful Privilege Elevation",
                description="An attacker elevates privileges via REST.",
                likelihood="Medium",
                severity="High",
                prerequisites=["REST API"],
                skills_required="Medium",
                resources_required=["API knowledge"],
                mitigations=[
                    "Proper authorization",
                    "Access controls"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-263": CAPECPattern(
                id="CAPEC-263",
                name="Force Use of Corrupted Files",
                description="An attacker forces use of corrupted files.",
                likelihood="Low",
                severity="High",
                prerequisites=["File processing"],
                skills_required="High",
                resources_required=["File corruption"],
                mitigations=[
                    "File integrity checks",
                    "Backup validation"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-264": CAPECPattern(
                id="CAPEC-264",
                name="Force Use of Corrupted Files",
                description="An attacker forces use of corrupted files.",
                likelihood="Low",
                severity="High",
                prerequisites=["File processing"],
                skills_required="High",
                resources_required=["File corruption"],
                mitigations=[
                    "File integrity checks",
                    "Backup validation"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-265": CAPECPattern(
                id="CAPEC-265",
                name="Force Use of Corrupted Files",
                description="An attacker forces use of corrupted files.",
                likelihood="Low",
                severity="High",
                prerequisites=["File processing"],
                skills_required="High",
                resources_required=["File corruption"],
                mitigations=[
                    "File integrity checks",
                    "Backup validation"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-266": CAPECPattern(
                id="CAPEC-266",
                name="Real Time Injection",
                description="An attacker injects in real time.",
                likelihood="Low",
                severity="High",
                prerequisites=["Real-time processing"],
                skills_required="High",
                resources_required=["Timing knowledge"],
                mitigations=[
                    "Input validation",
                    "Synchronization"
                ],
                related_weaknesses=["CWE-20"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-267": CAPECPattern(
                id="CAPEC-267",
                name="Leverage Alternate Encoding",
                description="An attacker uses alternate encoding.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Input processing"],
                skills_required="Medium",
                resources_required=["Encoding knowledge"],
                mitigations=[
                    "Canonicalize input",
                    "Validate encoding"
                ],
                related_weaknesses=["CWE-179"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-268": CAPECPattern(
                id="CAPEC-268",
                name="Audit Log Manipulation",
                description="An attacker manipulates audit logs.",
                likelihood="Medium",
                severity="Medium",
                prerequisites=["Audit logging"],
                skills_required="Medium",
                resources_required=["Log access"],
                mitigations=[
                    "Log integrity",
                    "Secure logging"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.REPUDIATION]
            ),
            "CAPEC-269": CAPECPattern(
                id="CAPEC-269",
                name="Configuration File Manipulation",
                description="An attacker manipulates configuration files.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Config access"],
                skills_required="Medium",
                resources_required=["Config knowledge"],
                mitigations=[
                    "Config protection",
                    "Validation"
                ],
                related_weaknesses=["CWE-15"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-270": CAPECPattern(
                id="CAPEC-270",
                name="Modification of Registry Run Keys",
                description="An attacker modifies registry run keys.",
                likelihood="Low",
                severity="High",
                prerequisites=["Registry access"],
                skills_required="Medium",
                resources_required=["Registry knowledge"],
                mitigations=[
                    "Registry protection",
                    "Startup monitoring"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]
            ),
            "CAPEC-271": CAPECPattern(
                id="CAPEC-271",
                name="Schema Poisoning",
                description="An attacker poisons schemas.",
                likelihood="Low",
                severity="High",
                prerequisites=["Schema processing"],
                skills_required="High",
                resources_required=["Schema knowledge"],
                mitigations=[
                    "Schema validation",
                    "Secure schema storage"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-272": CAPECPattern(
                id="CAPEC-272",
                name="Protocol Manipulation",
                description="An attacker manipulates protocols.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Protocol usage"],
                skills_required="Medium",
                resources_required=["Protocol knowledge"],
                mitigations=[
                    "Protocol validation",
                    "Secure protocols"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-273": CAPECPattern(
                id="CAPEC-273",
                name="HTTP Response Smuggling",
                description="An attacker smuggles HTTP responses.",
                likelihood="Low",
                severity="High",
                prerequisites=["HTTP processing"],
                skills_required="High",
                resources_required=["HTTP knowledge"],
                mitigations=[
                    "Safe HTTP parsing",
                    "Proxy validation"
                ],
                related_weaknesses=["CWE-436"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-274": CAPECPattern(
                id="CAPEC-274",
                name="HTTP Verb Tampering",
                description="An attacker tampers with HTTP verbs.",
                likelihood="Low",
                severity="Medium",
                prerequisites=["HTTP processing"],
                skills_required="Low",
                resources_required=["HTTP knowledge"],
                mitigations=[
                    "Verb validation",
                    "Method restrictions"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-275": CAPECPattern(
                id="CAPEC-275",
                name="DNS Rebinding",
                description="An attacker performs DNS rebinding.",
                likelihood="Low",
                severity="High",
                prerequisites=["DNS resolution"],
                skills_required="High",
                resources_required=["DNS knowledge"],
                mitigations=[
                    "DNS pinning",
                    "Network isolation"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-276": CAPECPattern(
                id="CAPEC-276",
                name="Inter-component Protocol Manipulation",
                description="An attacker manipulates inter-component protocols.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Component communication"],
                skills_required="Medium",
                resources_required=["Protocol knowledge"],
                mitigations=[
                    "Protocol security",
                    "Component validation"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-277": CAPECPattern(
                id="CAPEC-277",
                name="Data Interchange Format Injection",
                description="An attacker injects data interchange formats.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Data interchange"],
                skills_required="Medium",
                resources_required=["Format knowledge"],
                mitigations=[
                    "Format validation",
                    "Safe parsing"
                ],
                related_weaknesses=["CWE-20"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-278": CAPECPattern(
                id="CAPEC-278",
                name="Web Services Protocol Manipulation",
                description="An attacker manipulates web service protocols.",
                likelihood="Medium",
                severity="High",
                prerequisites=["Web services"],
                skills_required="Medium",
                resources_required=["WS knowledge"],
                mitigations=[
                    "Protocol validation",
                    "WS-Security"
                ],
                related_weaknesses=["CWE-284"],
                stride_categories=[STRIDECategory.TAMPERING]
            ),
            "CAPEC-279": CAPECPattern(
                id="CAPEC-279",
                name="SOAP Array Blowup",
                description="An attacker causes SOAP array blowup.",
                likelihood="Low",
                severity="High",
                prerequisites=["SOAP processing"],
                skills_required="Medium",
                resources_required=["SOAP knowledge"],
                mitigations=[
                    "Array limits",
                    "Safe SOAP processing"
                ],
                related_weaknesses=["CWE-400"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-280": CAPECPattern(
                id="CAPEC-280",
                name="SOAP Array Blowup",
                description="An attacker causes SOAP array blowup.",
                likelihood="Low",
                severity="High",
                prerequisites=["SOAP processing"],
                skills_required="Medium",
                resources_required=["SOAP knowledge"],
                mitigations=[
                    "Array limits",
                    "Safe SOAP processing"
                ],
                related_weaknesses=["CWE-400"],
                stride_categories=[STRIDECategory.DENIAL_OF_SERVICE]
            ),
            "CAPEC-281": CAPECPattern(
                id="CAPEC-281",
                name="Web Application Fingerprinting",
                description="An attacker fingerprints web applications.",
                likelihood="High",
                severity="Low",
                prerequisites=["Web application"],
                skills_required="Low",
                resources_required=["Fingerprinting tools"],
                mitigations=[
                    "Generic responses",
                    "Information minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-282": CAPECPattern(
                id="CAPEC-282",
                name="Credential Stuffing",
                description="An attacker uses credential stuffing.",
                likelihood="High",
                severity="High",
                prerequisites=["Authentication"],
                skills_required="Low",
                resources_required=["Credential lists"],
                mitigations=[
                    "Account lockout",
                    "Multi-factor authentication"
                ],
                related_weaknesses=["CWE-307"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-283": CAPECPattern(
                id="CAPEC-283",
                name="Certificate Authority Impersonation",
                description="An attacker impersonates a certificate authority.",
                likelihood="Low",
                severity="High",
                prerequisites=["Certificate validation"],
                skills_required="High",
                resources_required=["CA compromise"],
                mitigations=[
                    "Certificate pinning",
                    "CA validation"
                ],
                related_weaknesses=["CWE-295"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-284": CAPECPattern(
                id="CAPEC-284",
                name="Certificate Authority Impersonation",
                description="An attacker impersonates a certificate authority.",
                likelihood="Low",
                severity="High",
                prerequisites=["Certificate validation"],
                skills_required="High",
                resources_required=["CA compromise"],
                mitigations=[
                    "Certificate pinning",
                    "CA validation"
                ],
                related_weaknesses=["CWE-295"],
                stride_categories=[STRIDECategory.SPOOFING]
            ),
            "CAPEC-285": CAPECPattern(
                id="CAPEC-285",
                name="ICMP Echo Request Ping",
                description="An attacker uses ICMP ping for reconnaissance.",
                likelihood="High",
                severity="Low",
                prerequisites=["Network connectivity"],
                skills_required="Low",
                resources_required=["Ping tool"],
                mitigations=[
                    "Firewall rules",
                    "ICMP filtering"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-286": CAPECPattern(
                id="CAPEC-286",
                name="TCP SYN Scan",
                description="An attacker performs TCP SYN scanning.",
                likelihood="High",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-287": CAPECPattern(
                id="CAPEC-287",
                name="TCP SYN Scan",
                description="An attacker performs TCP SYN scanning.",
                likelihood="High",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-288": CAPECPattern(
                id="CAPEC-288",
                name="TCP SYN Scan",
                description="An attacker performs TCP SYN scanning.",
                likelihood="High",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-289": CAPECPattern(
                id="CAPEC-289",
                name="TCP SYN Scan",
                description="An attacker performs TCP SYN scanning.",
                likelihood="High",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-290": CAPECPattern(
                id="CAPEC-290",
                name="TCP SYN Scan",
                description="An attacker performs TCP SYN scanning.",
                likelihood="High",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-291": CAPECPattern(
                id="CAPEC-291",
                name="TCP SYN Scan",
                description="An attacker performs TCP SYN scanning.",
                likelihood="High",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-292": CAPECPattern(
                id="CAPEC-292",
                name="Host Discovery",
                description="An attacker discovers hosts.",
                likelihood="High",
                severity="Low",
                prerequisites=["Network access"],
                skills_required="Low",
                resources_required=["Network tools"],
                mitigations=[
                    "Network segmentation",
                    "Host minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-293": CAPECPattern(
                id="CAPEC-293",
                name="Traceroute",
                description="An attacker uses traceroute for reconnaissance.",
                likelihood="High",
                severity="Low",
                prerequisites=["Network connectivity"],
                skills_required="Low",
                resources_required=["Traceroute tool"],
                mitigations=[
                    "ICMP filtering",
                    "Network monitoring"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-294": CAPECPattern(
                id="CAPEC-294",
                name="ICMP Address Mask Request",
                description="An attacker requests address masks via ICMP.",
                likelihood="Low",
                severity="Low",
                prerequisites=["ICMP enabled"],
                skills_required="Low",
                resources_required=["ICMP tools"],
                mitigations=[
                    "ICMP filtering",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-295": CAPECPattern(
                id="CAPEC-295",
                name="Timestamp Request",
                description="An attacker requests timestamps.",
                likelihood="Low",
                severity="Low",
                prerequisites=["ICMP enabled"],
                skills_required="Low",
                resources_required=["ICMP tools"],
                mitigations=[
                    "ICMP filtering",
                    "Time service security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-296": CAPECPattern(
                id="CAPEC-296",
                name="ICMP Information Request",
                description="An attacker requests ICMP information.",
                likelihood="Low",
                severity="Low",
                prerequisites=["ICMP enabled"],
                skills_required="Low",
                resources_required=["ICMP tools"],
                mitigations=[
                    "ICMP filtering",
                    "Information minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-297": CAPECPattern(
                id="CAPEC-297",
                name="TCP ACK Scan",
                description="An attacker performs TCP ACK scanning.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Stateful inspection"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-298": CAPECPattern(
                id="CAPEC-298",
                name="TCP Window Scan",
                description="An attacker performs TCP window scanning.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-299": CAPECPattern(
                id="CAPEC-299",
                name="TCP FIN Scan",
                description="An attacker performs TCP FIN scanning.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-300": CAPECPattern(
                id="CAPEC-300",
                name="TCP NULL Scan",
                description="An attacker performs TCP NULL scanning.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-301": CAPECPattern(
                id="CAPEC-301",
                name="TCP XMAS Scan",
                description="An attacker performs TCP XMAS scanning.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-302": CAPECPattern(
                id="CAPEC-302",
                name="TCP Maimon Scan",
                description="An attacker performs TCP Maimon scanning.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-303": CAPECPattern(
                id="CAPEC-303",
                name="TCP Idle Scan",
                description="An attacker performs TCP idle scanning.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["TCP services"],
                skills_required="Medium",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-304": CAPECPattern(
                id="CAPEC-304",
                name="TCP UDP Scan",
                description="An attacker performs TCP UDP scanning.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["UDP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-305": CAPECPattern(
                id="CAPEC-305",
                name="TCP SCTP Scan",
                description="An attacker performs TCP SCTP scanning.",
                likelihood="Low",
                severity="Low",
                prerequisites=["SCTP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-306": CAPECPattern(
                id="CAPEC-306",
                name="Protocol-Specific Port Scanning",
                description="An attacker performs protocol-specific port scanning.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Protocol services"],
                skills_required="Medium",
                resources_required=["Protocol scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-307": CAPECPattern(
                id="CAPEC-307",
                name="TCP SCTP Scan",
                description="An attacker performs TCP SCTP scanning.",
                likelihood="Low",
                severity="Low",
                prerequisites=["SCTP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-308": CAPECPattern(
                id="CAPEC-308",
                name="TCP SCTP Scan",
                description="An attacker performs TCP SCTP scanning.",
                likelihood="Low",
                severity="Low",
                prerequisites=["SCTP services"],
                skills_required="Low",
                resources_required=["Port scanner"],
                mitigations=[
                    "Firewall rules",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-309": CAPECPattern(
                id="CAPEC-309",
                name="Host Discovery",
                description="An attacker discovers hosts.",
                likelihood="High",
                severity="Low",
                prerequisites=["Network access"],
                skills_required="Low",
                resources_required=["Network tools"],
                mitigations=[
                    "Network segmentation",
                    "Host minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-310": CAPECPattern(
                id="CAPEC-310",
                name="Scanning for Vulnerable Software",
                description="An attacker scans for vulnerable software.",
                likelihood="High",
                severity="Low",
                prerequisites=["Network services"],
                skills_required="Low",
                resources_required=["Vulnerability scanner"],
                mitigations=[
                    "Patch management",
                    "Service minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-311": CAPECPattern(
                id="CAPEC-311",
                name="Vulnerability Scanning",
                description="An attacker performs vulnerability scanning.",
                likelihood="High",
                severity="Low",
                prerequisites=["Network services"],
                skills_required="Low",
                resources_required=["Vulnerability scanner"],
                mitigations=[
                    "Patch management",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-312": CAPECPattern(
                id="CAPEC-312",
                name="Active OS Fingerprinting",
                description="An attacker performs active OS fingerprinting.",
                likelihood="High",
                severity="Low",
                prerequisites=["Network services"],
                skills_required="Low",
                resources_required=["Fingerprinting tools"],
                mitigations=[
                    "Generic responses",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-313": CAPECPattern(
                id="CAPEC-313",
                name="Passive OS Fingerprinting",
                description="An attacker performs passive OS fingerprinting.",
                likelihood="Medium",
                severity="Low",
                prerequisites=["Network traffic"],
                skills_required="Medium",
                resources_required=["Traffic analysis"],
                mitigations=[
                    "Traffic encryption",
                    "Information minimization"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-314": CAPECPattern(
                id="CAPEC-314",
                name="IP ID Sequencing Probe",
                description="An attacker probes IP ID sequencing.",
                likelihood="Low",
                severity="Low",
                prerequisites=["IP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "IP randomization",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-315": CAPECPattern(
                id="CAPEC-315",
                name="TCP Timestamp Probe",
                description="An attacker probes TCP timestamps.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Timestamp randomization",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-316": CAPECPattern(
                id="CAPEC-316",
                name="TCP ISN Probe",
                description="An attacker probes TCP ISN.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "ISN randomization",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-317": CAPECPattern(
                id="CAPEC-317",
                name="IP 'ID' Echoed Byte-Order Probe",
                description="An attacker probes IP ID echoed byte-order.",
                likelihood="Low",
                severity="Low",
                prerequisites=["IP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Byte-order handling",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-318": CAPECPattern(
                id="CAPEC-318",
                name="IP 'Don't Fragment' Bit Probe",
                description="An attacker probes IP don't fragment bit.",
                likelihood="Low",
                severity="Low",
                prerequisites=["IP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Fragmentation handling",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-319": CAPECPattern(
                id="CAPEC-319",
                name="IP 'Record Route' Probe",
                description="An attacker probes IP record route.",
                likelihood="Low",
                severity="Low",
                prerequisites=["IP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Route recording disable",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-320": CAPECPattern(
                id="CAPEC-320",
                name="TCP 'RST' Flag Checksum Probe",
                description="An attacker probes TCP RST flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-321": CAPECPattern(
                id="CAPEC-321",
                name="TCP Segment 'ACK' Flag Checksum Probe",
                description="An attacker probes TCP ACK flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-322": CAPECPattern(
                id="CAPEC-322",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-323": CAPECPattern(
                id="CAPEC-323",
                name="TCP Segment 'FIN' Flag Checksum Probe",
                description="An attacker probes TCP FIN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-324": CAPECPattern(
                id="CAPEC-324",
                name="TCP Segment 'PSH' Flag Checksum Probe",
                description="An attacker probes TCP PSH flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-325": CAPECPattern(
                id="CAPEC-325",
                name="TCP Segment 'URG' Flag Checksum Probe",
                description="An attacker probes TCP URG flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-326": CAPECPattern(
                id="CAPEC-326",
                name="TCP Segment 'ECE' Flag Checksum Probe",
                description="An attacker probes TCP ECE flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-327": CAPECPattern(
                id="CAPEC-327",
                name="TCP Segment 'CWR' Flag Checksum Probe",
                description="An attacker probes TCP CWR flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-328": CAPECPattern(
                id="CAPEC-328",
                name="TCP Segment 'NS' Flag Checksum Probe",
                description="An attacker probes TCP NS flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-329": CAPECPattern(
                id="CAPEC-329",
                name="ICMP Error Message Probe",
                description="An attacker probes ICMP error messages.",
                likelihood="Low",
                severity="Low",
                prerequisites=["ICMP enabled"],
                skills_required="Medium",
                resources_required=["ICMP tools"],
                mitigations=[
                    "ICMP filtering",
                    "Error message control"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-330": CAPECPattern(
                id="CAPEC-330",
                name="ICMP Error Message Probe",
                description="An attacker probes ICMP error messages.",
                likelihood="Low",
                severity="Low",
                prerequisites=["ICMP enabled"],
                skills_required="Medium",
                resources_required=["ICMP tools"],
                mitigations=[
                    "ICMP filtering",
                    "Error message control"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-331": CAPECPattern(
                id="CAPEC-331",
                name="ICMP Error Message Probe",
                description="An attacker probes ICMP error messages.",
                likelihood="Low",
                severity="Low",
                prerequisites=["ICMP enabled"],
                skills_required="Medium",
                resources_required=["ICMP tools"],
                mitigations=[
                    "ICMP filtering",
                    "Error message control"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-332": CAPECPattern(
                id="CAPEC-332",
                name="ICMP Error Message Probe",
                description="An attacker probes ICMP error messages.",
                likelihood="Low",
                severity="Low",
                prerequisites=["ICMP enabled"],
                skills_required="Medium",
                resources_required=["ICMP tools"],
                mitigations=[
                    "ICMP filtering",
                    "Error message control"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-333": CAPECPattern(
                id="CAPEC-333",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-334": CAPECPattern(
                id="CAPEC-334",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-335": CAPECPattern(
                id="CAPEC-335",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-336": CAPECPattern(
                id="CAPEC-336",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-337": CAPECPattern(
                id="CAPEC-337",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-338": CAPECPattern(
                id="CAPEC-338",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-339": CAPECPattern(
                id="CAPEC-339",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-340": CAPECPattern(
                id="CAPEC-340",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-341": CAPECPattern(
                id="CAPEC-341",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-342": CAPECPattern(
                id="CAPEC-342",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-343": CAPECPattern(
                id="CAPEC-343",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-344": CAPECPattern(
                id="CAPEC-344",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-345": CAPECPattern(
                id="CAPEC-345",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-346": CAPECPattern(
                id="CAPEC-346",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-347": CAPECPattern(
                id="CAPEC-347",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-348": CAPECPattern(
                id="CAPEC-348",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-349": CAPECPattern(
                id="CAPEC-349",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-350": CAPECPattern(
                id="CAPEC-350",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-351": CAPECPattern(
                id="CAPEC-351",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-352": CAPECPattern(
                id="CAPEC-352",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-353": CAPECPattern(
                id="CAPEC-353",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-354": CAPECPattern(
                id="CAPEC-354",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-355": CAPECPattern(
                id="CAPEC-355",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-356": CAPECPattern(
                id="CAPEC-356",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-357": CAPECPattern(
                id="CAPEC-357",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-358": CAPECPattern(
                id="CAPEC-358",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-359": CAPECPattern(
                id="CAPEC-359",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-360": CAPECPattern(
                id="CAPEC-360",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-361": CAPECPattern(
                id="CAPEC-361",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-362": CAPECPattern(
                id="CAPEC-362",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-363": CAPECPattern(
                id="CAPEC-363",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-364": CAPECPattern(
                id="CAPEC-364",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-365": CAPECPattern(
                id="CAPEC-365",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-366": CAPECPattern(
                id="CAPEC-366",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-367": CAPECPattern(
                id="CAPEC-367",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-368": CAPECPattern(
                id="CAPEC-368",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-369": CAPECPattern(
                id="CAPEC-369",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-370": CAPECPattern(
                id="CAPEC-370",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-371": CAPECPattern(
                id="CAPEC-371",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-372": CAPECPattern(
                id="CAPEC-372",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-373": CAPECPattern(
                id="CAPEC-373",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-374": CAPECPattern(
                id="CAPEC-374",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-375": CAPECPattern(
                id="CAPEC-375",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-376": CAPECPattern(
                id="CAPEC-376",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-377": CAPECPattern(
                id="CAPEC-377",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-378": CAPECPattern(
                id="CAPEC-378",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-379": CAPECPattern(
                id="CAPEC-379",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-380": CAPECPattern(
                id="CAPEC-380",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-381": CAPECPattern(
                id="CAPEC-381",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-382": CAPECPattern(
                id="CAPEC-382",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-383": CAPECPattern(
                id="CAPEC-383",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-384": CAPECPattern(
                id="CAPEC-384",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-385": CAPECPattern(
                id="CAPEC-385",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-386": CAPECPattern(
                id="CAPEC-386",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-387": CAPECPattern(
                id="CAPEC-387",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-388": CAPECPattern(
                id="CAPEC-388",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-389": CAPECPattern(
                id="CAPEC-389",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-390": CAPECPattern(
                id="CAPEC-390",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-391": CAPECPattern(
                id="CAPEC-391",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-392": CAPECPattern(
                id="CAPEC-392",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-393": CAPECPattern(
                id="CAPEC-393",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-394": CAPECPattern(
                id="CAPEC-394",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-395": CAPECPattern(
                id="CAPEC-395",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-396": CAPECPattern(
                id="CAPEC-396",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-397": CAPECPattern(
                id="CAPEC-397",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-398": CAPECPattern(
                id="CAPEC-398",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-399": CAPECPattern(
                id="CAPEC-399",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-400": CAPECPattern(
                id="CAPEC-400",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-401": CAPECPattern(
                id="CAPEC-401",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-402": CAPECPattern(
                id="CAPEC-402",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-403": CAPECPattern(
                id="CAPEC-403",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-404": CAPECPattern(
                id="CAPEC-404",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-405": CAPECPattern(
                id="CAPEC-405",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-406": CAPECPattern(
                id="CAPEC-406",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-407": CAPECPattern(
                id="CAPEC-407",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-408": CAPECPattern(
                id="CAPEC-408",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
            "CAPEC-409": CAPECPattern(
                id="CAPEC-409",
                name="TCP Segment 'SYN' Flag Checksum Probe",
                description="An attacker probes TCP SYN flag checksum.",
                likelihood="Low",
                severity="Low",
                prerequisites=["TCP traffic"],
                skills_required="Medium",
                resources_required=["Network tools"],
                mitigations=[
                    "Checksum validation",
                    "Network security"
                ],
                related_weaknesses=["CWE-200"],
                stride_categories=[STRIDECategory.INFORMATION_DISCLOSURE]
            ),
        }

    def enrich_threat(self, threat: ThreatItem) -> ThreatItem:
        """Enrich a threat with CAPEC information."""
        # Find matching CAPEC patterns
        matching_patterns = []
        for pattern in self.patterns.values():
            if pattern.matches_threat(threat):
                matching_patterns.append(pattern)

        if not matching_patterns:
            return threat

        # Use the best matching pattern (first one for now)
        best_pattern = matching_patterns[0]

        # Update threat with CAPEC information
        threat.capec_id = best_pattern.id
        threat.asvs_controls = best_pattern.mitigations[:3]  # Limit to 3 controls

        return threat
