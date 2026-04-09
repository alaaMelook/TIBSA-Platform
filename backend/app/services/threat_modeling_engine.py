"""
Threat Modeling – Enhanced threat generation engine.

This module provides a comprehensive threat modeling engine that integrates
multiple specialized services for advanced threat analysis, including:

- Normalized schema for data standardization
- STRIDE-based threat categorization
- CAPEC attack-pattern enrichment
- ASVS control mapping
- LLM-powered summarization
- Heatmap generation
- Export functionality

The engine maintains backward compatibility with the original rule-based approach
while adding advanced features for enterprise threat modeling.
"""
from __future__ import annotations

from typing import List, Optional, Dict, Any
from datetime import datetime

from app.models.threat_modeling import (
    ThreatItem,
    ThreatModelCreateRequest,
    ThreatModelAnalyzeResponse,
    ThreatModelAnalysis,
    Mitigation,
    HeatmapData,
    STRIDECategory,
    ThreatStatus,
)
from app.services.normalized_schema import NormalizedThreatModel, ThreatModelNormalizer
from app.services.stride_rules import STRIDEEngine
from app.services.capec_enrichment import CAPECEnrichmentService
from app.services.asvs_mapping import ASVSControlDatabase
from app.services.llm_summarization import LLMSummarizationService
from app.services.heatmap_generator import HeatmapGenerator
from app.services.export_service import ExportService


class EnhancedThreatModelingEngine:
    """Enhanced threat modeling engine with integrated services."""

    def __init__(self):
        self.normalized_schema = ThreatModelNormalizer()
        self.stride_engine = STRIDEEngine()
        self.capec_service = CAPECEnrichmentService()
        self.asvs_database = ASVSControlDatabase()
        self.llm_service = LLMSummarizationService()
        self.heatmap_generator = HeatmapGenerator()
        self.export_service = ExportService()

    def analyze_comprehensive(
        self,
        request: ThreatModelCreateRequest,
        generate_heatmap: bool = True,
        include_summaries: bool = True
    ) -> ThreatModelAnalysis:
        """
        Perform comprehensive threat modeling analysis.

        This method integrates all services to provide a complete threat model
        with enriched threats, mitigations, heatmaps, and summaries.
        """
        # Step 1: Normalize the input data
        normalized_model = self.normalized_schema.normalize_request(request)

        # Step 2: Generate base threats using STRIDE rules
        base_threats = self.stride_engine.generate_threats(normalized_model)

        # Step 3: Enrich threats with CAPEC information
        enriched_threats = []
        for threat in base_threats:
            enriched_threat = self.capec_service.enrich_threat(threat)
            enriched_threat = self.asvs_database.enrich_threat(enriched_threat)
            enriched_threats.append(enriched_threat)

        # Step 4: Generate mitigations (placeholder - would be expanded)
        mitigations = self._generate_mitigations(enriched_threats)

        # Step 5: Generate heatmap if requested
        heatmap_data = None
        if generate_heatmap:
            heatmap_data = self.heatmap_generator.generate_heatmap_data(enriched_threats)

        # Step 6: Add LLM summaries if requested
        if include_summaries:
            for threat in enriched_threats:
                summary = self.llm_service.generate_threat_summary(threat)
                # Store summary in threat's extended fields (would need model update)
                threat.description += f"\n\nLLM Summary: {summary.threat_description}"

        # Step 7: Create comprehensive analysis response
        analysis = ThreatModelAnalysis(
            id=f"analysis_{datetime.utcnow().timestamp()}",
            title=request.title or "Threat Model Analysis",
            description=request.description,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            system_metadata=request.system_metadata,
            architecture_diagram=request.architecture_diagram,
            assets=request.assets,
            entry_points=request.entry_points,
            trust_boundaries=request.trust_boundaries,
            auth_questions=getattr(request, 'auth_questions', None),
            data_questions=getattr(request, 'data_questions', None),
            control_questions=getattr(request, 'control_questions', None),
            threats=enriched_threats,
            mitigations=mitigations,
            heatmap_data=heatmap_data
        )

        return analysis

    def analyze_compatibility(
        self,
        request: ThreatModelCreateRequest
    ) -> ThreatModelAnalyzeResponse:
        """
        Maintain backward compatibility with the original analyze function.

        This provides the same interface as the original rule-based engine
        for existing integrations.
        """
        # Use the original rule-based approach for compatibility
        threats, raw_score = self._build_threats_legacy(request)
        capped = min(raw_score, 100)

        # Convert legacy threats to new format
        converted_threats = []
        for threat in threats:
            converted_threat = ThreatItem(
                id=threat.id,
                title=threat.title,
                description=threat.description,
                stride_category=self._map_legacy_category(threat.category),
                severity=self._map_legacy_risk(threat.risk),
                likelihood="Medium",  # Default
                impact=self._map_legacy_risk(threat.risk),
                status=ThreatStatus.OPEN,
                mitigation=threat.mitigation,
                affected_assets=[],  # Would need to be inferred
                entry_points=[],
                trust_boundaries=[],
                capec_id=None,
                capec_description=None,
                asvs_controls=[]
            )
            converted_threats.append(converted_threat)

        return ThreatModelAnalyzeResponse(
            threats=converted_threats,
            risk_score=capped,
            risk_label=self._risk_label(capped)
        )

    def _generate_mitigations(self, threats: List[ThreatItem]) -> List[Mitigation]:
        """Generate mitigation strategies based on threats."""
        mitigations = []
        mitigation_counter = 1

        # Group threats by STRIDE category for mitigation planning
        stride_groups = {}
        for threat in threats:
            category = threat.stride_category.value if threat.stride_category else "Unknown"
            if category not in stride_groups:
                stride_groups[category] = []
            stride_groups[category].append(threat)

        # Generate category-specific mitigations
        for category, category_threats in stride_groups.items():
            if category == "SPOOFING":
                mitigation = Mitigation(
                    id=f"mit_{mitigation_counter}",
                    title="Implement Multi-Factor Authentication",
                    description="Deploy MFA across all authentication points to prevent credential-based spoofing attacks.",
                    implementation_steps=[
                        "Configure MFA for all user accounts",
                        "Implement backup codes for MFA recovery",
                        "Set up MFA for administrative accounts",
                        "Monitor for MFA bypass attempts"
                    ],
                    cost="Medium",
                    effectiveness="High",
                    priority=8,
                    related_threats=[t.id for t in category_threats]
                )
                mitigations.append(mitigation)
                mitigation_counter += 1

            elif category == "TAMPERING":
                mitigation = Mitigation(
                    id=f"mit_{mitigation_counter}",
                    title="Implement Input Validation and Integrity Controls",
                    description="Add comprehensive input validation and integrity checking to prevent data tampering.",
                    implementation_steps=[
                        "Implement server-side input validation",
                        "Add integrity checks for critical data",
                        "Use parameterized queries to prevent injection",
                        "Implement digital signatures for data integrity"
                    ],
                    cost="Medium",
                    effectiveness="High",
                    priority=9,
                    related_threats=[t.id for t in category_threats]
                )
                mitigations.append(mitigation)
                mitigation_counter += 1

            elif category == "INFORMATION_DISCLOSURE":
                mitigation = Mitigation(
                    id=f"mit_{mitigation_counter}",
                    title="Encrypt Data and Secure Communications",
                    description="Implement encryption for data at rest and in transit to prevent information disclosure.",
                    implementation_steps=[
                        "Enable TLS 1.3 for all communications",
                        "Encrypt sensitive data at rest",
                        "Implement proper access controls",
                        "Regular security audits and monitoring"
                    ],
                    cost="High",
                    effectiveness="High",
                    priority=9,
                    related_threats=[t.id for t in category_threats]
                )
                mitigations.append(mitigation)
                mitigation_counter += 1

            elif category == "DENIAL_OF_SERVICE":
                mitigation = Mitigation(
                    id=f"mit_{mitigation_counter}",
                    title="Implement Rate Limiting and DDoS Protection",
                    description="Add rate limiting and DDoS protection to maintain service availability.",
                    implementation_steps=[
                        "Implement rate limiting on APIs",
                        "Deploy DDoS protection service",
                        "Set up monitoring and alerting",
                        "Design for horizontal scaling"
                    ],
                    cost="Medium",
                    effectiveness="Medium",
                    priority=7,
                    related_threats=[t.id for t in category_threats]
                )
                mitigations.append(mitigation)
                mitigation_counter += 1

            elif category == "ELEVATION_OF_PRIVILEGE":
                mitigation = Mitigation(
                    id=f"mit_{mitigation_counter}",
                    title="Implement Principle of Least Privilege",
                    description="Apply least privilege access controls to prevent privilege escalation.",
                    implementation_steps=[
                        "Implement role-based access control",
                        "Regular access reviews and audits",
                        "Just-in-time access for administrative tasks",
                        "Monitor for privilege escalation attempts"
                    ],
                    cost="Medium",
                    effectiveness="High",
                    priority=8,
                    related_threats=[t.id for t in category_threats]
                )
                mitigations.append(mitigation)
                mitigation_counter += 1

        return mitigations

    def _map_legacy_category(self, category: str) -> STRIDECategory:
        """Map legacy categories to STRIDE categories."""
        mapping = {
            "Injection": STRIDECategory.TAMPERING,
            "Authentication": STRIDECategory.SPOOFING,
            "Authorization": STRIDECategory.ELEVATION_OF_PRIVILEGE,
            "Data Security": STRIDECategory.INFORMATION_DISCLOSURE,
            "Web Security": STRIDECategory.TAMPERING,
            "Infrastructure": STRIDECategory.ELEVATION_OF_PRIVILEGE,
            "API Security": STRIDECategory.ELEVATION_OF_PRIVILEGE,
            "Supply Chain": STRIDECategory.TAMPERING,
            "Network Security": STRIDECategory.INFORMATION_DISCLOSURE,
            "IoT Security": STRIDECategory.SPOOFING,
            "Multi-tenancy": STRIDECategory.ELEVATION_OF_PRIVILEGE,
            "Framework Risk": STRIDECategory.TAMPERING,
            "Language Risk": STRIDECategory.TAMPERING,
        }
        return mapping.get(category, STRIDECategory.TAMPERING)

    def _map_legacy_risk(self, risk: str) -> str:
        """Map legacy risk levels to new severity levels."""
        mapping = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low"
        }
        return mapping.get(risk, "Medium")

    def _calculate_risk_score_from_threats(self, threats: List[ThreatItem]) -> int:
        """Calculate a summary risk score from STRIDE threats."""
        score = 0
        for threat in threats:
            if threat.risk:
                normalized = threat.risk.lower()
                if normalized == "critical":
                    score += 25
                elif normalized == "high":
                    score += 15
                elif normalized == "medium":
                    score += 8
                elif normalized == "low":
                    score += 3
                else:
                    score += min(getattr(threat, 'priority_score', 0), 10)
            else:
                score += min(getattr(threat, 'priority_score', 0), 10)

        return min(score, 100)

    def _risk_label(self, score: int) -> str:
        """Convert risk score to label."""
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    # Legacy implementation for backward compatibility
    def _build_threats_legacy(self, req: ThreatModelCreateRequest) -> tuple[List[ThreatItem], int]:
        """
        Legacy threat generation for backward compatibility.
        This mirrors the original _build_threats function.
        """
        items: List[ThreatItem] = []
        score: int = 0

        def add(title: str, risk: str, category: str, description: str, mitigation: str, pts: int) -> None:
            items.append(ThreatItem(
                id=self._make_id(title),
                title=title,
                description=description,
                stride_category=self._map_legacy_category(category),
                severity=risk,
                likelihood="Medium",
                impact=risk,
                status=ThreatStatus.OPEN,
                mitigation=mitigation,
                affected_assets=[],
                entry_points=[],
                trust_boundaries=[],
                capec_id=None,
                capec_description=None,
                asvs_controls=[]
            ))
            nonlocal score
            score += pts

        # Include all the original rules here (truncated for brevity)
        # This would contain the full original implementation
        if req.uses_database:
            add(
                title="SQL / Query Injection",
                risk="High", category="Injection",
                description="Malicious query statements injected through unsanitized user inputs...",
                mitigation="Use parameterized queries, prepared statements, or a trusted ORM...",
                pts=20,
            )

        # Add more legacy rules as needed...

        return items, score

    def _make_id(self, title: str) -> str:
        """Create a URL-safe ID from a title."""
        return title.lower().replace(" ", "-").replace("(", "").replace(")", "").replace("/", "").replace(".", "")


# Global instance for backward compatibility
_engine = EnhancedThreatModelingEngine()


def analyze(req: ThreatModelCreateRequest) -> ThreatModelAnalyzeResponse:
    """
    Backward-compatible analyze function using the enhanced engine.
    Uses STRIDE-based threat modeling by default.
    """
    return analyze_stride(req)


def analyze_stride(
    req: ThreatModelCreateRequest,
    generate_heatmap: bool = False,
) -> ThreatModelAnalyzeResponse:
    """
    Stateless STRIDE-based threat modeling analysis.
    """
    normalized_architecture = _engine.normalized_schema.normalize_architecture(req.architecture_diagram)
    threats = _engine.stride_engine.generate_threats(
        normalized_architecture,
        req.system_metadata or {}
    )

    mitigations = _engine._generate_mitigations(threats)
    heatmap_data = []
    if generate_heatmap:
        heatmap_obj = _engine.heatmap_generator.generate_heatmap_data(threats)
        heatmap_data = [heatmap_obj]

    score = _engine._calculate_risk_score_from_threats(threats)
    return ThreatModelAnalyzeResponse(
        threats=threats,
        mitigations=mitigations,
        heatmap_data=heatmap_data,
        risk_score=score,
        risk_label=_engine._risk_label(score),
    )


def analyze_comprehensive(
    request: ThreatModelCreateRequest,
    generate_heatmap: bool = True,
    include_summaries: bool = True
) -> ThreatModelAnalysis:
    """
    Comprehensive threat modeling analysis with all enhanced features.
    """
    return _engine.analyze_comprehensive(request, generate_heatmap, include_summaries)


# ─── Rule definitions ────────────────────────────────────────────────────
# Each rule is a tuple: (condition_fn, threat_dict, points)

def _build_threats(req: ThreatModelCreateRequest) -> Tuple[List[ThreatItem], int]:
    """
    Apply all rules against the request and return (threats, raw_score).
    """
    items: List[ThreatItem] = []
    score: int = 0

    def add(title: str, risk: str, category: str, description: str, mitigation: str, pts: int) -> None:
        items.append(ThreatItem(
            id=_make_id(title),
            title=title,
            risk=risk,       # type: ignore[arg-type]
            category=category,
            description=description,
            mitigation=mitigation,
        ))
        nonlocal score
        score += pts

    # ── System characteristics ────────────────────────────────────────

    if req.uses_database:
        add(
            title="SQL / Query Injection",
            risk="High", category="Injection",
            description=(
                "Malicious query statements injected through unsanitized user inputs can "
                "manipulate or destroy your database, leading to unauthorized access or data leakage."
            ),
            mitigation=(
                "Use parameterized queries, prepared statements, or a trusted ORM. "
                "Validate all inputs server-side and apply least-privilege DB accounts."
            ),
            pts=20,
        )

    if req.uses_auth:
        add(
            title="Identity Spoofing",
            risk="High", category="Authentication",
            description=(
                "Attackers may impersonate legitimate users by stealing or forging authentication "
                "credentials via phishing, credential stuffing, or session hijacking."
            ),
            mitigation=(
                "Enforce MFA, use short-lived JWTs with rotation, implement account-lockout policies, "
                "and adopt a zero-trust session model."
            ),
            pts=18,
        )

    if req.has_admin_panel:
        add(
            title="Privilege Escalation",
            risk="High", category="Authorization",
            description=(
                "An attacker with low-privilege access may exploit misconfigured logic to gain "
                "admin-level control over the application."
            ),
            mitigation=(
                "Implement strict RBAC, audit all elevated-privilege actions, enforce least privilege "
                "everywhere, and pen-test your admin surface."
            ),
            pts=20,
        )

    if req.stores_sensitive_data:
        add(
            title="Sensitive Data Exposure",
            risk="High", category="Data Security",
            description=(
                "PII, credentials, or financial records may be exposed through insecure storage, "
                "unencrypted transmission, or access-control misconfigurations."
            ),
            mitigation=(
                "Encrypt data at rest (AES-256) and in transit (TLS 1.3+). Mask sensitive fields in "
                "logs. Apply data minimization and run regular access audits."
            ),
            pts=18,
        )

    if not req.uses_auth:
        add(
            title="Missing Authentication Controls",
            risk="High", category="Authentication",
            description=(
                "Without authentication, any user can access protected resources, enabling data theft, "
                "unauthorized actions, and full system compromise."
            ),
            mitigation=(
                "Implement OAuth 2.0 / OpenID Connect. Protect all sensitive routes with server-side "
                "auth middleware and enforce session management best practices."
            ),
            pts=22,
        )

    # ── App-type specific ──────────────────────────────────────────────

    if req.app_type in ("Web", "Mobile"):
        add(
            title="Cross-Site Request Forgery (CSRF)",
            risk="Medium", category="Web Security",
            description=(
                "An attacker tricks an authenticated user's browser into sending unwanted state-changing "
                "requests without the user's knowledge."
            ),
            mitigation=(
                "Use CSRF tokens on all state-changing endpoints. Set SameSite=Strict cookies and "
                "validate Origin / Referer headers server-side."
            ),
            pts=12,
        )

    if req.app_type == "Web":
        add(
            title="Cross-Site Scripting (XSS)",
            risk="Medium", category="Web Security",
            description=(
                "Injected malicious scripts execute in victims' browsers, enabling session theft, "
                "credential harvesting, and DOM manipulation."
            ),
            mitigation=(
                "Sanitize and encode all user-generated output. Enforce a strict Content Security "
                "Policy (CSP) and prefer auto-escaping frameworks."
            ),
            pts=12,
        )

    if req.app_type == "Cloud":
        add(
            title="Cloud Misconfiguration",
            risk="High", category="Infrastructure",
            description=(
                "Misconfigured storage buckets, over-permissive IAM roles, or open security groups "
                "expose sensitive data and cloud resources to the internet."
            ),
            mitigation=(
                "Enable CSPM tools, apply least-privilege IAM, use infrastructure-as-code with "
                "security linting, and enforce MFA on all cloud accounts."
            ),
            pts=20,
        )

    if req.app_type == "API":
        add(
            title="Broken Object-Level Authorization",
            risk="High", category="API Security",
            description=(
                "APIs that accept object IDs without verifying ownership allow attackers to access "
                "any other user's resources by simply changing an ID."
            ),
            mitigation=(
                "Validate object ownership on every API request server-side. Use UUIDs instead of "
                "sequential IDs and maintain comprehensive authorization tests."
            ),
            pts=18,
        )

    if req.uses_external_apis:
        add(
            title="Third-Party API Compromise",
            risk="Medium", category="Supply Chain",
            description=(
                "Compromised or misconfigured third-party integrations expose your system to "
                "supply-chain attacks, data leakage, and unauthorized actions."
            ),
            mitigation=(
                "Audit every third-party API. Store keys in a secrets manager. Apply minimal API "
                "scopes and monitor for anomalous usage in real time."
            ),
            pts=10,
        )

    # ── Protocol threats ───────────────────────────────────────────────

    if "HTTP (plain)" in req.protocols:
        add(
            title="Unencrypted HTTP Traffic",
            risk="High", category="Network Security",
            description=(
                "Transmitting data over plain HTTP exposes it to man-in-the-middle interception, "
                "eavesdropping, and content injection attacks."
            ),
            mitigation=(
                "Migrate to HTTPS everywhere. Enforce HSTS, redirect all HTTP to HTTPS, and configure "
                "TLS 1.2+ with strong cipher suites."
            ),
            pts=15,
        )

    if "WebSocket / WSS" in req.protocols:
        add(
            title="WebSocket Hijacking",
            risk="Medium", category="Network Security",
            description=(
                "WebSocket connections lacking proper origin validation can be hijacked, allowing "
                "attackers to inject commands or read sensitive messages."
            ),
            mitigation=(
                "Validate the Origin header on every WebSocket upgrade. Use WSS exclusively and "
                "enforce authentication tokens at connection time."
            ),
            pts=10,
        )

    if "MQTT" in req.protocols:
        add(
            title="MQTT Broker Unauthorized Access",
            risk="High", category="IoT Security",
            description=(
                "MQTT brokers without authentication allow any client to subscribe to all topics, "
                "enabling eavesdropping or injection of malicious commands."
            ),
            mitigation=(
                "Enable username/password or client-certificate auth on your broker. Use ACLs to "
                "restrict topic access per client and enable TLS transport."
            ),
            pts=14,
        )

    if "FTP / SFTP" in req.protocols:
        add(
            title="Insecure FTP Credential Exposure",
            risk="High", category="Network Security",
            description=(
                "Plain FTP transmits credentials and data in clear-text, making them trivially "
                "interceptable on any shared or hostile network."
            ),
            mitigation=(
                "Replace FTP with SFTP or SCP. Disable anonymous FTP. Enforce key-based "
                "authentication and restrict access by IP allowlist."
            ),
            pts=15,
        )

    if "gRPC" in req.protocols:
        add(
            title="gRPC Service Reflection Exposure",
            risk="Low", category="Network Security",
            description=(
                "Enabled gRPC server reflection allows external clients to enumerate all available "
                "services and methods, aiding reconnaissance."
            ),
            mitigation=(
                "Disable server reflection in production. Enforce mutual TLS (mTLS) and apply "
                "per-method authorization interceptors."
            ),
            pts=6,
        )

    # ── Database threats ───────────────────────────────────────────────

    if "MongoDB" in req.databases:
        add(
            title="NoSQL Injection (MongoDB)",
            risk="High", category="Injection",
            description=(
                "MongoDB query operators (e.g. $where, $regex) embedded in user input can bypass "
                "authentication or dump entire collections."
            ),
            mitigation=(
                "Sanitize inputs to remove MongoDB operators. Use Mongoose schema validation. "
                "Disable the $where operator in mongo config."
            ),
            pts=15,
        )

    if "Redis" in req.databases:
        add(
            title="Redis Unauthenticated Access",
            risk="High", category="Data Security",
            description=(
                "Redis instances without authentication or exposed to the internet can be fully "
                "read, flushed, or used as a pivot for remote code execution via config commands."
            ),
            mitigation=(
                "Bind Redis to 127.0.0.1 only. Enable requirepass. Use ACL rules (Redis 6+). "
                "Never expose Redis ports directly to the internet."
            ),
            pts=16,
        )

    if "Elasticsearch" in req.databases:
        add(
            title="Elasticsearch Open Cluster",
            risk="High", category="Data Security",
            description=(
                "Unsecured Elasticsearch clusters are routinely found exposed on the internet, "
                "leaking entire indices of sensitive user data."
            ),
            mitigation=(
                "Enable X-Pack security. Restrict cluster access via network policy. "
                "Use role-based access control and rotate API keys regularly."
            ),
            pts=15,
        )

    # ── Deployment threats ─────────────────────────────────────────────

    if "Containerized (Docker / K8s)" in req.deploy_envs:
        add(
            title="Container Escape",
            risk="High", category="Infrastructure",
            description=(
                "A compromised container can escape its sandbox via privilege escalation, exploiting "
                "the container runtime or misconfigured host mounts."
            ),
            mitigation=(
                "Run containers as non-root. Enable seccomp/AppArmor profiles, disable privileged "
                "mode, avoid host-path mounts, and keep runtimes patched."
            ),
            pts=15,
        )

    if "Serverless" in req.deploy_envs:
        add(
            title="Serverless Function Event Injection",
            risk="Medium", category="Infrastructure",
            description=(
                "Serverless functions that process untrusted event payloads without validation are "
                "vulnerable to injection attacks and may execute with over-broad permissions."
            ),
            mitigation=(
                "Validate and schema-check all event inputs. Apply least-privilege IAM roles per "
                "function. Enable function-level logging and anomaly alerts."
            ),
            pts=10,
        )

    if "Edge" in req.deploy_envs:
        add(
            title="Edge / CDN Cache Poisoning",
            risk="Medium", category="Infrastructure",
            description=(
                "Improperly configured edge nodes or CDN rules can be exploited to poison cached "
                "responses, serving malicious content to all subsequent users."
            ),
            mitigation=(
                "Set strict Cache-Control headers. Use vary keys carefully. Purge the cache after "
                "every deployment and audit edge configuration regularly."
            ),
            pts=8,
        )

    # ── Framework threats ──────────────────────────────────────────────

    if any(fw in req.frameworks for fw in ("Express", "NestJS")):
        add(
            title="Missing HTTP Security Headers (Node)",
            risk="Low", category="Web Security",
            description=(
                "Node.js web servers don't set secure HTTP headers by default, leaving apps exposed "
                "to clickjacking, MIME sniffing, and other browser-based attacks."
            ),
            mitigation=(
                "Add Helmet.js to your Express / NestJS app to automatically set X-Frame-Options, "
                "CSP, X-Content-Type-Options, and other protective headers."
            ),
            pts=6,
        )

    if any(fw in req.frameworks for fw in ("Django", "Rails", "Laravel", "ASP.NET")):
        add(
            title="Mass Assignment Vulnerability",
            risk="Medium", category="Framework Risk",
            description=(
                "MVC frameworks can allow users to overwrite model fields not intended to be "
                "user-editable if whitelisting is not enforced on form input."
            ),
            mitigation=(
                "Use strong parameters (Rails), fillable arrays (Laravel), form serializers (Django), "
                "or binding whitelists (ASP.NET MVC) on every model update."
            ),
            pts=10,
        )

    if "Flask" in req.frameworks:
        add(
            title="Flask Debug Mode in Production",
            risk="High", category="Framework Risk",
            description=(
                "Running Flask with DEBUG=True in production exposes an interactive debugger console "
                "that gives attackers arbitrary remote code execution."
            ),
            mitigation=(
                "Always set FLASK_DEBUG=0 / app.debug=False in production. Use an environment "
                "variable check and a production WSGI server like Gunicorn."
            ),
            pts=15,
        )

    # ── Language threats ───────────────────────────────────────────────

    if "PHP" in req.languages:
        add(
            title="PHP Remote Code Execution Risk",
            risk="High", category="Language Risk",
            description=(
                "PHP's permissive design and functions like eval(), system(), and shell_exec() "
                "create remote code execution risk when user input is not rigorously validated."
            ),
            mitigation=(
                "Disable dangerous functions in php.ini. Set allow_url_include=Off. Validate and "
                "escape all inputs. Keep PHP 8.x patched and avoid eval() entirely."
            ),
            pts=15,
        )

    if "C / C++" in req.languages:
        add(
            title="Memory Safety Vulnerabilities",
            risk="High", category="Language Risk",
            description=(
                "C/C++ components are susceptible to buffer overflows, use-after-free, and other "
                "memory corruption issues that can lead to remote code execution."
            ),
            mitigation=(
                "Use modern C++20 features, smart pointers, and bounds-checked containers. Enable "
                "compiler flags (-fstack-protector, -D_FORTIFY_SOURCE). Consider Rust for new critical components."
            ),
            pts=18,
        )

    # ── SaaS-specific ──────────────────────────────────────────────────

    if "SaaS" in req.deploy_types:
        add(
            title="Tenant Data Isolation Failure",
            risk="High", category="Multi-tenancy",
            description=(
                "In SaaS applications, missing or incorrect tenant scoping in queries can allow one "
                "customer to access another customer's data."
            ),
            mitigation=(
                "Enforce tenant_id checks on every data query. Use Row-Level Security in the DB. "
                "Audit cross-tenant queries and add integration tests for isolation."
            ),
            pts=18,
        )

    if "IoT / Embedded" in req.deploy_types:
        add(
            title="Hardcoded Credentials in Firmware",
            risk="High", category="IoT Security",
            description=(
                "IoT devices often ship with hardcoded passwords or SSH keys that are identical "
                "across all units, enabling mass compromise once one device is reverse-engineered."
            ),
            mitigation=(
                "Generate unique credentials per device at provisioning time. Enforce OTA update "
                "capability and sign firmware images. Apply secure boot."
            ),
            pts=18,
        )

    return items, score


# ─── Public API ──────────────────────────────────────────────────────────

def analyze(req: ThreatModelCreateRequest) -> ThreatModelAnalyzeResponse:
    """
    Run the rule engine and return a stateless AnalyzeResponse
    (no DB interaction – mirrors generateThreats() on the frontend).
    """
    threats, raw_score = _build_threats(req)
    capped = min(raw_score, 100)
    return ThreatModelAnalyzeResponse(
        threats=threats,
        risk_score=capped,
        risk_label=_risk_label(capped),  # type: ignore[arg-type]
    )
