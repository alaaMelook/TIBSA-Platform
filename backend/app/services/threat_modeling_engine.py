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

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime

from app.models.threat_modeling import (
    ThreatItem,
    ThreatModelCreateRequest,
    ThreatModelAnalyzeResponse,
    ThreatModelAnalysis,
    Mitigation,
    MitigationPriority,
    HeatmapData,
    STRIDECategory,
    ThreatStatus,
)
from app.services.normalized_schema import NormalizedThreatModel, ThreatModelNormalizer
from app.services.stride_rules import (
    STRIDEEngine,
    CATEGORY_TO_STRIDE,
    STRIDE_DEFAULTS,
    RISK_ADJUSTMENTS,
)
from app.services.capec_enrichment import CAPECEnrichmentService, THREAT_TITLE_TO_CAPEC
from app.services.asvs_mapping import ASVSControlDatabase, STRIDE_TO_ASVS_IDS
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

        Delegates to the module-level analyze_stride() so that the enrichment
        pipeline (STRIDE, CAPEC, ASVS, priority_score, LLM) is applied consistently
        regardless of which entry-point is called.
        """
        result = analyze_stride(request, generate_heatmap=generate_heatmap)

        return ThreatModelAnalysis(
            id=f"analysis_{datetime.utcnow().timestamp()}",
            title=request.project_name,
            description=None,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            system_metadata=request.system_metadata,
            architecture_diagram=request.architecture_diagram,
            assets=request.assets,
            entry_points=request.entry_points,
            trust_boundaries=request.trust_boundaries,
            auth_questions=request.auth_questions,
            data_questions=request.data_questions,
            control_questions=request.control_questions,
            threats=result.threats,
            mitigations=result.mitigations,
            heatmap_data=result.heatmap_data[0] if result.heatmap_data else None,
        )

    def _generate_mitigations(self, threats: List[ThreatItem]) -> List[Mitigation]:
        """Generate one mitigation strategy per distinct STRIDE category found in threats."""
        mitigations: List[Mitigation] = []
        mitigation_counter = 1
        seen_categories: set = set()

        # Per-STRIDE mitigation templates using correct Mitigation field names
        STRIDE_MITIGATIONS: Dict[str, Dict] = {
            STRIDECategory.SPOOFING.value: {
                "title": "Implement Multi-Factor Authentication",
                "description": "Deploy MFA across all authentication points to prevent credential-based spoofing attacks.",
                "priority": MitigationPriority.HIGH,
                "estimated_effort": "Medium",
                "estimated_cost": "Medium",
            },
            STRIDECategory.TAMPERING.value: {
                "title": "Implement Input Validation and Integrity Controls",
                "description": "Add comprehensive input validation and integrity checking to prevent data tampering.",
                "priority": MitigationPriority.HIGH,
                "estimated_effort": "Medium",
                "estimated_cost": "Low",
            },
            STRIDECategory.REPUDIATION.value: {
                "title": "Implement Centralised Audit Logging",
                "description": "Log all security-relevant events with tamper-proof, immutable storage.",
                "priority": MitigationPriority.MEDIUM,
                "estimated_effort": "Low",
                "estimated_cost": "Low",
            },
            STRIDECategory.INFORMATION_DISCLOSURE.value: {
                "title": "Encrypt Data at Rest and in Transit",
                "description": "Implement encryption for data at rest (AES-256) and in transit (TLS 1.3).",
                "priority": MitigationPriority.CRITICAL,
                "estimated_effort": "High",
                "estimated_cost": "High",
            },
            STRIDECategory.DENIAL_OF_SERVICE.value: {
                "title": "Implement Rate Limiting and DDoS Protection",
                "description": "Add rate limiting, DDoS protection, and resource quotas to maintain availability.",
                "priority": MitigationPriority.HIGH,
                "estimated_effort": "Medium",
                "estimated_cost": "Medium",
            },
            STRIDECategory.ELEVATION_OF_PRIVILEGE.value: {
                "title": "Implement Principle of Least Privilege",
                "description": "Apply strict RBAC and least-privilege access controls to prevent privilege escalation.",
                "priority": MitigationPriority.HIGH,
                "estimated_effort": "Medium",
                "estimated_cost": "Low",
            },
        }

        for threat in threats:
            # Null-safe: skip threats without a STRIDE category
            if not threat.stride_category:
                continue
            category_val = threat.stride_category.value
            if category_val in seen_categories:
                continue
            seen_categories.add(category_val)

            template = STRIDE_MITIGATIONS.get(category_val)
            if not template:
                continue

            mitigation = Mitigation(
                id=f"mit_{mitigation_counter}",
                threat_id=threat.id,
                title=template["title"],
                description=template["description"],
                priority=template["priority"],
                estimated_effort=template["estimated_effort"],
                estimated_cost=template["estimated_cost"],
                implementation_status="Not Started",
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
            "Critical": "High",  # Map Critical to High (ThreatItem only accepts High/Medium/Low)
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


# ─── Helper functions ────────────────────────────────────────────────

def _make_id(title: str) -> str:
    """Create a URL-safe ID from a title."""
    return title.lower().replace(" ", "-").replace("(", "").replace(")", "").replace("/", "").replace(".", "")


def _enrich_threat(threat: ThreatItem) -> ThreatItem:
    """
    Deterministically enrich a ThreatItem with:
      - stride_category  : from CATEGORY_TO_STRIDE lookup
      - capec_id         : from THREAT_TITLE_TO_CAPEC lookup (+ CWE annotation)
      - asvs_controls    : ASVS control IDs from STRIDE_TO_ASVS_IDS
      - priority_score   : Likelihood × Impact (0–100)
      - llm_summary      : rule-based plain-text summary

    All lookups are O(1) dict accesses – no fuzzy matching, no false positives.
    """
    # 1. STRIDE category – deterministic category-string lookup
    stride_cat = CATEGORY_TO_STRIDE.get(threat.category)
    if stride_cat:
        threat.stride_category = stride_cat

    # 2. CAPEC ID – direct title lookup (always set the ID string)
    capec_id_str = THREAT_TITLE_TO_CAPEC.get(threat.title)
    if capec_id_str:
        threat.capec_id = capec_id_str
        # Try to annotate with CWE references if the pattern is in local DB
        try:
            pattern = _engine.capec_service.get_capec_for_threat(threat.title)
            if pattern and pattern.related_weaknesses and "[CWE:" not in threat.description:
                cwe_refs = ", ".join(pattern.related_weaknesses[:3])
                threat.description = f"{threat.description} [CWE: {cwe_refs}]"
        except Exception:
            pass  # CWE annotation is non-critical

    # 3. ASVS control IDs – direct STRIDE → ASVS lookup
    if stride_cat:
        asvs_ids = STRIDE_TO_ASVS_IDS.get(stride_cat, [])
        existing = set(threat.asvs_controls)
        for cid in asvs_ids:
            if cid not in existing:
                threat.asvs_controls.append(cid)

    # 4. Priority score = Likelihood × Impact (normalised to 0–100)
    if stride_cat:
        defaults = STRIDE_DEFAULTS.get(stride_cat, {"likelihood": 3, "impact": 3})
        adj = RISK_ADJUSTMENTS.get(threat.risk or "Medium", 0)
        L = max(1, min(5, defaults["likelihood"] + adj))
        I = max(1, min(5, defaults["impact"] + adj))
        threat.priority_score = round((L * I) / 25 * 100)

    # 5. LLM summary (rule-based for now; swap in a real LLM call later)
    try:
        threat.llm_summary = _engine.llm_service.generate_llm_summary_text(threat)
    except Exception:
        pass  # Non-critical

    return threat


def _risk_label(score: int) -> str:
    """Convert risk score to label."""
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _map_threat_to_stride(category: str) -> Optional[STRIDECategory]:
    """Map threat category to STRIDE framework."""
    category_lower = category.lower()

    if "auth" in category_lower or "spoof" in category_lower:
        return STRIDECategory.SPOOFING
    elif "tampering" in category_lower or "injection" in category_lower or "integrity" in category_lower:
        return STRIDECategory.TAMPERING
    elif "audit" in category_lower or "repudiation" in category_lower:
        return STRIDECategory.REPUDIATION
    elif "disclosure" in category_lower or "data security" in category_lower or "exposure" in category_lower:
        return STRIDECategory.INFORMATION_DISCLOSURE
    elif "denial" in category_lower or "dos" in category_lower or "availability" in category_lower:
        return STRIDECategory.DENIAL_OF_SERVICE
    elif "privilege" in category_lower or "escalation" in category_lower or "authorization" in category_lower:
        return STRIDECategory.ELEVATION_OF_PRIVILEGE

    return None


def analyze(req: ThreatModelCreateRequest) -> ThreatModelAnalyzeResponse:
    """
    Backward-compatible analyze function using the enhanced engine.
    Uses STRIDE-based threat modeling by default.
    """
    return analyze_stride(req)


def _apply_stack_context(threats: List[ThreatItem], req: ThreatModelCreateRequest) -> Tuple[List[ThreatItem], bool]:
    """
    Apply stack-specific context to the generated threats.
    Returns (modified_threats, generic_warning_flag)
    """
    if not req.frameworks and not req.languages:
        return threats, True

    # 1. Suppress mitigated threats
    suppressions = {
        "Django": {"Cross-Site Request Forgery (CSRF)": "Mitigated by Django's built-in CSRF middleware."},
        "Rails": {"Cross-Site Request Forgery (CSRF)": "Mitigated by Rails protect_from_forgery."},
        "Laravel": {"Cross-Site Request Forgery (CSRF)": "Mitigated by Laravel VerifyCsrfToken middleware."},
        "ASP.NET": {"Cross-Site Request Forgery (CSRF)": "Mitigated by ASP.NET AntiForgeryToken."},
        "FastAPI": {"Missing HTTP Security Headers (Node)": "Not applicable to FastAPI."},
        "React": {"Cross-Site Scripting (XSS)": "Mitigated by React's JSX auto-escaping."},
        "Next.js": {"Cross-Site Scripting (XSS)": "Mitigated by React's JSX auto-escaping."},
        "Angular": {"Cross-Site Scripting (XSS)": "Mitigated by Angular's template sanitizer."},
        "Svelte": {"Cross-Site Scripting (XSS)": "Mitigated by Svelte's compiler auto-escaping."},
    }

    frameworks_lower = {fw.lower(): fw for fw in req.frameworks}
    
    final_threats = []
    for threat in threats:
        suppressed = False
        for fw_key, fw_name in frameworks_lower.items():
            # Check exact match in suppressions table
            if fw_name in suppressions and threat.title in suppressions[fw_name]:
                threat.mitigation = suppressions[fw_name][threat.title]
                threat.status = ThreatStatus.MITIGATED
                threat.risk = "Low"
                # Keep it in the list so the user sees it's handled
                break
        final_threats.append(threat)

    # 2. Inject stack-specific threats
    injections = []
    existing_titles = {t.title for t in final_threats}

    def add_injection(title, risk, category, description, mitigation):
        if title not in existing_titles:
            injections.append(ThreatItem(
                id=_make_id(title),
                title=title,
                risk=risk,
                category=category,
                description=description,
                mitigation=mitigation,
            ))
            existing_titles.add(title)

    if "django" in frameworks_lower:
        add_injection("Django SECRET_KEY Exposure", "High", "Framework Risk", "Exposure of Django's SECRET_KEY can allow attackers to forge session cookies and reset passwords.", "Use environment variables for SECRET_KEY and ensure it is not committed to source control.")
        add_injection("Django DEBUG=True in Production", "High", "Framework Risk", "Running Django with DEBUG=True in production exposes detailed traceback pages with sensitive settings.", "Ensure DEBUG=False in production settings.")
    
    if "flask" in frameworks_lower:
        add_injection("Flask Debug Mode in Production", "High", "Framework Risk", "Running Flask with app.debug=True exposes an interactive debugger.", "Ensure FLASK_DEBUG=0 and app.debug=False in production.")
        
    if "react" in frameworks_lower or "next.js" in frameworks_lower:
        has_auth = (
            req.uses_auth or
            any(any(x in p.lower() for x in ("jwt", "token", "session", "oauth")) for p in req.protocols) or
            any(any(x in str(k).lower() or x in str(v).lower() for x in ("jwt", "token", "session", "oauth")) for k, v in req.auth_questions.items()) or
            any(any(x in str(k).lower() or x in str(v).lower() for x in ("jwt", "token", "session", "oauth")) for k, v in req.system_metadata.items())
        )
        if has_auth:
            add_injection("Insecure localStorage Token Storage", "High", "Web Security", "Storing JWTs or sensitive tokens in localStorage makes them vulnerable to XSS theft.", "Store tokens in secure, HttpOnly cookies instead of localStorage.")
        add_injection("Missing Content Security Policy (CSP)", "Medium", "Web Security", "Modern frontend applications should restrict resource loading origins to prevent XSS.", "Implement a strict Content Security Policy (CSP) header.")
        
    if "spring boot" in frameworks_lower:
        add_injection("Spring Actuator Endpoint Exposure", "High", "Framework Risk", "Exposed Spring Actuator endpoints can leak environment variables, heap dumps, and system state.", "Secure /actuator endpoints with authentication and disable unnecessary endpoints.")
        
    if "fastapi" in frameworks_lower:
        add_injection("FastAPI Docs Exposure", "Medium", "Framework Risk", "Leaving /docs and /redoc enabled in production can expose API surface area to attackers.", "Disable Swagger/ReDoc in production or protect them with authentication.")

    final_threats.extend(injections)

    return final_threats, False


def analyze_stride(
    req: ThreatModelCreateRequest,
    generate_heatmap: bool = False,
) -> ThreatModelAnalyzeResponse:
    """
    Stateless STRIDE-based threat modeling analysis (primary public entry-point).

    Pipeline:
      1. _build_threats(req)          – rule-based threat generation (unchanged)
      2. _apply_stack_context(t, req) - stack-specific context logic
      3. _enrich_threat(t)            – STRIDE / CAPEC / ASVS / priority / LLM
      4. _generate_mitigations(...)   – one mitigation per STRIDE category
      5. generate_per_threat_heatmap  – optional, correct List[HeatmapData] schema
    """
    # We do not block stateless analysis when frameworks and languages are empty
    # to allow backward-compatible previews and test suite executions.

    # Step 1: Generate base threats + raw additive score (backward-compatible)
    threats, raw_score = _build_threats(req)
    
    # Step 2: Apply stack-specific context (suppressions & injections)
    context_threats, generic_warning = _apply_stack_context(threats, req)
    
    capped_score = min(raw_score, 100) # (Optionally recalculate raw_score here based on injections)

    # Step 3: Deterministic enrichment for every threat
    enriched_threats = [_enrich_threat(t) for t in context_threats]

    # Step 4: One mitigation per distinct STRIDE category
    mitigations = _engine._generate_mitigations(enriched_threats)

    # Step 5: Per-threat heatmap (uses correct List[HeatmapData] schema)
    heatmap_data: List[HeatmapData] = []
    if generate_heatmap:
        heatmap_data = _engine.heatmap_generator.generate_per_threat_heatmap(enriched_threats)

    return ThreatModelAnalyzeResponse(
        threats=enriched_threats,
        mitigations=mitigations,
        heatmap_data=heatmap_data,
        risk_score=capped_score,
        risk_label=_risk_label(capped_score),
        generic_warning=generic_warning,
    )


def analyze_comprehensive(
    request: ThreatModelCreateRequest,
    generate_heatmap: bool = True,
    include_summaries: bool = True
) -> ThreatModelAnalysis:
    """
    Comprehensive threat modeling analysis with all enhanced features.
    Delegates to the engine instance which in turn calls analyze_stride().
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

    has_csrf_auth = (
        req.uses_auth or
        any(any(x in p.lower() for x in ("session", "cookie")) for p in req.protocols) or
        any(any(x in str(k).lower() or x in str(v).lower() for x in ("session", "cookie")) for k, v in req.auth_questions.items()) or
        any(any(x in str(k).lower() or x in str(v).lower() for x in ("session", "cookie")) for k, v in req.system_metadata.items())
    )
    if req.app_type in ("Web", "Mobile") and has_csrf_auth:
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

    # ── Combined / Advanced threats ────────────────────────────────────

    if req.uses_database and req.uses_external_apis:
        add(
            title="Database Poisoning via Third-Party Integration",
            risk="High", category="Supply Chain",
            description=(
                "If external APIs are trusted to directly populate your database without validation, "
                "a compromised third-party service could inject malicious data into your core database."
            ),
            mitigation=(
                "Validate all data from external APIs before inserting into the database. Implement "
                "schema validation, rate limiting, and anomaly detection for API responses."
            ),
            pts=16,
        )

    if req.stores_sensitive_data and req.uses_external_apis:
        add(
            title="Sensitive Data Leakage through Third-Party APIs",
            risk="High", category="Data Security",
            description=(
                "When sending sensitive data to external APIs (e.g. for processing, analytics), "
                "that data could be logged, cached, or misused if the third-party service is compromised."
            ),
            mitigation=(
                "Minimize PII sent to third parties. Use data anonymization/pseudonymization. "
                "Implement data retention policies and audit third-party data handling practices."
            ),
            pts=14,
        )

    if req.stores_sensitive_data and "Elasticsearch" in req.databases:
        add(
            title="Elasticsearch PII Exposure",
            risk="High", category="Data Security",
            description=(
                "Elasticsearch is commonly misconfigured and exposed to the internet, and it does not "
                "encrypt indexed data by default, making PII easily searchable by attackers."
            ),
            mitigation=(
                "Never expose Elasticsearch to the internet. Bind to 127.0.0.1. Enable X-Pack encryption "
                "and authentication. Use VPC/security groups and regularly audit indices for sensitive data."
            ),
            pts=17,
        )

    if req.app_type == "API" and req.uses_auth:
        add(
            title="API Token Theft and Replay Attacks",
            risk="High", category="API Security",
            description=(
                "API tokens transmitted over HTTP or stored in browser localStorage are vulnerable to theft "
                "and replay. Attackers can reuse stolen tokens until expiration."
            ),
            mitigation=(
                "Always use HTTPS. Implement short token expiry (15-30 min) with refresh token rotation. "
                "Use opaque tokens and store them securely (httpOnly cookies). Add token binding."
            ),
            pts=15,
        )

    if req.has_admin_panel and not req.uses_auth:
        add(
            title="Unrestricted Admin Panel Access",
            risk="High", category="Authorization",
            description=(
                "An admin panel without authentication is a critical vulnerability that allows any attacker "
                "to gain full administrative control over the application and its data."
            ),
            mitigation=(
                "Implement strong authentication on ALL admin routes. Separate admin route handling from "
                "public routes. Implement IP whitelisting and require MFA for admin accounts."
            ),
            pts=25,
        )

    if "MongoDB" in req.databases and req.uses_external_apis:
        add(
            title="NoSQL Database Injection via External API",
            risk="High", category="Injection",
            description=(
                "External APIs providing data that gets queried against MongoDB can inject MongoDB operators "
                "if the data is not properly sanitized before constructing queries."
            ),
            mitigation=(
                "Use mongoose schema validation and sanitize inputs before any database query. Never construct "
                "MongoDB queries by string concatenation. Use parameterized queries."
            ),
            pts=14,
        )

    if len(req.deploy_envs) >= 2 and "Hybrid" in req.deploy_envs:
        add(
            title="Multi-Environment Configuration Drift",
            risk="Medium", category="Infrastructure",
            description=(
                "Applications deployed across multiple environments (on-premise, cloud, hybrid) often suffer "
                "from configuration inconsistencies that create security gaps between environments."
            ),
            mitigation=(
                "Use infrastructure-as-code for all environments. Implement automated compliance checking "
                "and drift detection. Run the same security tests across all environments."
            ),
            pts=10,
        )

    if "GraphQL" in req.protocols and len(req.frameworks) > 0:
        add(
            title="GraphQL Query Complexity Attacks",
            risk="Medium", category="API Security",
            description=(
                "GraphQL endpoints without proper validation can be exploited with deeply nested queries "
                "or field aliasing to cause denial of service through excessive computation."
            ),
            mitigation=(
                "Implement query depth and complexity limits. Use query whitelisting for production. "
                "Monitor query execution time and add rate limiting per user/token."
            ),
            pts=10,
        )

    if "REST" in req.protocols and req.uses_external_apis:
        add(
            title="Server-Side Request Forgery (SSRF) via REST APIs",
            risk="High", category="API Security",
            description=(
                "If your application fetches resources from URLs provided in user input or external APIs, "
                "an attacker can trick it into making requests to internal systems or sensitive endpoints."
            ),
            mitigation=(
                "Validate and whitelist all URLs before making requests. Disable access to private IP ranges. "
                "Use DNS rebinding protection and implement request timeouts."
            ),
            pts=14,
        )

    return items, score


# ─── Public API ──────────────────────────────────────────────────────────
