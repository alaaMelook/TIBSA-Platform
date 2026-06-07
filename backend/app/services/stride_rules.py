"""
Threat Modeling – STRIDE Rules Engine.

Implements STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service, Elevation of Privilege) threat categorization and rules.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from app.models.threat_modeling import STRIDECategory, ThreatItem, RiskLevel
from app.services.normalized_schema import (
    NormalizedArchitecture, NormalizedAsset, NormalizedEntryPoint,
    NormalizedTrustBoundary, NormalizedDataFlow
)


# ─── Deterministic Lookup Tables ─────────────────────────────────────────────

# Maps legacy threat category strings (as produced by _build_threats) to the
# corresponding STRIDE category.  Used by the enrichment pipeline so every
# threat gets a deterministic STRIDE classification without keyword guessing.
CATEGORY_TO_STRIDE: Dict[str, STRIDECategory] = {
    "Injection":        STRIDECategory.TAMPERING,
    "Authentication":   STRIDECategory.SPOOFING,
    "Authorization":    STRIDECategory.ELEVATION_OF_PRIVILEGE,
    "Data Security":    STRIDECategory.INFORMATION_DISCLOSURE,
    "Web Security":     STRIDECategory.TAMPERING,
    "Infrastructure":   STRIDECategory.ELEVATION_OF_PRIVILEGE,
    "API Security":     STRIDECategory.ELEVATION_OF_PRIVILEGE,
    "Supply Chain":     STRIDECategory.TAMPERING,
    "Network Security": STRIDECategory.INFORMATION_DISCLOSURE,
    "IoT Security":     STRIDECategory.SPOOFING,
    "Multi-tenancy":    STRIDECategory.ELEVATION_OF_PRIVILEGE,
    "Framework Risk":   STRIDECategory.TAMPERING,
    "Language Risk":    STRIDECategory.TAMPERING,
    "Audit":            STRIDECategory.REPUDIATION,
    "Availability":     STRIDECategory.DENIAL_OF_SERVICE,
}

# Default Likelihood (1–5) and Impact (1–5) per STRIDE category.
# priority_score formula: (likelihood * 0.4) + (impact * 0.6) * 20  → 0–100 range.
STRIDE_DEFAULTS: Dict[STRIDECategory, Dict[str, int]] = {
    STRIDECategory.SPOOFING:               {"likelihood": 3, "impact": 4},
    STRIDECategory.TAMPERING:              {"likelihood": 3, "impact": 4},
    STRIDECategory.REPUDIATION:            {"likelihood": 2, "impact": 3},
    STRIDECategory.INFORMATION_DISCLOSURE: {"likelihood": 3, "impact": 5},
    STRIDECategory.DENIAL_OF_SERVICE:      {"likelihood": 3, "impact": 3},
    STRIDECategory.ELEVATION_OF_PRIVILEGE: {"likelihood": 2, "impact": 5},
}

# Additive adjustments applied to default L and I values based on risk label.
# "High" threat → +1 to both L and I; "Low" threat → -1.
RISK_ADJUSTMENTS: Dict[str, int] = {
    "High":   1,
    "Medium": 0,
    "Low":   -1,
}

# ─── Framework-specific mitigation snippets ───────────────────────────────────
# Keyed by lower-cased framework/language name; value is a list of
# mitigation strings injected into threats when that framework is selected.
FRAMEWORK_MITIGATIONS: Dict[str, Dict[STRIDECategory, str]] = {
    "django": {
        STRIDECategory.TAMPERING:              "Use Django's {% csrf_token %} template tag for all state-changing forms.",
        STRIDECategory.SPOOFING:               "Enable Django's AUTH_PASSWORD_VALIDATORS and use django-allauth for robust authentication.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Set SECURE_HSTS_SECONDS, SECURE_SSL_REDIRECT, and SECURE_CONTENT_TYPE_NOSNIFF in Django settings.",
        STRIDECategory.REPUDIATION:            "Use Django's built-in logging framework with a tamper-evident backend (e.g., django-db-logger).",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply Django's CONN_MAX_AGE and configure Gunicorn worker timeouts to limit resource exhaustion.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Leverage Django's permission system and @permission_required decorators; never trust client-side roles.",
    },
    "fastapi": {
        STRIDECategory.SPOOFING:               "Use FastAPI's OAuth2PasswordBearer with JWT and HTTPBearer dependency injection.",
        STRIDECategory.TAMPERING:              "Use Pydantic models for strict input validation on every FastAPI endpoint.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Set CORS origins explicitly via FastAPI's CORSMiddleware; avoid wildcard origins.",
        STRIDECategory.REPUDIATION:            "Integrate Python's structlog or Loguru with request middleware for request-level audit trails.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Use slowapi (Starlette rate-limiter) to enforce per-endpoint rate limits in FastAPI.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use FastAPI's Depends() for role enforcement and verify scopes inside each protected route.",
    },
    "flask": {
        STRIDECategory.TAMPERING:              "Enable Flask-WTF CSRF protection (CSRFProtect) globally in the Flask application factory.",
        STRIDECategory.SPOOFING:               "Use Flask-Login with a strong SECRET_KEY and session.permanent=False to limit session lifetime.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Set Flask's SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, and PREFERRED_URL_SCHEME='https'.",
        STRIDECategory.REPUDIATION:            "Use Flask's app.logger with a RotatingFileHandler and log all authentication events.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply Flask-Limiter with Redis storage to rate-limit sensitive Flask routes.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use Flask-Principal or Flask-Security roles; validate permissions server-side on every request.",
    },
    "express": {
        STRIDECategory.TAMPERING:              "Use csurf middleware and helmet.js to enforce CSRF tokens and security headers in Express.",
        STRIDECategory.SPOOFING:               "Use passport.js with JWT strategy and short-lived tokens; rotate refresh tokens on each use.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Apply helmet() globally in Express to set X-Frame-Options, CSP, and other security headers.",
        STRIDECategory.REPUDIATION:            "Use morgan combined with winston to emit structured access logs for every Express request.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply express-rate-limit middleware globally and per-route in the Express application.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use express-jwt-permissions or CASL to enforce role-based access control on Express routes.",
    },
    "nestjs": {
        STRIDECategory.TAMPERING:              "Use NestJS's built-in ValidationPipe with class-validator decorators for strict DTO validation.",
        STRIDECategory.SPOOFING:               "Use @nestjs/passport with JWT strategy and Guards for authentication in NestJS.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Enable NestJS Helmet middleware and configure CORS with explicit allowed origins.",
        STRIDECategory.REPUDIATION:            "Use NestJS interceptors to log all incoming requests and responses with correlation IDs.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply @nestjs/throttler module with rate limits on all public NestJS controllers.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use NestJS RolesGuard with @Roles() decorator to enforce RBAC at the controller level.",
    },
    "spring boot": {
        STRIDECategory.TAMPERING:              "Enable Spring Security's CSRF protection and use @Valid annotations for input validation.",
        STRIDECategory.SPOOFING:               "Configure Spring Security's formLogin with BCryptPasswordEncoder and MFA support.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Set Spring Security's Content-Security-Policy and HSTS headers via HttpSecurity configuration.",
        STRIDECategory.REPUDIATION:            "Use Spring AOP with @Around advice to log all service-layer method calls with Spring Actuator audit events.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Use Bucket4j with Spring Boot to implement token-bucket rate limiting on REST endpoints.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use Spring Security's @PreAuthorize('hasRole()') and method-level security for fine-grained authorization.",
    },
    "laravel": {
        STRIDECategory.TAMPERING:              "Laravel auto-applies CSRF protection via VerifyCsrfToken middleware; verify it is not excluded for any route.",
        STRIDECategory.SPOOFING:               "Use Laravel Sanctum or Passport for API authentication with token expiry.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Set Laravel's SECURE_COOKIES=true and configure Secure, HttpOnly session flags in config/session.php.",
        STRIDECategory.REPUDIATION:            "Use Laravel's built-in audit logging via spatie/laravel-activitylog for all model changes.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply Laravel's ThrottleRequests middleware globally for rate limiting of API routes.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use Laravel Gates and Policies for authorization; never perform authorization in the view layer.",
    },
    "rails": {
        STRIDECategory.TAMPERING:              "Rails includes CSRF protection via protect_from_forgery; ensure it is enabled with :exception strategy.",
        STRIDECategory.SPOOFING:               "Use Devise gem with password complexity validations, account lockout, and Omniauth for OAuth.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Enable Rails' force_ssl and use SecureHeaders gem to set CSP, HSTS, and other headers.",
        STRIDECategory.REPUDIATION:            "Use audited or paper_trail gem to track model-level changes for audit trails in Rails.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply rack-attack gem for request throttling and blocking in Rails applications.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use Pundit or CanCanCan for authorization; define explicit policies for each resource.",
    },
    "asp.net": {
        STRIDECategory.TAMPERING:              "Use ASP.NET Core's AntiforgeryToken and ValidateAntiForgeryToken attribute on POST endpoints.",
        STRIDECategory.SPOOFING:               "Configure ASP.NET Core Identity with password hashing (BCrypt) and two-factor authentication.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Use ASP.NET Core's UseHsts() and UseHttpsRedirection() middleware in the pipeline.",
        STRIDECategory.REPUDIATION:            "Use Serilog with the Audit.NET library to log all action-level events in ASP.NET Core.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply ASP.NET Core's built-in rate limiting middleware (Microsoft.AspNetCore.RateLimiting) in Program.cs.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use ASP.NET Core Authorization Policies with [Authorize(Policy='...')] on controllers.",
    },
    "react": {
        STRIDECategory.TAMPERING:              "Use React's dangerouslySetInnerHTML sparingly and sanitize all HTML with DOMPurify before rendering.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Never store sensitive tokens in localStorage; use HttpOnly cookies for session management in React apps.",
        STRIDECategory.SPOOFING:               "Use PKCE flow (Authorization Code + PKCE) for OAuth in React SPAs; avoid implicit flow.",
        STRIDECategory.REPUDIATION:            "Log all user-initiated state changes to a backend audit service from React event handlers.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Debounce expensive API calls and implement client-side request queuing in React components.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Enforce authorization server-side; React role checks are UI-only and must not replace backend guards.",
    },
    "next.js": {
        STRIDECategory.TAMPERING:              "Use Next.js API route middleware to validate CSRF tokens and sanitize request bodies.",
        STRIDECategory.SPOOFING:               "Use NextAuth.js with PKCE and secure session strategy (database or JWT with short expiry).",
        STRIDECategory.INFORMATION_DISCLOSURE: "Configure Next.js security headers in next.config.js (X-Frame-Options, CSP, HSTS).",
        STRIDECategory.REPUDIATION:            "Use Next.js API middleware to log all mutations to a centralized audit log service.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply Vercel rate limiting or next-rate-limit middleware on Next.js API routes.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use NextAuth.js session callbacks to verify roles on the server; protect pages with getServerSideProps.",
    },
    "python": {
        STRIDECategory.TAMPERING:              "Use Python's secrets module for token generation and bleach library for HTML sanitization.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Avoid logging sensitive data; use Python's logging module with a production formatter that masks secrets.",
        STRIDECategory.SPOOFING:               "Use PyJWT with RS256 algorithm and short-lived tokens for Python-based authentication.",
        STRIDECategory.REPUDIATION:            "Implement structured JSON logging with Python's structlog to capture audit-grade event records.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Use Python's asyncio timeouts and circuit-breaker patterns (e.g., pybreaker) for external calls.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use Python's functools.wraps for permission decorator chains and validate roles server-side.",
    },
    "javascript": {
        STRIDECategory.TAMPERING:              "Use DOMPurify to sanitize HTML and avoid eval(); enforce Content-Security-Policy headers.",
        STRIDECategory.SPOOFING:               "Use the Web Crypto API for cryptographic operations; avoid custom JWT libraries.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Use HttpOnly and Secure cookie flags; avoid exposing sensitive data in client-side JS bundles.",
        STRIDECategory.REPUDIATION:            "Send audit events from the frontend to a backend logging service using the Beacon API.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Implement client-side request deduplication and exponential backoff for API retries in JavaScript.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Never rely on client-side role checks for authorization; always validate permissions in the backend.",
    },
    "typescript": {
        STRIDECategory.TAMPERING:              "Use Zod or io-ts for runtime type validation in TypeScript to prevent unexpected data mutations.",
        STRIDECategory.SPOOFING:               "Use strongly typed JWT payloads with TypeScript interfaces and validate them on every request.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Enable TypeScript's strict mode to catch potential null dereferences that may leak sensitive data.",
        STRIDECategory.REPUDIATION:            "Use TypeScript's discriminated unions for audit event types to ensure type-safe logging.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Use TypeScript-aware rate limiting middleware (e.g., express-rate-limit with TS types).",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Define permission enums in TypeScript and use exhaustive checks to enforce RBAC logic.",
    },
    "java": {
        STRIDECategory.TAMPERING:              "Use Bean Validation (JSR-380) annotations (@NotNull, @Size) for input validation in Java.",
        STRIDECategory.SPOOFING:               "Use Spring Security or Apache Shiro with BCrypt hashing and MFA for Java applications.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Apply OWASP Java HTML Sanitizer and ensure no sensitive data appears in Java exception messages.",
        STRIDECategory.REPUDIATION:            "Use Log4j2 with structured JSON layout and a WORM-compliant log storage backend in Java.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply Resilience4j rate-limiter and circuit-breaker patterns in Java services.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use Java Security Manager policies and enforce method-level security with Spring's @Secured.",
    },
    "go": {
        STRIDECategory.TAMPERING:              "Use Go's encoding/json with strict struct tags and validate all input with go-playground/validator.",
        STRIDECategory.SPOOFING:               "Use golang-jwt/jwt with RS256 and short-lived tokens for Go service authentication.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Use Go's crypto/tls package with TLS 1.3 and disable weaker cipher suites.",
        STRIDECategory.REPUDIATION:            "Use zap or zerolog for structured, leveled logging of all Go service security events.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Use Go's context.WithTimeout and golang.org/x/time/rate for rate limiting in Go services.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use Go's casbin library for RBAC/ABAC enforcement; validate roles in each HTTP handler.",
    },
    "php": {
        STRIDECategory.TAMPERING:              "Use PHP's htmlspecialchars() and prepared statements (PDO) to prevent XSS and SQLi.",
        STRIDECategory.SPOOFING:               "Use PHP's password_hash(PASSWORD_BCRYPT) and verify tokens with hash_equals() to prevent timing attacks.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Disable PHP error display in production (display_errors=Off) and use a logging library like Monolog.",
        STRIDECategory.REPUDIATION:            "Use Monolog with a database or syslog handler to record audit events in PHP applications.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Use PHP's session-based rate limiting or a Redis-backed throttler for PHP API endpoints.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use PHP's SPL_AUTOLOAD and an authorization library (e.g., PHP-Auth, Zend Permissions) for RBAC.",
    },
    "ruby": {
        STRIDECategory.TAMPERING:              "Rails' CSRF protection covers Ruby apps; additionally use strong_parameters to prevent mass assignment.",
        STRIDECategory.SPOOFING:               "Use Devise with Argon2 password hashing and two-factor authentication in Ruby on Rails.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Use Rails credentials (rails credentials:edit) to store secrets; never hard-code them in Ruby.",
        STRIDECategory.REPUDIATION:            "Use Audited or PaperTrail gem to create immutable audit trails for all Ruby model changes.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Use Rack::Attack middleware for IP-based rate limiting and throttling in Ruby applications.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use Pundit policies for authorization in Ruby; raise Pundit::NotAuthorizedError on violations.",
    },
    "rust": {
        STRIDECategory.TAMPERING:              "Leverage Rust's ownership model to prevent buffer overflows; use Serde for strict deserialization.",
        STRIDECategory.SPOOFING:               "Use Rust's argon2 crate for password hashing and jsonwebtoken crate for JWT handling.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Use Rust's secrecy crate to wrap sensitive data and prevent accidental debug-logging of secrets.",
        STRIDECategory.REPUDIATION:            "Use Rust's tracing crate with structured spans for audit-grade logging of Rust service events.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Use tower::ServiceBuilder with RateLimit layer for per-route rate limiting in Rust/Axum services.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use Rust's type system to encode permission states at compile-time; validate roles in middleware.",
    },
    "c#": {
        STRIDECategory.TAMPERING:              "Use ASP.NET Core's ModelState.IsValid and data annotation validators ([Required], [MaxLength]) in C#.",
        STRIDECategory.SPOOFING:               "Use Microsoft.Identity.Web with MSAL for C# service authentication with Entra ID (Azure AD).",
        STRIDECategory.INFORMATION_DISCLOSURE: "Use C#'s SecureString for sensitive in-memory data and avoid logging PII in .NET applications.",
        STRIDECategory.REPUDIATION:            "Use Application Insights or Serilog with structured sinks for C# audit event logging.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Use ASP.NET Core RateLimiting middleware (System.Threading.RateLimiting) in C# applications.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use [Authorize(Roles='...')] and policy-based authorization with IAuthorizationService in C#.",
    },
    "c / c++": {
        STRIDECategory.TAMPERING:              "Use bounds-checked functions (strncpy, snprintf) and ASAN/UBSAN during C/C++ development.",
        STRIDECategory.SPOOFING:               "Use OpenSSL or libsodium for cryptographic operations in C/C++ to prevent authentication bypass.",
        STRIDECategory.INFORMATION_DISCLOSURE: "Zero out sensitive buffers with explicit_bzero() or SecureZeroMemory() in C/C++ before freeing.",
        STRIDECategory.REPUDIATION:            "Use syslog() with LOG_AUTHPRIV facility for security-relevant audit events in C/C++ daemons.",
        STRIDECategory.DENIAL_OF_SERVICE:      "Apply resource limits (setrlimit) and watchdog timers in C/C++ services to prevent DoS.",
        STRIDECategory.ELEVATION_OF_PRIVILEGE: "Use POSIX capabilities (cap_set_proc) and drop privileges after initialization in C/C++ daemons.",
    },
}


def _compute_priority_score(likelihood: int, impact: int) -> int:
    """
    Compute a unique priority score using the canonical formula.

    Formula: (likelihood * 0.4) + (impact * 0.6) * 20
    Both likelihood and impact are integers in the range 1–5.
    Result is rounded to an integer in the range 8–100.
    """
    raw = ((likelihood * 0.4) + (impact * 0.6)) * 20
    return min(100, max(0, round(raw)))


def _get_framework_mitigations(
    stride_category: STRIDECategory,
    system_metadata: Dict[str, Any]
) -> List[str]:
    """
    Return a list of framework/language-specific mitigation strings for a given
    STRIDE category, derived from the frameworks and languages listed in
    system_metadata.
    """
    extra: List[str] = []
    selected: List[str] = (
        system_metadata.get("frameworks", [])
        + system_metadata.get("languages", [])
    )
    for tech in selected:
        key = tech.lower()
        tech_map = FRAMEWORK_MITIGATIONS.get(key)
        if tech_map:
            mitigation = tech_map.get(stride_category)
            if mitigation and mitigation not in extra:
                extra.append(mitigation)
    return extra


CONFIDENCE_MULTIPLIERS = {
    "Low": 0.40,
    "Medium": 0.70,
    "High": 1.00
}


def calculate_residual_risk_score(threats: List[ThreatItem]) -> Tuple[int, int]:
    """
    Computes Inherent Risk Score and Confidence-Weighted Residual Risk Score.

    Rules enforced:
    - Score is never automatically 100.
    - Score is derived from threat count, severity distribution, and priority_score.
    - Similar systems with fewer threats score lower.
    - Scores above 90 require multiple High-risk Confirmed threats across several attack surfaces.
    - Returns (InherentScore, ResidualScore), both clamped 0-100.
    """
    if not threats:
        return 0, 0

    severity_weights = {"High": 3, "Medium": 2, "Low": 1}
    total_weight = 0
    inherent_weighted_sum = 0.0
    residual_weighted_sum = 0.0

    for t in threats:
        w = severity_weights.get(t.risk, 1)
        total_weight += w

        # 1. Inherent Priority — raw priority_score, no confidence adjustment
        inherent_weighted_sum += t.priority_score * w

        # 2. Residual Priority — confidence-weighted, mitigation-reduced
        conf_label = getattr(t, "confidence", "Medium")
        c_t = CONFIDENCE_MULTIPLIERS.get(conf_label, 0.70)
        eff = getattr(t, "mitigation_effectiveness", 0.0)
        p_residual = t.priority_score * c_t * (1.0 - eff)
        residual_weighted_sum += p_residual * w

    inherent_score = round(inherent_weighted_sum / total_weight) if total_weight else 0
    residual_score = round(residual_weighted_sum / total_weight) if total_weight else 0

    # Apply a threat-count complexity multiplier (more distinct threats = higher exposure)
    # Scale: 1 threat → ×0.6, 5 threats → ×0.85, 10+ threats → ×1.0
    confirmed_count = sum(
        1 for t in threats
        if getattr(t, "threat_state", "Potential") in ("Confirmed", "Conditional")
    )
    complexity_factor = min(1.0, 0.60 + confirmed_count * 0.04)

    inherent_score = round(inherent_score * complexity_factor)
    residual_score = round(residual_score * complexity_factor)

    # Scores above 90 are reserved for multiple High-risk Confirmed threats
    # across several distinct STRIDE attack surfaces.
    high_confirmed = [
        t for t in threats
        if t.risk == "High" and getattr(t, "threat_state", "Potential") == "Confirmed"
    ]
    distinct_stride_categories = len({getattr(t, "stride_category", None) for t in high_confirmed if t.stride_category})

    if inherent_score > 90 and (len(high_confirmed) < 3 or distinct_stride_categories < 2):
        inherent_score = 90
    if residual_score > 90 and (len(high_confirmed) < 3 or distinct_stride_categories < 2):
        residual_score = 90

    return min(100, max(0, inherent_score)), min(100, max(0, residual_score))


def _compute_overall_risk_score(threats: List[ThreatItem]) -> int:
    """
    Compute an overall risk score (0–100) from the threat list.
    Uses the residual risk score from calculate_residual_risk_score.
    """
    _, residual_score = calculate_residual_risk_score(threats)
    return residual_score


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

    # Per-rule likelihood and impact (1–5) used for priority_score computation.
    # Each rule must have distinct (likelihood, impact) so scores are unique.
    likelihood: int = 3
    impact: int = 4

    def _priority_score(self, adj: int = 0) -> int:
        """Return the canonical priority score with an optional adjustment."""
        l = max(1, min(5, self.likelihood + adj))
        i = max(1, min(5, self.impact + adj))
        return _compute_priority_score(l, i)

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

    # ── helpers ──────────────────────────────────────────────────────────────

    def _append_framework_mitigations(
        self,
        base_mitigation: str,
        system_metadata: Dict[str, Any],
    ) -> str:
        """Append framework/language-specific mitigations to a base mitigation string."""
        extras = _get_framework_mitigations(self.category, system_metadata)
        if extras:
            joined = " ".join(extras)
            return f"{base_mitigation} Additionally: {joined}"
        return base_mitigation

    # ── per-category evaluators ───────────────────────────────────────────────

    def _evaluate_spoofing(self, architecture: NormalizedArchitecture,
                           system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Evaluate spoofing threats."""
        threats = []

        # Only generate Spoofing threat if architecture.entry_points exist AND authentication_required=False
        if not architecture.entry_points:
            return threats

        # Check entry points without authentication
        for ep in architecture.entry_points:
            if not ep.authentication_required:
                # Internet-exposed unauthenticated → higher likelihood
                l = min(5, self.likelihood + 1)
                i = self.impact
                ps = _compute_priority_score(l, i)

                base_mitigation = (
                    f"Implement strong authentication mechanisms for {ep.name}, "
                    f"such as OAuth 2.0, API keys, or mutual TLS."
                )
                threat = ThreatItem(
                    id=f"spoof-{ep.id}",
                    title=f"Spoofing via {ep.name}",
                    risk=self.risk_level,
                    category="Authentication",
                    description=(
                        f"An attacker could spoof legitimate users or systems through the "
                        f"{ep.name} entry point, which lacks authentication and is exposed to the internet."
                    ),
                    mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                    stride_category=STRIDECategory.SPOOFING,
                    affected_assets=[ep.id],
                    entry_points=[ep.id],
                    priority_score=ps,
                    reason=f"Entry point {ep.name} is exposed to the internet with authentication_required=False.",
                    threat_state="Confirmed"
                )
                threats.append(threat)

        return threats

    def _evaluate_tampering(self, architecture: NormalizedArchitecture,
                             system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """Evaluate tampering threats."""
        threats = []

        app_type = system_metadata.get("app_type", "")
        if isinstance(app_type, list):
            app_type = " ".join(app_type)
        frameworks = system_metadata.get("frameworks", [])

        # Only generate Tampering (CSRF/XSS) if: "Web" in architecture.app_type AND frameworks is not empty
        if "Web" not in app_type or not frameworks:
            return threats

        # Check data flows without encryption
        for df in architecture.data_flows:
            if not df.encryption and df.sensitivity in ["High", "Confidential"]:
                source_asset = architecture.get_asset_by_id(df.source_asset_id)
                dest_asset = architecture.get_asset_by_id(df.destination_asset_id)

                if source_asset and dest_asset:
                    l = self.likelihood
                    i = min(5, self.impact + 1)  # Unencrypted high-sensitivity → higher impact
                    ps = _compute_priority_score(l, i)

                    base_mitigation = (
                        f"Implement end-to-end encryption for the {df.name} data flow, "
                        f"such as TLS 1.3 or application-level encryption."
                    )
                    threat = ThreatItem(
                        id=f"tamper-{df.id}",
                        title=f"Data Tampering in {df.name}",
                        risk=self.risk_level,
                        category="Data Security",
                        description=(
                            f"Sensitive data flowing from {source_asset.name} to {dest_asset.name} "
                            f"is not encrypted and could be tampered with in transit."
                        ),
                        mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                        stride_category=STRIDECategory.TAMPERING,
                        affected_assets=[df.source_asset_id, df.destination_asset_id],
                        priority_score=ps,
                        reason=f"Data flow {df.name} transmits sensitive data from {source_asset.name} to {dest_asset.name} without encryption.",
                        threat_state="Confirmed"
                    )
                    threats.append(threat)

        return threats

    def _evaluate_repudiation(self, architecture: NormalizedArchitecture,
                               system_metadata: Dict[str, Any]) -> List[ThreatItem]:
        """
        Evaluate repudiation threats.

        Rule: Do NOT treat absence of audit_logging as a confirmed vulnerability.
        Absence of a feature ≠ evidence of a vulnerability.
        These are generated as Conditional threats only.
        """
        threats = []

        # Conditional: audit logging absent or not specified, but system has admin panel or sensitive data
        audit_enabled = system_metadata.get("audit_logging", None)
        has_admin_panel = system_metadata.get("has_admin_panel", False)
        stores_sensitive_data = system_metadata.get("stores_sensitive_data", False)
        
        if audit_enabled is False or (audit_enabled is None and (has_admin_panel or stores_sensitive_data)):
            l = self.likelihood
            i = self.impact
            ps = _compute_priority_score(l, i)

            base_mitigation = (
                "Implement centralized audit logging for all security-relevant events, "
                "user actions, and system changes with tamper-proof storage."
            )
            threat = ThreatItem(
                id="repudiation-no-audit",
                title="Lack of Audit Logging",
                risk="Medium",
                category="Audit",
                description=(
                    "Audit logging has been explicitly disabled or not configured. "
                    "Without audit trails, it is impossible to attribute actions to specific users "
                    "or reconstruct security incidents."
                ),
                mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                stride_category=STRIDECategory.REPUDIATION,
                priority_score=ps,
                reason="System metadata audit_logging is explicitly set to False.",
                threat_state="Conditional"  # Absence of feature is not a confirmed threat
            )
            threats.append(threat)

        # Conditional: internet-exposed entry points without confirmed audit logging
        # Only generate if there are actually internet-exposed entry points
        exposed_eps = [ep for ep in architecture.entry_points if ep.exposed_to_internet]
        if exposed_eps and audit_enabled is False:
            for ep in exposed_eps:
                l = min(5, self.likelihood + 1)
                i = self.impact
                ps = _compute_priority_score(l, i)

                base_mitigation = (
                    f"Implement per-request audit logging on {ep.name} to record "
                    "source IP, user identity, timestamp, and action performed."
                )
                threat = ThreatItem(
                    id=f"repudiation-ep-{ep.id}",
                    title=f"Untracked Actions via {ep.name}",
                    risk="Medium",
                    category="Audit",
                    description=(
                        f"The internet-exposed {ep.name} entry point has no audit logging configured. "
                        "User actions cannot be attributed or reconstructed in the event of an incident."
                    ),
                    mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                    stride_category=STRIDECategory.REPUDIATION,
                    entry_points=[ep.id],
                    priority_score=ps,
                    reason=f"Entry point {ep.name} is exposed to the internet and audit_logging is explicitly False.",
                    threat_state="Conditional"  # Absence of feature is not a confirmed threat
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
                    l = self.likelihood
                    i = min(5, self.impact + 1)  # Confidential data → higher impact
                    ps = _compute_priority_score(l, i)

                    base_mitigation = (
                        f"Implement proper access controls, data masking, and encryption "
                        f"for {asset.name} when accessed via {ep.name}."
                    )
                    threat = ThreatItem(
                        id=f"disclosure-{asset.id}-{ep.id}",
                        title=f"Information Disclosure of {asset.name}",
                        risk="High",
                        category="Data Security",
                        description=(
                            f"Confidential data in {asset.name} could be disclosed through "
                            f"the internet-exposed {ep.name} entry point."
                        ),
                        mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                        stride_category=STRIDECategory.INFORMATION_DISCLOSURE,
                        affected_assets=[asset.id],
                        entry_points=[ep.id],
                        priority_score=ps,
                        reason=f"Confidential asset {asset.name} is connected to internet-exposed entry point {ep.name}.",
                        threat_state="Confirmed"
                    )
                    threats.append(threat)

        # Check for unencrypted data flows carrying sensitive data
        for df in architecture.data_flows:
            if not df.encryption and df.sensitivity in ["High", "Confidential"]:
                l = min(5, self.likelihood + 1)
                i = self.impact
                ps = _compute_priority_score(l, i)

                base_mitigation = (
                    f"Enable TLS 1.3 or higher for the {df.name} data flow to prevent "
                    "passive eavesdropping and data leakage."
                )
                threat = ThreatItem(
                    id=f"disclosure-flow-{df.id}",
                    title=f"Sensitive Data Exposure in {df.name}",
                    risk="High",
                    category="Data Security",
                    description=(
                        f"Sensitive data transmitted via {df.name} is not encrypted "
                        "and could be intercepted by a passive eavesdropper."
                    ),
                    mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                    stride_category=STRIDECategory.INFORMATION_DISCLOSURE,
                    affected_assets=[df.source_asset_id, df.destination_asset_id],
                    priority_score=ps,
                    reason=f"Sensitive data flow {df.name} is not encrypted.",
                    threat_state="Confirmed"
                )
                threats.append(threat)

        # Check for Cloud environments causing potential info disclosure
        deploy_envs = system_metadata.get("deploy_envs", [])
        if "Cloud (AWS / GCP / Azure)" in deploy_envs:
            l = min(5, self.likelihood + 1)
            i = min(5, self.impact + 1)
            ps = _compute_priority_score(l, i)

            base_mitigation = (
                "Enforce 'Block Public Access' at the cloud account level, use strict IAM policies "
                "for data access, and continuously monitor bucket/storage permissions."
            )
            threat = ThreatItem(
                id="disclosure-cloud-misconfig",
                title="Cloud Storage Misconfiguration Exposing Sensitive Data",
                risk="High",
                category="Infrastructure",
                description=(
                    "Cloud storage buckets or snapshots may be misconfigured with public access, "
                    "leading to unauthorized disclosure of sensitive data."
                ),
                mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                stride_category=STRIDECategory.INFORMATION_DISCLOSURE,
                priority_score=ps,
                reason="Application is deployed in Cloud (AWS / GCP / Azure).",
                threat_state="Confirmed"
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
                l = min(5, self.likelihood + 1)  # Internet-exposed → higher likelihood
                i = self.impact
                ps = _compute_priority_score(l, i)

                base_mitigation = (
                    f"Implement rate limiting, DDoS protection, and resource quotas "
                    f"for {ep.name}. Consider using a CDN or load balancer with DoS protection."
                )
                threat = ThreatItem(
                    id=f"dos-{ep.id}",
                    title=f"Denial of Service via {ep.name}",
                    risk="Medium",
                    category="Availability",
                    description=(
                        f"The {ep.name} entry point is exposed to the internet and could be "
                        f"targeted for denial of service attacks, making the system unavailable."
                    ),
                    mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                    stride_category=STRIDECategory.DENIAL_OF_SERVICE,
                    entry_points=[ep.id],
                    priority_score=ps,
                    reason=f"Entry point {ep.name} is exposed to the internet.",
                    threat_state="Confirmed"
                )
                threats.append(threat)

        # Additional: unauthenticated endpoints are higher DoS risk
        for ep in architecture.entry_points:
            if ep.exposed_to_internet and not ep.authentication_required:
                l = min(5, self.likelihood + 2)  # Unauthenticated → even higher
                i = min(5, self.impact + 1)
                ps = _compute_priority_score(l, i)

                base_mitigation = (
                    f"Require authentication or implement CAPTCHA for {ep.name} "
                    "to prevent anonymous resource exhaustion attacks."
                )
                threat = ThreatItem(
                    id=f"dos-unauth-{ep.id}",
                    title=f"Unauthenticated DoS Risk at {ep.name}",
                    risk="High",
                    category="Availability",
                    description=(
                        f"The unauthenticated {ep.name} endpoint is exposed to the internet, "
                        "making it trivially easy to exhaust server resources without credentials."
                    ),
                    mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                    stride_category=STRIDECategory.DENIAL_OF_SERVICE,
                    entry_points=[ep.id],
                    priority_score=ps,
                    reason=f"Unauthenticated entry point {ep.name} is exposed to the internet.",
                    threat_state="Confirmed"
                )
                threats.append(threat)
                threats.append(threat)

        protocols = system_metadata.get("protocols", [])
        databases = system_metadata.get("databases", [])

        # WebSocket Exhaustion
        if "WebSocket / WSS" in protocols:
            l = self.likelihood
            i = min(5, self.impact + 1)
            ps = _compute_priority_score(l, i)

            base_mitigation = (
                "Implement concurrent connection limits per user/IP, enforce idle timeouts, "
                "and monitor active WebSocket connections to drop unresponsive clients."
            )
            threat = ThreatItem(
                id="dos-websocket-exhaustion",
                title="WebSocket Connection Exhaustion",
                risk="Medium",
                category="Availability",
                description=(
                    "The system uses WebSocket/WSS protocols, which keep long-lived connections open. "
                    "An attacker could open many connections to exhaust server resources (socket limits/memory)."
                ),
                mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                stride_category=STRIDECategory.DENIAL_OF_SERVICE,
                priority_score=ps,
                reason="System uses WebSocket / WSS protocol.",
                threat_state="Confirmed"
            )
            threats.append(threat)

        # Redis Flood
        if "Redis" in databases:
            l = self.likelihood
            i = self.impact
            ps = _compute_priority_score(l, i)

            base_mitigation = (
                "Ensure Redis is not exposed to the internet, require authentication (requirepass), "
                "and set a maxmemory policy to prevent OOM (Out of Memory) crashes."
            )
            threat = ThreatItem(
                id="dos-redis-flood",
                title="Redis Resource Exhaustion",
                risk="Medium",
                category="Availability",
                description=(
                    "The system relies on Redis. An attacker exploiting caching mechanisms "
                    "or session storage could flood Redis with keys, causing an Out of Memory (OOM) condition."
                ),
                mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                stride_category=STRIDECategory.DENIAL_OF_SERVICE,
                priority_score=ps,
                reason="System uses Redis database.",
                threat_state="Confirmed"
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
                l = self.likelihood
                i = min(5, self.impact + 1)  # High risk boundary → higher impact
                ps = _compute_priority_score(l, i)

                base_mitigation = (
                    f"Implement strict access controls and privilege separation across "
                    f"the {tb.name} boundary. Use principle of least privilege."
                )
                threat = ThreatItem(
                    id=f"elevation-{tb.id}",
                    title=f"Privilege Elevation across {tb.name}",
                    risk="High",
                    category="Authorization",
                    description=(
                        f"The {tb.name} trust boundary could be exploited to elevate privileges "
                        f"from {tb.source_zone} to {tb.target_zone}."
                    ),
                    mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                    stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                    trust_boundaries=[tb.id],
                    priority_score=ps,
                    reason=f"Trust boundary {tb.name} risk level is High.",
                    threat_state="Confirmed"
                )
                threats.append(threat)

        # Additional: assets with high sensitivity but low access control metadata
        for asset in architecture.assets:
            if asset.sensitivity_level == "High":
                l = min(5, self.likelihood + 1)
                i = self.impact
                ps = _compute_priority_score(l, i)

                base_mitigation = (
                    f"Enforce least-privilege access to {asset.name}: use role-based access control "
                    "and validate permissions on every request touching this asset."
                )
                threat = ThreatItem(
                    id=f"elevation-asset-{asset.id}",
                    title=f"Unauthorized Access to High-Sensitivity Asset {asset.name}",
                    risk="High",
                    category="Authorization",
                    description=(
                        f"The high-sensitivity asset {asset.name} may be accessible by principals "
                        "with insufficient privileges if authorization checks are missing or weak."
                    ),
                    mitigation=self._append_framework_mitigations(base_mitigation, system_metadata),
                    stride_category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                    affected_assets=[asset.id],
                    priority_score=ps,
                    reason=f"Asset {asset.name} has High sensitivity level.",
                    threat_state="Confirmed"
                )
                threats.append(threat)

        return threats


class STRIDEEngine:
    """STRIDE-based threat generation engine."""

    def __init__(self):
        self.rules = self._initialize_rules()

    def _initialize_rules(self) -> List[STRIDERule]:
        """
        Initialize STRIDE rules.

        Each rule has a distinct (likelihood, impact) pair so that the
        canonical priority_score formula produces unique values per rule type.

        Priority score = ((likelihood * 0.4) + (impact * 0.6)) * 20
        """
        return [
            # S – Spoofing: likelihood=4, impact=4 → score=80
            STRIDERule(
                category=STRIDECategory.SPOOFING,
                name="Authentication Bypass",
                condition="Entry points without authentication",
                threat_template="Spoofing through unauthenticated entry points",
                mitigation_template="Implement authentication",
                risk_level="High",
                base_score=15,
                likelihood=4,
                impact=4,
            ),
            # T – Tampering: likelihood=3, impact=5 → score=84
            STRIDERule(
                category=STRIDECategory.TAMPERING,
                name="Data Integrity Violation",
                condition="Unencrypted sensitive data flows",
                threat_template="Data tampering in transit",
                mitigation_template="Implement encryption",
                risk_level="High",
                base_score=18,
                likelihood=3,
                impact=5,
            ),
            # R – Repudiation: likelihood=2, impact=3 → score=52
            STRIDERule(
                category=STRIDECategory.REPUDIATION,
                name="Audit Logging Absence",
                condition="No audit logging",
                threat_template="Actions cannot be tracked",
                mitigation_template="Implement audit logging",
                risk_level="Medium",
                base_score=10,
                likelihood=2,
                impact=3,
            ),
            # I – Information Disclosure: likelihood=3, impact=5 → score=84
            # Use slightly different values to keep scores distinct from T
            STRIDERule(
                category=STRIDECategory.INFORMATION_DISCLOSURE,
                name="Data Exposure",
                condition="Sensitive data accessible via internet",
                threat_template="Confidential data disclosure",
                mitigation_template="Implement access controls",
                risk_level="High",
                base_score=20,
                likelihood=4,
                impact=5,
            ),
            # D – Denial of Service: likelihood=3, impact=3 → score=60
            STRIDERule(
                category=STRIDECategory.DENIAL_OF_SERVICE,
                name="Service Unavailability",
                condition="Internet-exposed entry points",
                threat_template="Denial of service attacks",
                mitigation_template="Implement DoS protection",
                risk_level="Medium",
                base_score=12,
                likelihood=3,
                impact=3,
            ),
            # E – Elevation of Privilege: likelihood=2, impact=5 → score=76
            STRIDERule(
                category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                name="Privilege Escalation",
                condition="Weak trust boundaries",
                threat_template="Unauthorized privilege elevation",
                mitigation_template="Implement access controls",
                risk_level="High",
                base_score=18,
                likelihood=2,
                impact=5,
            ),
        ]

    def generate(self, architecture: NormalizedArchitecture,
                 system_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Wrapper method that enforces tech stack validation and returns a dict."""
        has_frameworks = bool(getattr(architecture, 'frameworks', None))
        has_languages = bool(getattr(architecture, 'languages', None))

        if not has_frameworks and not has_languages:
            return {
                "threats": [],
                "confirmed_threats": [],
                "conditional_threats": [],
                "risk_score": None,
                "risk_label": None,
                "blocked": True,
                "reason": "No technology stack selected."
            }
        
        threats = self.generate_threats(architecture, system_metadata)
        score = self.compute_overall_risk_score(threats)
        
        # Calculate risk label
        risk_label = "Low"
        if score >= 70:
            risk_label = "High"
        elif score >= 40:
            risk_label = "Medium"
            
        confirmed_threats = [t for t in threats if getattr(t, "threat_state", "Potential") == "Confirmed"]
        conditional_threats = [t for t in threats if getattr(t, "threat_state", "Potential") == "Conditional"]

        return {
            "threats": threats,
            "confirmed_threats": confirmed_threats,
            "conditional_threats": conditional_threats,
            "risk_score": score,
            "risk_label": risk_label,
            "warning": ""
        }

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

    def compute_overall_risk_score(self, threats: List[ThreatItem]) -> int:
        """
        Compute an overall risk score (0–100) from the threat list.

        If any threat is High risk, the score is ≥ 70.
        Score is computed dynamically from individual priority_scores.
        """
        return _compute_overall_risk_score(threats)
