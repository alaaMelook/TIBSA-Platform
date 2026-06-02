"""
Tests for the Threat Modeling feature.

Run with:
    pytest backend/tests/test_threat_modeling.py -v
"""
from __future__ import annotations

import pytest
from app.models.threat_modeling import ThreatModelCreateRequest
from app.services.threat_modeling_engine import analyze, _risk_label


# ─── _risk_label ──────────────────────────────────────────────────────

class TestRiskLabel:
    def test_low(self):        assert _risk_label(0)  == "Low"
    def test_low_boundary(self): assert _risk_label(34) == "Low"
    def test_medium(self):     assert _risk_label(35) == "Medium"
    def test_medium_top(self): assert _risk_label(59) == "Medium"
    def test_high(self):       assert _risk_label(60) == "High"
    def test_high_top(self):   assert _risk_label(79) == "High"
    def test_critical(self):   assert _risk_label(80) == "Critical"
    def test_critical_100(self): assert _risk_label(100) == "Critical"


# ─── Minimal request helper ───────────────────────────────────────────

def _req(**kwargs) -> ThreatModelCreateRequest:
    defaults = dict(
        project_name="Test Project",
        app_type="Web",
        uses_auth=False,
        uses_database=False,
        has_admin_panel=False,
        uses_external_apis=False,
        stores_sensitive_data=False,
        frameworks=[],
        languages=[],
        deploy_envs=[],
        deploy_types=[],
        databases=[],
        protocols=[],
    )
    defaults.update(kwargs)
    return ThreatModelCreateRequest(**defaults)


# ─── analyze() ────────────────────────────────────────────────────────

class TestAnalyze:


    def test_uses_database_adds_sql_injection(self):
        result = analyze(_req(uses_database=True))
        ids = [t.id for t in result.threats]
        assert "sql--query-injection" in ids

    def test_stores_sensitive_data_adds_exposure(self):
        result = analyze(_req(stores_sensitive_data=True))
        ids = [t.id for t in result.threats]
        assert "sensitive-data-exposure" in ids

    def test_uses_external_apis_adds_supply_chain(self):
        result = analyze(_req(uses_external_apis=True))
        ids = [t.id for t in result.threats]
        assert "third-party-api-compromise" in ids

    def test_has_admin_panel_adds_privilege_escalation(self):
        result = analyze(_req(has_admin_panel=True))
        ids = [t.id for t in result.threats]
        assert "privilege-escalation" in ids

    def test_http_plain_adds_unencrypted_traffic(self):
        result = analyze(_req(protocols=["HTTP (plain)"]))
        ids = [t.id for t in result.threats]
        assert "unencrypted-http-traffic" in ids

    def test_cloud_app_type_adds_misconfiguration(self):
        result = analyze(_req(app_type="Cloud"))
        ids = [t.id for t in result.threats]
        assert "cloud-misconfiguration" in ids

    def test_api_app_type_adds_bola(self):
        result = analyze(_req(app_type="API"))
        ids = [t.id for t in result.threats]
        assert "broken-object-level-authorization" in ids

    def test_flask_framework_adds_debug_risk(self):
        result = analyze(_req(
            frameworks=["Flask"],
            control_questions={"flask_debug_enabled": True}
        ))
        ids = [t.id for t in result.threats]
        assert "flask-debug-mode-in-production" in ids

    def test_php_language_adds_rce_risk(self):
        result = analyze(_req(languages=["PHP"]))
        ids = [t.id for t in result.threats]
        assert "php-remote-code-execution-risk" in ids

    def test_mongodb_adds_nosql_injection(self):
        result = analyze(_req(databases=["MongoDB"]))
        ids = [t.id for t in result.threats]
        assert "nosql-injection-mongodb" in ids

    def test_redis_adds_unauth_access(self):
        result = analyze(_req(databases=["Redis"]))
        ids = [t.id for t in result.threats]
        assert "redis-unauthenticated-access" in ids

    def test_saas_deploy_adds_tenant_isolation(self):
        result = analyze(_req(deploy_types=["SaaS"]))
        ids = [t.id for t in result.threats]
        assert "tenant-data-isolation-failure" in ids

    def test_score_capped_at_100(self):
        # All flags on should not exceed 100
        result = analyze(_req(
            app_type="Web",
            uses_auth=True,
            uses_database=True,
            has_admin_panel=True,
            uses_external_apis=True,
            stores_sensitive_data=True,
            frameworks=["Flask", "Express", "Django"],
            languages=["PHP", "C / C++"],
            deploy_envs=["Containerized (Docker / K8s)", "Serverless", "Edge"],
            deploy_types=["SaaS", "IoT / Embedded"],
            databases=["MongoDB", "Redis", "Elasticsearch"],
            protocols=["HTTP (plain)", "WebSocket / WSS", "MQTT", "FTP / SFTP"],
        ))
        assert result.risk_score <= 100

    def test_risk_label_matches_score(self):
        result = analyze(_req(
            uses_auth=True,
            uses_database=True,
            has_admin_panel=True,
            stores_sensitive_data=True,
        ))
        assert result.risk_label == _risk_label(result.risk_score)

    def test_threat_ids_are_unique(self):
        result = analyze(_req(
            app_type="Web",
            uses_auth=True,
            uses_database=True,
            has_admin_panel=True,
            stores_sensitive_data=True,
            uses_external_apis=True,
            frameworks=["Flask", "Django"],
            languages=["PHP"],
            protocols=["HTTP (plain)", "WebSocket / WSS"],
            databases=["MongoDB", "Redis"],
            deploy_envs=["Containerized (Docker / K8s)"],
            deploy_types=["SaaS"],
        ))
        ids = [t.id for t in result.threats]
        assert len(ids) == len(set(ids)), "Duplicate threat IDs found"

    def test_all_threats_have_required_fields(self):
        result = analyze(_req(uses_auth=True, uses_database=True))
        for t in result.threats:
            assert t.id
            assert t.title
            assert t.risk in ("Low", "Medium", "High")
            assert t.category
            assert t.description
            assert t.mitigation

    def test_threat_generation_rules_validation(self):
        # 1. Test unevidenced misconfigurations are omitted
        result_no_evidence = analyze(_req(
            app_type="Web",
            frameworks=["React", "Express", "Flask"],
            uses_auth=True,
        ))
        ids_no_evidence = [t.id for t in result_no_evidence.threats]
        assert "missing-content-security-policy-csp" not in ids_no_evidence
        assert "insecure-localstorage-token-storage" not in ids_no_evidence
        assert "missing-http-security-headers-node" not in ids_no_evidence
        assert "flask-debug-mode-in-production" not in ids_no_evidence

        # 2. Test evidenced misconfigurations are reported as Confirmed
        result_with_evidence = analyze(_req(
            app_type="Web",
            frameworks=["React", "Express"],
            uses_auth=True,
            auth_questions={"stores_tokens_in_localstorage": True},
            control_questions={"uses_csp": False, "uses_helmet": False}
        ))
        
        # Every threat must have a reason
        for t in result_with_evidence.threats:
            assert t.reason is not None
            assert len(t.reason.strip()) > 0
            assert t.threat_state in ("Confirmed", "Conditional", "Mitigated")

        # Verify separated fields are populated
        assert len(result_with_evidence.confirmed_threats) > 0
        assert len(result_with_evidence.conditional_threats) > 0
        
        confirmed_ids = [t.id for t in result_with_evidence.confirmed_threats]
        conditional_ids = [t.id for t in result_with_evidence.conditional_threats]

        # Evidenced misconfigurations must be Confirmed
        assert "insecure-localstorage-token-storage" in confirmed_ids
        assert "missing-content-security-policy-csp" in confirmed_ids
        assert "missing-http-security-headers-node" in confirmed_ids

        # 3. Verify Redis selected -> Redis Unauthenticated Access = Confirmed
        result_redis = analyze(_req(databases=["Redis"]))
        redis_threat = next(t for t in result_redis.threats if t.id == "redis-unauthenticated-access")
        assert redis_threat.threat_state == "Confirmed"
        assert "Redis database is selected." in redis_threat.reason

        # 4. Verify SaaS selected -> Tenant Isolation Failure = Confirmed
        result_saas = analyze(_req(deploy_types=["SaaS"]))
        saas_threat = next(t for t in result_saas.threats if t.id == "tenant-data-isolation-failure")
        assert saas_threat.threat_state == "Confirmed"
        assert "SaaS delivery model is selected." in saas_threat.reason

        # 5. Verify REST selected -> SSRF = Conditional (when external APIs selected)
        result_rest = analyze(_req(protocols=["REST"], uses_external_apis=True))
        ssrf_threat = next(t for t in result_rest.threats if t.id == "server-side-request-forgery-ssrf-via-rest-apis")
        assert ssrf_threat.threat_state == "Conditional"
        assert "Requires additional assumption" in ssrf_threat.reason

        # 6. Verify React selected -> XSS = Conditional
        result_react = analyze(_req(app_type="Web", frameworks=["React"]))
        xss_threat = next(t for t in result_react.threats if t.id == "cross-site-scripting-xss")
        assert xss_threat.threat_state == "Conditional"
        assert "Requires additional assumption" in xss_threat.reason
