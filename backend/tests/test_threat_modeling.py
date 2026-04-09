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

    def test_no_auth_adds_missing_auth_control(self):
        result = analyze(_req(uses_auth=False))
        ids = [t.id for t in result.threats]
        assert "missing-authentication-controls" in ids

    def test_uses_auth_no_missing_auth_control(self):
        result = analyze(_req(uses_auth=True))
        ids = [t.id for t in result.threats]
        assert "missing-authentication-controls" not in ids

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
        result = analyze(_req(frameworks=["Flask"]))
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
