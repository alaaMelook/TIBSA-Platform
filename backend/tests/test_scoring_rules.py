"""
Validation tests for:
  1. Risk Scoring Rules  (no auto-100, proportional, similar systems differ)
  2. Threat Deduplication (same root cause merged)
  3. Absence-is-not-a-vulnerability (no auth != missing auth control)
"""
from app.services.threat_modeling_engine import analyze_stride
from app.models.threat_modeling import ThreatModelCreateRequest

SEP = "=" * 60


def make_banking_no_controls():
    return ThreatModelCreateRequest(
        project_name="Banking Portal (No Controls)",
        app_type="Web",
        uses_auth=True,
        uses_database=True,
        has_admin_panel=True,
        uses_external_apis=True,
        stores_sensitive_data=True,
        frameworks=["React", "FastAPI"],
        languages=["TypeScript", "Python"],
        databases=["PostgreSQL", "Redis"],
        protocols=["HTTPS", "REST"],
        deploy_envs=["Cloud (AWS / GCP / Azure)"],
        deploy_types=["SaaS"],
    )


def make_banking_strong_controls():
    return ThreatModelCreateRequest(
        project_name="Banking Portal (Strong Controls)",
        app_type="Web",
        uses_auth=True,
        uses_database=True,
        has_admin_panel=True,
        uses_external_apis=True,
        stores_sensitive_data=True,
        frameworks=["React", "FastAPI"],
        languages=["TypeScript", "Python"],
        databases=["PostgreSQL", "Redis"],
        protocols=["HTTPS", "REST"],
        deploy_envs=["Cloud (AWS / GCP / Azure)"],
        deploy_types=["SaaS"],
        control_questions={"uses_helmet": True, "uses_csp": True},
        auth_questions={"stores_tokens_in_localstorage": False},
    )


def make_static_website():
    return ThreatModelCreateRequest(
        project_name="Static Website",
        app_type="Web",
        uses_auth=False,
        uses_database=False,
        has_admin_panel=False,
        uses_external_apis=False,
        stores_sensitive_data=False,
        frameworks=["React"],
        languages=["TypeScript"],
        databases=[],
        protocols=["HTTPS"],
        deploy_envs=["Edge"],
    )


def make_nosql_api():
    return ThreatModelCreateRequest(
        project_name="NoSQL + API dedup test",
        app_type="API",
        uses_auth=True,
        uses_database=True,
        uses_external_apis=True,
        frameworks=["FastAPI"],
        languages=["Python"],
        databases=["MongoDB"],
        protocols=["REST"],
    )


def make_no_auth_system():
    """System with NO authentication selected — should NOT get a 'Missing Authentication' threat."""
    return ThreatModelCreateRequest(
        project_name="No-Auth Public Info Site",
        app_type="Web",
        uses_auth=False,
        uses_database=False,
        has_admin_panel=False,
        uses_external_apis=False,
        stores_sensitive_data=False,
        frameworks=["React"],
        languages=["JavaScript"],
        databases=[],
        protocols=["HTTPS"],
    )


def print_threats(threats):
    for t in threats:
        state = getattr(t, "threat_state", "?")
        print(f"    [{state:11}] [{t.risk:6}] ps={t.priority_score:3}  {t.title}")


def run_tests():
    failures = []

    # ── TEST 1: Banking Portal — No Controls ─────────────────────────────
    print(SEP)
    print("TEST 1: Banking Portal (No Controls)")
    r1 = analyze_stride(make_banking_no_controls())
    print(f"  Threats          : {len(r1.threats)}")
    print(f"  Confirmed        : {len(r1.confirmed_threats)}")
    print(f"  Conditional      : {len(r1.conditional_threats)}")
    print(f"  Inherent Score   : {r1.inherent_risk_score}")
    print(f"  Residual Score   : {r1.residual_risk_score}")
    print(f"  Risk Label       : {r1.risk_label}")
    print_threats(r1.threats)

    if r1.residual_risk_score == 100:
        failures.append("TEST 1 FAIL: Score must not auto-assign 100")
    if r1.residual_risk_score == 0:
        failures.append("TEST 1 FAIL: Banking portal with no controls must not score 0")
    if r1.residual_risk_score < 40:
        failures.append(f"TEST 1 FAIL: Banking portal with no controls scored too low ({r1.residual_risk_score})")
    else:
        print("  PASS: Score > 40 for high-risk banking portal")

    # ── TEST 2: Banking Portal — Strong Controls ──────────────────────────
    print()
    print(SEP)
    print("TEST 2: Banking Portal (Strong Controls)")
    r2 = analyze_stride(make_banking_strong_controls())
    print(f"  Threats          : {len(r2.threats)}")
    print(f"  Confirmed        : {len(r2.confirmed_threats)}")
    print(f"  Conditional      : {len(r2.conditional_threats)}")
    print(f"  Inherent Score   : {r2.inherent_risk_score}")
    print(f"  Residual Score   : {r2.residual_risk_score}")
    print(f"  Risk Label       : {r2.risk_label}")

    # Strong controls should NOT produce higher score than no controls
    # (inherent can be same, residual should differ if controls affect confidence/effectiveness)
    if r2.residual_risk_score > r1.residual_risk_score:
        failures.append("TEST 2 FAIL: Strong controls scored HIGHER than no controls")
    else:
        print(f"  PASS: Strong controls ({r2.residual_risk_score}) <= No controls ({r1.residual_risk_score})")

    # ── TEST 3: Static Website — Minimal Attack Surface ──────────────────
    print()
    print(SEP)
    print("TEST 3: Static Website (Minimal Attack Surface)")
    r3 = analyze_stride(make_static_website())
    print(f"  Threats          : {len(r3.threats)}")
    print(f"  Confirmed        : {len(r3.confirmed_threats)}")
    print(f"  Conditional      : {len(r3.conditional_threats)}")
    print(f"  Inherent Score   : {r3.inherent_risk_score}")
    print(f"  Residual Score   : {r3.residual_risk_score}")
    print(f"  Risk Label       : {r3.risk_label}")
    print_threats(r3.threats)

    if r3.residual_risk_score >= r1.residual_risk_score:
        failures.append(f"TEST 3 FAIL: Static site ({r3.residual_risk_score}) scored >= banking portal ({r1.residual_risk_score})")
    else:
        print(f"  PASS: Static site ({r3.residual_risk_score}) scores lower than banking portal ({r1.residual_risk_score})")

    # ── TEST 4: Deduplication — NoSQL + External API ──────────────────────
    print()
    print(SEP)
    print("TEST 4: Deduplication — MongoDB + External API")
    r4 = analyze_stride(make_nosql_api())
    titles = [t.title for t in r4.threats]
    print(f"  Threats: {titles}")

    has_combined = any("NoSQL Database Injection via External API" in t for t in titles)
    has_basic    = any(t == "NoSQL Injection (MongoDB)" for t in titles)

    if has_combined and has_basic:
        failures.append("TEST 4 FAIL: Both 'NoSQL Injection' and 'NoSQL Database Injection via External API' present — should deduplicate")
    elif has_combined:
        print("  PASS: Kept specific 'NoSQL Database Injection via External API', removed generic duplicate")
    elif has_basic:
        print("  INFO: No External API + MongoDB combo found (check threat state); basic NoSQL present")
    else:
        print("  INFO: No injection threat present for this combination")

    # ── TEST 5: Absence-is-not-a-vulnerability ────────────────────────────
    print()
    print(SEP)
    print("TEST 5: Absence-is-not-a-vulnerability — No auth system")
    r5 = analyze_stride(make_no_auth_system())
    titles5 = [t.title for t in r5.threats]
    print(f"  Threats: {titles5}")

    forbidden = [
        "Missing Authentication Controls",
        "Missing Database",
        "Missing External API Security",
        "Lack of Audit Logging",  # should not appear unless audit_logging is explicitly False
    ]
    for name in forbidden:
        if name in titles5:
            failures.append(f"TEST 5 FAIL: '{name}' should NOT appear when feature is simply not selected")

    # Absence of auth should NOT produce an identity spoofing threat
    auth_threats = [t for t in r5.threats if "Identity Spoofing" in t.title]
    if auth_threats:
        failures.append("TEST 5 FAIL: 'Identity Spoofing' appeared even though uses_auth=False (no auth system selected)")
    else:
        print("  PASS: No 'Identity Spoofing' when uses_auth=False")

    # ── TEST 6: Score differentiation (same system, different threat counts) ─
    print()
    print(SEP)
    print("TEST 6: Score must not be identical for very different systems")
    if r1.residual_risk_score == r3.residual_risk_score:
        failures.append(f"TEST 6 FAIL: Banking portal and static website have identical scores ({r1.residual_risk_score})")
    else:
        diff = r1.residual_risk_score - r3.residual_risk_score
        print(f"  PASS: Banking={r1.residual_risk_score}, Static={r3.residual_risk_score}, diff={diff}")

    # ── TEST 7: Score <= 90 unless multi-High multi-STRIDE confirmed threats ─
    print()
    print(SEP)
    print("TEST 7: Score above 90 reserved for multi-High multi-STRIDE systems")
    if r1.inherent_risk_score > 90:
        high_confirmed = [t for t in r1.threats if t.risk == "High" and getattr(t, "threat_state", "") == "Confirmed"]
        stride_cats = set(getattr(t, "stride_category", None) for t in high_confirmed if t.stride_category)
        if len(high_confirmed) < 3 or len(stride_cats) < 2:
            failures.append(f"TEST 7 FAIL: Score {r1.inherent_risk_score} > 90 but only {len(high_confirmed)} High-confirmed across {len(stride_cats)} STRIDE categories")
        else:
            print(f"  PASS: Score {r1.inherent_risk_score} > 90 justified by {len(high_confirmed)} High-Confirmed across {len(stride_cats)} STRIDE categories")
    else:
        print(f"  PASS: Inherent score {r1.inherent_risk_score} is within expected range (<= 90)")

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    print(SEP)
    if failures:
        print(f"FAILURES ({len(failures)}):")
        for f in failures:
            print(f"  ✗ {f}")
    else:
        print("ALL TESTS PASSED")
    print(SEP)


if __name__ == "__main__":
    run_tests()
