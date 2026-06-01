"""
Unit tests for the compute_threat_score() helper.

Tests exercise every verdict bucket and edge cases (VT-only, AI-only,
zero engines, boundary values).
"""

from app.services.threat_scoring import compute_threat_score


def _score(**kwargs):
    """Helper — unpack 4-tuple return value."""
    score, verdict, level, _breakdown = compute_threat_score(**kwargs)
    return score, verdict, level


class TestComputeThreatScore:
    """Verify the weighted scoring formula and verdict mapping."""

    # ── Clean ────────────────────────────────────────────────────

    def test_both_safe_returns_clean(self):
        score, verdict, level = _score(
            vt_malicious=0, vt_total=70,
            ai_is_phishing=False, ai_confidence=0.95,
            ai_phishing_probability=0.05,
            ai_model_available=True,
        )
        assert verdict == "Clean"
        assert level == "clean"
        assert score < 0.20

    def test_all_zeros_returns_clean(self):
        score, verdict, level = _score(
            vt_malicious=0, vt_total=0,
            ai_is_phishing=False, ai_confidence=0.0,
            ai_model_available=False,
        )
        assert score == 0.0
        assert verdict == "Clean"
        assert level == "clean"

    # ── Malicious ────────────────────────────────────────────────

    def test_both_high_returns_malicious(self):
        score, verdict, level = _score(
            vt_malicious=60, vt_total=70,
            ai_is_phishing=True, ai_confidence=0.95,
            ai_phishing_probability=0.95,
            ai_model_available=True,
        )
        assert verdict == "Malicious"
        assert level == "high"
        assert score >= 0.65

    def test_vt_high_ai_disagrees_still_malicious(self):
        """VT confirms malicious; weak AI safe signal must not downgrade."""
        score, verdict, level = _score(
            vt_malicious=34, vt_total=93,
            ai_is_phishing=False, ai_confidence=0.95,
            ai_phishing_probability=0.05,
            ai_model_available=True,
        )
        assert verdict == "Malicious"
        assert level == "high"
        assert score >= 0.80

    # ── Suspicious ───────────────────────────────────────────────

    def test_moderate_threats_returns_suspicious(self):
        # VT 5/70 → vt_score ≈ 0.071, AI 0.80 → weighted ≈ 0.290 (below 0.40)
        # But AI-only contribution with high p_phishing pushes via ai weight
        score, verdict, level = _score(
            vt_malicious=5, vt_total=70,
            ai_is_phishing=True, ai_confidence=0.80,
            ai_phishing_probability=0.80,
            ai_model_available=True,
        )
        # 0.7*0.071 + 0.3*0.80 ≈ 0.290 — Warning unless VT override
        assert verdict in ("Warning", "Suspicious")
        assert level in ("low", "medium")

    def test_vt_three_malicious_override(self):
        score, verdict, level = _score(
            vt_malicious=3, vt_total=70,
            ai_is_phishing=False, ai_confidence=0.99,
            ai_phishing_probability=0.01,
            ai_model_available=True,
        )
        assert verdict == "Suspicious"
        assert level == "medium"
        assert score >= 0.50

    # ── Warning ──────────────────────────────────────────────────

    def test_light_threats_returns_warning(self):
        # AI-only moderate phishing probability (VT unavailable)
        score, verdict, level = _score(
            vt_malicious=0, vt_total=0,
            ai_is_phishing=True, ai_confidence=0.25,
            ai_phishing_probability=0.25,
            ai_model_available=True,
        )
        assert verdict == "Warning"
        assert level == "low"
        assert 0.20 <= score < 0.40

    def test_ai_only_borderline_suspicious(self):
        score, verdict, level = _score(
            vt_malicious=0, vt_total=0,
            ai_is_phishing=True, ai_confidence=0.50,
            ai_phishing_probability=0.50,
            ai_model_available=True,
        )
        assert verdict == "Suspicious"
        assert level == "medium"

    # ── Edge: VT only (AI model not loaded) ──────────────────────

    def test_vt_only_high_detection(self):
        score, verdict, level = _score(
            vt_malicious=60, vt_total=70,
            ai_is_phishing=False, ai_confidence=0.0,
            ai_model_available=False,
        )
        assert verdict == "Malicious"
        assert level == "high"
        assert score >= 0.80

    # ── Edge: AI only (VT unavailable) ───────────────────────────

    def test_ai_only_phishing(self):
        score, verdict, level = _score(
            vt_malicious=0, vt_total=0,
            ai_is_phishing=True, ai_confidence=0.95,
            ai_phishing_probability=0.95,
            ai_model_available=True,
        )
        assert verdict == "Malicious"
        assert level == "high"
        assert score >= 0.65

    # ── Boundary values ──────────────────────────────────────────

    def test_exact_065_threshold(self):
        score, verdict, level = _score(
            vt_malicious=0, vt_total=0,
            ai_is_phishing=True, ai_confidence=0.65,
            ai_phishing_probability=0.65,
            ai_model_available=True,
        )
        assert score >= 0.65
        assert verdict == "Malicious"
        assert level == "high"

    def test_exact_040_threshold(self):
        score, verdict, level = _score(
            vt_malicious=0, vt_total=0,
            ai_is_phishing=True, ai_confidence=0.40,
            ai_phishing_probability=0.40,
            ai_model_available=True,
        )
        assert score >= 0.40
        assert verdict == "Suspicious"
        assert level == "medium"

    def test_exact_020_threshold(self):
        score, verdict, level = _score(
            vt_malicious=0, vt_total=0,
            ai_is_phishing=True, ai_confidence=0.20,
            ai_phishing_probability=0.20,
            ai_model_available=True,
        )
        assert score >= 0.20
        assert verdict == "Warning"
        assert level == "low"

    def test_vt_clean_dilutes_ai_signal(self):
        """When VT scanned clean, AI contribution is weighted at 30%."""
        score, verdict, level = _score(
            vt_malicious=0, vt_total=70,
            ai_is_phishing=True, ai_confidence=0.65,
            ai_phishing_probability=0.65,
            ai_model_available=True,
        )
        assert score == 0.195  # 0.7*0 + 0.3*0.65
        assert verdict == "Clean"

    def test_breakdown_returned(self):
        score, verdict, level, breakdown = compute_threat_score(
            vt_malicious=10, vt_total=70, vt_suspicious=2,
            ai_is_phishing=True, ai_confidence=0.90,
            ai_phishing_probability=0.90,
            ai_model_available=True,
        )
        assert breakdown["vt_weight"] == 0.70
        assert breakdown["ai_weight"] == 0.30
        assert breakdown["vt_score"] > 0
        assert breakdown["ai_score"] == 0.90
