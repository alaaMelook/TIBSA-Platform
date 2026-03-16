"""
Unit tests for the compute_threat_score() helper.

Tests exercise every verdict bucket and edge cases (VT-only, AI-only,
zero engines, boundary values).
"""

from app.services.threat_scoring import compute_threat_score


class TestComputeThreatScore:
    """Verify the weighted scoring formula and verdict mapping."""

    # ── Clean ────────────────────────────────────────────────────

    def test_both_safe_returns_clean(self):
        score, verdict, level = compute_threat_score(
            vt_malicious=0, vt_total=70,
            ai_is_phishing=False, ai_confidence=0.05,
        )
        assert verdict == "Clean"
        assert level == "clean"
        assert score < 0.30

    def test_all_zeros_returns_clean(self):
        score, verdict, level = compute_threat_score(
            vt_malicious=0, vt_total=0,
            ai_is_phishing=False, ai_confidence=0.0,
        )
        assert score == 0.0
        assert verdict == "Clean"
        assert level == "clean"

    # ── Malicious ────────────────────────────────────────────────

    def test_both_high_returns_malicious(self):
        score, verdict, level = compute_threat_score(
            vt_malicious=60, vt_total=70,
            ai_is_phishing=True, ai_confidence=0.95,
        )
        assert verdict == "Malicious"
        assert level == "high"
        assert score >= 0.75

    # ── Suspicious ───────────────────────────────────────────────

    def test_moderate_threats_returns_suspicious(self):
        # AI phishing at 0.80 confidence → ai_score = 0.80
        # VT 5/70 → vt_score ≈ 0.071
        # threat_score = 0.6*0.80 + 0.4*0.071 ≈ 0.509
        score, verdict, level = compute_threat_score(
            vt_malicious=5, vt_total=70,
            ai_is_phishing=True, ai_confidence=0.80,
        )
        assert verdict == "Suspicious"
        assert level == "medium"
        assert 0.50 <= score < 0.75

    # ── Warning ──────────────────────────────────────────────────

    def test_light_threats_returns_warning(self):
        # AI phishing at 0.50 confidence → ai_score = 0.50
        # VT 0/70 → vt_score = 0
        # threat_score = 0.6*0.50 + 0.4*0 = 0.30
        score, verdict, level = compute_threat_score(
            vt_malicious=0, vt_total=70,
            ai_is_phishing=True, ai_confidence=0.50,
        )
        assert verdict == "Warning"
        assert level == "low"
        assert 0.30 <= score < 0.50

    # ── Edge: VT only (AI model not loaded) ──────────────────────

    def test_vt_only_high_detection(self):
        # AI not loaded → is_phishing=False, confidence=0 → ai_score = 0
        # VT 60/70 → vt_score ≈ 0.857
        # threat_score = 0.6*0 + 0.4*0.857 ≈ 0.343
        score, verdict, level = compute_threat_score(
            vt_malicious=60, vt_total=70,
            ai_is_phishing=False, ai_confidence=0.0,
        )
        assert verdict == "Warning"
        assert level == "low"
        assert 0.30 <= score < 0.50

    # ── Edge: AI only (VT unavailable) ───────────────────────────

    def test_ai_only_phishing(self):
        # VT total=0 → vt_score = 0 (division guarded)
        # AI phishing at 0.95 → ai_score = 0.95
        # threat_score = 0.6*0.95 + 0.4*0 = 0.57
        score, verdict, level = compute_threat_score(
            vt_malicious=0, vt_total=0,
            ai_is_phishing=True, ai_confidence=0.95,
        )
        assert verdict == "Suspicious"
        assert level == "medium"
        assert 0.50 <= score < 0.75

    # ── Boundary values ──────────────────────────────────────────

    def test_exact_075_threshold(self):
        # Need threat_score exactly 0.75
        # ai_score = 1.0 (phishing, confidence=1.0) → 0.6*1.0 = 0.60
        # vt_score needs to contribute 0.15 → 0.4*x = 0.15 → x = 0.375
        # vt_malicious/vt_total = 0.375 → e.g. 3/8
        score, verdict, level = compute_threat_score(
            vt_malicious=3, vt_total=8,
            ai_is_phishing=True, ai_confidence=1.0,
        )
        assert score >= 0.75
        assert verdict == "Malicious"
        assert level == "high"

    def test_exact_050_threshold(self):
        # Need threat_score exactly 0.50
        # ai_score = 0.50 (phishing, confidence=0.50) → 0.6*0.50 = 0.30
        # vt_score needs 0.20 → 0.4*x = 0.20 → x = 0.50
        # vt_malicious/vt_total = 0.50 → e.g. 1/2
        score, verdict, level = compute_threat_score(
            vt_malicious=1, vt_total=2,
            ai_is_phishing=True, ai_confidence=0.50,
        )
        assert score >= 0.50
        assert verdict == "Suspicious"
        assert level == "medium"

    def test_exact_030_threshold(self):
        # Need threat_score exactly 0.30
        # ai_score = 0.50 (phishing, confidence=0.50) → 0.6*0.50 = 0.30
        # vt_score = 0 → 0.4*0 = 0
        score, verdict, level = compute_threat_score(
            vt_malicious=0, vt_total=70,
            ai_is_phishing=True, ai_confidence=0.50,
        )
        assert score >= 0.30
        assert verdict == "Warning"
        assert level == "low"
