"""Tests for live phishing feedback loop."""

import pytest

from app.services.phishing_feedback import derive_feedback_label, record_scan_feedback
from app.services.phishing_trainer import PHISHING_CLASS, SAFE_CLASS, merge_datasets, parse_label


class TestDeriveFeedbackLabel:
    def test_vt_malicious_labels_phishing(self):
        label, source = derive_feedback_label(
            vt_malicious=10, vt_suspicious=2, vt_total=93,
            ai_is_phishing=False,
        )
        assert label == PHISHING_CLASS
        assert source == "vt_malicious"

    def test_vt_clean_ai_safe_labels_legitimate(self):
        label, source = derive_feedback_label(
            vt_malicious=0, vt_suspicious=0, vt_total=70,
            ai_is_phishing=False,
        )
        assert label == SAFE_CLASS
        assert source == "vt_clean_ai_safe"

    def test_ambiguous_vt_skipped(self):
        label, source = derive_feedback_label(
            vt_malicious=1, vt_suspicious=2, vt_total=70,
            ai_is_phishing=False,
        )
        assert label is None

    def test_vt_clean_but_ai_phishing_skipped(self):
        label, source = derive_feedback_label(
            vt_malicious=0, vt_suspicious=0, vt_total=70,
            ai_is_phishing=True,
        )
        assert label is None


class TestRecordScanFeedback:
    def test_writes_row_for_confirmed_malicious(self, monkeypatch, tmp_path):
        csv_path = tmp_path / "live_feedback.csv"
        monkeypatch.setattr("app.services.phishing_feedback.FEEDBACK_CSV", str(csv_path))

        written = record_scan_feedback(
            url="https://evil-phish.example/login",
            scan_id="scan-123",
            ai_data={"is_phishing": False, "phishing_probability": 0.1},
            vt_data={"malicious": 33, "suspicious": 5, "total_engines": 93},
        )
        assert written is True
        content = csv_path.read_text(encoding="utf-8")
        assert "evil-phish.example" in content


class TestMergeDatasets:
    def test_merge_deduplicates_by_url(self):
        import pandas as pd

        base = pd.DataFrame({
            "URL": ["https://a.com", "https://b.com"],
            "Label": ["good", "bad"],
        })
        feedback = pd.DataFrame({
            "url": ["https://a.com"],
            "final_label": [1],
            "timestamp": ["2026-05-31T00:00:00Z"],
        })
        merged, stats = merge_datasets(base, feedback)
        assert stats["feedback_added"] == 1
        assert len(merged) == 2
        a_row = merged[merged["URL"].str.contains("a.com")]
        assert parse_label(a_row.iloc[0]["Label"]) == PHISHING_CLASS
