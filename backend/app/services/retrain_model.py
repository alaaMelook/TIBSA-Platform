"""
Retrain phishing model by merging PhiUSIIL with live scan feedback.

Usage:
    python -m app.services.retrain_model
    python -m app.services.retrain_model --base-csv PhiUSIIL_Phishing_URL_Dataset.csv
"""

from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.phishing_feedback import FEEDBACK_CSV, load_feedback_dataframe  # noqa: E402
from app.services.phishing_trainer import (  # noqa: E402
    DEFAULT_THRESHOLD,
    MODELS_DIR,
    merge_datasets,
    parse_label,
    prepare_base_dataset,
    save_versioned_model,
    train_from_dataframe,
)

_BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
DEFAULT_BASE_CSV = os.path.join(_BACKEND_DIR, "PhiUSIIL_Phishing_URL_Dataset.csv")


def main() -> None:
    parser = argparse.ArgumentParser(description="Retrain phishing model with live feedback")
    parser.add_argument(
        "--base-csv",
        default=DEFAULT_BASE_CSV,
        help="Original training dataset (PhiUSIIL)",
    )
    parser.add_argument(
        "--feedback-csv",
        default=FEEDBACK_CSV,
        help="Live feedback CSV from scans",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="Phishing decision threshold",
    )
    parser.add_argument(
        "--sample", type=int, default=0, help="Subsample merged dataset (quick test)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("TIBSA Phishing Model — Retrain with Live Feedback")
    print("=" * 60)

    # ── Load base dataset ─────────────────────────────────────────
    print(f"\n[1/4] Loading base dataset: {args.base_csv}")
    if not os.path.isfile(args.base_csv):
        raise FileNotFoundError(f"Base dataset not found: {args.base_csv}")
    base_df = pd.read_csv(args.base_csv)
    base_size = len(base_df)
    base_counts = base_df["Label"].apply(parse_label).value_counts().to_dict()
    print(f"       Base size: {base_size}")
    print(f"       Base distribution: legitimate={base_counts.get(0, 0)}, phishing={base_counts.get(1, 0)}")

    # ── Load live feedback ────────────────────────────────────────
    print(f"\n[2/4] Loading live feedback: {args.feedback_csv}")
    if os.path.isfile(args.feedback_csv):
        feedback_df = load_feedback_dataframe()
    else:
        feedback_df = pd.DataFrame()
        print("       No feedback file yet — training on base dataset only")

    fb_size = len(feedback_df)
    if fb_size > 0:
        fb_counts = feedback_df["final_label"].value_counts().to_dict()
        print(f"       Feedback rows: {fb_size}")
        print(f"       Feedback distribution: legitimate={fb_counts.get(0, 0)}, phishing={fb_counts.get(1, 0)}")
        by_source = feedback_df["label_source"].value_counts().to_dict()
        print(f"       By source: {by_source}")
    else:
        print("       Feedback rows: 0")

    # ── Merge + prepare ───────────────────────────────────────────
    print(f"\n[3/4] Merging datasets and preparing training set ...")
    merged_df, merge_stats = merge_datasets(base_df, feedback_df if fb_size else None)
    print(f"       Merged size (before augment): {merge_stats['merged_size']}")
    print(f"       New samples from live system: {merge_stats['feedback_added']}")
    print(f"       Duplicates removed: {merge_stats['duplicates_removed']}")

    prepared = prepare_base_dataset(merged_df, balance_phiusil=True)
    prep_counts = prepared["Label"].apply(parse_label).value_counts().to_dict()
    print(f"       After augmentation: {len(prepared)} rows")
    print(f"       Final distribution: legitimate={prep_counts.get(0, 0)}, phishing={prep_counts.get(1, 0)}")

    # ── Train + version ───────────────────────────────────────────
    print(f"\n[4/4] Training new model version ...")
    pipeline, metadata = train_from_dataframe(
        prepared,
        threshold=args.threshold,
        sample=args.sample,
        merge_stats=merge_stats,
    )
    save_versioned_model(pipeline, metadata)

    print("\n-- Retrain complete --")
    print(f"       Version: {metadata['model_version']}")
    print(f"       Phishing F1: {metadata['metrics']['phishing_f1']:.4f}")
    print(f"       Restart backend or call MLEngine.reload() to load new model.")


if __name__ == "__main__":
    main()
