"""
Train a phishing URL classifier from a CSV dataset.

Pipeline:
    TfidfVectorizer (char n-grams 3-5) -> LogisticRegression (class_weight=balanced)

Usage:
    python -m app.services.train_phishing_model --csv <path_to_csv>

Output:
    backend/models/versions/phishing_pipeline_vN.joblib
    backend/models/phishing_pipeline.joblib  (latest, backward compatible)
    backend/models/phishing_model_meta.joblib
    backend/models/latest_model.json
"""

from __future__ import annotations

import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.phishing_trainer import (  # noqa: E402
    DEFAULT_THRESHOLD,
    MODELS_DIR,
    parse_label,
    prepare_base_dataset,
    save_versioned_model,
    train_from_dataframe,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train phishing URL TF-IDF model")
    parser.add_argument("--csv", required=True, help="CSV with URL and Label columns")
    parser.add_argument("--output-dir", default=MODELS_DIR, help="Model output directory")
    parser.add_argument("--sample", type=int, default=0, help="Subsample for quick runs")
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="Phishing decision threshold (default 0.35)",
    )
    args = parser.parse_args()

    print(f"[1/5] Loading dataset from {args.csv} ...")
    df = pd.read_csv(args.csv)
    raw_counts = df["Label"].value_counts().to_dict()
    print(f"       {len(df)} rows loaded  (raw labels: {raw_counts})")

    print("[2/5] Preparing dataset (balance + augmentation) ...")
    prepared = prepare_base_dataset(df, balance_phiusil=True)
    label_counts = prepared["Label"].apply(parse_label).value_counts().to_dict()
    print(f"       {len(prepared)} rows after prepare")
    print(f"       Class distribution: legitimate={label_counts.get(0, 0)}, phishing={label_counts.get(1, 0)}")

    print("[3/5] Training ...")
    pipeline, metadata = train_from_dataframe(
        prepared,
        threshold=args.threshold,
        sample=args.sample,
    )

    print("\n[4/5] Saving versioned model ...")
    save_versioned_model(pipeline, metadata, output_dir=args.output_dir)

    print("\n[5/5] Done.")
    print(f"       Version: {metadata['model_version']}")
    print(f"       Phishing recall: {metadata['metrics']['phishing_recall']:.4f}")


if __name__ == "__main__":
    main()
