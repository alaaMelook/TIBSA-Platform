"""
Shared phishing model training core.

Used by train_phishing_model.py and retrain_model.py.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from typing import Any

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from app.services.phishing_features import (
    CANONICAL_PHISHING_SEED_URLS,
    LEXICAL_FEATURE_NAMES,
    PhishingURLFeatureExtractor,
)
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

DEFAULT_THRESHOLD = 0.35
SAFE_CLASS = 0
PHISHING_CLASS = 1
MODEL_VERSION_PREFIX = "phishing_pipeline_v"

_BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
MODELS_DIR = os.path.join(_BACKEND_DIR, "models")
VERSIONS_DIR = os.path.join(MODELS_DIR, "versions")
LATEST_MODEL_JSON = os.path.join(MODELS_DIR, "latest_model.json")
PIPELINE_PATH = os.path.join(MODELS_DIR, "phishing_pipeline.joblib")
META_PATH = os.path.join(MODELS_DIR, "phishing_model_meta.joblib")


def normalize_url(url: str) -> str:
    return url.strip().lower()


def parse_label(value) -> int:
    text = str(value).strip().lower()
    if text in {"bad", "phishing", "malicious", "1", "true", "yes"}:
        return PHISHING_CLASS
    if text in {"good", "safe", "legitimate", "benign", "0", "false", "no"}:
        return SAFE_CLASS
    try:
        return PHISHING_CLASS if int(float(text)) == 1 else SAFE_CLASS
    except (ValueError, TypeError):
        return SAFE_CLASS


def label_to_str(label: int) -> str:
    return "bad" if label == PHISHING_CLASS else "good"


def synthetic_phishing_urls(n: int = 8000) -> list[str]:
    brands = [
        "microsoft", "google", "paypal", "apple", "amazon", "facebook",
        "instagram", "office365", "outlook", "netflix", "bank", "chase",
    ]
    tlds = ["xyz", "top", "club", "online", "site", "icu", "click", "link"]
    actions = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password"]
    urls: list[str] = list(CANONICAL_PHISHING_SEED_URLS)

    for i in range(n):
        brand = brands[i % len(brands)]
        tld = tlds[i % len(tlds)]
        action = actions[i % len(actions)]
        pattern = i % 12
        if pattern == 0:
            urls.append(f"https://{brand}-account-verify.{tld}")
        elif pattern == 1:
            urls.append(f"https://{brand}-login.{tld}")
        elif pattern == 2:
            urls.append(f"https://secure-{brand}-auth.{tld}")
        elif pattern == 3:
            urls.append(f"https://{brand}-billing-update.{tld}")
        elif pattern == 4:
            urls.append(f"https://{brand}-security-alert.{tld}")
        elif pattern == 5:
            urls.append(f"https://office365-{action}.{tld}" if brand == "microsoft" else f"https://{brand}-{action}.{tld}")
        elif pattern == 6:
            urls.append(f"https://appleid-verify.{tld}" if brand == "apple" else f"https://{brand}id-verify.{tld}")
        elif pattern == 7:
            urls.append(f"http://{action}-{brand}-secure.{tld}/verify?id={i}")
        elif pattern == 8:
            urls.append(f"https://{brand}.evil-{i}.{tld}/{action}")
        elif pattern == 9:
            urls.append(f"http://secure-{brand}.com.{tld}/{action}?user={i}")
        elif pattern == 10:
            urls.append(f"https://{brand}-account-recovery.{tld}")
        else:
            urls.append(f"https://{brand}-webmail-update.{tld}")
    return urls


def legitimate_urls() -> list[str]:
    bases = [
        "google.com", "www.google.com", "mail.google.com", "docs.google.com",
        "youtube.com", "www.youtube.com", "facebook.com", "www.facebook.com",
        "amazon.com", "www.amazon.com", "microsoft.com", "www.microsoft.com",
        "apple.com", "www.apple.com", "github.com", "www.github.com",
        "stackoverflow.com", "wikipedia.org", "www.wikipedia.org",
        "linkedin.com", "www.linkedin.com", "twitter.com", "www.twitter.com",
        "office.com", "www.office.com", "office365.com", "login.microsoftonline.com",
        "live.com", "outlook.live.com", "netflix.com", "www.netflix.com",
        "paypal.com", "www.paypal.com",
        "stripe.com", "www.stripe.com", "bbc.com", "www.bbc.com",
        "cnn.com", "www.cnn.com", "reddit.com", "www.reddit.com",
        "spotify.com", "www.spotify.com", "zoom.us", "www.zoom.us",
        "wixstudio.com", "www.wixstudio.com", "opensees.wixstudio.com",
    ]
    urls: list[str] = []
    for base in bases:
        urls.extend([
            base,
            f"https://{base}",
            f"http://{base}",
            f"https://www.{base.lstrip('www.')}" if not base.startswith("www.") else f"https://{base}",
        ])
    return urls * 400


def build_pipeline() -> Pipeline:
    return Pipeline(
        [
            ("features", PhishingURLFeatureExtractor()),
            (
                "clf",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=3000,
                    C=1.0,
                    solver="lbfgs",
                    random_state=42,
                ),
            ),
        ]
    )


def prepare_base_dataset(df: pd.DataFrame, *, balance_phiusil: bool = True) -> pd.DataFrame:
    """Filter, optionally balance PhiUSIIL rows, and augment with synthetic samples."""
    valid_mask = df["URL"].apply(lambda u: isinstance(u, str) and len(u.strip()) > 5)
    df = df[valid_mask].reset_index(drop=True)

    if balance_phiusil:
        df["_y"] = df["Label"].apply(parse_label)
        legit_df = df[df["_y"] == SAFE_CLASS]
        phish_df = df[df["_y"] == PHISHING_CLASS]
        n_legit = len(legit_df)
        if len(phish_df) > n_legit and n_legit > 0:
            phish_df = phish_df.sample(n=n_legit, random_state=42)
        df = pd.concat([legit_df, phish_df], ignore_index=True).drop(columns=["_y"])

    legit = legitimate_urls()
    phish = synthetic_phishing_urls(12000)
    augment_legit = pd.DataFrame({"URL": legit, "Label": "good"})
    augment_phish = pd.DataFrame({"URL": phish, "Label": "bad"})
    return pd.concat([df, augment_legit, augment_phish], ignore_index=True)


def merge_datasets(
    base_df: pd.DataFrame,
    feedback_df: pd.DataFrame | None,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Merge base dataset with live feedback; dedupe by normalized URL (keep latest)."""
    stats: dict[str, Any] = {
        "base_size": len(base_df),
        "feedback_size": 0,
        "feedback_added": 0,
        "duplicates_removed": 0,
    }

    if feedback_df is None or feedback_df.empty:
        stats["merged_size"] = len(base_df)
        return base_df.copy(), stats

    stats["feedback_size"] = len(feedback_df)
    fb = feedback_df.copy()
    fb["URL"] = fb["url"].astype(str)
    fb["Label"] = fb["final_label"].apply(label_to_str)
    fb["_norm"] = fb["URL"].apply(normalize_url)
    fb["_ts"] = pd.to_datetime(fb["timestamp"], errors="coerce")
    fb = fb.sort_values("_ts").drop_duplicates(subset=["_norm"], keep="last")

    fb_train = fb[["URL", "Label"]].copy()
    stats["feedback_added"] = len(fb_train)

    combined = pd.concat([base_df[["URL", "Label"]], fb_train], ignore_index=True)
    combined["_norm"] = combined["URL"].apply(normalize_url)
    before = len(combined)
    combined = combined.sort_index().drop_duplicates(subset=["_norm"], keep="last")
    stats["duplicates_removed"] = before - len(combined)
    combined = combined.drop(columns=["_norm"]).reset_index(drop=True)
    stats["merged_size"] = len(combined)
    return combined, stats


def evaluate_pipeline(
    pipeline: Pipeline,
    X_test: list[str],
    y_test: pd.Series,
    threshold: float,
    *,
    verbose: bool = True,
) -> dict:
    clf = pipeline.named_steps["clf"]
    class_to_index = {int(c): i for i, c in enumerate(clf.classes_)}
    phish_idx = class_to_index[PHISHING_CLASS]

    y_proba = pipeline.predict_proba(X_test)[:, phish_idx]
    y_pred_sensitive = (y_proba >= threshold).astype(int)

    if verbose:
        test_counts = y_test.value_counts().to_dict()
        print(f"\n-- Class distribution (test set) --")
        print(f"       legitimate={test_counts.get(0, 0)}, phishing={test_counts.get(1, 0)}")
        cm = confusion_matrix(y_test, y_pred_sensitive, labels=[SAFE_CLASS, PHISHING_CLASS])
        print(f"\n-- Confusion matrix (threshold={threshold}) --")
        print(f"       [[TN={cm[0][0]:5d}  FP={cm[0][1]:5d}]")
        print(f"        [FN={cm[1][0]:5d}  TP={cm[1][1]:5d}]]")
        print(classification_report(
            y_test, y_pred_sensitive,
            labels=[SAFE_CLASS, PHISHING_CLASS],
            target_names=["legitimate", "phishing"],
            zero_division=0,
        ))

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred_sensitive, labels=[PHISHING_CLASS], average="binary", zero_division=0
    )
    return {
        "accuracy": float(accuracy_score(y_test, y_pred_sensitive)),
        "phishing_precision": float(precision),
        "phishing_recall": float(recall),
        "phishing_f1": float(f1),
        "threshold": threshold,
    }


def get_next_version_number() -> int:
    os.makedirs(VERSIONS_DIR, exist_ok=True)
    pattern = re.compile(rf"^{MODEL_VERSION_PREFIX}(\d+)\.joblib$")
    versions = []
    for name in os.listdir(VERSIONS_DIR):
        match = pattern.match(name)
        if match:
            versions.append(int(match.group(1)))
    if os.path.isfile(LATEST_MODEL_JSON):
        try:
            with open(LATEST_MODEL_JSON, encoding="utf-8") as fh:
                versions.append(int(json.load(fh).get("version_number", 0)))
        except (json.JSONDecodeError, OSError, ValueError):
            pass
    return max(versions, default=0) + 1


def save_versioned_model(
    pipeline: Pipeline,
    metadata: dict[str, Any],
    *,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Save versioned pipeline + update latest pointers (backward compatible)."""
    out = output_dir or MODELS_DIR
    os.makedirs(out, exist_ok=True)
    os.makedirs(VERSIONS_DIR, exist_ok=True)

    version_num = metadata.get("version_number") or get_next_version_number()
    version_name = f"{MODEL_VERSION_PREFIX}{version_num}"
    metadata["version_number"] = version_num
    metadata["model_version"] = version_name

    version_pipeline = os.path.join(VERSIONS_DIR, f"{version_name}.joblib")
    version_meta = os.path.join(VERSIONS_DIR, f"{version_name}_meta.joblib")

    joblib.dump(pipeline, version_pipeline)
    joblib.dump(metadata, version_meta)

    # Backward-compatible latest copies
    shutil.copy2(version_pipeline, PIPELINE_PATH)
    shutil.copy2(version_meta, META_PATH)

    latest_info = {
        "version_number": version_num,
        "model_version": version_name,
        "pipeline_path": version_pipeline,
        "meta_path": version_meta,
        "updated_at": metadata.get("trained_at"),
    }
    with open(LATEST_MODEL_JSON, "w", encoding="utf-8") as fh:
        json.dump(latest_info, fh, indent=2)

    print(f"       Saved {version_name} -> {version_pipeline}")
    print(f"       Updated latest   -> {PIPELINE_PATH}")
    print(f"       Latest pointer   -> {LATEST_MODEL_JSON}")
    return latest_info


def train_from_dataframe(
    df: pd.DataFrame,
    *,
    threshold: float = DEFAULT_THRESHOLD,
    sample: int = 0,
    merge_stats: dict[str, Any] | None = None,
    verbose: bool = True,
) -> tuple[Pipeline, dict[str, Any]]:
    """Full train pipeline from a URL+Label dataframe."""
    if sample > 0:
        df = df.sample(n=min(sample, len(df)), random_state=42)

    y = df["Label"].apply(parse_label)
    X = df["URL"].apply(normalize_url).tolist()

    label_counts = y.value_counts().to_dict()
    n_safe = label_counts.get(SAFE_CLASS, 0)
    n_phish = label_counts.get(PHISHING_CLASS, 0)

    if verbose:
        print(f"       Class distribution: legitimate={n_safe}, phishing={n_phish}")
        if merge_stats:
            print(f"\n-- Dataset merge stats --")
            for key, val in merge_stats.items():
                print(f"       {key}: {val}")
        if n_safe > 0 and n_phish > 0:
            ratio = max(n_safe, n_phish) / min(n_safe, n_phish)
            print(f"       Imbalance ratio: {ratio:.2f}:1  (class_weight=balanced)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    if verbose:
        print("[train] Fitting TF-IDF + lexical features + LogisticRegression ...")
    t0 = time.time()
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)
    if verbose:
        print(f"       Done in {time.time() - t0:.1f}s")

    clf = pipeline.named_steps["clf"]
    classes = [int(c) for c in clf.classes_]
    class_to_index = {int(c): i for i, c in enumerate(classes)}

    metrics = evaluate_pipeline(pipeline, X_test, y_test, threshold, verbose=verbose)

    metadata: dict[str, Any] = {
        "pipeline_type": "TF-IDF+Lexical+LogisticRegression",
        "vectorizer": "char n-grams (3-5) + 8 lexical features",
        "lexical_features": list(LEXICAL_FEATURE_NAMES),
        "classes": classes,
        "class_to_index": class_to_index,
        "safe_class": SAFE_CLASS,
        "phishing_class": PHISHING_CLASS,
        "threshold": threshold,
        "class_weight": "balanced",
        "metrics": metrics,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "merge_stats": merge_stats or {},
        "training_rows": len(df),
    }
    return pipeline, metadata
