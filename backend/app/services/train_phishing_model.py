"""
Train a phishing URL classifier from a CSV dataset.

Usage:
    python -m app.services.train_phishing_model --csv <path_to_csv>

Output:
    backend/models/phishing_model.joblib   — trained model
    backend/models/phishing_scaler.joblib  — fitted StandardScaler
"""

import argparse
import os
import sys
import time

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Ensure project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.url_features import extract, FEATURE_NAMES  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Train phishing URL model")
    parser.add_argument(
        "--csv", required=True,
        help="Path to phishing_site_urls.csv (columns: URL, Label)",
    )
    parser.add_argument(
        "--output-dir", default=os.path.join(os.path.dirname(__file__), "..", "..", "models"),
        help="Directory to save the trained model files",
    )
    parser.add_argument(
        "--sample", type=int, default=0,
        help="If >0, only use this many rows (for quick testing)",
    )
    args = parser.parse_args()

    # ── Load data ─────────────────────────────────────────────
    print(f"[1/5] Loading dataset from {args.csv} ...")
    df = pd.read_csv(args.csv)
    print(f"       {len(df)} rows loaded  ({df['Label'].value_counts().to_dict()})")

    # Filter out garbage/non-ASCII rows that corrupt the model
    valid_mask = df["URL"].apply(
        lambda u: isinstance(u, str) and u.isascii() and "." in u and len(u) > 5
    )
    df = df[valid_mask].reset_index(drop=True)
    print(f"       {len(df)} rows after filtering invalid URLs")

    # Augment: add well-known legitimate bare domains as "good".
    # The dataset has no bare-domain entries in the "good" class,
    # which causes the model to misclassify short legitimate URLs.
    _LEGIT_DOMAINS = [
        "www.google.com", "google.com", "www.youtube.com", "youtube.com",
        "www.facebook.com", "facebook.com", "www.amazon.com", "amazon.com",
        "www.wikipedia.org", "wikipedia.org", "www.twitter.com", "twitter.com",
        "www.instagram.com", "instagram.com", "www.linkedin.com", "linkedin.com",
        "www.reddit.com", "reddit.com", "www.netflix.com", "netflix.com",
        "www.microsoft.com", "microsoft.com", "www.apple.com", "apple.com",
        "github.com", "www.github.com", "stackoverflow.com", "www.stackoverflow.com",
        "www.yahoo.com", "yahoo.com", "www.bing.com", "bing.com",
        "www.ebay.com", "ebay.com", "www.cnn.com", "cnn.com",
        "www.bbc.com", "bbc.com", "www.nytimes.com", "nytimes.com",
        "www.spotify.com", "spotify.com", "www.twitch.tv", "twitch.tv",
        "www.dropbox.com", "dropbox.com", "www.zoom.us", "zoom.us",
        "www.slack.com", "slack.com", "www.notion.so", "notion.so",
        "www.medium.com", "medium.com", "www.quora.com", "quora.com",
        "www.pinterest.com", "pinterest.com", "www.tumblr.com", "tumblr.com",
        "www.whatsapp.com", "whatsapp.com", "www.telegram.org", "telegram.org",
        "www.discord.com", "discord.com", "www.tiktok.com", "tiktok.com",
        "www.paypal.com", "paypal.com", "www.stripe.com", "stripe.com",
        "www.shopify.com", "shopify.com", "www.etsy.com", "etsy.com",
        "www.wordpress.com", "wordpress.com", "www.blogger.com", "blogger.com",
        "play.google.com", "maps.google.com", "docs.google.com",
        "drive.google.com", "mail.google.com", "cloud.google.com",
        "aws.amazon.com", "azure.microsoft.com", "portal.azure.com",
        "outlook.com", "www.outlook.com", "live.com", "www.live.com",
        "office.com", "www.office.com", "adobe.com", "www.adobe.com",
        "salesforce.com", "www.salesforce.com", "oracle.com", "www.oracle.com",
        "ibm.com", "www.ibm.com", "intel.com", "www.intel.com",
        "nvidia.com", "www.nvidia.com", "tesla.com", "www.tesla.com",
    ]
    augment_df = pd.DataFrame({"URL": _LEGIT_DOMAINS, "Label": "good"})
    # Repeat to give enough weight (~5000 entries)
    augment_df = pd.concat([augment_df] * 50, ignore_index=True)
    df = pd.concat([df, augment_df], ignore_index=True)
    print(f"       {len(augment_df)} augmented safe-domain entries added")

    if args.sample > 0:
        df = df.sample(n=min(args.sample, len(df)), random_state=42)
        print(f"       Sampled down to {len(df)} rows")

    # ── Extract features ──────────────────────────────────────
    print("[2/5] Extracting URL features ...")
    t0 = time.time()
    features = df["URL"].apply(extract)
    X = pd.DataFrame(features.tolist(), columns=FEATURE_NAMES)
    y = (df["Label"].str.strip().str.lower() == "bad").astype(int)  # 1 = phishing, 0 = safe
    print(f"       Done in {time.time() - t0:.1f}s  —  {len(FEATURE_NAMES)} features")

    # ── Split ─────────────────────────────────────────────────
    print("[3/5] Splitting train/test (80/20) ...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    # ── Scale ─────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # ── Train ─────────────────────────────────────────────────
    print("[4/5] Training RandomForest (n_estimators=200) ...")
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        min_samples_split=5,
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train_scaled, y_train)
    print(f"       Done in {time.time() - t0:.1f}s")

    # ── Evaluate ──────────────────────────────────────────────
    y_pred = model.predict(X_test_scaled)
    print("\n── Test Results ──")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred, target_names=["safe", "phishing"]))

    # ── Save ──────────────────────────────────────────────────
    os.makedirs(args.output_dir, exist_ok=True)
    model_path = os.path.join(args.output_dir, "phishing_model.joblib")
    scaler_path = os.path.join(args.output_dir, "phishing_scaler.joblib")

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"\n[5/5] Saved model  → {model_path}")
    print(f"       Saved scaler → {scaler_path}")


if __name__ == "__main__":
    main()
