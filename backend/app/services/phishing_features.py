"""
Lexical URL features and brand-impersonation heuristics for phishing detection.

Used by:
  - phishing_trainer (sklearn FeatureUnion / combined transformer)
  - ml_engine (post-model probability boost)
  - threat_scoring (minimum verdict floors)
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer

# ── Brand & TLD lists ─────────────────────────────────────────────────────────

BRAND_KEYWORDS: tuple[str, ...] = (
    "microsoft", "google", "paypal", "apple", "amazon",
    "facebook", "instagram", "office365", "outlook",
    "netflix", "linkedin", "twitter", "whatsapp", "telegram",
    "coinbase", "binance", "metamask", "bank", "chase", "wellsfargo",
    "icloud", "dropbox", "stripe",
)

TRUSTED_BRAND_SUFFIXES: tuple[str, ...] = (
    "microsoft.com", "google.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "paypal.com", "outlook.com",
    "office.com", "office365.com", "live.com", "github.com",
    "googleusercontent.com", "youtube.com", "linkedin.com",
    "netflix.com", "twitter.com", "x.com", "stripe.com",
    "icloud.com", "dropbox.com",
)

SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "club", "work", "buzz", "gq", "ml", "cf", "ga", "tk",
    "icu", "rest", "surf", "monster", "click", "link", "info", "biz",
    "online", "site", "live", "win", "loan", "racing", "review",
})

LOGIN_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "sign-in", "logon", "auth", "authenticate", "sso",
})
VERIFY_KEYWORDS: frozenset[str] = frozenset({
    "verify", "verification", "validate", "confirm", "confirmation",
})
ACCOUNT_KEYWORDS: frozenset[str] = frozenset({
    "account", "profile", "user", "member", "id", "myaccount",
})
PAYMENT_KEYWORDS: frozenset[str] = frozenset({
    "billing", "payment", "invoice", "wallet", "pay", "checkout",
    "security", "alert", "update", "recovery", "restore", "suspend",
})

# High-signal training seeds (brand-impersonation typosquats)
CANONICAL_PHISHING_SEED_URLS: tuple[str, ...] = (
    "https://microsoft-account-verify.top",
    "https://microsoft-login.top",
    "https://office365-auth.site",
    "https://appleid-verify.click",
    "https://amazon-billing-update.xyz",
    "https://paypal-security-alert.top",
    "https://google-account-recovery.site",
    "https://secure-google-auth.click",
    "https://bank-login-update.site",
    "https://office365-login.site",
    "https://paypal-security-update.xyz",
    "https://facebook-account-confirm.top",
    "https://instagram-verify-account.click",
    "https://outlook-webmail-update.site",
)

LEXICAL_FEATURE_NAMES: tuple[str, ...] = (
    "contains_brand_keyword",
    "contains_login_keyword",
    "contains_verify_keyword",
    "contains_account_keyword",
    "contains_payment_keyword",
    "suspicious_tld",
    "hyphen_count",
    "subdomain_depth",
)

_IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def normalize_url(url: str) -> str:
    return url.strip().lower()


def _parse_host(url: str) -> tuple[str, str, str]:
    """Return (hostname, registrable_label, tld)."""
    normalized = normalize_url(url)
    if "://" not in normalized:
        normalized = f"https://{normalized}"
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return "", "", ""
    parts = host.split(".")
    tld = parts[-1] if parts else ""
    label = parts[-2] if len(parts) >= 2 else host
    return host, label, tld


def is_trusted_brand_hostname(hostname: str) -> bool:
    """True for real brand domains (e.g. login.microsoft.com), not typosquats."""
    h = hostname.lower().rstrip(".")
    if not h or _IP_HOST_RE.match(h):
        return False
    for suffix in TRUSTED_BRAND_SUFFIXES:
        if h == suffix or h.endswith(f".{suffix}"):
            return True
    return False


def _text_has_keyword(text: str, keywords: frozenset[str]) -> bool:
    return any(kw in text for kw in keywords)


def extract_lexical_features(url: str) -> dict[str, float]:
    """Extract numeric lexical features for one URL."""
    normalized = normalize_url(url)
    if "://" not in normalized:
        normalized = f"https://{normalized}"
    host, label, tld = _parse_host(normalized)
    path_query = normalized.split("/", 3)
    path_part = path_query[3] if len(path_query) > 3 else ""
    host_and_path = f"{host}/{path_part}" if path_part else host

    trusted = is_trusted_brand_hostname(host)
    brand_hit = _text_has_keyword(host_and_path, frozenset(BRAND_KEYWORDS))
    # Brand on trusted domain is not impersonation signal
    contains_brand = 1.0 if (brand_hit and not trusted) else 0.0

    return {
        "contains_brand_keyword": contains_brand,
        "contains_login_keyword": 1.0 if _text_has_keyword(host_and_path, LOGIN_KEYWORDS) else 0.0,
        "contains_verify_keyword": 1.0 if _text_has_keyword(host_and_path, VERIFY_KEYWORDS) else 0.0,
        "contains_account_keyword": 1.0 if _text_has_keyword(host_and_path, ACCOUNT_KEYWORDS) else 0.0,
        "contains_payment_keyword": 1.0 if _text_has_keyword(host_and_path, PAYMENT_KEYWORDS) else 0.0,
        "suspicious_tld": 1.0 if tld in SUSPICIOUS_TLDS else 0.0,
        "hyphen_count": float(host.count("-")),
        "subdomain_depth": float(max(0, host.count(".") - 1)),
    }


def lexical_features_matrix(urls: list[str]) -> csr_matrix:
    """Dense lexical feature matrix (n_samples × n_features)."""
    rows = [
        [extract_lexical_features(u)[name] for name in LEXICAL_FEATURE_NAMES]
        for u in urls
    ]
    return csr_matrix(np.array(rows, dtype=np.float64))


def assess_brand_impersonation(url: str) -> dict[str, Any]:
    """
    Rule-based brand-impersonation assessment (independent of ML model).
    Returns metadata plus is_brand_impersonation and impersonation_risk (0–1).
    """
    feats = extract_lexical_features(url)
    host, _, _ = _parse_host(url)
    trusted = is_trusted_brand_hostname(host)

    has_brand = bool(feats["contains_brand_keyword"])
    has_cred = bool(
        feats["contains_login_keyword"]
        or feats["contains_verify_keyword"]
        or feats["contains_account_keyword"]
    )
    has_payment = bool(feats["contains_payment_keyword"])
    suspicious_tld = bool(feats["suspicious_tld"])
    hyphenated = feats["hyphen_count"] >= 2

    is_impersonation = has_brand and not trusted and (
        suspicious_tld
        or has_cred
        or has_payment
        or hyphenated
    )

    risk = 0.0
    if is_impersonation:
        risk = 0.55
        if suspicious_tld:
            risk += 0.20
        if has_cred:
            risk += 0.15
        if has_payment:
            risk += 0.05
        if hyphenated:
            risk += 0.05
        risk = min(1.0, risk)

    return {
        **feats,
        "hostname": host,
        "trusted_brand_domain": trusted,
        "is_brand_impersonation": is_impersonation,
        "impersonation_risk": round(risk, 4),
    }


def apply_lexical_phishing_boost(url: str, p_phishing: float) -> tuple[float, dict[str, Any]]:
    """Raise model P(phishing) when brand-impersonation rules fire."""
    meta = assess_brand_impersonation(url)
    risk = meta["impersonation_risk"]
    original = p_phishing

    if risk >= 0.85:
        p_phishing = max(p_phishing, 0.92)
    elif risk >= 0.70:
        p_phishing = max(p_phishing, 0.82)
    elif risk >= 0.55:
        p_phishing = max(p_phishing, 0.68)
    elif risk >= 0.45:
        p_phishing = max(p_phishing, 0.52)

    meta["model_p_phishing_before_boost"] = round(original, 4)
    meta["p_phishing_after_boost"] = round(p_phishing, 4)
    if p_phishing > original:
        meta["lexical_boost_applied"] = True
    return p_phishing, meta


class PhishingURLFeatureExtractor(BaseEstimator, TransformerMixin):
    """Char TF-IDF + lexical features (fit on URL strings)."""

    def __init__(self) -> None:
        self.tfidf_ = TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            max_features=80_000,
            sublinear_tf=True,
            min_df=5,
            max_df=0.95,
            strip_accents="unicode",
        )

    def fit(self, X, y=None):
        self.tfidf_.fit(X)
        return self

    def transform(self, X):
        tfidf_features = self.tfidf_.transform(X)
        lexical = lexical_features_matrix(list(X))
        return hstack([tfidf_features, lexical], format="csr")

    def fit_transform(self, X, y=None):
        return self.fit(X, y).transform(X)
