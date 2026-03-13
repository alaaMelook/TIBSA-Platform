"""
URL feature extraction for phishing detection.

Extracts structural and lexical features from a raw URL string.
These features are used by both the training script and the live classifier.
"""

import math
import re
from urllib.parse import urlparse


# Suspicious keywords commonly found in phishing URLs
_SUSPICIOUS_KEYWORDS = frozenset([
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "confirm", "password", "credential", "suspend",
    "alert", "unusual", "restriction", "limited", "paypal",
    "appleid", "icloud", "microsoft", "amazon", "netflix",
])

# Common/trusted TLDs — bare domains with these are less suspicious
_COMMON_TLDS = frozenset([
    "com", "org", "net", "edu", "gov", "mil", "int",
    "co", "io", "us", "uk", "ca", "au", "de", "fr", "jp",
])


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values()
    )


def extract(url: str) -> dict[str, float]:
    """Return a flat dict of numeric features for a single URL."""
    url_lower = url.lower().strip()

    # Strip scheme to normalise — training data has no schemes
    import re as _re
    url_no_scheme = _re.sub(r"^https?://", "", url_lower)

    # Prefix with http so urlparse can extract hostname/path/query
    parseable = f"http://{url_no_scheme}"
    try:
        parsed = urlparse(parseable)
    except ValueError:
        parsed = urlparse("http://invalid")

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = url_no_scheme  # features based on scheme-stripped URL

    # ── Length features ───────────────────────────────────────
    url_length = len(full)
    hostname_length = len(hostname)
    path_length = len(path)

    # ── Count features ────────────────────────────────────────
    dot_count = hostname.count(".")
    hyphen_count = hostname.count("-")
    at_count = full.count("@")
    slash_count = full.count("/")
    digit_count = sum(c.isdigit() for c in full)
    letter_count = sum(c.isalpha() for c in full)
    special_count = url_length - digit_count - letter_count

    # ── Binary features ───────────────────────────────────────
    has_ip = 1.0 if re.search(
        r"(?:\d{1,3}\.){3}\d{1,3}", hostname
    ) else 0.0
    try:
        has_port = 1.0 if parsed.port and parsed.port not in (80, 443) else 0.0
    except ValueError:
        has_port = 0.0
    has_at_symbol = 1.0 if "@" in full else 0.0

    # ── Ratio features ────────────────────────────────────────
    digit_ratio = digit_count / url_length if url_length else 0.0
    letter_ratio = letter_count / url_length if url_length else 0.0

    # ── Subdomain depth ───────────────────────────────────────
    subdomain_count = max(dot_count - 1, 0)

    # ── Suspicious keywords ───────────────────────────────────
    keyword_count = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in url_lower)

    # ── Path depth ────────────────────────────────────────────
    path_depth = path.strip("/").count("/") + 1 if path.strip("/") else 0
    has_path = 1.0 if path.strip("/") else 0.0

    # ── Query length ──────────────────────────────────────────
    query_length = len(query)

    # ── TLD features ──────────────────────────────────────────
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    tld_is_common = 1.0 if tld in _COMMON_TLDS else 0.0

    # ── Hostname token count (split by . and -) ──────────────
    hostname_token_count = float(len(re.split(r"[.\-]", hostname)))

    # ── Entropy of URL string ─────────────────────────────────
    entropy = _shannon_entropy(full)
    hostname_entropy = _shannon_entropy(hostname)

    return {
        "url_length":       float(url_length),
        "hostname_length":  float(hostname_length),
        "path_length":      float(path_length),
        "dot_count":        float(dot_count),
        "hyphen_count":     float(hyphen_count),
        "at_count":         float(at_count),
        "slash_count":      float(slash_count),
        "digit_count":      float(digit_count),
        "special_count":    float(special_count),
        "has_ip":           has_ip,
        "has_port":         has_port,
        "has_at_symbol":    has_at_symbol,
        "digit_ratio":      digit_ratio,
        "letter_ratio":     letter_ratio,
        "subdomain_count":  float(subdomain_count),
        "keyword_count":    float(keyword_count),
        "path_depth":       float(path_depth),
        "has_path":         has_path,
        "query_length":     float(query_length),
        "tld_is_common":    tld_is_common,
        "hostname_token_count": hostname_token_count,
        "entropy":          entropy,
        "hostname_entropy": hostname_entropy,
    }


# Ordered list of feature names — must match training column order
FEATURE_NAMES: list[str] = list(extract("http://example.com").keys())
