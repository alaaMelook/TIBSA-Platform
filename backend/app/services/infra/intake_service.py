"""
Intake Service – Stage 1 of the Infra Intelligence Pipeline.

Responsibilities:
  - Strip and normalize the raw user-supplied target string
  - Detect IOC type: url | domain | ip | hash | email
  - Extract the primary hostname for downstream DNS/WHOIS queries
"""
from __future__ import annotations

import re
from typing import Tuple
from urllib.parse import urlparse


# ─── Type Literals ────────────────────────────────────────────────────────────

InfraTargetType = str  # "url" | "domain" | "ip" | "hash" | "email"

# Known suspicious TLDs worth flagging later by the indicator service
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",        # Freenom abuse-prone
    "xyz", "top", "click", "link",        # commonly abused
    "loan", "win", "bid", "trade",
    "work", "review", "accountant",
    "stream", "download", "zip", "mov",
}

# Regex patterns
_IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$"
)
_IPV6_RE = re.compile(r"^\[?[0-9a-fA-F:]{3,45}\]?$")
_MD5_RE   = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE  = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class IntakeService:
    """
    Normalizes a raw target string and detects its IOC type.
    All methods are pure functions (no I/O).
    """

    @staticmethod
    def classify(raw: str) -> Tuple[str, InfraTargetType]:
        """
        Returns (normalized_target, target_type).

        Normalized target for URLs    → lowercased, scheme-stripped hostname+path
        Normalized target for domains → lowercase FQDN
        Normalized target for IPs     → cleaned IP string
        Normalized target for hashes  → lowercased hex string
        Normalized target for emails  → lowercased email
        """
        target = raw.strip()

        # ── Email ─────────────────────────────────────────────────────────────
        if _EMAIL_RE.match(target):
            return target.lower(), "email"

        # ── Hash ──────────────────────────────────────────────────────────────
        lower = target.lower()
        if _MD5_RE.match(lower) or _SHA1_RE.match(lower) or _SHA256_RE.match(lower):
            return lower, "hash"

        # ── URL ───────────────────────────────────────────────────────────────
        if target.startswith(("http://", "https://", "ftp://")):
            parsed = urlparse(target)
            hostname = (parsed.hostname or "").lower().rstrip(".")
            normalized = target.lower()
            return normalized, "url"

        # ── IP address ────────────────────────────────────────────────────────
        cleaned_ip = target.strip("[]")  # strip IPv6 brackets
        if _IPV4_RE.match(cleaned_ip) or _IPV6_RE.match(cleaned_ip):
            return cleaned_ip, "ip"

        # ── Domain (fallback) ─────────────────────────────────────────────────
        domain = target.lower().rstrip(".")
        return domain, "domain"

    @staticmethod
    def extract_hostname(normalized_target: str, target_type: InfraTargetType) -> str:
        """
        Returns the hostname component to use for DNS/WHOIS lookups.
        For URLs → parsed hostname; for others → as-is.
        """
        if target_type == "url":
            parsed = urlparse(normalized_target)
            host = parsed.hostname or normalized_target
            # Strip www. prefix for consistent lookups
            return host.lstrip("www.").rstrip(".")
        if target_type in ("domain", "ip"):
            return normalized_target.strip("[]")
        # hashes and emails – no valid hostname
        return ""

    @staticmethod
    def extract_registered_domain(hostname: str) -> str:
        """
        Extracts the registered (eTLD+1) part of a hostname.
        E.g. "sub.evil.example.com" → "example.com"
        Falls back gracefully without tldextract dependency.
        """
        parts = hostname.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname

    @staticmethod
    def is_ip_address(value: str) -> bool:
        """True if value looks like an IPv4 or IPv6 address."""
        cleaned = value.strip("[]")
        return bool(_IPV4_RE.match(cleaned) or _IPV6_RE.match(cleaned))

    @staticmethod
    def validate(raw: str) -> Tuple[bool, str]:
        """
        Returns (is_valid, error_message).
        Rejects obviously invalid or empty inputs.
        """
        stripped = raw.strip()
        if not stripped:
            return False, "Target must not be empty."
        if len(stripped) > 2048:
            return False, "Target exceeds maximum length of 2048 characters."
        # Block private/loopback ranges
        private_patterns = [
            r"^127\.", r"^10\.", r"^192\.168\.", r"^172\.(1[6-9]|2\d|3[01])\.",
            r"^localhost$", r"^::1$",
        ]
        for pat in private_patterns:
            if re.search(pat, stripped, re.IGNORECASE):
                return False, "Private/loopback addresses are not allowed."
        return True, ""
