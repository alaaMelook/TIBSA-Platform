"""
System prompt builder for the TIBSA AI Security Chatbot.
"""
from __future__ import annotations

from typing import Optional
from app.services.ai_chatbot.schemas import ChatContext


SYSTEM_PROMPT = """You are TIBSA AI Security Assistant — a concise, defensive cybersecurity helper.
Answer in the user's language (Arabic if Arabic, English if English).
Answer directly. No long introductions, no filler, no unnecessary reasoning. Keep answers under 120 words unless the user asks for "details", "step by step", or "explain deeply".

FORMATTING RULES:
- Keep formatting clean. Avoid excessive Markdown.
- Do not use large headings (# or ##).
- Do not overuse bold text.
- Use short paragraphs or simple bullets.
- Avoid code backticks unless mentioning a technical header, command, or config.
- Keep Arabic answers clean and natural.
- Do not escape newlines manually.

Rules:
- No exploit code, payloads, attack steps, or offensive tool guides (sqlmap, Metasploit, Burp Intruder, etc.). Refuse briefly and redirect to defense.
- If asked "Do I have X vulnerability?" without scan/report evidence: say you cannot confirm without a scan, then explain what it is and how to check safely.
- No auth/login → don't treat CSRF or session hijacking as primary risks.
- Payment redirects → prioritize: open redirect, callback validation, webhook signatures, amount/order tampering, replay protection, HTTPS."""


TIBSA_CONTEXT = """
About TIBSA Platform:
TIBSA (Threat Intelligence-Based Security Application) is a cybersecurity platform with these core modules:

1. Pentest Scanner: Discovers security findings, assets, endpoints, and technologies through automated scanning modules (auth security, headers, cookies, SSL/TLS, etc.).
2. Threat Intelligence: Correlates scanner output into attack context and risk assessment using sources like VirusTotal, MITRE ATT&CK, and CAPEC enrichment.
3. Threat Modeling: Generates possible threats based on discovered assets and features using STRIDE logic, producing structured threat scenarios.
4. Reports: Summarize all risks, findings, and remediation guidance from the above modules into actionable reports.
5. AI Malware Analysis: Uses AI to explain malware scan results from multiple AV engines.

The platform uses OWASP, MITRE ATT&CK, STRIDE, and ASVS frameworks for comprehensive security assessments.
"""


def build_system_prompt(context: Optional[ChatContext] = None) -> str:
    """
    Build the full system prompt, optionally enriched with page/module context.
    """
    prompt = SYSTEM_PROMPT + "\n" + TIBSA_CONTEXT

    if context:
        prompt += f"\nThe user is currently on the '{context.page}' page "
        prompt += f"in the '{context.module}' module of the TIBSA platform.\n"

    return prompt


def detect_language(message: str) -> str:
    """
    Simple heuristic to detect if the message is in Arabic or English.
    Checks for Arabic Unicode character range.
    """
    arabic_chars = sum(1 for c in message if '\u0600' <= c <= '\u06FF' or '\u0750' <= c <= '\u077F')
    total_alpha = sum(1 for c in message if c.isalpha())

    if total_alpha == 0:
        return "en"

    if arabic_chars / total_alpha > 0.3:
        return "ar"

    return "en"


def classify_category(message: str) -> str:
    """
    Classify the user's question into a response category.
    """
    message_lower = message.lower()

    category_keywords = {
        "vulnerability_explanation": [
            "xss", "sql injection", "csrf", "ssrf", "rce", "lfi", "rfi",
            "idor", "xxe", "deserialization", "injection", "vulnerability",
        ],
        "security_headers": [
            "csp", "content-security-policy", "hsts", "x-frame",
            "security header", "cors", "referrer-policy",
        ],
        "threat_modeling": [
            "threat model", "stride", "dread", "attack tree",
            "threat scenario", "threat modeling",
        ],
        "threat_intelligence": [
            "threat intelligence", "mitre", "att&ck", "ioc",
            "indicator of compromise", "ttp", "threat feed",
        ],
        "remediation": [
            "fix", "remediate", "patch", "secure", "harden",
            "mitigate", "protect", "prevent", "defense",
        ],
        "pentest_guidance": [
            "pentest", "penetration test", "scan", "scanner",
            "vulnerability scan", "security audit",
        ],
        "platform_help": [
            "tibsa", "how does", "platform", "dashboard",
            "feature", "module", "how to use",
        ],
        "authentication_security": [
            "login", "password", "auth", "session", "jwt",
            "token", "oauth", "mfa", "2fa", "authentication",
        ],
        "api_security": [
            "api", "rest", "graphql", "endpoint", "rate limit",
            "api key", "api security",
        ],
        "payment_security": [
            "payment", "checkout", "redirect", "callback",
            "webhook", "transaction", "order",
        ],
    }

    for category, keywords in category_keywords.items():
        if any(kw in message_lower for kw in keywords):
            return category

    return "security_explanation"
