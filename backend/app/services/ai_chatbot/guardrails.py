"""
Guardrails for the TIBSA AI Security Chatbot.

Blocks: exploit payloads, attack instructions, malware, credential theft,
phishing, cookie stealing, bypass instructions, persistence, evasion,
offensive tooling usage, payload generation.

Allows: defensive explanations, secure coding, remediation, hardening,
safe verification, authorized testing (high-level).
"""
from __future__ import annotations
import re, logging

logger = logging.getLogger(__name__)

BLOCKED_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b(give|show|write|create|generate|provide|send)\b.{0,30}\b(exploit|payload|shell ?code|reverse ?shell|bind ?shell)\b", re.I),
    re.compile(r"\b(craft|build|make)\b.{0,20}\b(malware|trojan|ransomware|worm|rootkit|keylogger|rat)\b", re.I),
    re.compile(r"\bexploit\s+(code|script|poc|proof.of.concept)\b", re.I),
    re.compile(r"\b(how\s+to|steps?\s+to|guide\s+to)\b.{0,30}\b(hack|attack|exploit|compromise|breach|penetrate|pwn)\b.{0,30}\b(server|website|system|network|target|victim)\b", re.I),
    re.compile(r"\bhack\s+(into|this|that|a|the|my\s+friend|someone)\b", re.I),
    re.compile(r"\b(attack|exploit|compromise|breach)\s+(this|that|a|the)\s+(server|website|ip|target|system)\b", re.I),
    re.compile(r"\b(steal|harvest|capture|dump|crack)\b.{0,20}\b(password|credential|hash|token|cookie|session)\b", re.I),
    re.compile(r"\b(phishing|spear.?phishing)\s+(page|site|email|template|kit)\b", re.I),
    re.compile(r"\bcreate.{0,20}(fake|clone).{0,20}(login|page|site)\b", re.I),
    re.compile(r"\b(steal|hijack|grab|extract|exfiltrate)\b.{0,20}\b(cookie|session|jwt|token)\b", re.I),
    re.compile(r"\bcookie\s+(steal|theft|grab|hijack|exfiltrat)\b", re.I),
    re.compile(r"\b(bypass|evade|disable|circumvent)\b.{0,20}\b(firewall|ids|ips|waf|antivirus|av|edr|detection|security|authentication|authorization|2fa|mfa|captcha)\b", re.I),
    re.compile(r"\b(obfuscate|encode|encrypt)\b.{0,20}\b(payload|malware|shell|backdoor)\b", re.I),
    re.compile(r"\b(maintain|establish)\b.{0,20}\b(persistence|backdoor|access)\b", re.I),
    re.compile(r"\b(command\s+and\s+control|c2|c&c)\s+(server|channel|infrastructure)\b", re.I),
    re.compile(r"\b(metasploit|cobalt\s*strike|empire|mimikatz)\b.{0,30}\b(use|run|execute|tutorial|guide|how)\b", re.I),
    re.compile(r"\b(use|run|execute)\b.{0,20}\b(sqlmap|burp\s*intruder|hydra|john\s+the\s+ripper|hashcat)\b.{0,20}\b(against|on|to\s+attack|to\s+crack)\b", re.I),
    re.compile(r"\b(generate|create|build|craft)\b.{0,20}\b(xss|sqli|sql\s+injection|csrf|rce)\s+(payload|vector|string)\b", re.I),
    re.compile(r"\bmsfvenom\b", re.I),
]

ALLOWED_OVERRIDES: list[re.Pattern] = [
    re.compile(r"\b(defend|protect|prevent|detect|mitigate|remediate|patch|fix|secure|harden)\b", re.I),
    re.compile(r"\b(what\s+is|explain|define|describe|how\s+does)\b", re.I),
    re.compile(r"\b(best\s+practice|recommendation|guideline|framework)\b", re.I),
    re.compile(r"\b(secure\s+coding|safe|safety|verification|audit|assessment)\b", re.I),
    re.compile(r"\b(authorized\s+test|pentest\s+report|security\s+audit|legitimate)\b", re.I),
]

REFUSAL_MESSAGE_EN = (
    "I can't provide offensive attack instructions, exploit code, or harmful guidance. "
    "However, I can help you understand this topic from a **defensive perspective** — "
    "including how to detect, prevent, and remediate such threats. "
    "Would you like me to explain the defensive side instead?"
)

REFUSAL_MESSAGE_AR = (
    "لا أستطيع تقديم تعليمات هجومية أو أكواد استغلال أو إرشادات ضارة. "
    "ولكن يمكنني مساعدتك في فهم هذا الموضوع من **منظور دفاعي** — "
    "بما في ذلك كيفية الكشف عن هذه التهديدات ومنعها ومعالجتها. "
    "هل تريد أن أشرح الجانب الدفاعي بدلاً من ذلك؟"
)


def check_guardrails(message: str, language: str = "en") -> tuple[bool, str | None]:
    """
    Check if the user's message violates guardrails.
    Returns (is_safe, refusal_message).
    """
    has_defensive_context = any(p.search(message) for p in ALLOWED_OVERRIDES)

    for pattern in BLOCKED_PATTERNS:
        if pattern.search(message):
            if has_defensive_context:
                logger.info("Guardrail override (defensive): %s", pattern.pattern[:60])
                continue
            logger.warning("Guardrail blocked: %s", pattern.pattern[:60])
            refusal = REFUSAL_MESSAGE_AR if language == "ar" else REFUSAL_MESSAGE_EN
            return False, refusal

    return True, None
