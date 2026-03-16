"""
Threat-scoring helper.

Combines VirusTotal results with AI phishing model predictions into
a single threat score, verdict, and threat level.
"""


def compute_threat_score(
    vt_malicious: int,
    vt_total: int,
    ai_is_phishing: bool,
    ai_confidence: float,
) -> tuple[float, str, str]:
    """Combine VirusTotal and AI phishing results into a single threat score.

    Returns:
        (threat_score, verdict, final_level)
        - threat_score: 0.0 – 1.0
        - verdict:      "Malicious" | "Suspicious" | "Warning" | "Clean"
        - final_level:  "high" | "medium" | "low" | "clean"
    """
    # 1. VirusTotal score
    vt_score = (vt_malicious / vt_total) if vt_total > 0 else 0.0

    # 2. AI score
    ai_score = ai_confidence if ai_is_phishing else 0.0

    # 3. Weighted combination
    threat_score = (0.6 * ai_score) + (0.4 * vt_score)

    # 4. Verdict mapping
    if threat_score >= 0.75:
        verdict = "Malicious"
        final_level = "high"
    elif threat_score >= 0.50:
        verdict = "Suspicious"
        final_level = "medium"
    elif threat_score >= 0.30:
        verdict = "Warning"
        final_level = "low"
    else:
        verdict = "Clean"
        final_level = "clean"

    return threat_score, verdict, final_level
