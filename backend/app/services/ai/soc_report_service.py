"""
AI Malware Investigation Report Generator — powered by Google Gemini.

Takes ML scan results and PE metadata to generate a professional,
enterprise-grade SOC malware investigation report via Gemini AI.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from fpdf import FPDF

from app.services.ai.gemini_client import call_gemini
from app.services.ai.schemas import GeminiReportResponse

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "generated_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)



# ── System Prompt ─────────────────────────────────────────────────────────────

GEMINI_SYSTEM_PROMPT = """\
You are a Senior SOC Analyst at a Tier-1 Threat Intelligence Center writing enterprise-grade malware investigation reports similar to CrowdStrike, Microsoft Defender, and SentinelOne.

You generate reports based ONLY on provided ML static analysis and PE metadata. You act as a report writer and analyst, NOT a detector.

ABSOLUTE RULES:
- NEVER hallucinate or invent data.
- NEVER mention YARA, CAPA, Malice AV, VirusTotal, or any tool not in the provided data.
- NEVER mention missing sources or unavailable scans.
- NEVER output: "Analysis unavailable", "Not available", "No data provided", "Not observed because no scan was performed".
- NEVER leave a section empty or use placeholders.
- NEVER output JSON syntax or markdown symbols in text fields.
- Every section MUST contain meaningful, professional analyst-written content.

SECTION INSTRUCTIONS:

1. executive_summary: Write a concise paragraph mentioning filename, verdict, malware probability, confidence, risk score, and risk level in natural SOC analyst language.

2. detection_summary: Summarize the ML verdict, malware probability, confidence score, and risk level. Explain WHY the file received this assessment based on the provided features.

3. final_verdict: Use exactly one of: "SAFE / LOW RISK", "SUSPICIOUS", "HIGH RISK", or "CRITICAL". Provide a short justification sentence.

4. malware_classification: If benign, write "Benign". If a malware family was detected, write the family name. If malware but family unknown, write "Unknown Malware Family".

5. confidence_assessment: Explain the confidence score in professional analyst language, e.g. "The ML model classified the file with 97% confidence, indicating strong certainty in the benign assessment."

6. technical_findings: Write a technical assessment using ALL available PE data: file size, hashes, PE characteristics, imports, sections, entry point, entropy, DLL count, APIs, metadata. Write natural analyst observations. For benign files: "Static PE analysis revealed no suspicious structural anomalies. The file exhibited characteristics consistent with legitimate software."

7. indicators_of_compromise: Always include: Filename, MD5, SHA1, SHA256 as separate items.

8. risk_assessment: Object with risk_score (0-100), risk_level (Low/Medium/High/Critical), and justification explaining why these values support the verdict. Scale: 0-30 Low, 31-60 Medium, 61-85 High, 86-100 Critical.

9. potential_impact: For benign: explain minimal impact if source is trusted. For malicious: explain technical and business consequences.

10. recommended_actions: For benign: verify source integrity, verify digital signature, maintain security practices. For malicious: provide containment and investigation steps.

11. analyst_conclusion: Professional SOC-style conclusion summarizing verdict, confidence, risk, and overall assessment.

OUTPUT FORMAT: Return a single raw JSON object (no markdown fences) with exactly two keys:

{
  "soc_report": {
    "executive_summary": "...",
    "detection_summary": "...",
    "final_verdict": "...",
    "malware_classification": "...",
    "confidence_assessment": "...",
    "technical_findings": "...",
    "indicators_of_compromise": ["Filename: ...", "MD5: ...", "SHA1: ...", "SHA256: ..."],
    "risk_assessment": {"risk_score": 0, "risk_level": "...", "justification": "..."},
    "potential_impact": "...",
    "recommended_actions": ["1. ...", "2. ...", "3. ..."],
    "analyst_conclusion": "..."
  },
  "pdf_report": "(ignored, PDF is generated server-side)"
}
"""



def _build_scan_context(scan_data: dict[str, Any]) -> str:
    """Build a strict JSON context string from all available scan data."""
    result = scan_data.get("result") or scan_data
    file_meta = scan_data.get("file_metadata") or {}
    features = scan_data.get("extracted_features") or {}
    
    # ML results
    raw_prob = float(result.get("malware_probability") or 0)
    ml_results = {
        "verdict": result.get("verdict", "Unknown"),
        "malware_probability": f"{raw_prob * 100:.2f}%",
        "risk_level": result.get("risk_level", "Unknown"),
        "risk_score": _compute_risk_score(result),
        "confidence": _compute_confidence(result),
        "explanation": result.get("explanation", []),
        "recommendation": result.get("recommendation", ""),
        "extracted_features": {
            k: features[k] for k in ["EntryPoint", "SizeOfCode", "SizeOfInitializedData", "dlls_calls", "apis"] if k in features
        }
    }
    
    context = {
        "file_metadata": file_meta,
        "ml_results": ml_results
    }
    
    return json.dumps(context, indent=2)


def _compute_risk_score(result: dict[str, Any]) -> int:
    """Compute a 0-100 risk score from the ML result."""
    malware_prob = float(result.get("malware_probability") or 0)
    risk_level = result.get("risk_level", "")

    if result.get("verdict") == "Benign":
        return max(0, min(100, round(malware_prob * 100)))

    if risk_level == "Critical":
        return max(90, round(malware_prob * 100))
    if risk_level == "High":
        return max(70, round(malware_prob * 100))
    if risk_level == "Medium":
        return max(40, round(malware_prob * 100))
    if risk_level == "Low":
        return max(10, round(malware_prob * 100))

    return round(malware_prob * 100)


def _compute_confidence(result: dict[str, Any]) -> int:
    """Compute a 0-100 confidence score from the ML result."""
    if result.get("verdict") == "Benign":
        benign_conf = 1 - float(result.get("malware_probability") or 0)
        return max(0, min(100, round(benign_conf * 100)))

    if (
        result.get("family_confidence") is not None
        and result.get("family_confidence") != ""
    ):
        return max(
            0, min(100, round(float(result["family_confidence"]) * 100))
        )

    return max(
        0, min(100, round(float(result.get("malware_probability") or 0) * 100))
    )


def _extract_json_from_response(text: str) -> dict:
    """
    Try to extract valid JSON from Gemini response text,
    handling cases where the model wraps it in markdown code fences.
    """
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code fences
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding the first { to last }
    start = text.find('{')
    end = text.rfind('}')
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    raise ValueError("Could not extract valid JSON from Gemini response")


def _parse_gemini_report(raw: dict[str, Any]) -> GeminiReportResponse:
    """Parse Gemini AI JSON into the typed response schema."""
    soc_raw = raw.get("soc_report", {})

    # Parse IOCs
    iocs_raw = soc_raw.get("indicators_of_compromise") or []
    iocs = [str(i) for i in iocs_raw[:50]] if isinstance(iocs_raw, list) else []

    # Parse recommended actions
    actions_raw = soc_raw.get("recommended_actions") or []
    actions = [str(a) for a in actions_raw[:20]] if isinstance(actions_raw, list) else []

    # Parse Risk Assessment
    risk_raw = soc_raw.get("risk_assessment", {})

    from app.services.ai.schemas import SOCReport, RiskAssessment
    
    soc_report = SOCReport(
        executive_summary=str(soc_raw.get("executive_summary", "No executive summary available.")),
        detection_summary=str(soc_raw.get("detection_summary", "No detection summary available.")),
        final_verdict=str(soc_raw.get("final_verdict", "Suspicious")),
        malware_classification=str(soc_raw.get("malware_classification", "Unknown")),
        confidence_assessment=str(soc_raw.get("confidence_assessment", "No assessment available.")),
        technical_findings=str(soc_raw.get("technical_findings", "No technical analysis available.")),
        indicators_of_compromise=iocs,
        risk_assessment=RiskAssessment(
            risk_score=int(risk_raw.get("risk_score", 50)),
            risk_level=str(risk_raw.get("risk_level", "Medium")),
            justification=str(risk_raw.get("justification", ""))
        ),
        potential_impact=str(soc_raw.get("potential_impact", "Unknown")),
        recommended_actions=actions,
        analyst_conclusion=str(soc_raw.get("analyst_conclusion", "Analysis complete.")),
    )

    return GeminiReportResponse(
        soc_report=soc_report,
        pdf_report=str(raw.get("pdf_report", "No PDF report generated."))
    )


async def generate_gemini_report(
    scan_data: dict[str, Any],
) -> dict[str, Any]:
    """
    Main entry point: build context -> call Gemini -> parse report.

    Returns a dict with the structured report and metadata.
    Never raises HTTP 500 — returns graceful error on failure.
    """
    logger.info(
        "Gemini report generation started — file=%s",
        scan_data.get("filename", "unknown"),
    )



    scan_context = _build_scan_context(scan_data)
    user_prompt = (
        "Analyze the following malware scan results and generate the "
        "complete professional malware investigation report.\n\n"
        f"{scan_context}\n\n"
        "Generate the structured JSON report now. Include all sections."
    )

    try:
        raw_text = await call_gemini(
            system_prompt=GEMINI_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            timeout=90,
        )

        logger.info("GEMINI PARSING - Attempting to extract JSON from response...")
        raw_json = _extract_json_from_response(raw_text)
        logger.info("GEMINI PARSING - Successfully extracted JSON, starting Pydantic parsing...")
        report = _parse_gemini_report(raw_json)
        logger.info("GEMINI PARSING - Successfully parsed report into schema.")

        logger.info(
            "Gemini report generated — verdict=%s",
            report.soc_report.final_verdict[:80],
        )
        
        # Save report JSON
        history_id = scan_data.get("history_id")
        if history_id:
            report_path = REPORTS_DIR / f"{history_id}.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report.model_dump(), f, indent=2, ensure_ascii=False)

        return {
            "success": True,
            "is_ai_generated": True,
            "generation_message": "Report generated successfully using Google Gemini AI.",
            "report": report.model_dump(),
        }

    except Exception as exc:
        logger.exception(
            "Gemini report generation failed (%s). File=%s",
            exc,
            scan_data.get("filename", "unknown"),
        )
        
        from app.services.ai.schemas import GeminiReportResponse, SOCReport, RiskAssessment
        
        empty_report = GeminiReportResponse(
            soc_report=SOCReport(
                executive_summary="AI report generation failed. Data unavailable.",
                detection_summary="No detection summary available due to AI failure.",
                final_verdict="Unknown",
                malware_classification="Unknown",
                confidence_assessment="Analysis unavailable.",
                technical_findings="Analysis unavailable.",
                indicators_of_compromise=[],
                risk_assessment=RiskAssessment(
                    risk_score=0,
                    risk_level="Low",
                    justification=""
                ),
                potential_impact="Unknown",
                recommended_actions=["Retry report generation", "Review logs for API failures"],
                analyst_conclusion="AI pipeline encountered an error. Manual review required."
            ),
            pdf_report="AI report generation failed. PDF unavailable."
        )

        return {
            "success": False,
            "is_ai_generated": False,
            "generation_message": f"AI report generation failed: {str(exc)}",
            "report": empty_report.model_dump(),
            "error": str(exc),
        }

def _safe_text(text: str) -> str:
    """Sanitise text for core-font PDF rendering (latin-1 safe)."""
    replacements = {
        "\u2014": "--",   # em dash
        "\u2013": "-",    # en dash
        "\u2018": "'",    # left single quote
        "\u2019": "'",    # right single quote
        "\u201c": '"',    # left double quote
        "\u201d": '"',    # right double quote
        "\u2022": "-",    # bullet
        "\u2026": "...",  # ellipsis
        "\u00a0": " ",    # non-breaking space
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    # Drop any remaining non-latin-1 characters to prevent encoding crashes
    return text.encode("latin-1", errors="replace").decode("latin-1")


def generate_pdf_report(report_id: str) -> str:
    """Generate a professional enterprise-grade PDF from a saved JSON report."""
    from datetime import datetime

    json_path = REPORTS_DIR / f"{report_id}.json"
    pdf_path = REPORTS_DIR / f"{report_id}.pdf"

    if not json_path.exists():
        raise FileNotFoundError(f"No generated report found for ID: {report_id}")

    if pdf_path.exists():
        return str(pdf_path)

    with open(json_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    soc = report.get("soc_report", {})
    risk = soc.get("risk_assessment", {})
    risk_score = int(risk.get("risk_score", 0))
    risk_level = str(risk.get("risk_level", "Low"))
    verdict = str(soc.get("final_verdict", "Unknown"))
    gen_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # ── Custom PDF class ──────────────────────────────────────────────
    class TIBSAMalwarePDF(FPDF):
        def header(self):
            if self.page_no() > 1:
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(100, 110, 120)
                self.cell(0, 8, "TIBSA  |  Threat Intelligence-Based Security Application  |  AI Malware Investigation Report", new_x="LMARGIN", new_y="NEXT", align="R")
                self.set_draw_color(210, 215, 220)
                self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
                self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(120, 120, 120)
            self.set_draw_color(210, 215, 220)
            self.line(self.l_margin, self.get_y() - 2, self.w - self.r_margin, self.get_y() - 2)
            self.cell(0, 10, f"Generated by TIBSA AI Engine  |  {gen_time}  |  Page {self.page_no()} of {{nb}}", align="C")

    pdf = TIBSAMalwarePDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.alias_nb_pages()
    ew = 180  # effective width

    # Helper: section heading
    def section_heading(title: str):
        if pdf.get_y() > 245:
            pdf.add_page()
        pdf.set_text_color(24, 43, 73)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, _safe_text(title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(0, 150, 200)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(5)

    # Helper: body text
    def body_text(text: str):
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 60, 70)
        pdf.multi_cell(ew, 5.5, _safe_text(text))
        pdf.ln(4)

    # ── PAGE 1: COVER ─────────────────────────────────────────────────
    pdf.add_page()

    # Navy banner
    pdf.set_fill_color(24, 43, 73)
    pdf.rect(0, 0, 210, 44, style="F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_xy(15, 10)
    pdf.cell(0, 8, "TIBSA")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_xy(15, 19)
    pdf.cell(0, 7, "Threat Intelligence-Based Security Application")
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_xy(15, 28)
    pdf.cell(0, 7, "AI Malware Investigation Report")

    # Title
    pdf.set_text_color(24, 43, 73)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_xy(15, 58)
    pdf.cell(0, 14, "AI Malware Investigation Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100, 110, 120)
    pdf.cell(0, 8, "Enterprise SOC Threat Analysis Report", new_x="LMARGIN", new_y="NEXT")

    # Accent line
    pdf.set_draw_color(0, 150, 200)
    pdf.line(15, pdf.get_y() + 4, 195, pdf.get_y() + 4)
    pdf.ln(14)

    # Verdict card
    if risk_level == "Critical" or verdict == "CRITICAL":
        card_fill = (192, 41, 43)
    elif risk_level == "High" or verdict == "HIGH RISK":
        card_fill = (230, 126, 34)
    elif risk_level == "Medium" or verdict == "SUSPICIOUS":
        card_fill = (241, 196, 15)
    else:
        card_fill = (46, 204, 113)

    card_y = pdf.get_y()
    pdf.set_fill_color(*card_fill)
    pdf.rect(15, card_y, 180, 36, style="F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_xy(25, card_y + 6)
    pdf.cell(100, 10, _safe_text(f"VERDICT: {verdict}"))
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_xy(25, card_y + 18)
    pdf.cell(100, 8, _safe_text(f"Risk Score: {risk_score}/100  |  Risk Level: {risk_level.upper()}"))
    pdf.set_xy(15, card_y + 42)

    # Metadata card
    pdf.ln(4)
    pdf.set_text_color(24, 43, 73)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Report Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    meta_y = pdf.get_y()
    pdf.set_fill_color(245, 247, 250)
    pdf.rect(15, meta_y, 180, 50, style="F")

    # Extract filename from IOCs or soc data
    iocs = soc.get("indicators_of_compromise", [])
    filename_val = "Unknown"
    for ioc in iocs:
        if str(ioc).startswith("Filename:"):
            filename_val = str(ioc).replace("Filename:", "").strip()
            break

    # Get confidence score if possible
    from app.services.ai.malware_investigation.malware_static_service import load_scan_history
    history = load_scan_history()
    scan_record = next((h for h in history if h.get("history_id") == report_id), None)
    
    confidence_score = 50
    if scan_record:
        res = scan_record.get("result", {})
        if res.get("verdict") == "Benign":
            confidence_score = max(0, min(100, round((1 - float(res.get("malware_probability") or 0)) * 100)))
        elif res.get("family_confidence") not in [None, ""]:
            confidence_score = max(0, min(100, round(float(res.get("family_confidence")) * 100)))
        else:
            confidence_score = max(0, min(100, round(float(res.get("malware_probability") or 0) * 100)))

    meta_items = [
        ("File Name:", filename_val),
        ("Scan Date:", gen_time),
        ("Final Verdict:", verdict),
        ("Risk Level:", risk_level),
        ("Risk Score:", f"{risk_score}/100"),
        ("Confidence Score:", f"{confidence_score}%"),
    ]

    pdf.set_text_color(80, 90, 100)
    curr_y = meta_y + 4
    for label, val in meta_items:
        pdf.set_xy(22, curr_y)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.cell(42, 6, label)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.cell(120, 6, _safe_text(str(val)))
        curr_y += 7

    pdf.set_xy(15, meta_y + 56)

    # ── PAGE 2+: REPORT SECTIONS ──────────────────────────────────────
    pdf.add_page()

    def _clean_pdf_text(t_str: str) -> str:
        import re
        t = re.sub(r'(?i)AI Malware Investigation Report', '', t_str)
        t = re.sub(r'(?m)^\s*(?:\d+\.?(?:\d+\.)*|\*|-)\s+', '', t)
        return _safe_text(t.strip())

    def section_card(title: str, text: str, highlight: bool = False):
        if pdf.get_y() > 240:
            pdf.add_page()
            
        pdf.set_text_color(24, 43, 73)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, _safe_text(title.upper()), new_x="LMARGIN", new_y="NEXT")
        
        clean_text = _clean_pdf_text(text)
        if not clean_text:
            clean_text = "Unavailable."
            
        # Approximate height
        lines = clean_text.split("\n")
        num_lines = sum((len(line) // 85) + 1 for line in lines)
        box_h = 8 + (num_lines * 5.5)
        
        # Prevent page overflow
        if pdf.get_y() + box_h > 275:
            pdf.add_page()
            
        box_y = pdf.get_y()
        
        if highlight:
            pdf.set_fill_color(240, 245, 250)
            pdf.set_draw_color(0, 150, 200)
            pdf.rect(15, box_y, 180, box_h, style="DF")
            pdf.set_fill_color(0, 150, 200)
            pdf.rect(15, box_y, 3, box_h, style="F")
        else:
            pdf.set_fill_color(252, 253, 255)
            pdf.set_draw_color(220, 225, 230)
            pdf.rect(15, box_y, 180, box_h, style="DF")
            
        pdf.set_xy(20, box_y + 4)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(50, 60, 70)
        pdf.multi_cell(170, 5.5, clean_text)
        
        pdf.set_xy(15, box_y + box_h + 6)

    # 1. Executive Summary (highlighted)
    section_card("1. Executive Summary", str(soc.get("executive_summary", "")), highlight=True)

    # 2. Detection Summary
    section_card("2. Detection Summary", str(soc.get("detection_summary", "")))

    # 3. Final Verdict (emphasized box)
    if pdf.get_y() > 240:
        pdf.add_page()
    pdf.set_text_color(24, 43, 73)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "3. FINAL VERDICT", new_x="LMARGIN", new_y="NEXT")
    v_y = pdf.get_y()
    pdf.set_fill_color(*card_fill)
    pdf.rect(15, v_y, 180, 16, style="F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_xy(20, v_y + 3)
    pdf.cell(170, 10, _safe_text(verdict), align="C")
    pdf.set_xy(15, v_y + 22)

    # 4. Malware Classification
    section_card("4. Malware Classification", str(soc.get("malware_classification", "")))

    # 5. Confidence Assessment
    section_card("5. Confidence Assessment", str(soc.get("confidence_assessment", "")))

    # 6. Technical Findings
    section_card("6. Technical Findings", str(soc.get("technical_findings", "")))

    # 7. Risk Assessment
    risk_text = f"Risk Score: {risk_score}/100\nRisk Level: {risk_level.upper()}\n\n{str(risk.get('justification', ''))}"
    section_card("7. Risk Assessment", risk_text)

    # 8. Indicators of Compromise (table)
    if pdf.get_y() > 230:
        pdf.add_page()
    pdf.set_text_color(24, 43, 73)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "8. INDICATORS OF COMPROMISE (IOCS)", new_x="LMARGIN", new_y="NEXT")
    
    if iocs:
        pdf.set_fill_color(24, 43, 73)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.cell(35, 8, " Indicator Type", border=1, fill=True)
        pdf.cell(145, 8, " Value", border=1, fill=True)
        pdf.ln()
        
        pdf.set_text_color(50, 60, 70)
        pdf.set_font("Helvetica", "", 9)
        for row_i, ioc_item in enumerate(iocs):
            ioc_str = str(ioc_item)
            fill_row = row_i % 2 == 1
            pdf.set_fill_color(248, 250, 252)
            if ":" in ioc_str:
                parts = ioc_str.split(":", 1)
                label = parts[0].strip()
                value = parts[1].strip()
            else:
                label = "Indicator"
                value = ioc_str
            pdf.cell(35, 7, _safe_text(f" {label}"), border=1, fill=fill_row)
            pdf.cell(145, 7, _safe_text(f" {value}"), border=1, fill=fill_row)
            pdf.ln()
        pdf.ln(6)
    else:
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(100, 110, 120)
        pdf.cell(0, 8, "No IOCs reported.", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # 9. Potential Impact
    section_card("9. Potential Impact", str(soc.get("potential_impact", "")))

    # 10. Recommended Actions (numbered)
    actions = soc.get("recommended_actions", [])
    if actions:
        actions_text = "\n".join(f"{i}. {action}" for i, action in enumerate(actions, 1))
        section_card("10. Recommended Actions", actions_text)

    # 11. Analyst Conclusion (highlighted box)
    section_card("11. Analyst Conclusion", str(soc.get("analyst_conclusion", "")), highlight=True)

    pdf.output(str(pdf_path))
    return str(pdf_path)

