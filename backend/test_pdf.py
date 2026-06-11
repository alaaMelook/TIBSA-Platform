import json
from fpdf import FPDF
from pathlib import Path

REPORTS_DIR = Path("app/services/ai/generated_reports")
report_id = "a1a628d8-6739-4e95-a2d9-ac9df375e945"
json_path = REPORTS_DIR / f"{report_id}.json"

with open(json_path, "r", encoding="utf-8") as f:
    report = json.load(f)

def _safe_text(text: str) -> str:
    replacements = {
        "\u2014": "--", "\u2013": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2022": "-", "\u2026": "...",
        "\u00a0": " ",
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    return text.encode("latin-1", errors="replace").decode("latin-1")

pdf = FPDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()
ew = pdf.w - pdf.l_margin - pdf.r_margin
print(f"pdf.w={pdf.w}, l_margin={pdf.l_margin}, r_margin={pdf.r_margin}, ew={ew}")

def _reset_x():
    pdf.set_x(pdf.l_margin)

def _write_block(text: str, font_size: int = 10, style: str = "",
                 line_h: int = 6, r: int = 50, g: int = 50, b: int = 50):
    _reset_x()
    pdf.set_font("Helvetica", style=style, size=font_size)
    pdf.set_text_color(r, g, b)
    safe_txt = _safe_text(str(text))
    print(f"Writing block: length={len(safe_txt)}")
    pdf.multi_cell(ew, line_h, safe_txt)
    _reset_x()

_reset_x()
pdf.set_font("Helvetica", style="B", size=18)
pdf.set_text_color(41, 128, 185)
pdf.cell(ew, 10, "AI Malware Investigation Report", ln=True, align="C")
pdf.ln(5)

def add_section(title: str, content: str | list):
    _reset_x()
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(ew, 10, _safe_text(title), ln=True)
    _reset_x()

    if isinstance(content, list):
        for item in content:
            _reset_x()
            if isinstance(item, dict):
                _write_block(f"{item.get('id', '')} - {item.get('technique', '')}", style="B")
                _write_block(str(item.get("evidence", "")))
                pdf.ln(2)
            else:
                _write_block(f"- {item}")
    else:
        _write_block(str(content) if content else "N/A")

    _reset_x()
    pdf.ln(5)

try:
    add_section("Executive Summary", report.get("executive_summary", ""))
    add_section("Detection Summary", report.get("detection_summary", ""))
    
    _reset_x()
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(ew, 10, "Final Verdict & Classification", ln=True)
    _reset_x()
    
    _write_block(f"Verdict: {report.get('final_verdict', '')}", font_size=12, line_h=8, r=192, g=57, b=43)
    _write_block(f"Classification: {report.get('malware_classification', '')}", font_size=12, line_h=8)
    _write_block(f"Confidence Assessment: {report.get('confidence_assessment', '')}")
    pdf.ln(5)
    
    add_section("Technical Findings", report.get("technical_findings", ""))
    add_section("Behavioral Analysis", report.get("behavioral_analysis", ""))
    add_section("Supporting Evidence", report.get("evidence_supporting_findings", ""))
    add_section("Indicators of Compromise", report.get("indicators_of_compromise", []))
    add_section("MITRE ATT&CK Mapping", report.get("mitre_attack_mapping", []))
    add_section("Risk Assessment", report.get("risk_assessment", ""))
    add_section("Potential Impact", report.get("potential_impact", ""))
    add_section("Recommended Actions", report.get("recommended_actions", []))
    add_section("Conclusion", report.get("conclusion", ""))
    
    pdf.output("test.pdf")
    print("Success")
except Exception as e:
    import traceback
    traceback.print_exc()
