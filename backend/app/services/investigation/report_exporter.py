"""
Report Exporter — JSON & PDF Export for Investigation Reports.

Exports completed investigation results as structured JSON files or
professional PDF reports. Used by the investigation API endpoints.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime
from io import BytesIO
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Export directory — created on demand
EXPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "exports")


class ReportExporter:
    """
    Exports investigation reports as JSON or PDF files.
    """

    def __init__(self):
        # Ensure export directory exists
        os.makedirs(EXPORT_DIR, exist_ok=True)

    # ── JSON Export ─────────────────────────────────────────────────

    async def export_json(
        self,
        investigation_id: str,
        investigation_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Export the full investigation as a structured JSON file.

        Returns dict with 'filename', 'filepath', and 'content' (bytes).
        """
        logger.info("[EXPORT] Generating JSON export for %s", investigation_id)

        # Build the export payload
        export_payload = {
            "export_metadata": {
                "investigation_id": investigation_id,
                "exported_at": datetime.utcnow().isoformat(),
                "format": "json",
                "version": "1.0",
            },
            "investigation": self._serialize_investigation(investigation_data),
        }

        # Serialize to JSON
        json_content = json.dumps(export_payload, indent=2, default=str, ensure_ascii=False)
        json_bytes = json_content.encode("utf-8")

        filename = f"investigation_{investigation_id[:8]}_{datetime.utcnow().strftime('%Y%m%d')}.json"
        filepath = os.path.join(EXPORT_DIR, filename)

        # Write to file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(json_content)

        logger.info("[EXPORT] JSON export saved: %s (%d bytes)", filename, len(json_bytes))

        return {
            "filename": filename,
            "filepath": filepath,
            "content": json_bytes,
            "mime_type": "application/json",
            "size_bytes": len(json_bytes),
        }

    # ── PDF Export ──────────────────────────────────────────────────

    async def export_pdf(
        self,
        investigation_id: str,
        investigation_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Export the investigation as a professional PDF report.

        Returns dict with 'filename', 'filepath', and 'content' (bytes).
        """
        logger.info("[EXPORT] Generating PDF export for %s", investigation_id)

        try:
            from fpdf import FPDF
        except ImportError:
            logger.error("[EXPORT] fpdf2 is not installed. PDF export unavailable.")
            raise RuntimeError("PDF export requires fpdf2. Install with: pip install fpdf2")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=20)

        # ── Page 1: Cover / Summary ────────────────────────────────
        pdf.add_page()
        self._render_cover_page(pdf, investigation_id, investigation_data)

        # ── Page 2+: Findings Summary ──────────────────────────────
        pdf.add_page()
        self._render_findings_section(pdf, investigation_data)

        # ── Correlated Threats ─────────────────────────────────────
        self._render_correlation_section(pdf, investigation_data)

        # ── STRIDE Matrix ──────────────────────────────────────────
        self._render_stride_section(pdf, investigation_data)

        # ── AI Summary & Recommendations ───────────────────────────
        self._render_ai_summary_section(pdf, investigation_data)

        # Generate PDF bytes
        pdf_bytes = pdf.output()
        if isinstance(pdf_bytes, str):
            pdf_bytes = pdf_bytes.encode("latin-1")

        filename = f"investigation_{investigation_id[:8]}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        filepath = os.path.join(EXPORT_DIR, filename)

        # Write to file
        with open(filepath, "wb") as f:
            f.write(pdf_bytes)

        logger.info("[EXPORT] PDF export saved: %s (%d bytes)", filename, len(pdf_bytes))

        return {
            "filename": filename,
            "filepath": filepath,
            "content": pdf_bytes,
            "mime_type": "application/pdf",
            "size_bytes": len(pdf_bytes),
        }

    # ── PDF Rendering Helpers ──────────────────────────────────────

    def _render_cover_page(self, pdf, investigation_id: str, data: Dict[str, Any]):
        """Render the cover page with investigation metadata and risk score."""
        # Title
        pdf.set_font("Helvetica", "B", 24)
        pdf.cell(0, 20, "TIBSA Security Investigation Report", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(10)

        # Investigation metadata
        pdf.set_font("Helvetica", "", 11)
        target = data.get("target", "Unknown")
        status = data.get("status", "Unknown")
        risk_score = data.get("risk_score", 0.0)
        risk_label = self._score_to_label(risk_score)
        started = data.get("started_at", "N/A")
        completed = data.get("completed_at", "N/A")

        meta_lines = [
            f"Investigation ID: {investigation_id}",
            f"Target: {target}",
            f"Status: {status}",
            f"Risk Score: {risk_score:.1f}/100 ({risk_label})",
            f"Started: {started}",
            f"Completed: {completed}",
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ]

        for line in meta_lines:
            pdf.cell(0, 8, self._safe_text(line), new_x="LMARGIN", new_y="NEXT")

        pdf.ln(10)

        # Findings count summary
        findings = data.get("findings", [])
        final_result = data.get("final_result", {}) or {}
        correlation = final_result.get("correlation", {}) or {}
        corr_threats = correlation.get("correlated_threats", [])

        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, self._safe_text(f"Total Findings: {len(findings)}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, self._safe_text(f"Correlated Threats: {len(corr_threats)}"), new_x="LMARGIN", new_y="NEXT")

        # Severity breakdown
        sev_counts = {}
        for f in findings:
            sev = (getattr(f, "severity", None) or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if sev_counts:
            sev_str = ", ".join(f"{k.title()}: {v}" for k, v in sorted(sev_counts.items()))
            pdf.cell(0, 8, self._safe_text(f"Severity Distribution: {sev_str}"), new_x="LMARGIN", new_y="NEXT")

    def _render_findings_section(self, pdf, data: Dict[str, Any]):
        """Render the findings summary section."""
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, "Security Findings", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        findings = data.get("findings", [])
        if not findings:
            pdf.set_font("Helvetica", "I", 11)
            pdf.cell(0, 8, "No findings recorded.", new_x="LMARGIN", new_y="NEXT")
            return

        for i, finding in enumerate(findings[:30], start=1):  # Limit to 30 findings
            title = getattr(finding, "title", "Unknown") if hasattr(finding, "title") else finding.get("title", "Unknown")
            severity = getattr(finding, "severity", "info") if hasattr(finding, "severity") else finding.get("severity", "info")
            category = getattr(finding, "category", "Unknown") if hasattr(finding, "category") else finding.get("category", "Unknown")
            url = getattr(finding, "affected_url", "") if hasattr(finding, "affected_url") else finding.get("affected_url", "")

            # Check if we need a new page
            if pdf.get_y() > 250:
                pdf.add_page()

            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 7, self._safe_text(f"{i}. [{severity.upper()}] {title}"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 6, self._safe_text(f"   Category: {category}"), new_x="LMARGIN", new_y="NEXT")
            if url:
                pdf.cell(0, 6, self._safe_text(f"   URL: {url[:100]}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

    def _render_correlation_section(self, pdf, data: Dict[str, Any]):
        """Render correlated threats section."""
        final_result = data.get("final_result", {}) or {}
        correlation = final_result.get("correlation", {}) or {}
        threats = correlation.get("correlated_threats", [])

        if not threats:
            return

        # New page for correlation
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, "Correlated Threats", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        global_risk = correlation.get("global_risk_score", 0)
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, self._safe_text(f"Global Risk Score: {global_risk:.1f}/100"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, self._safe_text(f"Total Correlated Threats: {len(threats)}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        for i, threat in enumerate(threats[:15], start=1):
            if pdf.get_y() > 250:
                pdf.add_page()

            title = threat.get("title", "Unknown Threat")
            severity = threat.get("severity", "medium")
            confidence = threat.get("confidence_score", 0)
            description = threat.get("description", "")

            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 7, self._safe_text(f"{i}. [{severity.upper()}] {title}"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 6, self._safe_text(f"   Confidence: {confidence:.0%}"), new_x="LMARGIN", new_y="NEXT")

            # Wrap description
            if description:
                pdf.set_font("Helvetica", "", 9)
                pdf.multi_cell(0, 5, self._safe_text(f"   {description[:300]}"))
            pdf.ln(3)

    def _render_stride_section(self, pdf, data: Dict[str, Any]):
        """Render STRIDE threat model matrix section."""
        final_result = data.get("final_result", {}) or {}
        stride = final_result.get("stride", {}) or {}
        matrix = stride.get("stride_matrix", {}) or {}

        if not matrix:
            return

        if pdf.get_y() > 200:
            pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, "STRIDE Threat Model", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # Render matrix as a simple table
        pdf.set_font("Helvetica", "B", 10)
        categories = [
            ("Spoofing", matrix.get("spoofing_count", 0)),
            ("Tampering", matrix.get("tampering_count", 0)),
            ("Repudiation", matrix.get("repudiation_count", 0)),
            ("Information Disclosure", matrix.get("information_disclosure_count", 0)),
            ("Denial of Service", matrix.get("denial_of_service_count", 0)),
            ("Elevation of Privilege", matrix.get("elevation_of_privilege_count", 0)),
        ]

        # Table header
        pdf.cell(120, 8, "STRIDE Category", border=1)
        pdf.cell(40, 8, "Count", border=1, align="C")
        pdf.ln()

        pdf.set_font("Helvetica", "", 10)
        for cat_name, count in categories:
            pdf.cell(120, 7, self._safe_text(cat_name), border=1)
            pdf.cell(40, 7, str(count), border=1, align="C")
            pdf.ln()

        total = sum(c for _, c in categories)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(120, 8, "Total", border=1)
        pdf.cell(40, 8, str(total), border=1, align="C")
        pdf.ln(10)

    def _render_ai_summary_section(self, pdf, data: Dict[str, Any]):
        """Render AI-generated summary and recommendations."""
        final_result = data.get("final_result", {}) or {}
        reporter = final_result.get("reporter", {}) or {}
        ai_summary = reporter.get("ai_summary", {}) or {}

        if not ai_summary:
            return

        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, "Security Analysis Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # Executive Summary
        exec_summary = ai_summary.get("executive_summary", "")
        if exec_summary:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, self._safe_text(exec_summary))
            pdf.ln(4)

        # Technical Summary
        tech_summary = ai_summary.get("technical_summary", "")
        if tech_summary:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Technical Summary", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, self._safe_text(tech_summary))
            pdf.ln(4)

        # Risk Explanation
        risk_exp = ai_summary.get("risk_explanation", "")
        if risk_exp:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Risk Explanation", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, self._safe_text(risk_exp))
            pdf.ln(4)

        # Remediation Plan
        remediation = ai_summary.get("remediation_plan", [])
        if remediation:
            if pdf.get_y() > 200:
                pdf.add_page()

            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Remediation Plan", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

            for step in remediation[:10]:
                if pdf.get_y() > 250:
                    pdf.add_page()

                priority = step.get("priority", 5)
                title = step.get("title", "Remediation Step")
                desc = step.get("description", "")
                effort = step.get("estimated_effort", "Medium")

                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 7, self._safe_text(f"[P{priority}] {title} (Effort: {effort})"), new_x="LMARGIN", new_y="NEXT")
                if desc:
                    pdf.set_font("Helvetica", "", 9)
                    pdf.multi_cell(0, 5, self._safe_text(f"  {desc[:400]}"))
                pdf.ln(2)

    # ── Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _serialize_investigation(data: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize investigation data for JSON export."""
        serialized = {}
        for key, value in data.items():
            if hasattr(value, "model_dump"):
                serialized[key] = value.model_dump()
            elif hasattr(value, "__dict__") and not isinstance(value, (str, int, float, bool)):
                try:
                    serialized[key] = {k: str(v) for k, v in value.__dict__.items() if not k.startswith("_")}
                except Exception:
                    serialized[key] = str(value)
            elif isinstance(value, list):
                serialized[key] = [
                    item.model_dump() if hasattr(item, "model_dump")
                    else (item.__dict__ if hasattr(item, "__dict__") and not isinstance(item, (str, int, float, bool)) else item)
                    for item in value
                ]
            elif isinstance(value, datetime):
                serialized[key] = value.isoformat()
            else:
                serialized[key] = value
        return serialized

    @staticmethod
    def _score_to_label(score: float) -> str:
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        return "Low"

    @staticmethod
    def _safe_text(text: str) -> str:
        """Remove characters that can't be encoded in latin-1 for PDF rendering."""
        if not text:
            return ""
        # Replace common problematic characters
        return text.encode("latin-1", errors="replace").decode("latin-1")
