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

    def _validate_and_sanitize(self, data: Dict[str, Any]):
        """Runs the validation layer to ensure evidence and narrative consistency before export."""
        from app.services.investigation.ai_reporter import AISecurityReporter
        
        findings = data.get("findings", [])
        final_result = data.get("final_result", {}) or {}
        correlation = final_result.get("correlation", {}) or {}
        correlated_threats = correlation.get("correlated_threats", [])
        stride = final_result.get("stride", {}) or {}
        stride_threats = stride.get("stride_threats", [])
        stride_matrix = stride.get("stride_matrix", {}) or {}
        reporter = final_result.get("reporter", {}) or {}
        ai_summary = reporter.get("ai_summary", {}) or {}
        
        # Call the consistency validation layer
        filtered_corr, filtered_stride, filtered_matrix, cleaned_summary = AISecurityReporter.validate_report_consistency(
            findings=findings,
            correlated_threats=correlated_threats,
            stride_threats=stride_threats,
            stride_matrix=stride_matrix,
            ai_summary=ai_summary
        )
        
        # Write back to dictionary
        if "final_result" not in data:
            data["final_result"] = {}
        if "correlation" not in data["final_result"]:
            data["final_result"]["correlation"] = {}
        if "stride" not in data["final_result"]:
            data["final_result"]["stride"] = {}
        if "reporter" not in data["final_result"]:
            data["final_result"]["reporter"] = {}
            
        data["final_result"]["correlation"]["correlated_threats"] = filtered_corr
        data["final_result"]["stride"]["stride_threats"] = filtered_stride
        data["final_result"]["stride"]["stride_matrix"] = filtered_matrix
        data["final_result"]["reporter"]["ai_summary"] = cleaned_summary

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
        self._validate_and_sanitize(investigation_data)

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
        self._validate_and_sanitize(investigation_data)

        try:
            from fpdf import FPDF
        except ImportError:
            logger.error("[EXPORT] fpdf2 is not installed. PDF export unavailable.")
            raise RuntimeError("PDF export requires fpdf2. Install with: pip install fpdf2")

        # Custom FPDF class with page Header/Footer controls
        class BeautifulReportPDF(FPDF):
            def __init__(self, target_url: str = "", *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.target_url = target_url

            def header(self):
                if self.page_no() > 1:
                    self.set_font("Helvetica", "I", 8)
                    self.set_text_color(100, 110, 120)
                    self.cell(0, 8, f"TIBSA Security Investigation Report  |  Target: {self.target_url}", new_x="LMARGIN", new_y="NEXT", align="R")
                    self.set_draw_color(210, 215, 220)
                    self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
                    self.ln(4)

            def footer(self):
                if self.page_no() > 1:
                    self.set_y(-15)
                    self.set_font("Helvetica", "I", 8)
                    self.set_text_color(120, 120, 120)
                    self.set_draw_color(210, 215, 220)
                    self.line(self.l_margin, self.get_y() - 2, self.w - self.r_margin, self.get_y() - 2)
                    self.cell(0, 10, f"Page {self.page_no()} of {{nb}}", align="L")
                    self.set_x(self.w - self.r_margin - 65)
                    self.cell(65, 10, "CONFIDENTIAL  -  CLIENT USE ONLY", align="R")

        pdf = BeautifulReportPDF(target_url=investigation_data.get("target", "Unknown"))
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.alias_nb_pages()

        # ── Page 1: Cover / Summary ────────────────────────────────
        pdf.add_page()
        self._render_cover_page(pdf, investigation_id, investigation_data)

        # ── Page 2: Investigation Timeline ─────────────────────────
        pdf.add_page()
        self._render_timeline_section(pdf, investigation_data)

        # ── Page 3+: Findings Summary ──────────────────────────────
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
        """Render a beautifully branded cover page with metadata and a colored risk dashboard card."""
        # Draw top colored banner
        pdf.set_fill_color(24, 43, 73)  # Corporate Dark Navy
        pdf.rect(0, 0, 210, 42, style="F")

        # Top banner title
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_xy(15, 16)
        pdf.cell(0, 10, "TIBSA SECURE PLATFORM")

        # Main Report Title
        pdf.set_text_color(24, 43, 73)
        pdf.set_font("Helvetica", "B", 24)
        pdf.set_xy(15, 58)
        pdf.cell(0, 14, "Security Investigation Report", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(100, 110, 120)
        pdf.cell(0, 8, "Automated Cybersecurity Analysis & Threat Intelligence Report", new_x="LMARGIN", new_y="NEXT")

        # Cyan Accent Rule
        pdf.set_draw_color(0, 150, 200)
        pdf.line(15, pdf.get_y() + 4, 195, pdf.get_y() + 4)
        pdf.ln(12)

        # Risk Score calculations & display
        risk_score = data.get("risk_score", 0.0)
        risk_label = self._score_to_label(risk_score)
        
        # Color palette by severity
        if risk_label == "Critical":
            card_fill = (192, 41, 43)      # Red
            risk_desc = "CRITICAL RISK: Immediate response and vulnerability containment required."
        elif risk_label == "High":
            card_fill = (230, 126, 34)     # Orange
            risk_desc = "HIGH RISK: Remediate flagged items within 24-48 hours to mitigate exposure."
        elif risk_label == "Medium":
            card_fill = (241, 196, 15)     # Amber/Yellow
            risk_desc = "MEDIUM RISK: Schedule remediation items in the upcoming patch cycles."
        else:
            card_fill = (46, 204, 113)     # Green
            risk_desc = "LOW RISK: Standard security posture. Maintain periodic scans and compliance."

        # Draw Risk Dashboard Card
        card_y = pdf.get_y()
        pdf.set_fill_color(*card_fill)
        pdf.rect(15, card_y, 180, 42, style="F")

        # Score & Rating Text inside card
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 26)
        pdf.set_xy(25, card_y + 8)
        pdf.cell(100, 12, f"{risk_score:.1f} / 100")
        
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_xy(25, card_y + 20)
        pdf.cell(100, 8, f"RATING: {risk_label.upper()}")
        
        pdf.set_font("Helvetica", "I", 9.5)
        pdf.set_xy(25, card_y + 28)
        pdf.cell(100, 8, self._safe_text(risk_desc))

        # Restore normal coordinate flow
        pdf.set_xy(15, card_y + 50)

        # Draw Investigation Metadata Card
        pdf.set_text_color(24, 43, 73)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, "Investigation Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        meta_y = pdf.get_y()
        pdf.set_fill_color(245, 247, 250)
        pdf.rect(15, meta_y, 180, 68, style="F")

        # Metadata table list
        target = data.get("target", "Unknown")
        status = data.get("status", "Unknown")
        started = data.get("started_at", "N/A")
        completed = data.get("completed_at", "N/A")
        findings = data.get("findings", [])
        
        # Format dates
        def format_date(dt_str):
            if not dt_str or dt_str == "N/A": return "N/A"
            try:
                return dt_str.split(".")[0].replace("T", " ")
            except Exception:
                return dt_str

        meta_items = [
            ("Investigation ID:", investigation_id),
            ("Target URL:", target),
            ("Scan Status:", status.upper()),
            ("Total Findings:", str(len(findings))),
            ("Scan Started:", format_date(started)),
            ("Scan Completed:", format_date(completed)),
            ("Report Generated:", datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')),
        ]

        pdf.set_text_color(80, 90, 100)
        pdf.set_font("Helvetica", "", 10)
        
        curr_y = meta_y + 6
        for label, val in meta_items:
            pdf.set_xy(22, curr_y)
            pdf.set_font("Helvetica", "B", 9.5)
            pdf.cell(45, 6, label)
            pdf.set_font("Helvetica", "", 9.5)
            pdf.cell(100, 6, self._safe_text(val))
            curr_y += 8

        # Restore flow below cover page components
        pdf.set_xy(15, meta_y + 75)

    def _render_timeline_section(self, pdf, data: Dict[str, Any]):
        """Render the persistent investigation timeline with clean grid design."""
        pdf.set_text_color(24, 43, 73)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 12, "Investigation Timeline", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(0, 150, 200)
        pdf.line(15, pdf.get_y() + 2, 195, pdf.get_y() + 2)
        pdf.ln(8)

        pipeline_state = data.get("pipeline_state", {}) or {}
        timeline = pipeline_state.get("timeline", [])

        if not timeline:
            final_result = data.get("final_result", {}) or {}
            reporter = final_result.get("reporter", {}) or {}
            ai_summary = reporter.get("ai_summary", {}) or {}
            timeline = ai_summary.get("investigation_timeline", [])

        if not timeline:
            pdf.set_font("Helvetica", "I", 10)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 8, "No timeline events recorded.", new_x="LMARGIN", new_y="NEXT")
            return

        # Render timeline events in a clean tabular grid
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_fill_color(24, 43, 73)
        pdf.set_text_color(255, 255, 255)
        
        # Table Header
        pdf.cell(38, 8, " Timestamp", border=1, fill=True)
        pdf.cell(50, 8, " Stage / Component", border=1, fill=True)
        pdf.cell(20, 8, " Status", border=1, fill=True, align="C")
        pdf.cell(72, 8, " Event Message", border=1, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(60, 70, 80)
        
        row_count = 0
        for event in timeline:
            if pdf.get_y() > 255:
                pdf.add_page()
                # Redraw header if page breaks
                pdf.set_font("Helvetica", "B", 9.5)
                pdf.set_fill_color(24, 43, 73)
                pdf.set_text_color(255, 255, 255)
                pdf.cell(38, 8, " Timestamp", border=1, fill=True)
                pdf.cell(50, 8, " Stage / Component", border=1, fill=True)
                pdf.cell(20, 8, " Status", border=1, fill=True, align="C")
                pdf.cell(72, 8, " Event Message", border=1, fill=True)
                pdf.ln()
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(60, 70, 80)

            ts_raw = event.get("timestamp", "")
            ts = ts_raw
            if "T" in ts_raw:
                parts = ts_raw.split("T")
                ts = f"{parts[0]} {parts[1][:8]}"

            stage = event.get("stage", "System")
            status = event.get("status", "info").upper()
            msg = event.get("message", "")

            # Zebra striping
            fill_row = row_count % 2 == 1
            pdf.set_fill_color(248, 250, 252)
            
            # Print row cells
            pdf.cell(38, 7, self._safe_text(ts), border=1, fill=fill_row)
            pdf.cell(50, 7, self._safe_text(stage), border=1, fill=fill_row)
            
            # Status colors
            if status in ["COMPLETED", "SUCCESS"]:
                pdf.set_text_color(39, 174, 96)
            elif status in ["FAILED", "CRITICAL", "FAILURE"]:
                pdf.set_text_color(192, 41, 43)
            else:
                pdf.set_text_color(230, 126, 34)
                
            pdf.cell(20, 7, self._safe_text(status), border=1, fill=fill_row, align="C")
            pdf.set_text_color(60, 70, 80)
            
            # Multi-cell for message
            pdf.cell(72, 7, self._safe_text(msg[:45] + "..." if len(msg) > 45 else msg), border=1, fill=fill_row)
            pdf.ln()
            row_count += 1
        pdf.ln(5)

    def _render_findings_section(self, pdf, data: Dict[str, Any]):
        """Render security findings in a beautiful badge-card layout."""
        pdf.set_text_color(24, 43, 73)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 12, "Detailed Security Findings", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(0, 150, 200)
        pdf.line(15, pdf.get_y() + 2, 195, pdf.get_y() + 2)
        pdf.ln(8)

        findings = data.get("findings", [])
        if not findings:
            pdf.set_font("Helvetica", "I", 10)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 8, "No findings recorded.", new_x="LMARGIN", new_y="NEXT")
            return

        # Sort findings by severity order: critical, high, medium, low, info
        sev_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        def get_priority_key(f):
            sev = (getattr(f, "severity", None) or "info").lower() if hasattr(f, "severity") else f.get("severity", "info").lower()
            return sev_priority.get(sev, 5)

        sorted_findings = sorted(findings, key=get_priority_key)

        for i, finding in enumerate(sorted_findings[:30], start=1):
            title = getattr(finding, "title", "Unknown") if hasattr(finding, "title") else finding.get("title", "Unknown")
            severity = (getattr(finding, "severity", "info") if hasattr(finding, "severity") else finding.get("severity", "info")).lower()
            category = getattr(finding, "category", "Unknown") if hasattr(finding, "category") else finding.get("category", "Unknown")
            url = getattr(finding, "affected_url", "") if hasattr(finding, "affected_url") else finding.get("affected_url", "")

            if pdf.get_y() > 240:
                pdf.add_page()

            # Set Severity Badge Colors
            if severity == "critical":
                badge_bg = (192, 41, 43)
                badge_text = (255, 255, 255)
            elif severity == "high":
                badge_bg = (230, 126, 34)
                badge_text = (255, 255, 255)
            elif severity == "medium":
                badge_bg = (241, 196, 15)
                badge_text = (0, 0, 0)
            elif severity == "low":
                badge_bg = (52, 152, 219)
                badge_text = (255, 255, 255)
            else:
                badge_bg = (149, 165, 166)
                badge_text = (255, 255, 255)

            # Draw a bordered panel card for the finding
            card_y = pdf.get_y()
            pdf.set_fill_color(250, 251, 253)
            pdf.set_draw_color(225, 230, 235)
            pdf.rect(15, card_y, 180, 26, style="DF")

            # Draw Severity Badge Box
            pdf.set_fill_color(*badge_bg)
            pdf.rect(20, card_y + 4, 18, 6, style="F")
            
            pdf.set_text_color(*badge_text)
            pdf.set_font("Helvetica", "B", 7.5)
            pdf.set_xy(20, card_y + 4)
            pdf.cell(18, 6, severity.upper(), align="C")

            # Finding Title next to badge
            pdf.set_text_color(24, 43, 73)
            pdf.set_font("Helvetica", "B", 10.5)
            pdf.set_xy(42, card_y + 3)
            pdf.cell(145, 8, self._safe_text(f"{i}. {title}"))

            # Metadata inside card
            pdf.set_text_color(100, 110, 120)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_xy(22, card_y + 11)
            pdf.cell(20, 6, "Category:")
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(130, 6, self._safe_text(category))

            if url:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_xy(22, card_y + 17)
                pdf.cell(20, 6, "Affected URL:")
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(0, 120, 200)
                pdf.cell(130, 6, self._safe_text(url[:85] + "..." if len(url) > 85 else url))

            pdf.set_xy(15, card_y + 29)

    def _render_correlation_section(self, pdf, data: Dict[str, Any]):
        """Render correlated threats section with custom visual panels."""
        final_result = data.get("final_result", {}) or {}
        correlation = final_result.get("correlation", {}) or {}
        threats = correlation.get("correlated_threats", [])

        if not threats:
            return

        pdf.add_page()
        pdf.set_text_color(24, 43, 73)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 12, "Correlated Attack Scenarios", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(0, 150, 200)
        pdf.line(15, pdf.get_y() + 2, 195, pdf.get_y() + 2)
        pdf.ln(8)

        # Overview statistics
        global_risk = correlation.get("global_risk_score", 0)
        pdf.set_fill_color(245, 247, 250)
        pdf.rect(15, pdf.get_y(), 180, 15, style="F")
        
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(80, 90, 100)
        pdf.set_xy(20, pdf.get_y() + 4)
        pdf.cell(70, 7, f"Global Risk Score: {global_risk:.1f}/100")
        pdf.cell(70, 7, f"Total Compound Threats Identified: {len(threats)}")
        
        pdf.set_xy(15, pdf.get_y() + 18)

        for i, threat in enumerate(threats[:10], start=1):
            if pdf.get_y() > 210:
                pdf.add_page()

            title = threat.get("title", "Unknown Threat")
            severity = threat.get("severity", "medium").lower()
            confidence = threat.get("confidence_score", 0)
            description = threat.get("description", "")
            impact = threat.get("impact", "")
            mitigation = threat.get("recommended_mitigation", "")

            # Set colors based on threat severity
            if severity == "critical":
                border_color = (192, 41, 43)
            elif severity == "high":
                border_color = (230, 126, 34)
            else:
                border_color = (241, 196, 15)

            # Draw threat panel with bold left border
            card_y = pdf.get_y()
            pdf.set_fill_color(252, 253, 255)
            pdf.set_draw_color(225, 230, 235)
            pdf.rect(15, card_y, 180, 52, style="DF")
            
            # Left side color accent border
            pdf.set_fill_color(*border_color)
            pdf.rect(15, card_y, 3, 52, style="F")

            # Title
            pdf.set_text_color(24, 43, 73)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_xy(22, card_y + 4)
            pdf.cell(165, 6, self._safe_text(f"{i}. [{severity.upper()}] {title}"))

            # Confidence
            pdf.set_text_color(110, 120, 130)
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_xy(22, card_y + 10)
            pdf.cell(100, 5, f"Confidence Level: {confidence:.0%}")

            # Description, Impact, Mitigation
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(60, 70, 80)
            
            pdf.set_xy(22, card_y + 16)
            pdf.multi_cell(168, 4.5, self._safe_text(f"Description: {description[:180]}..."), new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_x(22)
            pdf.multi_cell(168, 4.5, self._safe_text(f"Business Impact: {impact[:100]}..."), new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_x(22)
            pdf.multi_cell(168, 4.5, self._safe_text(f"Remediation: {mitigation[:120]}..."), new_x="LMARGIN", new_y="NEXT")

            pdf.set_xy(15, card_y + 56)

    def _render_stride_section(self, pdf, data: Dict[str, Any]):
        """Render STRIDE threat model matrix and threats section with clean table designs."""
        final_result = data.get("final_result", {}) or {}
        stride = final_result.get("stride", {}) or {}
        matrix = stride.get("stride_matrix", {}) or {}
        stride_threats = stride.get("stride_threats", [])

        if not matrix:
            return

        if pdf.get_y() > 180:
            pdf.add_page()

        pdf.set_text_color(24, 43, 73)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 12, "STRIDE Threat Matrix", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(0, 150, 200)
        pdf.line(15, pdf.get_y() + 2, 195, pdf.get_y() + 2)
        pdf.ln(8)

        # Render matrix as a table
        pdf.set_font("Helvetica", "B", 10)
        categories = [
            ("S", "Spoofing", "Impersonating something or someone else", matrix.get("spoofing_count", 0)),
            ("T", "Tampering", "Modifying code or data on disk or in transit", matrix.get("tampering_count", 0)),
            ("R", "Repudiation", "Claiming not to have performed an action", matrix.get("repudiation_count", 0)),
            ("I", "Information Disclosure", "Exposing private or sensitive data", matrix.get("information_disclosure_count", 0)),
            ("D", "Denial of Service", "Exhausting resources to deny access", matrix.get("denial_of_service_count", 0)),
            ("E", "Elevation of Privilege", "Gaining unauthorized admin/root capabilities", matrix.get("elevation_of_privilege_count", 0)),
        ]

        # Table header
        pdf.set_fill_color(24, 43, 73)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(10, 8, "  ", border=1, fill=True, align="C")
        pdf.cell(48, 8, " STRIDE Category", border=1, fill=True)
        pdf.cell(102, 8, " Description", border=1, fill=True)
        pdf.cell(20, 8, " Threats", border=1, fill=True, align="C")
        pdf.ln()

        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(60, 70, 80)
        
        row_count = 0
        for char, name, desc, count in categories:
            fill_row = row_count % 2 == 1
            pdf.set_fill_color(248, 250, 252)
            
            pdf.set_font("Helvetica", "B", 9.5)
            pdf.cell(10, 7.5, char, border=1, fill=fill_row, align="C")
            pdf.cell(48, 7.5, f" {name}", border=1, fill=fill_row)
            pdf.set_font("Helvetica", "", 9.5)
            pdf.cell(102, 7.5, f" {desc}", border=1, fill=fill_row)
            pdf.set_font("Helvetica", "B", 9.5)
            if count > 0:
                pdf.set_text_color(192, 41, 43)
            pdf.cell(20, 7.5, str(count), border=1, fill=fill_row, align="C")
            pdf.set_text_color(60, 70, 80)
            pdf.ln()
            row_count += 1
            
        pdf.ln(8)

        # Render STRIDE detailed Threats
        if stride_threats:
            if pdf.get_y() > 210:
                pdf.add_page()
            
            pdf.set_text_color(24, 43, 73)
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 8, "Identified Architecture Threats", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)

            for i, st in enumerate(stride_threats, start=1):
                cat = st.get("category", "")
                asset = st.get("affected_asset", "")
                full_sc = st.get("attack_scenario", "")
                sev = st.get("severity", "medium").lower()

                # Extract clean scenario description and clean evidence tracing
                scenario_clean = full_sc.split("[Evidence Tracing]")[0].strip()
                evidence_clean = ""
                if "[Evidence Tracing]" in full_sc:
                    raw_evidence = full_sc.split("[Evidence Tracing]")[1].strip()
                    ev_lines = []
                    for line in raw_evidence.split("\n"):
                        # Keep it clean and avoid raw code snippets in the report
                        if any(x in line for x in ["Snippet:", "function(", "var ", "const ", "let ", "return "]) or len(line) > 150:
                            continue
                        line_clean = line.strip()
                        if line_clean:
                            ev_lines.append(line_clean)
                    evidence_clean = "\n".join(ev_lines).strip()

                # Calculate height dynamically
                chars_per_line = 90
                desc_lines = max(1, int(len(scenario_clean) / chars_per_line) + 1)
                ev_lines_count = len(evidence_clean.split("\n")) if evidence_clean else 0
                
                card_height = 14 + (desc_lines * 4.5)
                if evidence_clean:
                    card_height += 6 + (ev_lines_count * 4.0)
                card_height = max(28, card_height)

                # Page overflow check
                if pdf.get_y() + card_height > 270:
                    pdf.add_page()

                card_y = pdf.get_y()
                pdf.set_fill_color(252, 253, 255)
                pdf.set_draw_color(225, 230, 235)
                pdf.rect(15, card_y, 180, card_height, style="DF")
                
                # Left accent severity colored bar
                accent = (192, 41, 43) if sev in ["critical", "high"] else (230, 126, 34)
                pdf.set_fill_color(*accent)
                pdf.rect(15, card_y, 3, card_height, style="F")

                pdf.set_text_color(24, 43, 73)
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_xy(22, card_y + 3)
                pdf.cell(160, 5, self._safe_text(f"{i}. [{cat}] - Target: {asset}"))

                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(70, 80, 90)
                pdf.set_xy(22, card_y + 9)
                pdf.multi_cell(168, 4.5, self._safe_text(f"Attack Scenario: {scenario_clean}"))

                if evidence_clean:
                    pdf.set_x(22)
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.set_text_color(100, 110, 120)
                    pdf.cell(0, 5, "Supporting Findings & Evidence:", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_x(22)
                    pdf.set_font("Helvetica", "", 8)
                    pdf.multi_cell(168, 4, self._safe_text(evidence_clean))

                pdf.set_xy(15, card_y + card_height + 4)

    def _render_ai_summary_section(self, pdf, data: Dict[str, Any]):
        """Render AI analysis and SOC remediation advisories in styled warning/info panels."""
        final_result = data.get("final_result", {}) or {}
        reporter = final_result.get("reporter", {}) or {}
        ai_summary = reporter.get("ai_summary", {}) or {}

        if not ai_summary:
            return

        pdf.add_page()
        pdf.set_text_color(24, 43, 73)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 12, "Security Posture Analysis Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(0, 150, 200)
        pdf.line(15, pdf.get_y() + 2, 195, pdf.get_y() + 2)
        pdf.ln(8)

        # Executive Summary Callout Panel
        exec_summary = ai_summary.get("executive_summary", "")
        if exec_summary:
            panel_y = pdf.get_y()
            num_chars = len(exec_summary)
            num_lines = max(1, int(num_chars / 82) + 2)
            height = 12 + (num_lines * 5)
            
            pdf.set_fill_color(240, 245, 250)
            pdf.set_draw_color(0, 150, 200)
            pdf.rect(15, panel_y, 180, height, style="DF")
            pdf.rect(15, panel_y, 3, height, style="F")
            
            pdf.set_xy(22, panel_y + 3)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(24, 43, 73)
            pdf.cell(0, 6, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_x(22)
            pdf.set_font("Helvetica", "", 9.5)
            pdf.set_text_color(50, 60, 70)
            pdf.multi_cell(168, 5, self._safe_text(exec_summary))
            
            pdf.set_xy(15, panel_y + height + 6)

        # Risk Overview & Threat Intel Summary (Inline sections)
        sections = [
            ("Risk Overview", ai_summary.get("risk_explanation", "") or ai_summary.get("risk_overview", "")),
            ("Attack Surface Summary", ai_summary.get("attack_surface_summary", "")),
            ("Threat Intelligence Correlation", ai_summary.get("threat_intelligence_summary", "")),
        ]

        for title, content in sections:
            if not content: continue
            if pdf.get_y() > 220:
                pdf.add_page()
                
            pdf.set_text_color(24, 43, 73)
            pdf.set_font("Helvetica", "B", 11.5)
            pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
            
            pdf.set_font("Helvetica", "", 9.5)
            pdf.set_text_color(60, 70, 80)
            pdf.multi_cell(180, 5, self._safe_text(content))
            pdf.ln(5)

        # Immediate Response Callout Panel (Yellow Warning Block)
        immediate = ai_summary.get("immediate_actions", [])
        if immediate:
            if pdf.get_y() > 200:
                pdf.add_page()
                
            panel_y = pdf.get_y()
            box_height = 12 + (len(immediate) * 6.5)
            
            pdf.set_fill_color(255, 251, 240)
            pdf.set_draw_color(241, 196, 15)
            pdf.rect(15, panel_y, 180, box_height, style="DF")
            pdf.rect(15, panel_y, 3, box_height, style="F")
            
            # Check if there are any high/critical severity findings
            findings = data.get("findings", [])
            has_high_or_critical = any(str(f.get("severity") or "").lower() in ["high", "critical"] for f in findings)
            
            panel_title = "Immediate Response Recommendations (Next 24-48 Hours)"
            if not has_high_or_critical:
                panel_title = "Recommended Security Hardening Actions"
                
            pdf.set_xy(22, panel_y + 3)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(230, 126, 34)
            pdf.cell(0, 6, panel_title, new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(70, 80, 90)
            
            curr_item_y = panel_y + 10
            for action in immediate:
                pdf.set_xy(22, curr_item_y)
                pdf.cell(0, 5.5, self._safe_text(f"* {action}"))
                curr_item_y += 6
                
            pdf.set_xy(15, panel_y + box_height + 6)

        # Long-Term Improvements
        long_term = ai_summary.get("long_term_improvements", [])
        if long_term:
            if pdf.get_y() > 200:
                pdf.add_page()
                
            pdf.set_text_color(24, 43, 73)
            pdf.set_font("Helvetica", "B", 11.5)
            pdf.cell(0, 8, "Long-Term Security Hardening & Improvements", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
            
            pdf.set_font("Helvetica", "", 9.5)
            pdf.set_text_color(60, 70, 80)
            for action in long_term:
                pdf.cell(0, 5.5, self._safe_text(f"  * {action}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)

        # Technical Appendix
        appendix = ai_summary.get("technical_appendix", "")
        if appendix:
            if pdf.get_y() > 200:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "Technical Appendix", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, self._safe_text(appendix))
            pdf.ln(4)

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
        replacements = {
            "\u2014": "-",  # EM dash
            "\u2013": "-",  # EN dash
            "\u201c": '"',  # Left double quote
            "\u201d": '"',  # Right double quote
            "\u2018": "'",  # Left single quote
            "\u2019": "'",  # Right single quote
            "\u2022": "*",  # Bullet
            "\u2026": "...", # Ellipsis
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
        return text.encode("latin-1", errors="replace").decode("latin-1")

