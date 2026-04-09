"""
Threat Modeling – Export Service.

Handles exporting threat models and reports in various formats:
PDF, JSON, CSV, XML, and integration with external systems.
"""
from __future__ import annotations

import json
import csv
import xml.etree.ElementTree as ET
from io import StringIO, BytesIO
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime

from app.models.threat_modeling import (
    ThreatModelAnalysis, ThreatItem, Mitigation, HeatmapData,
    ExportFormat, BacklogTicket
)


@dataclass
class ExportResult:
    """Result of an export operation."""
    format: ExportFormat
    content: Union[str, bytes]
    filename: str
    mime_type: str
    size_bytes: int


class ExportService:
    """Service for exporting threat model data in various formats."""

    def __init__(self):
        self.timestamp = datetime.utcnow().isoformat()

    def export_threat_model(
        self,
        analysis: ThreatModelAnalysis,
        format_type: ExportFormat,
        include_heatmap: bool = True
    ) -> ExportResult:
        """
        Export a complete threat model analysis in the specified format.
        """
        if format_type == ExportFormat.JSON:
            return self._export_json(analysis, include_heatmap)
        elif format_type == ExportFormat.CSV:
            return self._export_csv(analysis)
        elif format_type == ExportFormat.XML:
            return self._export_xml(analysis, include_heatmap)
        elif format_type == ExportFormat.PDF:
            return self._export_pdf(analysis, include_heatmap)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    def _export_json(self, analysis: ThreatModelAnalysis, include_heatmap: bool) -> ExportResult:
        """Export threat model as JSON."""
        export_data = self._prepare_export_data(analysis, include_heatmap)

        # Convert to JSON
        json_content = json.dumps(export_data, indent=2, default=str)

        filename = f"threat_model_{analysis.id}_{self.timestamp[:10]}.json"

        return ExportResult(
            format=ExportFormat.JSON,
            content=json_content,
            filename=filename,
            mime_type="application/json",
            size_bytes=len(json_content.encode('utf-8'))
        )

    def _export_csv(self, analysis: ThreatModelAnalysis) -> ExportResult:
        """Export threat model as CSV."""
        output = StringIO()

        # Write threats
        if analysis.threats:
            writer = csv.writer(output)

            # Header
            writer.writerow([
                'ID', 'Title', 'Description', 'STRIDE Category', 'Severity',
                'Likelihood', 'Impact', 'Status', 'CAPEC ID', 'Affected Assets',
                'Entry Points', 'Trust Boundaries', 'ASVS Controls'
            ])

            # Data rows
            for threat in analysis.threats:
                writer.writerow([
                    threat.id,
                    threat.title,
                    threat.description,
                    threat.stride_category.value if threat.stride_category else '',
                    threat.severity,
                    threat.likelihood,
                    threat.impact,
                    threat.status.value if threat.status else '',
                    threat.capec_id or '',
                    '; '.join(threat.affected_assets or []),
                    '; '.join(threat.entry_points or []),
                    '; '.join(threat.trust_boundaries or []),
                    '; '.join(threat.asvs_controls or [])
                ])

        # Write mitigations if present
        if analysis.mitigations:
            output.write('\n\nMITIGATIONS\n')
            writer = csv.writer(output)
            writer.writerow([
                'ID', 'Title', 'Description', 'Implementation Steps', 'Cost',
                'Effectiveness', 'Priority', 'Related Threats'
            ])

            for mitigation in analysis.mitigations:
                writer.writerow([
                    mitigation.id,
                    mitigation.title,
                    mitigation.description,
                    '; '.join(mitigation.implementation_steps or []),
                    mitigation.cost,
                    mitigation.effectiveness,
                    mitigation.priority,
                    '; '.join(mitigation.related_threats or [])
                ])

        csv_content = output.getvalue()
        filename = f"threat_model_{analysis.id}_{self.timestamp[:10]}.csv"

        return ExportResult(
            format=ExportFormat.CSV,
            content=csv_content,
            filename=filename,
            mime_type="text/csv",
            size_bytes=len(csv_content.encode('utf-8'))
        )

    def _export_xml(self, analysis: ThreatModelAnalysis, include_heatmap: bool) -> ExportResult:
        """Export threat model as XML."""
        root = ET.Element("ThreatModelAnalysis")
        root.set("id", analysis.id)
        root.set("exported_at", self.timestamp)

        # Add metadata
        metadata = ET.SubElement(root, "Metadata")
        ET.SubElement(metadata, "Title").text = analysis.title or "Threat Model Analysis"
        ET.SubElement(metadata, "Description").text = analysis.description or ""
        ET.SubElement(metadata, "CreatedAt").text = analysis.created_at.isoformat() if analysis.created_at else ""
        ET.SubElement(metadata, "UpdatedAt").text = analysis.updated_at.isoformat() if analysis.updated_at else ""

        # Add system metadata
        if analysis.system_metadata:
            sys_meta = ET.SubElement(root, "SystemMetadata")
            for key, value in analysis.system_metadata.items():
                ET.SubElement(sys_meta, key).text = str(value)

        # Add architecture diagram
        if analysis.architecture_diagram:
            arch = ET.SubElement(root, "ArchitectureDiagram")
            for key, value in analysis.architecture_diagram.items():
                ET.SubElement(arch, key).text = str(value)

        # Add assets
        if analysis.assets:
            assets = ET.SubElement(root, "Assets")
            for asset in analysis.assets:
                asset_elem = ET.SubElement(assets, "Asset")
                for key, value in asset.items():
                    ET.SubElement(asset_elem, key).text = str(value)

        # Add entry points
        if analysis.entry_points:
            entries = ET.SubElement(root, "EntryPoints")
            for entry in analysis.entry_points:
                entry_elem = ET.SubElement(entries, "EntryPoint")
                for key, value in entry.items():
                    ET.SubElement(entry_elem, key).text = str(value)

        # Add trust boundaries
        if analysis.trust_boundaries:
            boundaries = ET.SubElement(root, "TrustBoundaries")
            for boundary in analysis.trust_boundaries:
                boundary_elem = ET.SubElement(boundaries, "TrustBoundary")
                for key, value in boundary.items():
                    ET.SubElement(boundary_elem, key).text = str(value)

        # Add threats
        if analysis.threats:
            threats = ET.SubElement(root, "Threats")
            for threat in analysis.threats:
                threat_elem = ET.SubElement(threats, "Threat")
                threat_elem.set("id", threat.id)

                ET.SubElement(threat_elem, "Title").text = threat.title
                ET.SubElement(threat_elem, "Description").text = threat.description or ""

                if threat.stride_category:
                    ET.SubElement(threat_elem, "STRIDECategory").text = threat.stride_category.value

                ET.SubElement(threat_elem, "Severity").text = threat.severity or ""
                ET.SubElement(threat_elem, "Likelihood").text = threat.likelihood or ""
                ET.SubElement(threat_elem, "Impact").text = threat.impact or ""

                if threat.status:
                    ET.SubElement(threat_elem, "Status").text = threat.status.value

                if threat.capec_id:
                    ET.SubElement(threat_elem, "CAPECId").text = threat.capec_id

                if threat.capec_description:
                    ET.SubElement(threat_elem, "CAPECDescription").text = threat.capec_description

                if threat.affected_assets:
                    assets_elem = ET.SubElement(threat_elem, "AffectedAssets")
                    for asset in threat.affected_assets:
                        ET.SubElement(assets_elem, "Asset").text = asset

                if threat.entry_points:
                    entries_elem = ET.SubElement(threat_elem, "EntryPoints")
                    for entry in threat.entry_points:
                        ET.SubElement(entries_elem, "EntryPoint").text = entry

                if threat.trust_boundaries:
                    boundaries_elem = ET.SubElement(threat_elem, "TrustBoundaries")
                    for boundary in threat.trust_boundaries:
                        ET.SubElement(boundaries_elem, "TrustBoundary").text = boundary

                if threat.asvs_controls:
                    controls_elem = ET.SubElement(threat_elem, "ASVSControls")
                    for control in threat.asvs_controls:
                        ET.SubElement(controls_elem, "Control").text = control

        # Add mitigations
        if analysis.mitigations:
            mitigations = ET.SubElement(root, "Mitigations")
            for mitigation in analysis.mitigations:
                mitigation_elem = ET.SubElement(mitigations, "Mitigation")
                mitigation_elem.set("id", mitigation.id)

                ET.SubElement(mitigation_elem, "Title").text = mitigation.title or ""
                ET.SubElement(mitigation_elem, "Description").text = mitigation.description or ""
                ET.SubElement(mitigation_elem, "Cost").text = mitigation.cost or ""
                ET.SubElement(mitigation_elem, "Effectiveness").text = mitigation.effectiveness or ""
                ET.SubElement(mitigation_elem, "Priority").text = str(mitigation.priority or 0)

                if mitigation.implementation_steps:
                    steps_elem = ET.SubElement(mitigation_elem, "ImplementationSteps")
                    for step in mitigation.implementation_steps:
                        ET.SubElement(steps_elem, "Step").text = step

                if mitigation.related_threats:
                    threats_elem = ET.SubElement(mitigation_elem, "RelatedThreats")
                    for threat_id in mitigation.related_threats:
                        ET.SubElement(threats_elem, "ThreatId").text = threat_id

        # Add heatmap data if requested
        if include_heatmap and analysis.heatmap_data:
            heatmap = ET.SubElement(root, "HeatmapData")
            heatmap_data = analysis.heatmap_data

            if heatmap_data.risk_matrix:
                risk_matrix = ET.SubElement(heatmap, "RiskMatrix")
                for key, value in heatmap_data.risk_matrix.items():
                    if key == "data":
                        data_elem = ET.SubElement(risk_matrix, "Data")
                        for item in value:
                            item_elem = ET.SubElement(data_elem, "Item")
                            for k, v in item.items():
                                ET.SubElement(item_elem, k).text = str(v)
                    else:
                        ET.SubElement(risk_matrix, key).text = str(value)

        # Convert to string
        xml_content = ET.tostring(root, encoding='unicode', method='xml')

        filename = f"threat_model_{analysis.id}_{self.timestamp[:10]}.xml"

        return ExportResult(
            format=ExportFormat.XML,
            content=xml_content,
            filename=filename,
            mime_type="application/xml",
            size_bytes=len(xml_content.encode('utf-8'))
        )

    def _export_pdf(self, analysis: ThreatModelAnalysis, include_heatmap: bool) -> ExportResult:
        """
        Export threat model as PDF.

        Note: In a real implementation, this would use a PDF generation library
        like ReportLab, WeasyPrint, or similar. For now, we'll create a simple
        text-based representation that could be converted to PDF.
        """
        pdf_content = self._generate_pdf_content(analysis, include_heatmap)

        filename = f"threat_model_{analysis.id}_{self.timestamp[:10]}.pdf"

        # In production, this would be actual PDF bytes
        return ExportResult(
            format=ExportFormat.PDF,
            content=pdf_content.encode('utf-8'),  # Placeholder
            filename=filename,
            mime_type="application/pdf",
            size_bytes=len(pdf_content.encode('utf-8'))
        )

    def _generate_pdf_content(self, analysis: ThreatModelAnalysis, include_heatmap: bool) -> str:
        """Generate PDF content as text (placeholder for actual PDF generation)."""
        content_parts = [
            f"THREAT MODEL ANALYSIS REPORT",
            f"Generated: {self.timestamp}",
            f"",
            f"Analysis ID: {analysis.id}",
            f"Title: {analysis.title or 'N/A'}",
            f"Description: {analysis.description or 'N/A'}",
            f"",
            f"THREATS SUMMARY",
            f"Total Threats: {len(analysis.threats) if analysis.threats else 0}",
            f""
        ]

        if analysis.threats:
            for i, threat in enumerate(analysis.threats, 1):
                content_parts.extend([
                    f"Threat {i}: {threat.title}",
                    f"  Category: {threat.stride_category.value if threat.stride_category else 'N/A'}",
                    f"  Severity: {threat.severity or 'N/A'}",
                    f"  Status: {threat.status.value if threat.status else 'N/A'}",
                    f"  Description: {threat.description or 'N/A'}",
                    f""
                ])

        if analysis.mitigations:
            content_parts.extend([
                f"MITIGATIONS SUMMARY",
                f"Total Mitigations: {len(analysis.mitigations)}",
                f""
            ])

            for i, mitigation in enumerate(analysis.mitigations, 1):
                content_parts.extend([
                    f"Mitigation {i}: {mitigation.title or 'N/A'}",
                    f"  Cost: {mitigation.cost or 'N/A'}",
                    f"  Effectiveness: {mitigation.effectiveness or 'N/A'}",
                    f"  Description: {mitigation.description or 'N/A'}",
                    f""
                ])

        return "\n".join(content_parts)

    def _prepare_export_data(self, analysis: ThreatModelAnalysis, include_heatmap: bool) -> Dict[str, Any]:
        """Prepare data for export."""
        data = {
            "id": analysis.id,
            "title": analysis.title,
            "description": analysis.description,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            "updated_at": analysis.updated_at.isoformat() if analysis.updated_at else None,
            "system_metadata": analysis.system_metadata,
            "architecture_diagram": analysis.architecture_diagram,
            "assets": analysis.assets,
            "entry_points": analysis.entry_points,
            "trust_boundaries": analysis.trust_boundaries,
            "threats": [asdict(threat) for threat in (analysis.threats or [])],
            "mitigations": [asdict(mitigation) for mitigation in (analysis.mitigations or [])],
            "exported_at": self.timestamp,
            "export_format": "JSON"
        }

        if include_heatmap and analysis.heatmap_data:
            data["heatmap_data"] = asdict(analysis.heatmap_data)

        return data

    def create_backlog_tickets(self, analysis: ThreatModelAnalysis, system: str = "jira") -> List[BacklogTicket]:
        """
        Create backlog tickets from high-priority threats and mitigations.

        This would integrate with external systems like Jira, GitHub Issues, etc.
        """
        tickets = []

        # Create tickets for high-severity threats
        if analysis.threats:
            for threat in analysis.threats:
                if self._is_high_priority_threat(threat):
                    ticket = BacklogTicket(
                        id=f"TICKET-{threat.id}",
                        title=f"Security Threat: {threat.title}",
                        description=self._generate_ticket_description(threat),
                        priority=self._calculate_ticket_priority(threat),
                        labels=["security", "threat-modeling", threat.stride_category.value.lower() if threat.stride_category else "unknown"],
                        assignee=None,  # Would be assigned based on team structure
                        due_date=None,  # Would be calculated based on risk level
                        external_system=system,
                        external_id=None,  # Would be populated after creation in external system
                        created_from_threat=threat.id
                    )
                    tickets.append(ticket)

        # Create tickets for mitigations
        if analysis.mitigations:
            for mitigation in analysis.mitigations:
                if mitigation.priority and mitigation.priority >= 7:  # High priority
                    ticket = BacklogTicket(
                        id=f"MITIGATION-{mitigation.id}",
                        title=f"Implement Security Control: {mitigation.title}",
                        description=self._generate_mitigation_ticket_description(mitigation),
                        priority=mitigation.priority,
                        labels=["security", "mitigation", "implementation"],
                        assignee=None,
                        due_date=None,
                        external_system=system,
                        external_id=None,
                        created_from_mitigation=mitigation.id
                    )
                    tickets.append(ticket)

        return tickets

    def _is_high_priority_threat(self, threat: ThreatItem) -> bool:
        """Determine if a threat should generate a backlog ticket."""
        # High severity or likelihood
        high_severity = threat.severity and threat.severity.lower() in ["high", "critical"]
        high_likelihood = threat.likelihood and threat.likelihood.lower() in ["high", "critical"]

        # Open status
        is_open = not threat.status or threat.status.value in ["OPEN", "IN_PROGRESS"]

        return (high_severity or high_likelihood) and is_open

    def _calculate_ticket_priority(self, threat: ThreatItem) -> int:
        """Calculate ticket priority based on threat characteristics."""
        priority = 3  # Default medium

        if threat.severity and threat.severity.lower() == "critical":
            priority = 1  # Highest
        elif threat.severity and threat.severity.lower() == "high":
            priority = 2  # High

        if threat.likelihood and threat.likelihood.lower() in ["high", "critical"]:
            priority = min(priority, 2)  # Ensure at least high priority

        return priority

    def _generate_ticket_description(self, threat: ThreatItem) -> str:
        """Generate detailed ticket description for a threat."""
        description_parts = [
            f"**Threat Title:** {threat.title}",
            f"**Description:** {threat.description or 'No description provided'}",
            f"**STRIDE Category:** {threat.stride_category.value if threat.stride_category else 'Unknown'}",
            f"**Severity:** {threat.severity or 'Unknown'}",
            f"**Likelihood:** {threat.likelihood or 'Unknown'}",
            f"**Impact:** {threat.impact or 'Unknown'}",
        ]

        if threat.capec_id:
            description_parts.append(f"**CAPEC ID:** {threat.capec_id}")
        if threat.capec_description:
            description_parts.append(f"**CAPEC Description:** {threat.capec_description[:200]}...")

        if threat.affected_assets:
            description_parts.append(f"**Affected Assets:** {', '.join(threat.affected_assets)}")

        if threat.asvs_controls:
            description_parts.append(f"**ASVS Controls:** {', '.join(threat.asvs_controls[:3])}")

        description_parts.extend([
            "",
            "**Action Required:**",
            "- Assess the threat's impact on the system",
            "- Implement appropriate security controls",
            "- Update threat model with mitigation status"
        ])

        return "\n".join(description_parts)

    def _generate_mitigation_ticket_description(self, mitigation: Mitigation) -> str:
        """Generate detailed ticket description for a mitigation."""
        description_parts = [
            f"**Mitigation Title:** {mitigation.title or 'Unnamed Mitigation'}",
            f"**Description:** {mitigation.description or 'No description provided'}",
            f"**Cost:** {mitigation.cost or 'Unknown'}",
            f"**Effectiveness:** {mitigation.effectiveness or 'Unknown'}",
            f"**Priority:** {mitigation.priority or 'Unknown'}",
        ]

        if mitigation.implementation_steps:
            description_parts.append("**Implementation Steps:**")
            for i, step in enumerate(mitigation.implementation_steps, 1):
                description_parts.append(f"{i}. {step}")

        if mitigation.related_threats:
            description_parts.append(f"**Related Threats:** {', '.join(mitigation.related_threats)}")

        description_parts.extend([
            "",
            "**Action Required:**",
            "- Implement the mitigation steps outlined above",
            "- Test the implementation for effectiveness",
            "- Update threat model with implementation status"
        ])

        return "\n".join(description_parts)
