"""
Threat Modeling – Heatmap Generation Service.

Generates visual heatmaps showing threat distribution, risk levels,
and security posture across the system architecture.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict

from app.models.threat_modeling import ThreatItem, HeatmapData, STRIDECategory, ThreatStatus


@dataclass
class HeatmapPoint:
    """Represents a point on the heatmap."""
    x: float  # Likelihood score (0-5)
    y: float  # Impact score (0-5)
    threat_count: int
    risk_level: str
    color: str
    threats: List[str]  # Threat IDs


@dataclass
class HeatmapZone:
    """Represents a risk zone on the heatmap."""
    name: str
    x_min: float
    x_max: float
    y_min: float
    y_max: float
    color: str
    description: str


class HeatmapGenerator:
    """Service for generating threat model heatmaps."""

    RISK_ZONES = [
        HeatmapZone("Accept", 0, 2, 0, 2, "#28a745", "Low risk - monitor periodically"),
        HeatmapZone("Transfer", 2, 3, 0, 2, "#ffc107", "Medium risk - consider mitigation"),
        HeatmapZone("Mitigate", 0, 2, 2, 5, "#fd7e14", "Medium-High risk - implement controls"),
        HeatmapZone("Avoid", 2, 5, 2, 5, "#dc3545", "High risk - immediate action required")
    ]

    def __init__(self):
        self.max_likelihood = 5
        self.max_impact = 5

    def generate_heatmap_data(self, threats: List[ThreatItem]) -> HeatmapData:
        """
        Generate comprehensive heatmap data from threats.

        Returns a HeatmapData object with various heatmap representations.
        """
        # Generate risk matrix heatmap
        risk_matrix = self._generate_risk_matrix(threats)

        # Generate STRIDE distribution heatmap
        stride_heatmap = self._generate_stride_heatmap(threats)

        # Generate asset-based heatmap
        asset_heatmap = self._generate_asset_heatmap(threats)

        # Generate temporal heatmap (by status)
        temporal_heatmap = self._generate_temporal_heatmap(threats)

        return HeatmapData(
            risk_matrix=risk_matrix,
            stride_distribution=stride_heatmap,
            asset_risk_map=asset_heatmap,
            temporal_distribution=temporal_heatmap,
            zones=[zone.__dict__ for zone in self.RISK_ZONES],
            metadata=self._generate_metadata(threats)
        )

    def _generate_risk_matrix(self, threats: List[ThreatItem]) -> Dict[str, Any]:
        """Generate a risk matrix heatmap (Likelihood vs Impact)."""
        # Initialize matrix
        matrix = {}
        for likelihood in range(self.max_likelihood + 1):
            for impact in range(self.max_impact + 1):
                key = f"{likelihood},{impact}"
                matrix[key] = {
                    "likelihood": likelihood,
                    "impact": impact,
                    "threat_count": 0,
                    "threats": [],
                    "risk_score": likelihood * impact,
                    "zone": self._get_risk_zone(likelihood, impact)
                }

        # Populate matrix with threats
        for threat in threats:
            likelihood_score = self._normalize_score(threat.likelihood)
            impact_score = self._normalize_score(threat.impact)

            if likelihood_score is not None and impact_score is not None:
                key = f"{likelihood_score},{impact_score}"
                if key in matrix:
                    matrix[key]["threat_count"] += 1
                    matrix[key]["threats"].append(threat.id)

        return {
            "data": list(matrix.values()),
            "dimensions": {
                "likelihood_range": [0, self.max_likelihood],
                "impact_range": [0, self.max_impact]
            }
        }

    def _generate_stride_heatmap(self, threats: List[ThreatItem]) -> Dict[str, Any]:
        """Generate STRIDE category distribution heatmap."""
        stride_counts = defaultdict(int)
        stride_risks = defaultdict(list)

        for threat in threats:
            if threat.stride_category:
                category = threat.stride_category.value
                stride_counts[category] += 1
                risk_score = self._calculate_risk_score(threat)
                stride_risks[category].append(risk_score)

        # Calculate average risk per category
        stride_data = []
        for category, count in stride_counts.items():
            avg_risk = sum(stride_risks[category]) / len(stride_risks[category]) if stride_risks[category] else 0
            stride_data.append({
                "category": category,
                "threat_count": count,
                "average_risk": round(avg_risk, 2),
                "color": self._get_stride_color(category)
            })

        return {
            "data": stride_data,
            "total_threats": len(threats)
        }

    def _generate_asset_heatmap(self, threats: List[ThreatItem]) -> Dict[str, Any]:
        """Generate asset-based risk heatmap."""
        asset_risks = defaultdict(list)

        for threat in threats:
            if threat.affected_assets:
                risk_score = self._calculate_risk_score(threat)
                for asset in threat.affected_assets:
                    asset_risks[asset].append(risk_score)

        # Calculate risk per asset
        asset_data = []
        for asset, risks in asset_risks.items():
            avg_risk = sum(risks) / len(risks)
            threat_count = len(risks)
            asset_data.append({
                "asset": asset,
                "average_risk": round(avg_risk, 2),
                "threat_count": threat_count,
                "color": self._get_risk_color(avg_risk)
            })

        # Sort by risk level
        asset_data.sort(key=lambda x: x["average_risk"], reverse=True)

        return {
            "data": asset_data,
            "total_assets": len(asset_data)
        }

    def _generate_temporal_heatmap(self, threats: List[ThreatItem]) -> Dict[str, Any]:
        """Generate temporal distribution heatmap by threat status."""
        status_counts = defaultdict(int)
        status_risks = defaultdict(list)

        for threat in threats:
            status = threat.status.value if threat.status else "Unknown"
            status_counts[status] += 1
            risk_score = self._calculate_risk_score(threat)
            status_risks[status].append(risk_score)

        # Calculate metrics per status
        temporal_data = []
        for status, count in status_counts.items():
            avg_risk = sum(status_risks[status]) / len(status_risks[status]) if status_risks[status] else 0
            temporal_data.append({
                "status": status,
                "threat_count": count,
                "average_risk": round(avg_risk, 2),
                "color": self._get_status_color(status)
            })

        return {
            "data": temporal_data,
            "total_threats": len(threats)
        }

    def _generate_metadata(self, threats: List[ThreatItem]) -> Dict[str, Any]:
        """Generate metadata for the heatmap."""
        total_threats = len(threats)
        high_risk_count = sum(1 for t in threats if self._calculate_risk_score(t) >= 12)  # High risk threshold

        stride_distribution = defaultdict(int)
        for threat in threats:
            if threat.stride_category:
                stride_distribution[threat.stride_category.value] += 1

        return {
            "total_threats": total_threats,
            "high_risk_threats": high_risk_count,
            "stride_breakdown": dict(stride_distribution),
            "generated_at": "2024-01-01T00:00:00Z",  # Would be current timestamp
            "version": "1.0"
        }

    def _normalize_score(self, level: Optional[str]) -> Optional[int]:
        """Convert severity level to numeric score (0-5)."""
        if not level:
            return None

        level_map = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "moderate": 3,
            "low": 2,
            "info": 1,
            "informational": 1
        }

        return level_map.get(level.lower())

    def _calculate_risk_score(self, threat: ThreatItem) -> float:
        """Calculate overall risk score for a threat."""
        likelihood_score = self._normalize_score(threat.likelihood) or 3
        impact_score = self._normalize_score(threat.impact) or 3

        return likelihood_score * impact_score

    def _get_risk_zone(self, likelihood: int, impact: int) -> str:
        """Determine which risk zone a point falls into."""
        for zone in self.RISK_ZONES:
            if (zone.x_min <= likelihood < zone.x_max and
                zone.y_min <= impact < zone.y_max):
                return zone.name
        return "Unknown"

    def _get_stride_color(self, category: str) -> str:
        """Get color for STRIDE category."""
        color_map = {
            "SPOOFING": "#FF6B6B",
            "TAMPERING": "#4ECDC4",
            "REPUDIATION": "#45B7D1",
            "INFORMATION_DISCLOSURE": "#FFA07A",
            "DENIAL_OF_SERVICE": "#98D8C8",
            "ELEVATION_OF_PRIVILEGE": "#F7DC6F"
        }
        return color_map.get(category.upper(), "#BDC3C7")

    def _get_risk_color(self, risk_score: float) -> str:
        """Get color based on risk score."""
        if risk_score >= 16:  # 4x4 or higher
            return "#dc3545"  # Red
        elif risk_score >= 9:  # 3x3 or higher
            return "#fd7e14"  # Orange
        elif risk_score >= 4:  # 2x2 or higher
            return "#ffc107"  # Yellow
        else:
            return "#28a745"  # Green

    def _get_status_color(self, status: str) -> str:
        """Get color for threat status."""
        color_map = {
            "OPEN": "#dc3545",
            "MITIGATED": "#28a745",
            "ACCEPTED": "#ffc107",
            "CLOSED": "#6c757d",
            "IN_PROGRESS": "#007bff"
        }
        return color_map.get(status.upper(), "#BDC3C7")

    def generate_svg_heatmap(self, heatmap_data: HeatmapData, width: int = 800, height: int = 600) -> str:
        """
        Generate an SVG representation of the risk matrix heatmap.

        This creates a visual heatmap that can be displayed in browsers or exported.
        """
        # Extract risk matrix data
        risk_data = heatmap_data.risk_matrix.get("data", [])

        # Calculate cell dimensions
        cell_width = width // (self.max_likelihood + 1)
        cell_height = height // (self.max_impact + 1)

        svg_parts = [
            f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">',
            '<defs>',
            '<pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse">',
            '<path d="M 10 0 L 0 0 0 10" fill="none" stroke="#e9ecef" stroke-width="0.5"/>',
            '</pattern>',
            '</defs>',
            '<rect width="100%" height="100%" fill="white"/>'
        ]

        # Add risk zone backgrounds
        for zone in self.RISK_ZONES:
            x = zone.x_min * cell_width
            y = (self.max_impact - zone.y_max) * cell_height  # Flip Y axis
            zone_width = (zone.x_max - zone.x_min) * cell_width
            zone_height = (zone.y_max - zone.y_min) * cell_height

            svg_parts.append(
                f'<rect x="{x}" y="{y}" width="{zone_width}" height="{zone_height}" '
                f'fill="{zone.color}" fill-opacity="0.1" stroke="{zone.color}" stroke-width="1"/>'
            )

        # Add threat count cells
        for cell in risk_data:
            if cell["threat_count"] > 0:
                x = cell["likelihood"] * cell_width
                y = (self.max_impact - cell["impact"]) * cell_height  # Flip Y axis

                # Color intensity based on threat count
                intensity = min(cell["threat_count"] / 5, 1)  # Max at 5 threats
                color = self._get_risk_color(cell["risk_score"])

                svg_parts.append(
                    f'<rect x="{x}" y="{y}" width="{cell_width}" height="{cell_height}" '
                    f'fill="{color}" fill-opacity="{0.3 + intensity * 0.7}" '
                    f'stroke="#333" stroke-width="1">'
                    f'<title>{cell["threat_count"]} threats (Risk: {cell["risk_score"]})</title>'
                    '</rect>'
                )

                # Add threat count text
                if cell["threat_count"] > 0:
                    text_x = x + cell_width / 2
                    text_y = y + cell_height / 2
                    svg_parts.append(
                        f'<text x="{text_x}" y="{text_y}" text-anchor="middle" '
                        f'dominant-baseline="middle" font-family="Arial" font-size="12" fill="white">'
                        f'{cell["threat_count"]}</text>'
                    )

        # Add axes labels
        # X-axis (Likelihood)
        for i in range(self.max_likelihood + 1):
            x = i * cell_width + cell_width / 2
            y = height - 20
            svg_parts.append(
                f'<text x="{x}" y="{y}" text-anchor="middle" font-family="Arial" font-size="10">{i}</text>'
            )

        # Y-axis (Impact)
        for i in range(self.max_impact + 1):
            x = 20
            y = (self.max_impact - i) * cell_height + cell_height / 2
            svg_parts.append(
                f'<text x="{x}" y="{y}" text-anchor="middle" font-family="Arial" font-size="10">{i}</text>'
            )

        # Add axis titles
        svg_parts.extend([
            f'<text x="{width/2}" y="{height-5}" text-anchor="middle" font-family="Arial" font-size="12" font-weight="bold">Likelihood</text>',
            f'<text x="10" y="{height/2}" text-anchor="middle" font-family="Arial" font-size="12" font-weight="bold" transform="rotate(-90 10,{height/2})">Impact</text>'
        ])

        svg_parts.append('</svg>')

        return '\n'.join(svg_parts)
