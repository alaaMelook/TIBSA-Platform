"""
Threat Modeling – Normalized Schema Module.

Provides standardized data structures and validation for threat modeling inputs.
"""
from __future__ import annotations

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from app.models.threat_modeling import (
    Asset, EntryPoint, TrustBoundary, DataFlow, ArchitectureDiagram,
    ThreatItem, Mitigation, HeatmapData, STRIDECategory
)


@dataclass
class NormalizedThreatModel:
    """Normalized representation of a complete threat model."""
    project_name: str
    system_metadata: Dict[str, Any]
    architecture: NormalizedArchitecture
    threats: List[NormalizedThreat]
    mitigations: List[NormalizedMitigation]
    risk_score: int
    risk_label: str
    created_at: datetime
    updated_at: datetime


@dataclass
class NormalizedArchitecture:
    """Normalized architecture representation."""
    assets: List[NormalizedAsset]
    entry_points: List[NormalizedEntryPoint]
    trust_boundaries: List[NormalizedTrustBoundary]
    data_flows: List[NormalizedDataFlow]

    def get_asset_by_id(self, asset_id: str) -> Optional[NormalizedAsset]:
        """Get asset by ID."""
        return next((a for a in self.assets if a.id == asset_id), None)

    def get_entry_point_by_id(self, ep_id: str) -> Optional[NormalizedEntryPoint]:
        """Get entry point by ID."""
        return next((ep for ep in self.entry_points if ep.id == ep_id), None)


@dataclass
class NormalizedAsset:
    """Normalized asset representation."""
    id: str
    name: str
    type: str
    description: str
    sensitivity_level: str
    data_classification: str
    tags: List[str]
    connected_assets: List[str]  # Asset IDs this asset connects to

    @classmethod
    def from_asset(cls, asset: Asset) -> NormalizedAsset:
        """Create normalized asset from model."""
        return cls(
            id=asset.id,
            name=asset.name,
            type=asset.type,
            description=asset.description,
            sensitivity_level=asset.sensitivity_level,
            data_classification=asset.data_classification,
            tags=[],
            connected_assets=[]
        )


@dataclass
class NormalizedEntryPoint:
    """Normalized entry point representation."""
    id: str
    name: str
    type: str
    description: str
    authentication_required: bool
    exposed_to_internet: bool
    connected_assets: List[str]  # Asset IDs this entry point accesses
    risk_level: str

    @classmethod
    def from_entry_point(cls, ep: EntryPoint) -> NormalizedEntryPoint:
        """Create normalized entry point from model."""
        return cls(
            id=ep.id,
            name=ep.name,
            type=ep.type,
            description=ep.description,
            authentication_required=ep.authentication_required,
            exposed_to_internet=ep.exposed_to_internet,
            connected_assets=[],
            risk_level="High" if ep.exposed_to_internet and not ep.authentication_required else "Medium"
        )


@dataclass
class NormalizedTrustBoundary:
    """Normalized trust boundary representation."""
    id: str
    name: str
    type: str
    description: str
    source_zone: str
    target_zone: str
    crossing_assets: List[str]  # Asset IDs that cross this boundary
    risk_level: str

    @classmethod
    def from_trust_boundary(cls, tb: TrustBoundary) -> NormalizedTrustBoundary:
        """Create normalized trust boundary from model."""
        return cls(
            id=tb.id,
            name=tb.name,
            type=tb.type,
            description=tb.description,
            source_zone=tb.source_zone,
            target_zone=tb.target_zone,
            crossing_assets=[],
            risk_level="High" if tb.type == "Network" else "Medium"
        )


@dataclass
class NormalizedDataFlow:
    """Normalized data flow representation."""
    id: str
    name: str
    source_asset_id: str
    destination_asset_id: str
    data_type: str
    encryption: bool
    authentication: bool
    volume: str  # "Low", "Medium", "High"
    sensitivity: str

    @classmethod
    def from_data_flow(cls, df: DataFlow) -> NormalizedDataFlow:
        """Create normalized data flow from model."""
        return cls(
            id=df.id,
            name=df.name,
            source_asset_id=df.source,
            destination_asset_id=df.destination,
            data_type=df.data_type,
            encryption=df.encryption,
            authentication=df.authentication,
            volume="Medium",  # Default, could be enhanced
            sensitivity="Medium"  # Default, could be enhanced
        )


@dataclass
class NormalizedThreat:
    """Normalized threat representation with enhanced metadata."""
    id: str
    title: str
    description: str
    stride_category: STRIDECategory
    risk_level: str
    priority_score: int
    affected_assets: List[str]
    entry_points: List[str]
    trust_boundaries: List[str]
    capec_id: Optional[str]
    asvs_controls: List[str]
    mitigation_suggestions: List[str]
    status: str
    llm_summary: Optional[str]

    @classmethod
    def from_threat_item(cls, threat: ThreatItem) -> NormalizedThreat:
        """Create normalized threat from model."""
        return cls(
            id=threat.id,
            title=threat.title,
            description=threat.description,
            stride_category=threat.stride_category or STRIDECategory.SPOOFING,
            risk_level=threat.risk,
            priority_score=threat.priority_score,
            affected_assets=threat.affected_assets,
            entry_points=threat.entry_points,
            trust_boundaries=threat.trust_boundaries,
            capec_id=threat.capec_id,
            asvs_controls=threat.asvs_controls,
            mitigation_suggestions=[threat.mitigation],
            status=threat.status,
            llm_summary=threat.llm_summary
        )


@dataclass
class NormalizedMitigation:
    """Normalized mitigation representation."""
    id: str
    threat_id: str
    title: str
    description: str
    priority: str
    estimated_effort: str
    estimated_cost: str
    implementation_status: str
    assigned_to: Optional[str]
    due_date: Optional[datetime]

    @classmethod
    def from_mitigation(cls, mitigation: Mitigation) -> NormalizedMitigation:
        """Create normalized mitigation from model."""
        return cls(
            id=mitigation.id,
            threat_id=mitigation.threat_id,
            title=mitigation.title,
            description=mitigation.description,
            priority=mitigation.priority,
            estimated_effort=mitigation.estimated_effort,
            estimated_cost=mitigation.estimated_cost,
            implementation_status=mitigation.implementation_status,
            assigned_to=mitigation.assigned_to,
            due_date=mitigation.due_date
        )


class ThreatModelNormalizer:
    """Normalizes threat modeling inputs into standardized format."""

    @staticmethod
    def normalize_architecture(dfd: Optional[ArchitectureDiagram]) -> NormalizedArchitecture:
        """Normalize architecture diagram."""
        if not dfd:
            return NormalizedArchitecture([], [], [], [])

        assets = [NormalizedAsset.from_asset(a) for a in dfd.assets]
        entry_points = [NormalizedEntryPoint.from_entry_point(ep) for ep in dfd.entry_points]
        trust_boundaries = [NormalizedTrustBoundary.from_trust_boundary(tb) for tb in dfd.trust_boundaries]
        data_flows = [NormalizedDataFlow.from_data_flow(df) for df in dfd.data_flows]

        # Build connections
        for df in data_flows:
            if df.source_asset_id not in [a.id for a in assets]:
                continue
            if df.destination_asset_id not in [a.id for a in assets]:
                continue

            # Add to asset connections
            source_asset = next((a for a in assets if a.id == df.source_asset_id), None)
            dest_asset = next((a for a in assets if a.id == df.destination_asset_id), None)

            if source_asset and dest_asset:
                if dest_asset.id not in source_asset.connected_assets:
                    source_asset.connected_assets.append(dest_asset.id)

        return NormalizedArchitecture(assets, entry_points, trust_boundaries, data_flows)

    @staticmethod
    def normalize_threats(threats: List[ThreatItem]) -> List[NormalizedThreat]:
        """Normalize threat items."""
        return [NormalizedThreat.from_threat_item(t) for t in threats]

    @staticmethod
    def normalize_mitigations(mitigations: List[Mitigation]) -> List[NormalizedMitigation]:
        """Normalize mitigation items."""
        return [NormalizedMitigation.from_mitigation(m) for m in mitigations]
