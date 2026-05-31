"""
Graph Builder – builds node/edge graph from collected pipeline data.

Nodes represent: target, resolved IPs, domains (passive DNS),
ASN / ISP, registrar, OTX campaigns, ThreatFox malware families.
Edges represent relationships between nodes.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.schemas.infra_investigation import GraphEdge, GraphNode, InfraGraph


_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _risk_level_from_score(score: float) -> str:
    if score <= 20:
        return "clean"
    elif score <= 40:
        return "low"
    elif score <= 60:
        return "medium"
    elif score <= 80:
        return "high"
    return "critical"


class GraphBuilder:

    def build(
        self,
        target: str,
        target_type: str,
        risk_score: float,
        enrichment: Optional[Dict[str, Any]],
        passive_dns: Optional[Dict[str, Any]],
        reputation: Optional[Dict[str, Any]],
    ) -> InfraGraph:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        seen_node_ids: set = set()
        risk_level = _risk_level_from_score(risk_score)

        def add_node(node: GraphNode) -> None:
            if node.id not in seen_node_ids:
                seen_node_ids.add(node.id)
                nodes.append(node)

        def add_edge(edge: GraphEdge) -> None:
            edges.append(edge)

        # ── Target node ───────────────────────────────────────────────────────
        target_id = f"target:{target}"
        add_node(GraphNode(
            id=target_id,
            label=target,
            type="target",
            risk_level=risk_level,
        ))

        enr = enrichment or {}
        dns_data = enr.get("dns") or {}
        geoip = enr.get("geoip") or {}
        whois = enr.get("whois") or {}

        # ── DNS A/AAAA records → IP nodes ─────────────────────────────────────
        resolved_ips: set = set()
        for record in (dns_data.get("records") or []):
            rtype = record.get("type", "")
            val = record.get("value", "")
            if rtype in ("A", "AAAA") and val:
                resolved_ips.add(val)
                ip_id = f"ip:{val}"
                add_node(GraphNode(
                    id=ip_id,
                    label=val,
                    type="ip",
                    risk_level="medium",  # updated later from abuse data
                ))
                add_edge(GraphEdge(
                    source=target_id,
                    target=ip_id,
                    relationship="resolves_to",
                    confidence="high",
                ))

        # ── GeoIP → ASN node ─────────────────────────────────────────────────
        asn_val = (geoip.get("asn") or "") if isinstance(geoip, dict) else ""
        if asn_val:
            asn_id = f"asn:{asn_val}"
            add_node(GraphNode(
                id=asn_id,
                label=asn_val,
                type="asn",
                risk_level="clean",
                metadata={"country": geoip.get("country"), "org": geoip.get("org")},
            ))
            # Connect each resolved IP to the ASN
            for ip in resolved_ips:
                ip_id = f"ip:{ip}"
                if ip_id in seen_node_ids:
                    add_edge(GraphEdge(
                        source=ip_id,
                        target=asn_id,
                        relationship="belongs_to_asn",
                        confidence="high",
                    ))

        # ── WHOIS → Registrar node ────────────────────────────────────────────
        registrar = (whois.get("registrar") or "") if isinstance(whois, dict) else ""
        if registrar:
            reg_id = f"registrar:{registrar}"
            add_node(GraphNode(
                id=reg_id,
                label=registrar,
                type="registrar",
                risk_level="clean",
            ))
            add_edge(GraphEdge(
                source=target_id,
                target=reg_id,
                relationship="registered_with",
                confidence="high",
            ))

        # ── Passive DNS → historical domain nodes ─────────────────────────────
        pdns = passive_dns or {}
        seen_passive_ips: set = set()
        for entry in (pdns.get("passive_dns") or [])[:20]:
            addr = entry.get("address") or ""
            if addr and addr not in seen_passive_ips and addr not in resolved_ips:
                seen_passive_ips.add(addr)
                ip_id = f"ip:{addr}"
                add_node(GraphNode(
                    id=ip_id,
                    label=addr,
                    type="ip",
                    risk_level="low",
                    metadata={
                        "first_seen": entry.get("first"),
                        "last_seen": entry.get("last"),
                    },
                ))
                add_edge(GraphEdge(
                    source=target_id,
                    target=ip_id,
                    relationship="historically_resolved_to",
                    confidence="medium",
                ))

        # ── OTX → Campaign nodes ──────────────────────────────────────────────
        rep = reputation or {}
        otx = rep.get("otx") or {}
        seen_campaigns: set = set()
        if isinstance(otx, dict):
            for pulse in (otx.get("pulses") or [])[:5]:
                campaign_name = pulse.get("name", "")[:60]
                if not campaign_name or campaign_name in seen_campaigns:
                    continue
                seen_campaigns.add(campaign_name)
                camp_id = f"campaign:{campaign_name}"
                add_node(GraphNode(
                    id=camp_id,
                    label=campaign_name,
                    type="campaign",
                    risk_level="high",
                    metadata={"tags": pulse.get("tags", [])[:5]},
                ))
                add_edge(GraphEdge(
                    source=target_id,
                    target=camp_id,
                    relationship="attributed_to_campaign",
                    confidence="medium",
                ))

        # ── ThreatFox → Malware family nodes ─────────────────────────────────
        threatfox = rep.get("threatfox") or {}
        seen_malware: set = set()
        if isinstance(threatfox, dict):
            for ioc in (threatfox.get("iocs") or [])[:5]:
                mp = ioc.get("malware_printable", "")
                if not mp or mp in seen_malware:
                    continue
                seen_malware.add(mp)
                mal_id = f"malware:{mp}"
                add_node(GraphNode(
                    id=mal_id,
                    label=mp,
                    type="malware",
                    risk_level="critical",
                    metadata={"threat_type": ioc.get("threat_type")},
                ))
                add_edge(GraphEdge(
                    source=target_id,
                    target=mal_id,
                    relationship="distributes_malware",
                    confidence="high",
                ))

        return InfraGraph(nodes=nodes, edges=edges)
