import base64
import logging
import asyncio
import httpx
from typing import Dict, Any, List, Optional
from app.config import settings
from app.schemas.investigation import TIFinding
from app.schemas.finding import FindingBase

logger = logging.getLogger(__name__)

class VirusTotalProvider:
    """
    Provider for querying VirusTotal reputation details (IPs, domains, URLs).
    Includes demo-mode mocks and failure safety.
    """
    def __init__(self):
        self.api_key = settings.virustotal_api_key
        self.demo_mode = settings.demo_mode
        self.headers = {"x-apikey": self.api_key}

    async def lookup(self, indicator: str, type_: str) -> dict:
        if self.demo_mode or not self.api_key:
            # Generate realistic mock VT data
            is_bad = len(indicator) % 7 == 0
            malicious = 12 if is_bad else 0
            suspicious = 2 if is_bad else 0
            return {
                "found": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": 72,
                "status": "completed",
                "threat_level": "high" if is_bad else "clean"
            }

        async with httpx.AsyncClient(timeout=15, http2=False) as client:
            try:
                if type_ == "ip":
                    url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
                elif type_ == "domain":
                    url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
                elif type_ in ["url", "js_resource"]:
                    url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
                    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                else:
                    return {"found": False, "malicious": 0, "suspicious": 0, "total_engines": 0}

                r = await client.get(url, headers=self.headers)
                if r.status_code == 404:
                    return {"found": False, "malicious": 0, "suspicious": 0, "total_engines": 0}
                r.raise_for_status()
                
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                return {
                    "found": True,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total_engines": sum(stats.values()),
                    "status": "completed",
                    "threat_level": "high" if (malicious + suspicious) > 3 else ("medium" if (malicious + suspicious) > 0 else "clean")
                }
            except Exception as e:
                logger.error(f"[VT-PROVIDER] Error querying {indicator}: {e}")
                return {"found": False, "malicious": 0, "suspicious": 0, "total_engines": 0, "error": str(e)}

class OTXProvider:
    """
    Provider for querying AlienVault OTX context details (IPs, domains, URLs).
    Extracts pulses, campaigns, targeted countries, and tags.
    """
    def __init__(self):
        self.api_key = settings.otx_api_key
        self.demo_mode = settings.demo_mode
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}

    async def lookup(self, indicator: str, type_: str) -> dict:
        if self.demo_mode or not self.api_key:
            # Generate realistic mock OTX data
            is_bad = len(indicator) % 7 == 0
            if is_bad:
                pulses = [
                    {
                        "name": "Credential Harvesting Campaign",
                        "description": "Phishing campaign targeting financial organizations",
                        "tags": ["phishing", "credential-theft", "banking"],
                        "malware_families": ["RedLine Stealer"],
                        "targeted_countries": ["US", "GB", "DE"]
                    },
                    {
                        "name": "CozyBear Infrastructure Lookup",
                        "description": "Indicators associated with CozyBear activity group",
                        "tags": ["apt29", "cozybear", "espionage"],
                        "malware_families": ["WellMess"],
                        "targeted_countries": ["UA", "US"]
                    }
                ]
            else:
                pulses = []

            return {
                "found": True,
                "pulses": pulses,
                "pulse_count": len(pulses)
            }

        # Map type to OTX types
        otx_type = None
        if type_ == "ip":
            otx_type = "IPv4"
        elif type_ == "domain":
            otx_type = "domain"
        elif type_ in ["url", "js_resource"]:
            otx_type = "url"

        if not otx_type:
            return {"found": False, "pulses": [], "pulse_count": 0}

        async with httpx.AsyncClient(timeout=15, http2=False) as client:
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general"
                r = await client.get(url, headers=self.headers)
                if r.status_code == 404:
                    return {"found": False, "pulses": [], "pulse_count": 0}
                r.raise_for_status()
                
                res = r.json()
                pulse_info = res.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                
                parsed_pulses = []
                for p in pulses:
                    parsed_pulses.append({
                        "name": p.get("name", "Unknown Pulse"),
                        "description": p.get("description", ""),
                        "tags": p.get("tags", []),
                        "malware_families": [m.get("name") for m in p.get("malware_families", []) if m.get("name")] if isinstance(p.get("malware_families"), list) else [],
                        "targeted_countries": p.get("targeted_countries", [])
                    })

                return {
                    "found": True,
                    "pulses": parsed_pulses,
                    "pulse_count": len(parsed_pulses)
                }
            except Exception as e:
                logger.error(f"[OTX-PROVIDER] Error querying {indicator}: {e}")
                return {"found": False, "pulses": [], "pulse_count": 0, "error": str(e)}

class IntelAggregator:
    """
    Aggregates and normalizes VirusTotal & AlienVault OTX lookups.
    Computes a unified confidence_score (0-100) and extracts malware, tags, campaigns.
    """
    @staticmethod
    def aggregate(indicator: str, type_: str, vt_res: dict, otx_res: dict) -> dict:
        vt_malicious = vt_res.get("malicious", 0)
        vt_total = vt_res.get("total_engines", 0)
        pulses = otx_res.get("pulses", [])
        pulse_count = len(pulses)

        # 1. Realistic Threat Intelligence Enforcement thresholds:
        # - domain/JS asset is malicious ONLY IF VT malicious detections >= 3 AND OTX pulse count >= 1
        is_real_threat = vt_malicious >= 3 and pulse_count >= 1

        if is_real_threat:
            vt_status = "malicious"
            confidence_score = min(100, 90 + vt_malicious)
            severity = "high" if confidence_score < 95 else "critical"
        elif vt_malicious >= 1 or pulse_count >= 1:
            vt_status = "suspicious"
            confidence_score = min(75, 45 + vt_malicious + pulse_count)
            severity = "medium"
        else:
            vt_status = "clean"
            confidence_score = 10
            severity = "info"

        # Extract details only if threshold is met, otherwise scrub malicious details
        pulse_names = []
        threat_tags = []
        campaign_context = []
        malware_families = []
        
        if vt_status == "malicious":
            pulse_names = [p["name"] for p in pulses]
            for p in pulses:
                threat_tags.extend(p.get("tags", []))
                if "campaign" in p.get("description", "").lower() or p.get("name").endswith("Campaign"):
                    campaign_context.append(p["name"])
                malware_families.extend(p.get("malware_families", []))
        elif vt_status == "suspicious":
            # For suspicious, we only extract generic indicators and avoid aggressive campaigns/malware naming
            pulse_names = [p["name"] for p in pulses]
            for p in pulses:
                for tag in p.get("tags", []):
                    # Filter out malware/attacker tags
                    if not any(w in tag.lower() for w in ["malware", "apt", "campaign", "attacker", "stealer", "ransomware"]):
                        threat_tags.append(tag)
        
        threat_tags = list(set(threat_tags))
        campaign_context = list(set(campaign_context))
        malware_families = list(set(malware_families))

        # Risk explanation and recommended action
        if vt_status == "malicious":
            risk_reason = f"Flagged by {vt_malicious}/{vt_total} security engines on VirusTotal and matching active OTX pulses."
            rec_action = "Block resource load at proxy level and review local system assets."
        elif vt_status == "suspicious":
            risk_reason = "Indicator shows minor suspicious reputation patterns. Classified as suspicious."
            rec_action = "Monitor host network connections. No immediate block required."
        else:
            risk_reason = "clean/no significant reputation"
            rec_action = "No action required. Resource appears benign."

        confidence_levels = {
            10: "low",
            60: "medium",
            75: "high",
            90: "high",
            100: "critical"
        }
        conf_level_label = "low"
        for thresh, label in sorted(confidence_levels.items()):
            if confidence_score >= thresh:
                conf_level_label = label

        # Final check: enforce low confidence label for clean/no-reputation
        if vt_status == "clean":
            conf_level_label = "low"

        return {
            "ioc": indicator,
            "type": type_,
            "vt_score": vt_malicious if vt_status != "clean" else 0,
            "vt_status": vt_status,
            "otx_pulses": pulse_names,
            "threat_tags": threat_tags,
            "campaign_context": campaign_context,
            "related_malware_families": malware_families,
            "confidence_level": conf_level_label,
            "confidence_score": confidence_score,
            "risk_reason": risk_reason,
            "recommended_action": rec_action,
            "severity": severity
        }

class ThreatIntelService:
    """
    Main Threat Intelligence orchestrator.
    Resolves VirusTotal and AlienVault OTX concurrently and aggregates results.
    """
    def __init__(self):
        self.vt = VirusTotalProvider()
        self.otx = OTXProvider()

    async def enrich_ioc(self, indicator: str, type_: str) -> dict:
        try:
            # Run lookup concurrently
            vt_task = self.vt.lookup(indicator, type_)
            otx_task = self.otx.lookup(indicator, type_)
            
            vt_res, otx_res = await asyncio.gather(vt_task, otx_task)
            
            # Check if any provider lookup raised an error internally
            if vt_res.get("error") or otx_res.get("error"):
                return {
                    "ioc": indicator,
                    "type": type_,
                    "vt_score": 0,
                    "vt_status": "unverified",
                    "otx_pulses": [],
                    "threat_tags": [],
                    "campaign_context": [],
                    "related_malware_families": [],
                    "confidence_level": "low",
                    "confidence_score": 10,
                    "risk_reason": "Threat intelligence check encountered an unhandled lookup error.",
                    "recommended_action": "No actions required.",
                    "severity": "info"
                }
            
            return IntelAggregator.aggregate(indicator, type_, vt_res, otx_res)
        except Exception as e:
            logger.warning(f"[TI-SERVICE] Lookup failed for {indicator}: {e}")
            return {
                "ioc": indicator,
                "type": type_,
                "vt_score": 0,
                "vt_status": "unverified",
                "otx_pulses": [],
                "threat_tags": [],
                "campaign_context": [],
                "related_malware_families": [],
                "confidence_level": "low",
                "confidence_score": 10,
                "risk_reason": f"Threat intelligence enrichment failed: {str(e)}",
                "recommended_action": "No actions required.",
                "severity": "info"
            }
