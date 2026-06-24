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
        api_key_present = bool(self.api_key)
        
        if not api_key_present:
            logger.info(f"""
[VIRUSTOTAL PROVIDER]
indicator = {indicator}
api_key_present = false
mode = not_configured
malicious = 0
suspicious = 0
status = not_configured
error = VirusTotal API key is not configured
""")
            return {
                "found": False,
                "available": False,
                "provider": "virustotal",
                "status": "not_configured",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_engines": 0,
                "error": "VirusTotal API key is not configured"
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
                    err_msg = f"Unsupported type: {type_}"
                    logger.info(f"""
[VIRUSTOTAL PROVIDER]
indicator = {indicator}
api_key_present = true
mode = api_error
malicious = 0
suspicious = 0
status = api_error
error = {err_msg}
""")
                    return {"found": False, "available": False, "provider": "virustotal", "status": "api_error", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total_engines": 0, "error": err_msg}

                r = await client.get(url, headers=self.headers)
                if r.status_code == 404:
                    logger.info(f"""
[VIRUSTOTAL PROVIDER]
indicator = {indicator}
api_key_present = true
mode = real_api
malicious = 0
suspicious = 0
status = not_found
error = 
""")
                    return {"found": False, "available": True, "provider": "virustotal", "status": "not_found", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total_engines": 0}
                r.raise_for_status()
                
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total_engines = sum(stats.values())
                
                logger.info(f"""
[VIRUSTOTAL PROVIDER]
indicator = {indicator}
api_key_present = true
mode = real_api
malicious = {malicious}
suspicious = {suspicious}
status = completed
error = 
""")
                
                return {
                    "found": True,
                    "available": True,
                    "provider": "virustotal",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total_engines,
                    "status": "completed",
                    "threat_level": "high" if (malicious + suspicious) > 3 else ("medium" if (malicious + suspicious) > 0 else "clean")
                }
            except Exception as e:
                logger.info(f"""
[VIRUSTOTAL PROVIDER]
indicator = {indicator}
api_key_present = true
mode = api_error
malicious = 0
suspicious = 0
status = api_error
error = {str(e)}
""")
                logger.error(f"[VT-PROVIDER] Error querying {indicator}: {e}")
                return {
                  "found": False,
                  "available": False,
                  "provider": "virustotal",
                  "status": "api_error",
                  "malicious": 0,
                  "suspicious": 0,
                  "harmless": 0,
                  "undetected": 0,
                  "total_engines": 0,
                  "error": str(e)
                }

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
    VirusTotal is the ONLY source allowed to decide reputation, score, and threat status.
    AlienVault OTX is enrichment/context only and never affects scoring or status.
    """
    @staticmethod
    def aggregate(indicator: str, type_: str, vt_res: dict, otx_res: dict) -> dict:
        vt_found = vt_res.get("found", False)
        vt_status = vt_res.get("status")
        vt_malicious = vt_res.get("malicious", 0)
        vt_suspicious = vt_res.get("suspicious", 0)
        vt_total = vt_res.get("total_engines", 0)
        
        pulses = otx_res.get("pulses", [])
        pulse_count = len(pulses)
        otx_found = otx_res.get("found", False)

        # 1. Source label rules (for display only)
        if vt_status in ("not_configured", "api_error"):
            source = "VirusTotal unavailable"
        elif vt_found and otx_found and pulse_count > 0:
            source = "VirusTotal + OTX Context"
        else:
            source = "VirusTotal"

        # 2. VirusTotal ONLY scoring rules
        if vt_status in ("not_configured", "api_error"):
            threat_level = "unknown"
            flagged = False
            reputation_score = 0
            risk_reason = f"VirusTotal is unavailable: {vt_res.get('error', 'unknown error')}"
            severity = "info"
        elif not vt_found:
            threat_level = "unknown"
            flagged = False
            reputation_score = 10
            risk_reason = "VirusTotal has no reputation data for this host."
            severity = "info"
        elif vt_malicious == 0 and vt_suspicious == 0:
            threat_level = "clean"
            flagged = False
            reputation_score = 10
            risk_reason = "VirusTotal analysis clean (0 malicious, 0 suspicious engines)."
            severity = "info"
        elif vt_malicious == 0 and vt_suspicious > 0:
            threat_level = "suspicious"
            flagged = True
            # reputation_score between 30 and 50
            reputation_score = min(50, 30 + vt_suspicious * 5)
            risk_reason = f"VirusTotal: 0 malicious but {vt_suspicious} suspicious engines flagged."
            severity = "medium"
        elif vt_malicious == 1:
            threat_level = "suspicious"
            flagged = True
            # reputation_score between 50 and 60
            reputation_score = 55
            risk_reason = "VirusTotal: 1 security engine flagged malicious."
            severity = "medium"
        else:  # vt_malicious >= 2
            threat_level = "malicious"
            flagged = True
            # reputation_score between 70 and 100
            reputation_score = min(100, 70 + vt_malicious * 5)
            risk_reason = f"VirusTotal: {vt_malicious}/{vt_total} engines flagged malicious."
            severity = "high" if reputation_score < 90 else "critical"

        # Recommended action based on threat_level
        if threat_level == "malicious":
            recommended_action = "Block resource load at proxy level and review local system assets."
        elif threat_level == "suspicious":
            recommended_action = "Monitor host network connections. No immediate block required."
        else:
            recommended_action = "No action required. Resource appears benign."

        # OTX pulses and tags as context only
        pulse_names = [p.get("name", "Unknown Pulse") for p in pulses]
        threat_tags = []
        campaign_context = []
        malware_families = []
        
        for p in pulses:
            threat_tags.extend(p.get("tags", []))
            desc = p.get("description", "").lower()
            if "campaign" in desc or p.get("name", "").endswith("Campaign"):
                campaign_context.append(p.get("name"))
            malware_families.extend(p.get("malware_families", []))
        
        threat_tags = list(set(threat_tags))
        campaign_context = list(set(campaign_context))
        malware_families = list(set(malware_families))

        # Confidence level mapping based on reputation_score
        if threat_level == "clean" or threat_level == "unknown":
            confidence_level = "low"
        elif reputation_score >= 70:
            confidence_level = "high"
        else:
            confidence_level = "medium"

        return {
            "ioc": indicator,
            "type": type_,
            "source": source,
            "vt_score": vt_malicious,
            "vt_status": threat_level,
            "vt_malicious": vt_malicious,
            "vt_suspicious": vt_suspicious,
            "otx_pulses": pulse_names,
            "otx_pulse_count": pulse_count,
            "threat_tags": threat_tags,
            "campaign_context": campaign_context,
            "related_malware_families": malware_families,
            "confidence_level": confidence_level,
            "confidence_score": reputation_score,
            "risk_reason": risk_reason,
            "recommended_action": recommended_action,
            "severity": severity,
            "flagged": flagged,
            "threat_level": threat_level
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
            
            return IntelAggregator.aggregate(indicator, type_, vt_res, otx_res)
        except Exception as e:
            logger.warning(f"[TI-SERVICE] Lookup failed for {indicator}: {e}")
            vt_res = {"found": False, "available": False, "status": "api_error", "error": str(e), "malicious": 0, "suspicious": 0, "total_engines": 0}
            otx_res = {"found": False, "pulses": []}
            return IntelAggregator.aggregate(indicator, type_, vt_res, otx_res)
