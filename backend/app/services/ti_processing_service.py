from typing import List, Dict, Any
from app.schemas.investigation import TIFinding
from app.schemas.finding import FindingBase

class TIProcessingService:
    """
    Threat Intelligence Processing Layer.
    Consumes normalized findings and applies false-positive reduction,
    confidence scoring, and final risk interpretation.
    """

    @staticmethod
    def process_findings(normalized_findings: List[FindingBase]) -> List[TIFinding]:
        ti_findings: List[TIFinding] = []
        
        # Deduplication dictionaries
        header_findings = {}
        
        for finding in normalized_findings:
            title_lower = finding.title.lower()
            category_lower = finding.category.lower()
            
            # --- False Positive Suppression Layer & Confidence Mapping ---
            conf_val_map = {"confirmed": 0.95, "probable": 0.75, "heuristic": 0.45, "informational": 0.20}
            confidence = conf_val_map.get(finding.confidence, 0.45)
            
            fp_prob = round(1.0 - confidence, 2)
            exploitability = "unknown"
            verification = "unverified"
            risk_multiplier = 1.0
            
            # Map verification based on confidence
            if finding.confidence == "confirmed":
                verification = "confirmed"
                exploitability = "high"
                risk_multiplier = 1.2
            elif finding.confidence == "probable":
                verification = "verified"
                exploitability = "medium"
                risk_multiplier = 1.0
            elif finding.confidence == "heuristic":
                verification = "heuristic"
                exploitability = "low"
                risk_multiplier = 0.5
            else:
                verification = "informational"
                exploitability = "low"
                risk_multiplier = 0.2
            
            # Deduplicate security header and cache header findings
            if "header" in title_lower or "missing" in title_lower or "public cache" in title_lower:
                if title_lower in header_findings:
                    continue
                header_findings[title_lower] = True
                
            # Apply 0.3x modifier for missing headers and cache observations only
            is_passive_header_cache = ("missing" in title_lower or "public cache" in title_lower or "weak cache" in title_lower) and any(
                kw in title_lower for kw in [
                    "header", "csp", "hsts", "x-frame", "cookie", "cache",
                    "content-security-policy", "content security policy",
                    "strict-transport-security", "transport-security", "clickjacking"
                ]
            )
            if is_passive_header_cache:
                risk_multiplier = 0.3
                verification = "heuristic"
                exploitability = "low"
                
            # Reflection-based XSS detection (downgrade unless browser validated)
            if "xss" in title_lower or "cross-site scripting" in title_lower:
                if finding.confidence == "confirmed":
                    confidence = 0.9
                    verification = "confirmed"
                    exploitability = "high"
                    risk_multiplier = 1.5
                else:
                    confidence = 0.4
                    verification = "heuristic"
                    exploitability = "low"
                    risk_multiplier = 0.5
            
            # Determine Risk Score using the new weighted logic:
            # CRITICAL = 40, HIGH = 20, MEDIUM = 8, LOW = 3, INFO = 0.5
            severity_weights = {
                "critical": 40.0,
                "high": 20.0,
                "medium": 8.0,
                "low": 3.0,
                "info": 0.5
            }
            base_score = severity_weights.get(finding.severity.lower(), 0.5)
            
            # Scaled to 0-100 range by multiplying by 2.5
            final_risk_score = round(base_score * 2.5 * confidence * risk_multiplier, 2)
            
            # Build TIFinding
            ti_finding = TIFinding(
                finding_id=finding.finding_id,
                title=finding.title,
                category=finding.category,
                classification="threat_intel",
                severity=finding.severity,
                confidence=confidence,
                false_positive_probability=fp_prob,
                verification_status=verification,
                exploitability=exploitability,
                affected_asset=finding.affected_url,
                risk_score=final_risk_score,
                risk_multiplier=risk_multiplier,
                reputation_context={"source": "Internal Scan", "last_seen": "now"},
                source_modules=["ti_processor"],
                evidence=finding.evidence,
                tags=finding.tags,
                exploitability_score=finding.exploitability_score
            )
            ti_findings.append(ti_finding)
            
        return ti_findings

    @staticmethod
    def calculate_aggregate_risk(findings: List[Any]) -> float:
        """
        Calculate aggregate risk score based on findings, applying strict caps.
        """
        if not findings:
            return 0.0
            
        finding_dicts = []
        for f in findings:
            if hasattr(f, 'model_dump'):
                finding_dicts.append(f.model_dump())
            elif isinstance(f, dict):
                finding_dicts.append(f)
                
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        has_confirmed_exploitability = False
        all_heuristic = True
        scores = []
        
        for f in finding_dicts:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            
            # Check for confirmed exploitability (status must be confirmed/verified)
            ver = str(f.get("verification_status", f.get("confidence", f.get("verification", "")))).lower()
            exp = str(f.get("exploitability", "")).lower()
            if ver in ["confirmed", "verified"] or exp in ["high", "medium"]:
                has_confirmed_exploitability = True
                
            # If any finding is probable/confirmed (not heuristic or informational), it's not all heuristic
            conf = str(f.get("confidence", "heuristic")).lower()
            if conf in ["confirmed", "probable"] or ver in ["confirmed", "verified"]:
                all_heuristic = False
                
            scores.append(float(f.get("risk_score", 0.0)))
            
        base_risk = max(scores) if scores else 0.0
        
        # Apply severity caps
        if severity_counts["critical"] > 0:
            highest_sev = "critical"
        elif severity_counts["high"] > 0:
            highest_sev = "high"
        elif severity_counts["medium"] > 0:
            highest_sev = "medium"
        else:
            highest_sev = "low"
            
        if highest_sev == "low":
            base_risk = min(base_risk, 35.0)
        elif highest_sev == "medium":
            base_risk = min(base_risk, 65.0)
        elif highest_sev == "high":
            base_risk = min(base_risk, 85.0)
            
        # CRITICAL required for 90+
        if highest_sev != "critical":
            base_risk = min(base_risk, 89.0)
            
        # Cap if no confirmed exploitability
        if not has_confirmed_exploitability:
            base_risk = min(base_risk, 85.0)
            
        # Heuristic-only scans cannot exceed 85
        if all_heuristic:
            base_risk = min(base_risk, 85.0)
            
        # Missing headers alone or Exposed files alone MUST NEVER produce Critical risk
        only_headers = True
        only_files = True
        if not finding_dicts:
            only_headers = False
            only_files = False
        for f in finding_dicts:
            title_lower = (f.get("title") or "").lower()
            url_val = f.get("affected_asset", f.get("affected_url", ""))
            from app.services.translators.finding_normalizer import FindingNormalizer
            is_header = ("missing" in title_lower or "weak" in title_lower or "clickjack" in title_lower) and any(
                kw in title_lower for kw in [
                    "header", "csp", "hsts", "x-frame", "cookie", "cache",
                    "content-security-policy", "content security policy",
                    "strict-transport-security", "transport-security"
                ]
            )
            is_exposed_file = "robots.txt" in title_lower or "sitemap.xml" in title_lower or "robots.txt" in url_val.lower() or "sitemap.xml" in url_val.lower()
            if not is_header:
                only_headers = False
            if not is_exposed_file:
                only_files = False
                
        if only_headers or only_files:
            base_risk = min(base_risk, 65.0)
            
        # Determine if there are any active/exploitable vulnerabilities
        has_active_vulnerabilities = False
        has_exploit_capable = False
        has_non_passive = False
        for f in finding_dicts:
            title_lower = (f.get("title") or "").lower()
            cat_lower = (f.get("category") or "").lower()
            sev_lower = (f.get("severity") or "info").lower()
            url_val = f.get("affected_asset", f.get("affected_url", ""))
            
            is_heuristic_title = any(kw in title_lower for kw in ["potential", "candidate", "heuristic"])
            
            from app.services.translators.finding_normalizer import FindingNormalizer
            is_passive = FindingNormalizer.is_passive_finding(title_lower, url_val)
            if not is_passive and not is_heuristic_title:
                has_non_passive = True
                
            # Default fallback based on severity if exploitability_score is missing in dict
            exp_score = float(f.get("exploitability_score") or (4.0 if sev_lower == "medium" else 7.0 if sev_lower == "high" else 9.0 if sev_lower == "critical" else 0.0))
            if sev_lower in ["medium", "high", "critical"] and exp_score >= 3.0 and not is_heuristic_title:
                has_exploit_capable = True
            
            is_real_xss = ("xss" in title_lower or "cross-site scripting" in title_lower) and not any(
                kw in title_lower for kw in [
                    "missing", "weak", "csp", "content-security-policy", "content security policy", "clickjacking"
                ]
            ) and not is_heuristic_title
            is_active_vuln_category = any(kw in cat_lower for kw in ["injection", "authorization", "authentication", "api"]) and not is_heuristic_title
            is_header_or_hardening = any(
                kw in title_lower or kw in cat_lower for kw in [
                    "missing", "header", "csp", "hsts", "x-frame", "cookie", "cache",
                    "clickjacking", "robots.txt", "sitemap.xml", "informational", "hardening"
                ]
            )
            is_high_non_header = (sev_lower in ["medium", "high", "critical"]) and not is_header_or_hardening and not is_heuristic_title
            
            if is_real_xss or is_active_vuln_category or is_high_non_header:
                has_active_vulnerabilities = True
                
        if not has_active_vulnerabilities or not has_exploit_capable or not has_non_passive:
            base_risk = min(base_risk, 35.0)
            
        return min(100.0, round(base_risk, 1))
        return min(100.0, round(base_risk, 1))
