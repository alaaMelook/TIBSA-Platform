"""
Finding Normalizer service.
Translates varying raw scanner findings into a unified data structure.
"""
import re
import json
from typing import Dict, Any, List
from app.schemas.finding import FindingBase
from app.services.translators.severity_mapper import map_severity
from app.services.threat_context.context_interpreter import interpret_context

class FindingNormalizer:
    @staticmethod
    def normalize_url(url: str) -> str:
        """
        Consistently normalizes a URL by:
        - Lowercasing the hostname
        - Removing trailing slash
        - Sorting query parameters alphabetically
        """
        if not url:
            return ""
        from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower() if parsed.scheme else "http"
            netloc = parsed.netloc.lower()
            path = parsed.path
            if path.endswith("/"):
                path = path[:-1]
            if parsed.query:
                q_params = parse_qsl(parsed.query, keep_blank_values=True)
                q_params.sort(key=lambda x: x[0])
                query = urlencode(q_params)
            else:
                query = ""
            return urlunparse((scheme, netloc, path, parsed.params, query, parsed.fragment))
        except Exception:
            val = url.strip().lower()
            if val.endswith("/"):
                val = val[:-1]
            return val

    @staticmethod
    def is_passive_finding(title_lower: str, url: str) -> bool:
        """
        Determines if a finding is passive/noisy.
        """
        if any(kw in title_lower for kw in ["potential", "candidate", "heuristic", "mapped"]):
            return True

        # Active exploit categories should never be treated as passive routes/hardening findings
        is_active_exploit = any(kw in title_lower for kw in [
            "xss", "cross-site scripting", "sqli", "sql injection", "injection", 
            "command execution", "rce", "auth bypass", "authentication bypass",
            "idor", "bac", "broken access", "privilege escalation"
        ])
        if is_active_exploit:
            return False

        # 1. Missing headers
        is_missing_header = ("missing" in title_lower or "weak" in title_lower or "clickjack" in title_lower) and any(
            kw in title_lower for kw in [
                "header", "csp", "hsts", "x-frame", "cookie", "cache",
                "content-security-policy", "content security policy",
                "strict-transport-security", "transport-security", "x-content-type-options",
                "x-xss-protection", "referrer-policy"
            ]
        )
        if is_missing_header:
            return True
            
        # 2. robots.txt / sitemap.xml
        if "robots.txt" in title_lower or "sitemap.xml" in title_lower or "robots.txt" in url.lower() or "sitemap.xml" in url.lower():
            return True
            
        # 3. Cache observations
        if "cache" in title_lower or "caching" in title_lower:
            return True
            
        # 4. Generic admin/protected routes without verified auth weakness
        is_generic_path = any(kw in title_lower for kw in ["route", "path", "directory", "exposed file", "sensitive endpoint", "discovery"]) or any(
            f"/{kw}" in url.lower() for kw in ["admin", "login", "config", "backup"]
        )
        has_auth_weakness = any(kw in title_lower for kw in ["bypass", "brute", "unauthorized", "leak", "vulnerability", "weakness"])
        if is_generic_path and not has_auth_weakness:
            return True
            
        return False

    @staticmethod
    def filter_noise(raw_findings: List[Dict[str, Any]], default_url: str = "") -> List[Dict[str, Any]]:
        """
        Groups repeated passive findings on the same host, demotes
        generic /admin or path discovery findings without validated authn/authz issues
        to informational, and demotes crawler assumptions to heuristic.
        """
        from urllib.parse import urlparse
        grouped: Dict[tuple, Dict[str, Any]] = {}
        filtered: List[Dict[str, Any]] = []

        for f in raw_findings:
            title = f.get("title", "Unknown Finding").strip()
            title_lower = title.lower()
            
            # Determine host
            url_val = f.get("url") or f.get("affected_url") or default_url or ""
            host = ""
            if url_val:
                try:
                    host = urlparse(url_val).netloc.split(":")[0]
                except Exception:
                    pass

            is_passive = FindingNormalizer.is_passive_finding(title_lower, url_val)
            if is_passive:
                # Group by host and normalized title
                key = (host, title_lower)
                if key in grouped:
                    existing = grouped[key]
                    ev = str(existing.get("evidence") or existing.get("details") or "")
                    if url_val and url_val not in ev:
                        existing["evidence"] = ev + f"\nAlso observed at: {url_val}"
                    continue
                else:
                    grouped[key] = f
                    filtered.append(f)
            else:
                filtered.append(f)
        return filtered

    @staticmethod
    def normalize(raw_finding: Dict[str, Any], default_url: str = "", include_ti: bool = True) -> FindingBase:
        """
        Takes raw dictionary finding from any scanner and normalizes it.
        """
        # Title normalization
        title = raw_finding.get("title", "Unknown Finding").strip()
        title_lower = title.lower()
        
        # Unique finding_id slugification if not present
        finding_id = raw_finding.get("finding_id")
        if not finding_id:
            finding_id = re.sub(r'[^a-z0-9]+', '_', title_lower).strip('_')
            if not finding_id:
                finding_id = "generic_finding"
                
        # Severity mapping
        raw_sev = raw_finding.get("severity") or raw_finding.get("sev") or "info"
        severity = map_severity(str(raw_sev))
        
        # Category interpretation
        raw_cat = raw_finding.get("classification") or raw_finding.get("category") or raw_finding.get("type") or "Informational"
        if include_ti:
            category = interpret_context(title, str(raw_cat))
        else:
            category = str(raw_cat)
        
        # URL normalization
        raw_url = raw_finding.get("url") or raw_finding.get("affected_url") or default_url or "unknown"
        affected_url = FindingNormalizer.normalize_url(raw_url)
        
        # Evidence serialization
        raw_evidence = raw_finding.get("evidence") or raw_finding.get("details") or ""
        if isinstance(raw_evidence, (dict, list)):
            try:
                evidence = json.dumps(raw_evidence)
            except Exception:
                evidence = str(raw_evidence)
        else:
            evidence = str(raw_evidence)
            
        evidence_lower = evidence.lower()
        
        # Determine confidence and apply safe defaults / downgrades
        confidence = "probable"
        raw_confidence = str(raw_finding.get("confidence") or "").lower().strip()
        raw_verified = raw_finding.get("verified")
        
        if (
            raw_verified is True or
            raw_confidence in ("verified", "confirmed", "high") or
            "confirmed" in evidence_lower or
            "alert(" in evidence_lower or
            "database error" in evidence_lower or
            "sqli" in title_lower or
            "sql injection" in title_lower or
            "xss" in title_lower or
            "cross-site scripting" in title_lower or
            "ssrf" in title_lower or
            "server-side request forgery" in title_lower or
            "auth bypass" in title_lower or
            "authentication bypass" in title_lower or
            "privilege escalation" in title_lower
        ):
            confidence = "confirmed"
        elif severity == "info":
            confidence = "informational"
            
        is_passive = False
        if "auth boundary" in title_lower or "authentication boundary" in title_lower or "login boundary" in title_lower:
            confidence = "informational"
            severity = "info"
        elif "robots.txt" in title_lower or "sitemap.xml" in title_lower:
            confidence = "heuristic"
            is_passive = True
        elif "potential protected route" in title_lower or "protected route" in title_lower:
            confidence = "heuristic"
            is_passive = True
        else:
            is_passive = FindingNormalizer.is_passive_finding(title_lower, affected_url)
            if is_passive:
                confidence = "heuristic"

        # Explicitly downgrade confidence to heuristic if the title contains potential, candidate, heuristic, or mapped
        if any(kw in title_lower for kw in ["potential", "candidate", "heuristic", "mapped"]):
            confidence = "heuristic"
            is_passive = True
            
        # Apply automatic severity downgrade if confidence is heuristic
        if confidence == "heuristic":
            if severity == "critical":
                severity = "high"
            elif severity == "high":
                severity = "medium"
            elif severity == "medium":
                severity = "low"
            elif severity == "low":
                severity = "info"
                
            if not title_lower.startswith("potential"):
                title = "Potential " + title
                title_lower = title.lower()
                
        # Apply passive/noisy severity caps after heuristic downgrade
        if is_passive or "robots.txt" in title_lower or "sitemap.xml" in title_lower or "protected route" in title_lower:
            if severity not in ["low", "info"]:
                severity = "low"
                
        # Determine exploitability score dynamically
        exploitability_score = 0.0
        if is_passive or "robots.txt" in title_lower or "sitemap.xml" in title_lower:
            exploitability_score = 0.1
        elif any(kw in title_lower for kw in ["cookie", "cache", "session"]):
            exploitability_score = 2.0
        elif "xss" in title_lower or "cross-site scripting" in title_lower:
            exploitability_score = 8.0
        elif any(kw in title_lower or kw in category.lower() for kw in ["sqli", "sql injection", "injection", "auth bypass", "authentication bypass", "idor", "bac", "broken access", "rce", "command execution"]):
            exploitability_score = 10.0
        else:
            # Fallback based on severity
            if severity == "critical":
                exploitability_score = 9.0
            elif severity == "high":
                exploitability_score = 7.0
            elif severity == "medium":
                exploitability_score = 4.0
            elif severity == "low":
                exploitability_score = 1.0
            else:
                exploitability_score = 0.1
            
        # Tags normalization
        tags = raw_finding.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        elif not isinstance(tags, list):
            tags = []
            
        cat_tag = category.lower().replace(" ", "-")
        if cat_tag not in tags:
            tags.append(cat_tag)

        # Centralized Trusted Provider Registry demotions
        from app.services.pentest.utils import is_globally_trusted
        if is_globally_trusted(affected_url):
            is_discovery_probe = any(kw in title_lower for kw in [
                "backup", "exposed", "directory", "listing", "discovery", "path", "route", "robots.txt", "sitemap"
            ])
            if is_discovery_probe:
                is_verified = ("confirmed" in evidence_lower or "alert(" in evidence_lower or "database error" in evidence_lower)
            else:
                is_verified = (
                    (raw_finding.get("verified") is True) or
                    (raw_finding.get("confidence") in ("verified", "confirmed", "high")) or
                    ("confirmed" in evidence_lower or "alert(" in evidence_lower or "database error" in evidence_lower)
                )
            if not is_verified:
                if confidence in ("confirmed", "probable"):
                    confidence = "heuristic"
                    severity = "low"
                    if not title_lower.startswith("potential"):
                        title = "Potential " + title
                        title_lower = title.lower()
                elif confidence in ("heuristic", "informational"):
                    confidence = "informational"
                    severity = "info"
                    category = "Informational"
            
        return FindingBase(
            finding_id=finding_id,
            title=title,
            severity=severity,
            category=category,
            affected_url=affected_url,
            evidence=evidence,
            tags=tags,
            confidence=confidence,
            exploitability_score=exploitability_score
        )
