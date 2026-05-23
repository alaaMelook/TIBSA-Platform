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
    def normalize(raw_finding: Dict[str, Any], default_url: str = "", include_ti: bool = True) -> FindingBase:
        """
        Takes raw dictionary finding from any scanner and normalizes it.
        """
        # Title normalization
        title = raw_finding.get("title", "Unknown Finding").strip()
        
        # Unique finding_id slugification if not present
        finding_id = raw_finding.get("finding_id")
        if not finding_id:
            finding_id = re.sub(r'[^a-z0-9]+', '_', title.lower()).strip('_')
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
        affected_url = raw_finding.get("url") or raw_finding.get("affected_url") or default_url or "unknown"
        
        # Evidence serialization
        raw_evidence = raw_finding.get("evidence") or raw_finding.get("details") or ""
        if isinstance(raw_evidence, (dict, list)):
            try:
                evidence = json.dumps(raw_evidence)
            except Exception:
                evidence = str(raw_evidence)
        else:
            evidence = str(raw_evidence)
            
        # Tags normalization
        tags = raw_finding.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        elif not isinstance(tags, list):
            tags = []
            
        # Append categorization tag if not present
        cat_tag = category.lower().replace(" ", "-")
        if cat_tag not in tags:
            tags.append(cat_tag)
            
        return FindingBase(
            finding_id=finding_id,
            title=title,
            severity=severity,
            category=category,
            affected_url=affected_url,
            evidence=evidence,
            tags=tags
        )
