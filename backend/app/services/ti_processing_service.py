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
        hardening_findings = []
        
        for finding in normalized_findings:
            title_lower = finding.title.lower()
            category_lower = finding.category.lower()
            
            # --- False Positive Reduction & Confidence Scoring ---
            confidence = 0.5
            fp_prob = 0.5
            exploitability = "unknown"
            verification = "unverified"
            risk_multiplier = 1.0
            
            # 1. Deduplicate security header findings
            if "header" in title_lower and finding.severity in ["low", "info", "medium"]:
                if title_lower in header_findings:
                    continue
                header_findings[title_lower] = True
            
            # 2. Group hardening findings (or apply suppression)
            if "hardening" in category_lower or finding.severity == "info":
                hardening_findings.append(finding)
                confidence = 0.3
                fp_prob = 0.8
                verification = "heuristic"
                risk_multiplier = 0.1
                # Suppress noisy informational spam by downgrading severity to info
                finding.severity = "info"
            
            # 3. Reflection-based XSS detection (downgrade unless browser validated)
            elif "xss" in title_lower or "cross-site scripting" in title_lower:
                if "confirmed" in (finding.evidence or "").lower() or "alert" in (finding.evidence or "").lower():
                    confidence = 0.9
                    fp_prob = 0.1
                    verification = "confirmed"
                    exploitability = "high"
                    risk_multiplier = 1.5
                else:
                    confidence = 0.4
                    fp_prob = 0.6
                    verification = "heuristic"
                    exploitability = "low"
                    risk_multiplier = 0.5
            
            # 4. Backup file discovery (require content fingerprints)
            elif "backup" in title_lower or "exposed path" in title_lower:
                if "content matches" in (finding.evidence or "").lower():
                    confidence = 0.95
                    fp_prob = 0.05
                    verification = "confirmed"
                    exploitability = "high"
                else:
                    confidence = 0.2
                    fp_prob = 0.9
                    verification = "unverified"
                    exploitability = "low"
                    risk_multiplier = 0.2
                    
            # 5. Technology Fingerprinting (reduce confidence unless multi-indicator)
            elif "technology" in title_lower or "fingerprint" in title_lower:
                confidence = 0.6
                fp_prob = 0.4
                verification = "heuristic"
                risk_multiplier = 0.5

            # 6. Generic 200/soft-404 responses handled by scanner, but if they leak through:
            elif "generic 200" in (finding.evidence or "").lower():
                confidence = 0.1
                fp_prob = 0.95
                verification = "heuristic"
                risk_multiplier = 0.0

            # Default handling for confirmed vulnerabilities (SQLi, etc.)
            else:
                if finding.severity in ["critical", "high"]:
                    confidence = 0.85
                    fp_prob = 0.15
                    verification = "verified"
                    exploitability = "high"
                    risk_multiplier = 1.2
                else:
                    confidence = 0.7
                    fp_prob = 0.3
                    verification = "heuristic"
                    exploitability = "medium"

            # Determine Risk Score
            severity_weights = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.0}
            base_score = severity_weights.get(finding.severity.lower(), 0.0)
            final_risk_score = round(base_score * confidence * risk_multiplier * 10, 2)
            
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
                tags=finding.tags
            )
            ti_findings.append(ti_finding)
            
        return ti_findings
