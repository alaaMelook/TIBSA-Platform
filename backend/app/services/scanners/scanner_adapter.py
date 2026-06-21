"""
Scanner Adapter.
Adapts the existing PentestOrchestrator scanner output formats.
"""
from typing import Dict, Any, List, Optional
from app.services.pentest import PentestOrchestrator
from app.services.pentest.models import ScanConfig

class ScannerAdapter:
    @staticmethod
    async def run_scan(
        target: str,
        tests: List[str],
        mode: str = "safe",
        enable_sqlmap: bool = False,
        auth_browser_analysis: bool = False,
        authorized_auth_mode: bool = False,
        auth_lifecycle_checks: bool = False,
        authz_transition_checks: bool = False,
        session_cookie: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Invokes the existing PentestOrchestrator scan pipeline.
        Returns the raw results dictionary containing findings, assets, technologies, and logs.
        """
        import logging
        logger = logging.getLogger(__name__)

        # Check target against system blocklist
        try:
            from app.dependencies import get_supabase
            supabase = get_supabase()
            block_res = supabase.table("system_blocklist").select("indicator").execute()
            blocked_targets = [item.get("indicator") for item in (block_res.data or [])]
            for blocked in blocked_targets:
                if blocked and blocked.lower() in target.lower():
                    raise Exception(f"Scan aborted: Target '{target}' matches blocklisted indicator '{blocked}'.")
        except Exception as e:
            if "Scan aborted" in str(e):
                raise e
            logger.error(f"Error checking blocklist: {e}")

        config = ScanConfig(
            target=target,
            tests=tests,
            mode=mode,
            enable_sqlmap=enable_sqlmap,
            auth_browser_analysis=auth_browser_analysis,
            authorized_auth_mode=authorized_auth_mode,
            auth_lifecycle_checks=auth_lifecycle_checks,
            authz_transition_checks=authz_transition_checks,
            session_cookie=session_cookie,
        )
        orchestrator = PentestOrchestrator(config=config)
        # Execute the scan on the target URL
        raw_result = await orchestrator.scan(target, tests, mode=mode, investigation_id=investigation_id)
        
        # Build normalized output contract robustly
        normalized_output = {}
        
        # 1. Extract findings (checking top level, then nested scanner_json)
        findings = []
        if isinstance(raw_result, dict):
            if isinstance(raw_result.get("findings"), list):
                findings = raw_result["findings"]
            elif "scanner_json" in raw_result and isinstance(raw_result["scanner_json"].get("findings"), list):
                findings = raw_result["scanner_json"]["findings"]
                
        normalized_output["findings"] = findings
        
        # 2. Extract detected technologies
        detected_techs = []
        if isinstance(raw_result, dict):
            if isinstance(raw_result.get("detected_technologies"), list):
                detected_techs = raw_result["detected_technologies"]
            elif "scanner_json" in raw_result and isinstance(raw_result["scanner_json"].get("detected_technologies"), list):
                detected_techs = raw_result["scanner_json"]["detected_technologies"]
                
        normalized_output["detected_technologies"] = detected_techs
        
        # 3. Extract detected assets
        detected_assets = []
        if isinstance(raw_result, dict):
            if isinstance(raw_result.get("detected_assets"), list):
                detected_assets = raw_result["detected_assets"]
            elif "scanner_json" in raw_result and isinstance(raw_result["scanner_json"].get("detected_assets"), list):
                detected_assets = raw_result["scanner_json"]["detected_assets"]
                
        normalized_output["detected_assets"] = detected_assets
        
        # 4. Extract risk score
        risk_score = 0.0
        if isinstance(raw_result, dict):
            risk_score = raw_result.get("risk_score") or raw_result.get("scanner_json", {}).get("risk_score") or 0.0
            
        normalized_output["risk_score"] = float(risk_score)
        
        # 5. Preserve other keys for backward compatibility
        if isinstance(raw_result, dict):
            for k, v in raw_result.items():
                if k not in normalized_output:
                    normalized_output[k] = v
                    
        return normalized_output
