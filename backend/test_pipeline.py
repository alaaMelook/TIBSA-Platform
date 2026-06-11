import asyncio
import json
from unittest.mock import patch
from app.services.ai.soc_report_service import generate_gemini_report

mock_response = """
{
  "soc_report": {
    "executive_summary": "This is a mocked executive summary.",
    "detection_summary": "Mock detection summary.",
    "final_verdict": "Suspicious",
    "confidence_score": 85,
    "technical_analysis": "Mock technical analysis.",
    "behavioral_analysis": {
      "persistence": ["Mock persistence"],
      "injection": [],
      "execution": ["Mock execution"],
      "network_activity": [],
      "evasion": []
    },
    "yara_analysis": [
      {
        "rule": "mock_rule",
        "explanation": "mock explanation"
      }
    ],
    "malice_av_analysis": {
      "detection_ratio": "5/50",
      "engines_triggered": ["MockAV"]
    },
    "mitre_attack_mapping": [
      {
        "id": "T1059",
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "evidence": "Mock evidence"
      }
    ],
    "indicators_of_compromise": ["mock_hash"],
    "risk_assessment": {
      "final_score": 75,
      "breakdown": {
        "ml_contribution": "Mock ML",
        "yara_contribution": "Mock Yara",
        "capa_contribution": "Mock Capa",
        "av_contribution": "Mock AV"
      }
    },
    "recommended_actions": ["Mock Action 1"],
    "analyst_conclusion": "Mock conclusion."
  },
  "pdf_report": "Mock PDF content here"
}
"""

async def test():
    scan_data = {
        "filename": "test.exe",
        "history_id": "mock_id_123",
        "extracted_features": {
            "yara_matches": [{"rule": "test"}],
            "capa_behaviors": [{"behavior": "test"}],
            "malice_engines": ["test_av"]
        }
    }
    
    with patch("app.services.ai.soc_report_service.call_gemini") as mock_call:
        mock_call.return_value = mock_response
        result = await generate_gemini_report(scan_data)
        
        print("Success:", result.get("success"))
        print("Verdict:", result["report"]["soc_report"]["final_verdict"])
        print("PDF length:", len(result["report"]["pdf_report"]))
        print("MOCK TEST COMPLETED SUCCESSFULLY!")

asyncio.run(test())

