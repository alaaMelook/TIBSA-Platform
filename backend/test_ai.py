import asyncio
from app.services.ai.yara_scanner import scan_file_bytes
from app.services.ai.schemas import MalwareScanInput
from app.services.ai.malware_explainer import explain_malware
import os
import json

async def main():
    with open("../tibsa_fake_malware.txt", "rb") as f:
        content = f.read()
    
    yara_matches = scan_file_bytes("tibsa_fake_malware.txt", content)
    print("YARA Matches:", yara_matches)
    
    yara_score = min(100, len(yara_matches) * 15)
    threat_score = int(0 * 0.4 + yara_score * 0.3 + 0 * 0.3)
    
    scan_input = MalwareScanInput(
        file_name="tibsa_fake_malware.txt",
        file_type=".txt file",
        detections=[],
        detection_count=0,
        yara_matches=yara_matches,
        capa_behaviors=[],
        threat_score=threat_score,
    )
    print("Scan Input:", scan_input.dict())
    
    result = await explain_malware(scan_input)
    print("AI Result:", result.json(indent=2))

if __name__ == "__main__":
    asyncio.run(main())
