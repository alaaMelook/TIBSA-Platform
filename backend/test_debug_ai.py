"""
Debug test: Directly test the AI malware analysis pipeline end-to-end.
Tests both scenarios:
  1. What happens when you upload a plain JSON file (the user's scenario)
  2. What happens when you provide the scan data directly to the AI
"""
import asyncio
import json
import sys

sys.stdout.reconfigure(encoding="utf-8")

async def main():
    print("=" * 60)
    print("TIBSA AI Analysis Debug Test")
    print("=" * 60)

    # ── Step 1: Check OpenRouter API key ──
    from app.config import settings
    print(f"\n[1] OpenRouter API Key: {'SET (' + settings.openrouter_api_key[:10] + '...)' if settings.openrouter_api_key else 'NOT SET'}")

    # ── Step 2: Test the YARA scanner on the user's JSON content ──
    print("\n[2] Testing YARA scanner on JSON content...")
    from app.services.ai.yara_scanner import scan_file_bytes
    
    json_content = json.dumps({
        "file_name": "chrome_update.exe",
        "file_type": "PE32 executable",
        "detections": ["Trojan.Downloader", "Malware.Injector"],
        "detection_count": 11,
        "yara_matches": ["Process_Injection", "Downloader_Family"],
        "capa_behaviors": [
            "download file from internet",
            "inject into explorer.exe",
            "execute shell commands",
            "persistence via startup folder"
        ],
        "threat_score": 81
    }).encode("utf-8")
    
    yara_matches = scan_file_bytes("test_malware.json", json_content)
    print(f"    YARA matches on JSON file: {yara_matches}")
    print(f"    (Expected: EMPTY, because it's a text/JSON file, not a binary)")

    # ── Step 3: Test CAPA analyzer ──
    print("\n[3] Testing CAPA analyzer on JSON content...")
    from app.services.ai.capa_analyzer import analyze_file
    capa_results = await analyze_file("test_malware.json", json_content)
    print(f"    CAPA results: {capa_results}")
    print(f"    (Expected: EMPTY, because capa can't analyze JSON text files)")

    # ── Step 4: Compute threat score with empty results ──
    print("\n[4] Computing threat score with empty scan results...")
    yara_count = len(yara_matches)
    capa_count = len(capa_results)
    malice_detected = 0
    malice_total = 0
    
    # Same formula as ai_analysis.py
    if malice_total > 0:
        malice_score = min(100, int((malice_detected / malice_total) * 100))
    else:
        malice_score = 0
    yara_score = min(100, yara_count * 15)
    capa_score = min(100, capa_count * 10)
    threat_score = min(100, int(malice_score * 0.4 + yara_score * 0.3 + capa_score * 0.3))
    
    print(f"    Malice score: {malice_score} (detected={malice_detected}, total={malice_total})")
    print(f"    YARA score:   {yara_score} (matches={yara_count})")
    print(f"    CAPA score:   {capa_score} (behaviors={capa_count})")
    print(f"    TOTAL threat_score: {threat_score}")
    print(f"    >>> THIS IS THE PROBLEM! Score = 0, so AI sees 'clean' data")

    # ── Step 5: Test what AI sees ──
    print("\n[5] Building the prompt that gets sent to AI...")
    from app.services.ai.schemas import MalwareScanInput
    from app.services.ai.prompts import build_user_prompt, SYSTEM_PROMPT
    
    # This is what actually gets built when uploading a JSON file
    scan_input_bad = MalwareScanInput(
        file_name="test_malware.json",
        file_type=".json file",
        detections=[],          # empty - Malice found nothing
        detection_count=0,       # zero
        yara_matches=[],         # empty - YARA found nothing in JSON text
        capa_behaviors=[],       # empty - CAPA can't analyze JSON
        threat_score=0,          # zero
    )
    prompt_bad = build_user_prompt(scan_input_bad)
    print(f"    Prompt (with empty results):\n{prompt_bad}")
    print("\n    >>> The AI is CORRECTLY saying 'None risk' because all inputs are empty!")
    
    # ── Step 6: Test with proper data ──
    print("\n" + "=" * 60)
    print("[6] Now testing with REAL malicious data fed directly to AI...")
    print("=" * 60)
    
    scan_input_good = MalwareScanInput(
        file_name="chrome_update.exe",
        file_type="PE32 executable",
        detections=["Trojan.Downloader", "Malware.Injector"],
        detection_count=11,
        yara_matches=["Process_Injection", "Downloader_Family"],
        capa_behaviors=[
            "download file from internet",
            "inject into explorer.exe",
            "execute shell commands",
            "persistence via startup folder"
        ],
        threat_score=81,
    )
    prompt_good = build_user_prompt(scan_input_good)
    print(f"    Prompt (with real data):\n{prompt_good}")
    
    print("\n    Calling OpenRouter API...")
    try:
        from app.services.ai.malware_explainer import explain_malware
        result = await explain_malware(scan_input_good)
        print(f"\n    SUCCESS! AI Response:")
        print(f"    Risk Level:  {result.risk_level}")
        print(f"    Risk Score:  {result.risk_score}")
        print(f"    Summary:     {result.summary}")
        print(f"    Confidence:  {result.confidence}")
        print(f"    What it does: {result.what_it_does}")
    except Exception as e:
        print(f"\n    ERROR calling OpenRouter: {type(e).__name__}: {e}")

    print("\n" + "=" * 60)
    print("DIAGNOSIS COMPLETE")
    print("=" * 60)
    print("""
ROOT CAUSE: When you upload a .json file, the system runs the ACTUAL
scanners (Malice, YARA, CAPA) on the file bytes. Since a .json text 
file is NOT a real malware binary:
  - Malice AV engines: find nothing (it's just text)
  - YARA scanner: no pattern matches in JSON text
  - CAPA analyzer: can't analyze non-PE/ELF files
  
So ALL scan results are EMPTY, the threat_score computes to 0,
and the AI correctly reports "None risk detected."

The JSON data INSIDE the file is never parsed or used as scan input.
The system scans the file itself, not the data it contains.
""")

if __name__ == "__main__":
    asyncio.run(main())
