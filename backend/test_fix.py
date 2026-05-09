"""
Quick test: Directly call the explain_malware function with the user's
malicious scan data to verify the AI pipeline + OpenRouter works correctly.
"""
import asyncio
import sys
import json

sys.stdout.reconfigure(encoding="utf-8")

async def main():
    print("=" * 60)
    print("TESTING AI PIPELINE WITH JSON SCAN DATA")
    print("=" * 60)

    # Step 1: Test _try_parse_scan_json
    print("\n[1] Testing JSON scan data detection...")
    from app.routers.ai_analysis import _try_parse_scan_json

    test_json = json.dumps({
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

    scan_input = _try_parse_scan_json("test_malware.json", test_json)
    
    if scan_input is None:
        print("    FAIL: _try_parse_scan_json returned None!")
        return
    
    print(f"    SUCCESS: Parsed scan data:")
    print(f"      file_name:     {scan_input.file_name}")
    print(f"      file_type:     {scan_input.file_type}")
    print(f"      detections:    {scan_input.detections}")
    print(f"      detection_count: {scan_input.detection_count}")
    print(f"      yara_matches:  {scan_input.yara_matches}")
    print(f"      capa_behaviors: {scan_input.capa_behaviors}")
    print(f"      threat_score:  {scan_input.threat_score}")

    # Step 2: Test that non-JSON files are NOT intercepted
    print("\n[2] Testing non-JSON files are not intercepted...")
    result_txt = _try_parse_scan_json("readme.txt", b"hello world")
    result_exe = _try_parse_scan_json("malware.exe", b"\x4d\x5a\x90\x00")
    result_random_json = _try_parse_scan_json("config.json", json.dumps({"name": "test", "version": "1.0"}).encode())
    
    print(f"    .txt file: {'PASS (None)' if result_txt is None else 'FAIL'}")
    print(f"    .exe file: {'PASS (None)' if result_exe is None else 'FAIL'}")
    print(f"    config.json (no scan fields): {'PASS (None)' if result_random_json is None else 'FAIL'}")

    # Step 3: Call OpenRouter API via explain_malware
    print("\n[3] Calling OpenRouter AI with malicious scan data...")
    from app.services.ai.malware_explainer import explain_malware
    
    try:
        result = await explain_malware(scan_input)
        print(f"\n    SUCCESS! AI Response:")
        print(f"    Risk Level:   {result.risk_level}")
        print(f"    Risk Score:   {result.risk_score}")
        print(f"    Summary:      {result.summary}")
        print(f"    Confidence:   {result.confidence}")
        print(f"    What it does: {result.what_it_does}")
        print(f"    Impact:       {result.attack_impact}")
        print(f"    Actions:      {result.recommended_actions}")
        
        # Verify the AI correctly identified it as high risk
        if result.risk_level.lower() in ("critical", "high"):
            print(f"\n    PASS: AI correctly identified as {result.risk_level} risk!")
        elif result.risk_level.lower() == "none":
            print(f"\n    FAIL: AI still says 'None' risk - OpenRouter may have issues")
        else:
            print(f"\n    PARTIAL: AI says '{result.risk_level}' - reasonable but expected High/Critical")
            
    except Exception as e:
        print(f"\n    ERROR: {type(e).__name__}: {e}")

    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
