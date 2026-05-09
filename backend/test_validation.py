from app.services.ai.validators import validate_scan_json, ScanValidationError
import json

def test_payload(name, payload, should_fail, expect_error_snippet=None):
    print(f"--- Testing {name} ---")
    try:
        clean_data, warnings = validate_scan_json(payload)
        if should_fail:
            print(f"[FAIL] Expected validation error but got success.")
        else:
            print(f"[PASS] Clean Data: {clean_data}, Warnings: {warnings}")
    except ScanValidationError as e:
        if not should_fail:
            print(f"[FAIL] Expected success but got error: {e.errors}")
        else:
            if expect_error_snippet:
                if any(expect_error_snippet in str(err) for err in e.errors):
                    print(f"[PASS] Got expected error: {e.errors}")
                else:
                    print(f"[FAIL] Error {e.errors} did not contain '{expect_error_snippet}'")
            else:
                print(f"[PASS] Got error: {e.errors}")
    except Exception as e:
        print(f"[FAIL] Got unexpected exception type: {type(e)}: {e}")

# Issue 2: Missing Required Fields
test_payload("Missing fields", {"file_name": "partial.exe", "threat_score": 80}, True, "Missing required field: file_type")

# Issue 3: Extra Unexpected Fields
test_payload(
    "Extra fields", 
    {
        "file_name": "bad.exe", "file_type": "exe", "detections": [], "detection_count": 0, 
        "yara_matches": [], "capa_behaviors": [], "threat_score": 50, "hacker_mode": True
    }, 
    False
)

# Issue 4: Null values
test_payload(
    "Null values", 
    {
        "file_name": None, "file_type": None, "detections": None, "detection_count": None, 
        "yara_matches": None, "capa_behaviors": None, "threat_score": None
    }, 
    True, "Field 'file_name' must not be null"
)

# Issue 5: Wrong Data Types
test_payload(
    "Wrong types", 
    {
        "file_name": 12345, "file_type": True, "detections": "Trojan", "detection_count": "five", 
        "yara_matches": {}, "capa_behaviors": 999, "threat_score": "high"
    }, 
    True, "Field 'file_name' must be a str"
)

# Numeric range violations
test_payload(
    "Range violations", 
    {
        "file_name": "bad.exe", "file_type": "exe", "detections": [], "detection_count": -5, 
        "yara_matches": [], "capa_behaviors": [], "threat_score": 140
    }, 
    True, "threat_score' must be between 0 and 100"
)

# Invalid Array Items
test_payload(
    "Invalid array items", 
    {
        "file_name": "bad.exe", "file_type": "exe", "detections": [123, True, None], "detection_count": 0, 
        "yara_matches": [], "capa_behaviors": [], "threat_score": 50
    }, 
    True, "contains non-string items at positions: 0, 1, 2"
)
