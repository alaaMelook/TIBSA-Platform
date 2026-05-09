import requests
import json

URL = "http://localhost:8000/api/v1/ai-analysis/explain"

def test_endpoint(name, filename, content, content_type="application/json"):
    print(f"\n--- API Test: {name} ---")
    files = {
        "file": (filename, content, content_type)
    }
    
    # We need a dummy user token or the auth middleware will reject it
    # Looking at main.py and auth.py, we might be able to create a user or get a token.
    # Alternatively, we can just check if we get a 400 Bad Request *before* auth?
    # No, FastAPI Depends(get_current_user) runs before the route logic.
    # So we'll get a 401 Unauthorized.
    # Let's send the request and see.
    try:
        response = requests.post(URL, files=files)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:500]}")
    except Exception as e:
        print(f"Request failed: {e}")

test_endpoint("Malformed JSON", "bad.json", b"{bad json", "application/json")
test_endpoint("Missing Fields", "missing.json", json.dumps({"threat_score": 80}).encode(), "application/json")
