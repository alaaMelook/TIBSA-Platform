import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
try:
    response = client.get("/api/v1/admin/settings")
    print("Response Status Code:", response.status_code)
    print("Response Body (Unauthorized expected):", response.json())
except Exception as e:
    print("Test failed:", str(e))
