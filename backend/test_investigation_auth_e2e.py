"""
End-to-end test: Submit an authenticated Investigation scan via the API
and verify auth wiring reaches the orchestrator.
Uses the TIBSA backend /api/v1/auth/login endpoint.
"""
import asyncio
import httpx
import json
import sys

API_BASE = "http://127.0.0.1:8000"


async def get_token():
    """Get a valid JWT token by signing in via the TIBSA backend auth endpoint."""
    body = {
        "email": "admin@tibsa.com",
        "password": "password",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(f"{API_BASE}/api/v1/auth/login", json=body)
        data = r.json()
        
        if data.get("mfa_required"):
            print(f"  MFA required! factor_id={data.get('factor_id')}")
            print(f"  mfa_token present = {bool(data.get('mfa_token'))}")
            # Prompt for TOTP code
            code = input("  Enter TOTP code: ").strip()
            r2 = await client.post(f"{API_BASE}/api/v1/auth/mfa/verify", json={
                "factor_id": data["factor_id"],
                "code": code,
                "mfa_token": data["mfa_token"],
            })
            data2 = r2.json()
            if "access_token" not in data2:
                print(f"[MFA ERROR] {data2}")
                sys.exit(1)
            return data2["access_token"]
        
        if "access_token" not in data:
            print(f"[AUTH ERROR] Could not get token: {data}")
            sys.exit(1)
        return data["access_token"]


async def start_investigation(token: str):
    """Submit an authenticated investigation scan."""
    payload = {
        "target": "http://localhost:8083/sqli_1.php",
        "target_url": "http://localhost:8083/sqli_1.php",
        "mode": "safe",
        "scan_mode": "safe",
        "tests": ["sqli"],
        "include_ti": False,
        "tm_mode": "enhanced",
        "enable_sqlmap": False,
        "auth": {
            "mode": "auto_login",
            "login_url": "http://localhost:8083/login.php",
            "username": "bee",
            "password": "bug",
            "security_level": "low"
        }
    }

    print("\n=== PAYLOAD SENT TO BACKEND ===")
    safe_payload = json.loads(json.dumps(payload))
    safe_payload["auth"]["password"] = "***"
    print(json.dumps(safe_payload, indent=2))

    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(f"{API_BASE}/api/v1/investigations/start", json=payload, headers=headers)
        print(f"\n=== RESPONSE STATUS: {r.status_code} ===")
        data = r.json()
        print(json.dumps(data, indent=2))
        return data


async def main():
    print("Step 1: Getting auth token...")
    token = await get_token()
    print(f"  Token obtained (length={len(token)})")

    print("\nStep 2: Submitting authenticated investigation...")
    result = await start_investigation(token)

    if result.get("success"):
        inv_id = result["data"].get("investigation_id") or result["data"].get("scan_id")
        print(f"\n  Investigation started: {inv_id}")
        print("\n  >>> Check backend console for:")
        print("  [INVESTIGATION API AUTH RECEIVED]")
        print("  [INVESTIGATION AUTH CONTEXT]")
        print("  [sqli] final_findings")
        print(f"\n  >>> Poll status at: {API_BASE}/api/v1/investigations/{inv_id}/status")
    else:
        print("\n  FAILED to start investigation.")


if __name__ == "__main__":
    asyncio.run(main())
