from supabase import create_client
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import settings

def main():
    supabase = create_client(settings.supabase_url, settings.supabase_service_role_key)
    user_id = '60386d5e-5850-40a3-9a19-34c499e69ccd' # faridamelook@gmail.com ID
    
    print("Testing insert into audit_logs...")
    try:
        res = supabase.table("audit_logs").insert({
            "user_id": user_id,
            "action_type": "TEST_ACTION",
            "severity": "info",
            "message": "Testing successful login/registration logging.",
            "ip_address": "127.0.0.1",
            "metadata": {
                "resource": "auth",
                "user_agent": "Chrome (Windows 10/11)"
            }
        }).execute()
        print("Success! Inserted row:", res.data)
    except Exception as e:
        print("Insert failed with error:", str(e))

if __name__ == '__main__':
    main()
