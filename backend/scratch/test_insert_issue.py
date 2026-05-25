import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.dependencies import get_supabase

def main():
    supabase = get_supabase()
    try:
        res = supabase.table("audit_logs").insert({
            "action_type": "TEST_INSERT",
            "severity": "info",
            "message": "Testing RLS inserting from backend script."
        }).execute()
        print("Success inserting audit_log:", res.data)
    except Exception as e:
        print("Failed inserting audit_log:", e)

    try:
        res = supabase.table("login_attempts").insert({
            "email": "test@example.com",
            "ip_address": "127.0.0.1",
            "user_agent": "TestAgent",
            "status": "success"
        }).execute()
        print("Success inserting login_attempt:", res.data)
    except Exception as e:
        print("Failed inserting login_attempt:", e)

if __name__ == '__main__':
    main()
