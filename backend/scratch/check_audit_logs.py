import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.dependencies import get_supabase

def main():
    supabase = get_supabase()
    res = supabase.table("login_attempts").select("*").order("attempted_at", desc=True).limit(20).execute()
    print("=== Login Attempts in Database ===")
    for row in res.data or []:
        print(f"Email: {row['email']} | Status: {row['status']} | IP: {row['ip_address']} | Time: {row['attempted_at']}")

if __name__ == '__main__':
    main()
