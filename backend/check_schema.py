import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from app.dependencies import get_supabase

def check_schema():
    supabase = get_supabase()
    # To guess schema, let's insert a dummy row or select limit 1
    res = supabase.table('login_attempts').select('*').limit(1).execute()
    print("login_attempts data:", res.data)
    
    res_logs = supabase.table('audit_logs').select('*').limit(1).execute()
    print("audit_logs data:", res_logs.data)

if __name__ == "__main__":
    check_schema()
