import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from app.dependencies import get_supabase

def check_logs():
    supabase = get_supabase()
    res = supabase.table('audit_logs').select('*').execute()
    print(f"Total records found: {len(res.data)}")
    for record in res.data:
        print(record)

if __name__ == "__main__":
    check_logs()
