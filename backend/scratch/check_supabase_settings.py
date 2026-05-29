import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.dependencies import get_supabase

supabase = get_supabase()
try:
    res = supabase.table("system_settings").select("*").execute()
    print("Success! system_settings contents:", res.data)
except Exception as e:
    print("Failed to query system_settings:", str(e))
