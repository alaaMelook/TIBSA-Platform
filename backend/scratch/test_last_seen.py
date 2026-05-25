from supabase import create_client
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import settings

def main():
    supabase = create_client(settings.supabase_url, settings.supabase_service_role_key)
    print("Fetching one user to inspect available columns...")
    try:
        res = supabase.table("users").select("*").limit(1).execute()
        if res.data:
            print("Row data:", res.data[0])
            if "last_seen" in res.data[0]:
                print("SUCCESS: last_seen column IS present in the database!")
            else:
                print("WARNING: last_seen is NOT present in the database columns.")
        else:
            print("No users found to inspect.")
    except Exception as e:
        print("Inspection failed:", str(e))

if __name__ == '__main__':
    main()
