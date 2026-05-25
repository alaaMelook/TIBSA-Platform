import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.dependencies import get_supabase

def main():
    supabase = get_supabase()
    try:
        res = supabase.table("findings").select("*").limit(1).execute()
        print("=== findings schema ===")
        if res.data:
            print("Keys:", list(res.data[0].keys()))
            print("Sample:", res.data[0])
        else:
            print("No data in findings")
    except Exception as e:
        print("Failed to select findings:", e)

    try:
        res = supabase.table("assets").select("*").limit(1).execute()
        print("=== assets schema ===")
        if res.data:
            print("Keys:", list(res.data[0].keys()))
            print("Sample:", res.data[0])
        else:
            print("No data in assets")
    except Exception as e:
        print("Failed to select assets:", e)

    try:
        res = supabase.table("scans").select("*").limit(1).execute()
        print("=== scans schema ===")
        if res.data:
            print("Keys:", list(res.data[0].keys()))
            print("Sample:", res.data[0])
        else:
            print("No data in scans")
    except Exception as e:
        print("Failed to select scans:", e)

if __name__ == '__main__':
    main()
