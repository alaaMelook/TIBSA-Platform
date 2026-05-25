import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.dependencies import get_supabase

def main():
    supabase = get_supabase()
    try:
        res = supabase.table("threat_feeds").select("*").limit(1).execute()
        print("=== threat_feeds schema ===")
        if res.data:
            print("Keys:", list(res.data[0].keys()))
            print("Sample:", res.data[0])
        else:
            print("No data in threat_feeds")
    except Exception as e:
        print("Failed to select threat_feeds:", e)

    try:
        res = supabase.table("threat_indicators").select("*").limit(1).execute()
        print("=== threat_indicators schema ===")
        if res.data:
            print("Keys:", list(res.data[0].keys()))
            print("Sample:", res.data[0])
        else:
            print("No data in threat_indicators")
    except Exception as e:
        print("Failed to select threat_indicators:", e)

if __name__ == '__main__':
    main()
