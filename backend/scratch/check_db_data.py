import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.dependencies import get_supabase

def main():
    supabase = get_supabase()
    
    scans = supabase.table("scans").select("*").limit(1).execute()
    print("=== Scans Columns ===")
    if scans.data:
        print("Keys:", list(scans.data[0].keys()))
        print("Sample:", scans.data[0])

if __name__ == '__main__':
    main()
