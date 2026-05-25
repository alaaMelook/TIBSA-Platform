import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.dependencies import get_supabase

def main():
    supabase = get_supabase()
    
    users_resp = supabase.table("users").select("*").execute()
    users_data = users_resp.data or []
    
    scans_resp = supabase.table("scans").select("user_id, threat_level").execute()
    scans_data = scans_resp.data or []

    user_scan_counts = {}
    user_threat_counts = {}
    for s in scans_data:
        uid = s.get("user_id")
        if uid:
            user_scan_counts[uid] = user_scan_counts.get(uid, 0) + 1
            threat = s.get("threat_level")
            if threat and threat.lower() not in ["safe", "none", "clear", "clean"]:
                user_threat_counts[uid] = user_threat_counts.get(uid, 0) + 1

    print("ALL USERS AND MAPPED COUNTS:")
    for u in users_data:
        uid = u.get("id")
        scans_count = user_scan_counts.get(uid, 0)
        threats_count = user_threat_counts.get(uid, 0)
        print(f"Name: {u['full_name']} | ID: {uid} | Scans: {scans_count} | Threats: {threats_count}")

if __name__ == '__main__':
    main()
