import asyncio
import os
import sys

# Add backend directory to sys.path so we can import app modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.dependencies import get_supabase

async def inject_log():
    try:
        # Get Supabase client
        supabase = get_supabase()
        
        # 1. First, get a real user from the users table so we can attribute the log properly
        users_resp = supabase.table("users").select("id").limit(1).execute()
        users_data = users_resp.data
        
        user_id = None
        if users_data and len(users_data) > 0:
            user_id = users_data[0]["id"]
            
        print(f"Found user_id: {user_id}")
        
        # 2. Insert an audit log
        log_data = {
            "action_type": "system_config_update",
            "severity": "info",
            "message": "Updated SOC platform configuration. Realism migration completed.",
            "ip_address": "192.168.1.1",
            "metadata": {"resource": "admin_panel"}
        }
        
        if user_id:
            log_data["user_id"] = user_id
            
        result = supabase.table("audit_logs").insert(log_data).execute()
        print(f"Successfully inserted audit log: {result.data}")
        
    except Exception as e:
        print(f"Error injecting audit log: {e}")

if __name__ == "__main__":
    asyncio.run(inject_log())
