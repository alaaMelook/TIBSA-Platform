from supabase import create_client
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import settings

def main():
    supabase = create_client(settings.supabase_url, settings.supabase_service_role_key)
    res = supabase.table('users').select('*').execute()
    print("Users found:", len(res.data))
    for u in res.data:
        print(u)

if __name__ == '__main__':
    main()
