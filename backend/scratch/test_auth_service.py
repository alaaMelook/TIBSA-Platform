from supabase import create_client
import sys
import os
import asyncio

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import settings
from app.services.auth_service import AuthService

async def main():
    supabase = create_client(settings.supabase_url, settings.supabase_service_role_key)
    service = AuthService(supabase)
    
    # We will register a unique test email
    import random
    test_num = random.randint(1000, 9999)
    email = f"presence_test_{test_num}@tibsa.com"
    password = "SecurePassword123!"
    full_name = f"Test User {test_num}"
    
    print(f"Registering test user: {email}...")
    try:
        res = await service.register(email, password, full_name, "127.0.0.1", "Mozilla/5.0")
        print("Registration completed successfully:", res)
    except Exception as e:
        print("Registration failed with error:", str(e))
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    asyncio.run(main())
