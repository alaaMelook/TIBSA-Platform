import httpx
import asyncio

async def run_auth_test():
    async with httpx.AsyncClient() as c:
        r = await c.post("http://127.0.0.1:8000/api/v1/auth/token", data={"username": "admin@tibsa.com", "password": "password"})
        print(r.json())

if __name__ == "__main__":
    asyncio.run(run_auth_test())
