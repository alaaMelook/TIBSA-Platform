"""One-off VT API probe — compare analysis stats vs URL object."""
import asyncio
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

import httpx

VT_BASE = "https://www.virustotal.com/api/v3"


def url_id(u: str) -> str:
    return base64.urlsafe_b64encode(u.encode()).decode().strip("=")


async def probe(url: str, key: str) -> None:
    headers = {"x-apikey": key}
    async with httpx.AsyncClient(timeout=60, http2=False) as c:
        print("===", url, "===")
        uid = url_id(url)
        print("vt_url_id:", uid[:50])
        r = await c.get(f"{VT_BASE}/urls/{uid}", headers=headers)
        print("GET /urls status", r.status_code)
        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            print("url in object:", (attrs.get("url") or attrs.get("last_final_url") or "N/A")[:100])
            print("last_analysis_stats:", attrs.get("last_analysis_stats"))
        r2 = await c.post(f"{VT_BASE}/urls", headers=headers, data={"url": url})
        r2.raise_for_status()
        aid = r2.json()["data"]["id"]
        print("analysis_id:", aid)
        for _ in range(20):
            ra = await c.get(f"{VT_BASE}/analyses/{aid}", headers=headers)
            ra.raise_for_status()
            attrs = ra.json()["data"]["attributes"]
            st = attrs["status"]
            if st == "completed":
                print("analysis stats:", attrs.get("stats"))
                ri = await c.get(f"{VT_BASE}/analyses/{aid}/item", headers=headers)
                print("item status", ri.status_code)
                if ri.status_code == 200:
                    iattrs = ri.json().get("data", {}).get("attributes", {})
                    print("item url:", str(iattrs.get("url", "N/A"))[:100])
                    print("item last_analysis_stats:", iattrs.get("last_analysis_stats"))
                return
            await asyncio.sleep(3)
        print("analysis timeout")


async def main() -> None:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        print("NO_API_KEY")
        return
    for u in ["https://microsoft.com", "https://google.com", "https://github.com"]:
        await probe(u, key)
        print()


if __name__ == "__main__":
    asyncio.run(main())
