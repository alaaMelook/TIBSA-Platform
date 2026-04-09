"""
main_threat_modeling.py
=======================
Extended entry-point that mounts the Threat Modeling router on top of the
existing TIBSA app – WITHOUT modifying app/main.py.

Usage
-----
Instead of:
    uvicorn app.main:app --reload

Run:
    uvicorn app.main_threat_modeling:app --reload

How it works
------------
1. Import the FastAPI `app` object that `app.main` already built
   (all existing routers, middleware, lifespan, CORS stay intact).
2. Attach only the new threat_modeling router.
3. Re-export the extended `app` under the same name so uvicorn picks it up.
"""

# ── 1. Import the already-configured app (unchanged) ──────────────────
from app.main import app  # noqa: F401  (re-exported below)

# ── 2. Import & register the new router ───────────────────────────────
from app.routers.threat_modeling import router as threat_modeling_router

app.include_router(
    threat_modeling_router,
    prefix="/api/v1/threat-modeling",
    tags=["Threat Modeling"],
)

# ── 3. `app` is now the extended application ──────────────────────────
# Nothing else changes – all existing endpoints still work as before.
