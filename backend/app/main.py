"""
TIBSA - Threat Intelligence-Based Security Application
FastAPI Backend Entry Point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import settings
from app.routers import auth, users, scans, threats


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    print("🚀 TIBSA Backend starting up...")
    yield
    print("👋 TIBSA Backend shutting down...")


app = FastAPI(
    title="TIBSA API",
    description="Threat Intelligence-Based Security Application API",
    version="1.0.0",
    lifespan=lifespan,
)

# ─── CORS Middleware ──────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers ─────────────────────────────────────────────────
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["Threat Intelligence"])


# ─── Health Check ─────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": "TIBSA API", "version": "1.0.0"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok"}
