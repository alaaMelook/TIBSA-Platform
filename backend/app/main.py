"""
TIBSA - Threat Intelligence-Based Security Application
FastAPI Backend Entry Point
"""
import sys
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

sys.stdout.reconfigure(encoding="utf-8")
# uvicorn_reload_trigger = True

import sys
import asyncio

if sys.platform == "win32":
    # Required for Playwright/Subprocess on Windows + Python 3.13
    print("[INIT] Setting WindowsProactorEventLoopPolicy for Playwright support...")
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())



from app.config import settings
from app.routers import auth, users, scans, threats, notifications, website_scanner, threat_modeling, ai_analysis, ai_chatbot
from app.api import investigations as api_investigations
from app.api import scans as api_scans
from app.api import health as api_health
from app.utils.limiter import limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https: wss:;"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if "Server" in response.headers:
            del response.headers["Server"]
        return response

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    print("TIBSA Backend starting up...")
    if not settings.virustotal_api_key:
        print("WARNING: VIRUSTOTAL_API_KEY is not set — URL/file scans will fail!")
    else:
        print("VirusTotal API key loaded")
    
    yield
    print("TIBSA Backend shutting down...")


from fastapi.exceptions import RequestValidationError

app = FastAPI(
    title="TIBSA API",
    description="Threat Intelligence-Based Security Application API",
    version="1.0.0",
    lifespan=lifespan,
    redirect_slashes=False
)

app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    sensitive_fields = {"password", "confirm_password", "current_password", "new_password", "token", "access_token", "refresh_token"}
    for error in errors:
        if any(str(loc_item) in sensitive_fields for loc_item in error.get("loc", [])):
            if "input" in error:
                del error["input"]
    return JSONResponse(
        status_code=422,
        content={"detail": jsonable_encoder(errors)},
    )

# ─── Middlewares ──────────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SlowAPIMiddleware)
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
app.include_router(notifications.router, prefix="/api/v1/notifications", tags=["Notifications"])
app.include_router(website_scanner.router, prefix="/api/v1/website-scanner", tags=["Website Scanner"])
app.include_router(threat_modeling.router, prefix="/api/v1/threat-modeling", tags=["Threat Modeling"])
app.include_router(ai_analysis.router, prefix="/api/v1/ai-analysis", tags=["AI Analysis"])
app.include_router(ai_chatbot.router, prefix="/api/v1/ai-chatbot", tags=["AI Chatbot"])

# New infrastructure routers
app.include_router(api_investigations.router, prefix="/api/v1/investigations", tags=["Investigations"])
app.include_router(api_scans.router, prefix="/api/v1/investigation-scans", tags=["Investigation Scans"])
app.include_router(api_health.router, prefix="/api/v1/health", tags=["Health"])


# ─── Health Check ─────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def health_check():
    return {"status": "healthy", "service": "TIBSA API", "version": "1.0.0"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok"}
