"""
Authentication router.
Handles login, register, token refresh, and MFA verification.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from supabase import Client

from app.dependencies import get_supabase, get_current_user
from app.models.user import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    RefreshTokenRequest,
    MFAVerifyRequest,
    MFAChallengeRequest,
    MFAEnrollResponse,
)
from app.services.auth_service import AuthService
from app.utils.limiter import limiter

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(request: Request, payload: LoginRequest, supabase: Client = Depends(get_supabase)):
    """Authenticate user and return access token."""
    print("[RATE LIMIT] login limiter active")
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    service = AuthService(supabase)
    return await service.login(payload.email, payload.password, client_ip, user_agent)


@router.post("/register", response_model=TokenResponse)
@limiter.limit("3/minute")
async def register(request: Request, payload: RegisterRequest, supabase: Client = Depends(get_supabase)):
    """Register a new user (defaults to 'user' role)."""
    print("[RATE LIMIT] register limiter active")
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    service = AuthService(supabase)
    return await service.register(
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        ip_address=client_ip,
        user_agent=user_agent,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest, supabase: Client = Depends(get_supabase)
):
    """Refresh an access token."""
    service = AuthService(supabase)
    return await service.refresh_token(request.refresh_token)


@router.post("/logout")
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Sign out the current user."""
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    try:
        auth_user = current_user["auth_user"]
        
        # 1. Update last_seen in DB
        try:
            from datetime import datetime, timezone
            supabase.table("users").update({
                "last_seen": datetime.now(timezone.utc).isoformat()
            }).eq("id", auth_user.id).execute()
        except Exception:
            pass
            
        # 2. Write LOGOUT audit log
        try:
            from app.services.auth_service import parse_user_agent
            supabase.table("audit_logs").insert({
                "user_id": auth_user.id,
                "action_type": "LOGOUT",
                "severity": "info",
                "message": "User logged out successfully.",
                "ip_address": client_ip,
                "metadata": {
                    "resource": "auth",
                    "user_agent": parse_user_agent(user_agent)
                }
            }).execute()
        except Exception:
            pass

        supabase.auth.sign_out()
        return {"message": "Logged out successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}",
        )


@router.post("/mfa/enroll", response_model=MFAEnrollResponse)
async def mfa_enroll(current_user: dict = Depends(get_current_user), supabase: Client = Depends(get_supabase)):
    """Enroll the current user in TOTP MFA."""
    try:
        res = supabase.auth.mfa.enroll(factor_type="totp")
        return {
            "factor_id": res.id,
            "totp_uri": res.totp.qr_code,  # Returns svg string
            "qr_code": res.totp.qr_code,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/mfa/challenge")
async def mfa_challenge(request: MFAChallengeRequest, current_user: dict = Depends(get_current_user), supabase: Client = Depends(get_supabase)):
    """Create a challenge for a factor."""
    try:
        res = supabase.auth.mfa.challenge(request.factor_id)
        return {"challenge_id": res.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/mfa/verify", response_model=TokenResponse)
async def mfa_verify(request: MFAVerifyRequest):
    """Verify a TOTP code and upgrade session to AAL2."""
    import logging
    logger = logging.getLogger("security")

    # ── Stage 1: Input validation ─────────────────────────────
    code = request.code.strip()
    factor_id_prefix = request.factor_id[:8] if request.factor_id else "unknown"
    token_present = bool(request.mfa_token)
    logger.info(
        f"[MFA] Stage 1 - factor_id_prefix={factor_id_prefix}, "
        f"code_length={len(code)}, mfa_token_present={token_present}"
    )

    if not token_present:
        raise HTTPException(status_code=401, detail="MFA token is required")

    if not code.isdigit() or len(code) != 6:
        raise HTTPException(status_code=401, detail="Invalid authenticator code")

    # ── Stage 2: Resolve pending MFA token ────────────────────
    from app.services.auth_service import get_pending_mfa, increment_failed_mfa, delete_pending_mfa
    pending_data = get_pending_mfa(request.mfa_token)
    logger.info(
        f"[MFA] Stage 2 - pending_token_resolved={pending_data is not None}, "
        f"pending_user_id={pending_data.get('user_id', 'N/A')[:8] if pending_data else 'N/A'}"
    )
    if not pending_data:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    # ── Stage 3: Create fresh user-scoped Supabase client ─────
    try:
        from supabase import create_client
        from app.config import settings

        user_client = create_client(
            settings.supabase_url, settings.supabase_service_role_key
        )

        set_session_resp = user_client.auth.set_session(
            pending_data["access_token"], pending_data["refresh_token"]
        )
        
        # If set_session proactively refreshed the token (e.g. due to clock drift), update the store!
        if set_session_resp and getattr(set_session_resp, "session", None):
            pending_data["access_token"] = set_session_resp.session.access_token
            pending_data["refresh_token"] = set_session_resp.session.refresh_token

        logger.info(
            f"[MFA] Stage 3 - set_session_success={set_session_resp is not None and getattr(set_session_resp, 'session', None) is not None}"
        )
    except Exception as e:
        logger.error(f"[MFA] Stage 3 FAILED - set_session error: {type(e).__name__}", exc_info=True)
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    # ── Stage 4: Validate user and factor ─────────────────────
    try:
        user_resp = user_client.auth.get_user()
        factors = getattr(user_resp.user, "factors", []) or []
        factor_summaries = [
            f"{getattr(f, 'id', '?')[:8]}|{getattr(f, 'status', '?')}|{getattr(f, 'factor_type', '?')}"
            for f in factors
        ]
        logger.info(
            f"[MFA] Stage 4 - get_user_success=True, "
            f"factors={factor_summaries}"
        )
    except Exception as e:
        logger.error(f"[MFA] Stage 4 FAILED - get_user error: {type(e).__name__}", exc_info=True)
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")

    if not factors:
        raise HTTPException(status_code=400, detail="No enrolled MFA factors found")

    valid_factor = any(
        getattr(f, "id", None) == request.factor_id
        and getattr(f, "status", None) == "verified"
        for f in factors
    )
    logger.info(f"[MFA] Stage 4 - valid_factor={valid_factor}")
    if not valid_factor:
        raise HTTPException(status_code=400, detail="Invalid factor ID for user")

    # ── Stage 5: Challenge and verify ─────────────────────────
    try:
        res = user_client.auth.mfa.challenge_and_verify(
            {"factor_id": request.factor_id, "code": code}
        )
        logger.info(
            f"[MFA] Stage 5 - challenge_and_verify_success=True, "
            f"has_access_token={bool(getattr(res, 'access_token', None))}, "
            f"has_refresh_token={bool(getattr(res, 'refresh_token', None))}"
        )
    except Exception as e:
        logger.error(f"[MFA] Stage 5 FAILED - verify error: {type(e).__name__}: {e}", exc_info=True)
        
        # Increment failed attempts
        failed_attempts = increment_failed_mfa(request.mfa_token)
        if failed_attempts >= 5:
            delete_pending_mfa(request.mfa_token)
            raise HTTPException(status_code=401, detail="Too many invalid MFA attempts. Please login again.")

        error_msg = str(e).lower()
        if "expired" in error_msg or "missing" in error_msg or "session" in error_msg:
            raise HTTPException(status_code=400, detail="MFA challenge expired or missing")
        raise HTTPException(status_code=401, detail="Invalid authenticator code")

    # ── Stage 6: Consume the pending token (single-use) ───────
    delete_pending_mfa(request.mfa_token)
    logger.info(f"[MFA] Stage 6 - pending_token_consumed=True")

    # Extract tokens to ensure no lazy evaluation or proxy object hangs
    access_token_val = getattr(res, "access_token", None) or getattr(getattr(res, "session", None), "access_token", None)
    refresh_token_val = getattr(res, "refresh_token", None) or getattr(getattr(res, "session", None), "refresh_token", None)

    if not access_token_val:
        logger.error("[MFA] FATAL: Failed to extract access_token from response object")
        raise HTTPException(status_code=500, detail="MFA verification failed internally")

    logger.info(f"[MFA] Stage 7 - preparing to return tokens (access_token_len={len(access_token_val)})")

    return {
        "access_token": access_token_val,
        "refresh_token": refresh_token_val,
        "token_type": "bearer",
    }
