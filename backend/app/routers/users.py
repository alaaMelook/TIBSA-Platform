"""
Users router.
Handles user profiles, role management (admin-only), and user CRUD.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List
from supabase import Client

from app.dependencies import get_supabase, get_current_user, require_admin
from app.models.user import UserResponse, UserRegisterProfile, UpdateRoleRequest
from app.services.user_service import UserService

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_my_profile(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Get the current user's profile. Auto-creates it if not found."""
    service = UserService(supabase)
    auth_user = current_user["auth_user"]
    try:
        return await service.get_profile(auth_user.id)
    except Exception:
        # Profile doesn't exist yet (e.g., email confirmation flow).
        # Auto-create it from auth user data.
        email = auth_user.email or ""
        full_name = (auth_user.user_metadata or {}).get("full_name", email.split("@")[0])
        return await service.create_profile(
            user_id=auth_user.id,
            email=email,
            full_name=full_name,
        )


@router.post("/register")
async def register_profile(
    data: UserRegisterProfile,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Create a user profile after Supabase Auth registration."""
    service = UserService(supabase)
    auth_user = current_user["auth_user"]
    return await service.create_profile(
        user_id=auth_user.id,
        email=data.email,
        full_name=data.full_name,
    )


@router.put("/me", response_model=UserResponse)
async def update_my_profile(
    data: UserRegisterProfile,
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Update the current user's profile."""
    service = UserService(supabase)
    auth_user = current_user["auth_user"]
    return await service.update_profile(auth_user.id, data.dict(exclude_unset=True))


# ─── Admin-Only Endpoints ────────────────────────────────────

@router.get("/", response_model=List[UserResponse])
async def list_users(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """List all users (admin only)."""
    service = UserService(supabase)
    return await service.list_all_users()


@router.patch("/{user_id}/role")
async def update_user_role(
    request: Request,
    user_id: str,
    data: UpdateRoleRequest,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """Change a user's role (admin only). This is how admins promote users."""
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    # 1. Fetch user email
    email = "Unknown User"
    try:
        user_res = supabase.table("users").select("email").eq("id", user_id).single().execute()
        if user_res.data:
            email = user_res.data.get("email")
    except Exception:
        pass
        
    service = UserService(supabase)
    result = await service.update_role(user_id, data.role)
    
    # 2. Write USER_ROLE_CHANGE audit log
    try:
        from app.services.auth_service import parse_user_agent
        auth_user = _admin["auth_user"]
        supabase.table("audit_logs").insert({
            "user_id": auth_user.id,
            "action_type": "USER_ROLE_CHANGE",
            "severity": "warning",
            "message": f"Administrator changed role of user {email} to {data.role}.",
            "ip_address": client_ip,
            "metadata": {
                "resource": "users",
                "target_user_id": user_id,
                "target_email": email,
                "new_role": data.role,
                "user_agent": parse_user_agent(user_agent)
            }
        }).execute()
    except Exception:
        pass
        
    return result


@router.patch("/{user_id}/status")
async def update_user_status(
    request: Request,
    user_id: str,
    data: dict,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """Change a user's active status (admin only)."""
    client_ip = request.client.host if request.client else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "Unknown")
    
    is_active = data.get("is_active")
    if is_active is None:
        raise HTTPException(
            status_code=400,
            detail="Missing is_active field in request body",
        )
        
    # 1. Fetch user details
    email = "Unknown User"
    try:
        user_res = supabase.table("users").select("email").eq("id", user_id).single().execute()
        if user_res.data:
            email = user_res.data.get("email")
    except Exception:
        pass

    # 2. Update user status in Supabase
    res = supabase.table("users").update({"is_active": is_active}).eq("id", user_id).execute()
    if not res.data:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )
        
    # 3. Write USER_STATUS_CHANGE audit log
    try:
        from app.services.auth_service import parse_user_agent
        auth_user = _admin["auth_user"]
        action = "Enabled" if is_active else "Disabled"
        severity = "info" if is_active else "critical"
        supabase.table("audit_logs").insert({
            "user_id": auth_user.id,
            "action_type": "USER_STATUS_CHANGE",
            "severity": severity,
            "message": f"Administrator {action} account for user {email}.",
            "ip_address": client_ip,
            "metadata": {
                "resource": "users",
                "target_user_id": user_id,
                "target_email": email,
                "is_active": is_active,
                "user_agent": parse_user_agent(user_agent)
            }
        }).execute()
    except Exception:
        pass

    return {"message": f"User account active status set to {is_active}", "user": res.data[0]}


@router.get("/dashboard/stats")
async def get_dashboard_stats(
    current_user: dict = Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Get dashboard statistics for the current user."""
    auth_user = current_user["auth_user"]
    user_id = auth_user.id

    # Get user's scan stats
    scans = supabase.table("scans").select("id, status, threat_level").eq("user_id", user_id).execute()
    scan_data = scans.data or []

    total_scans = len(scan_data)
    active_scans = len([s for s in scan_data if s.get("status") in ("pending", "running")])
    threats_detected = len([s for s in scan_data if s.get("threat_level") and s.get("threat_level") not in ("safe", None)])
    completed_scans = len([s for s in scan_data if s.get("status") == "completed"])

    # Get recent scans
    recent = supabase.table("scans").select("*").eq("user_id", user_id).order("created_at", desc=True).limit(5).execute()

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "threats_detected": threats_detected,
        "completed_scans": completed_scans,
        "recent_scans": recent.data or [],
    }

