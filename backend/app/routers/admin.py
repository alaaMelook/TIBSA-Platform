import httpx
from fastapi import APIRouter, Depends
from supabase import Client
from typing import Dict, Any, List
from datetime import datetime, timezone, timedelta

from app.dependencies import get_supabase, require_admin, ACTIVE_PRESENCE
from app.services.auth_service import parse_user_agent

router = APIRouter()

@router.get("/stats", response_model=Dict[str, Any])
async def get_admin_stats(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get core metrics for the Admin SOC dashboard.
    """
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_str = today.isoformat()

    # Source: users table
    # Query: COUNT(*)
    # Endpoint: GET /api/v1/admin/stats
    users_resp = supabase.table("users").select("id, is_active, created_at").execute()
    users_data = users_resp.data or []
    
    total_users = len(users_data)
    active_users = sum(1 for u in users_data if u.get("is_active"))
    new_users_today = sum(1 for u in users_data if u.get("created_at") and u.get("created_at") >= today_str)

    # Source: investigations table
    # Query: COUNT(*)
    # Endpoint: GET /api/v1/admin/stats
    inv_resp = supabase.table("investigations").select("id, started_at, status").execute()
    inv_data = inv_resp.data or []
    
    total_scans = len(inv_data)
    scans_today = sum(1 for s in inv_data if s.get("started_at") and s.get("started_at") >= today_str)
    
    completed_scans = sum(1 for s in inv_data if s.get("status") == "completed")
    scan_success_rate = round((completed_scans / total_scans * 100), 1) if total_scans > 0 else 0

    # Source: findings table
    # Query: COUNT(*)
    # Endpoint: GET /api/v1/admin/stats
    findings_resp = supabase.table("findings").select("id, severity, investigation_id, created_at").execute()
    findings_data = findings_resp.data or []
    
    total_threats = len(findings_data)
    critical_threats = sum(1 for f in findings_data if f.get("severity", "").lower() == "critical")
    threats_today = sum(1 for f in findings_data if f.get("created_at") and f.get("created_at") >= today_str)
    scans_with_threats = len(set(f.get("investigation_id") for f in findings_data if f.get("investigation_id")))
    detection_rate = round((scans_with_threats / total_scans * 100), 1) if total_scans > 0 else 0.0

    # Source: infra_investigations table
    # Query: COUNT(*)
    # Endpoint: GET /api/v1/admin/stats
    try:
        infra_resp = supabase.table("infra_investigations").select("id, started_at, status, risk_score").execute()
        infra_data = infra_resp.data or []
    except Exception:
        infra_data = []

    total_infra = len(infra_data)
    infra_today = sum(1 for i in infra_data if i.get("started_at") and i.get("started_at") >= today_str)
    infra_running = sum(1 for i in infra_data if i.get("status") in ("running", "pending"))
    infra_completed = sum(1 for i in infra_data if i.get("status") == "completed")
    infra_failed = sum(1 for i in infra_data if i.get("status") == "failed")
    
    completed_risk_scores = [i.get("risk_score") or 0.0 for i in infra_data if i.get("status") == "completed"]
    avg_risk_score = round(sum(completed_risk_scores) / len(completed_risk_scores), 1) if completed_risk_scores else 0.0
    high_risk_infra = sum(1 for i in infra_data if (i.get("risk_score") or 0.0) >= 60.0)

    return {
        "users": {
            "total": total_users,
            "active": active_users,
            "newToday": new_users_today
        },
        "scans": {
            "total": total_scans,
            "today": scans_today,
            "successRate": scan_success_rate
        },
        "threats": {
            "total": total_threats,
            "critical": critical_threats,
            "today": threats_today,
            "detectionRate": detection_rate
        },
        "infra": {
            "total": total_infra,
            "today": infra_today,
            "running": infra_running,
            "completed": infra_completed,
            "failed": infra_failed,
            "avgRiskScore": avg_risk_score,
            "highRiskCount": high_risk_infra
        }
    }

@router.get("/charts", response_model=Dict[str, Any])
async def get_admin_charts(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get data for admin charts: Threat Trends, Scan Volume, Threat Distribution, Top Scanned URLs.
    """
    # Source: findings table
    # Query: GROUP BY category
    # Endpoint: GET /api/v1/admin/charts
    findings_resp = supabase.table("findings").select("category, severity").execute()
    findings_data = findings_resp.data or []
    
    distribution_counts = {}
    for f in findings_data:
        cat = f.get("category", "Unknown")
        distribution_counts[cat] = distribution_counts.get(cat, 0) + 1
        
    threat_distribution = [{"name": k, "value": v} for k, v in distribution_counts.items()]
    threat_distribution.sort(key=lambda x: x["value"], reverse=True)

    # Source: investigations table
    # Query: GROUP BY target ORDER BY count DESC LIMIT 5
    # Endpoint: GET /api/v1/admin/charts
    inv_resp = supabase.table("investigations").select("target, risk_score").execute()
    inv_data = inv_resp.data or []
    
    url_stats = {}
    for inv in inv_data:
        url = inv.get("target")
        if url:
            if url not in url_stats:
                url_stats[url] = {"count": 0, "max_risk": 0}
            url_stats[url]["count"] += 1
            risk = inv.get("risk_score", 0) or 0
            if risk > url_stats[url]["max_risk"]:
                url_stats[url]["max_risk"] = risk
                
    top_urls = []
    for url, stats in url_stats.items():
        # Derive threat level from risk score
        risk = stats["max_risk"]
        t_level = "safe"
        if risk > 80: t_level = "critical"
        elif risk > 60: t_level = "high"
        elif risk > 40: t_level = "medium"
        elif risk > 20: t_level = "low"
        
        top_urls.append({"url": url, "scan_count": stats["count"], "threat_level": t_level})
        
    top_urls.sort(key=lambda x: x["scan_count"], reverse=True)
    top_scanned_urls = top_urls[:5]

    # Source: findings table
    # Query: Group by date(created_at), severity
    # Endpoint: GET /api/v1/admin/charts
    fourteen_days_ago = datetime.now(timezone.utc) - timedelta(days=14)
    fourteen_days_str = fourteen_days_ago.isoformat()
    
    recent_findings_resp = supabase.table("findings").select("severity, created_at").gte("created_at", fourteen_days_str).execute()
    recent_findings = recent_findings_resp.data or []
    
    trends_dict = {}
    for i in range(14, -1, -1):
        dt = (datetime.now(timezone.utc) - timedelta(days=i))
        date_str = dt.strftime("%b %d")
        trends_dict[date_str] = {"date": date_str, "critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
        
    for f in recent_findings:
        created_at_str = f.get("created_at")
        if created_at_str:
            try:
                if "." in created_at_str:
                    dt = datetime.strptime(created_at_str.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                else:
                    dt = datetime.strptime(created_at_str.split("+")[0], "%Y-%m-%dT%H:%M:%S")
                date_key = dt.strftime("%b %d")
                
                sev = f.get("severity", "low").lower()
                if date_key in trends_dict and sev in trends_dict[date_key]:
                    trends_dict[date_key][sev] += 1
            except Exception:
                pass
                
    threat_trends = list(trends_dict.values())

    # Source: investigations & scans tables
    # Query: Group by date(started_at / created_at)
    # Endpoint: GET /api/v1/admin/charts
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    seven_days_str = seven_days_ago.isoformat()
    
    recent_inv_resp = supabase.table("investigations").select("started_at, tm_mode").gte("started_at", seven_days_str).execute()
    recent_inv = recent_inv_resp.data or []

    recent_scans_resp = supabase.table("scans").select("scan_type, created_at").gte("created_at", seven_days_str).execute()
    recent_scans = recent_scans_resp.data or []
    
    volume_dict = {}
    for i in range(6, -1, -1):
        dt = (datetime.now(timezone.utc) - timedelta(days=i))
        day_str = dt.strftime("%a") # e.g. "Mon"
        volume_dict[day_str] = {
            "date": day_str, 
            "url_scans": 0, 
            "file_scans": 0, 
            "malware_analysis": 0
        }
        
    for scan in recent_scans:
        created_at_str = scan.get("created_at")
        if created_at_str:
            try:
                val = created_at_str.split(".")[0].split("+")[0]
                dt = datetime.strptime(val, "%Y-%m-%dT%H:%M:%S")
                day_key = dt.strftime("%a")
                if day_key in volume_dict:
                    stype = scan.get("scan_type", "url")
                    if stype in ["file", "file_hash", "file_upload"]:
                        volume_dict[day_key]["file_scans"] += 1
                    else:
                        volume_dict[day_key]["url_scans"] += 1
            except Exception:
                pass

    for inv in recent_inv:
        started_at_str = inv.get("started_at")
        if started_at_str:
            try:
                val = started_at_str.split(".")[0].split("+")[0]
                dt = datetime.strptime(val, "%Y-%m-%dT%H:%M:%S")
                day_key = dt.strftime("%a")
                if day_key in volume_dict:
                    tm_mode = inv.get("tm_mode", "standard")
                    if tm_mode == "enhanced":
                        volume_dict[day_key]["malware_analysis"] += 1
                    else:
                        volume_dict[day_key]["url_scans"] += 1
            except Exception:
                pass
                
    scan_volume = list(volume_dict.values())

    return {
        "threatDistribution": threat_distribution,
        "topScannedUrls": top_scanned_urls,
        "threatTrends": threat_trends,
        "scanVolume": scan_volume
    }

@router.get("/activity", response_model=Dict[str, Any])
async def get_admin_activity(
    limit: int = 100,
    offset: int = 0,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get recent activity feed using real audit logs.
    """
    # Source: audit_logs table JOIN users
    # Query: SELECT audit_logs.*, users.full_name ORDER BY created_at DESC LIMIT {limit} OFFSET {offset}
    # Endpoint: GET /api/v1/admin/activity
    logs_resp = supabase.table("audit_logs").select("*, users(full_name)").order("created_at", desc=True).range(offset, offset + limit - 1).execute()
    logs_data = logs_resp.data or []
    
    activities = []
    for log in logs_data:
        severity = log.get("severity", "info").lower()
        if severity not in ["info", "warning", "critical", "success"]:
            severity = "info"
            
        user_obj = log.get("users") or {}
        metadata = log.get("metadata") or {}
        metadata_email = metadata.get("email") if isinstance(metadata, dict) else None
        
        full_name = user_obj.get("full_name")
        if not full_name:
            if metadata_email:
                full_name = metadata_email.split("@")[0]
            else:
                full_name = "System"
            
        activities.append({
            "id": log.get("id"),
            "type": log.get("action_type", "system"),
            "message": log.get("message", ""),
            "timestamp": log.get("created_at", ""),
            "severity": severity,
            "user": full_name
        })
        
    return {
        "recentActivity": activities
    }

@router.get("/audit/list", response_model=Dict[str, Any])
async def get_admin_audit_list(
    limit: int = 100,
    offset: int = 0,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get full paginated audit logs for the Audit Log page.
    """
    # Source: audit_logs table JOIN users
    # Query: SELECT audit_logs.*, users(email, full_name, role) ORDER BY created_at DESC LIMIT {limit} OFFSET {offset}
    logs_resp = supabase.table("audit_logs").select("*, users(email, full_name, role)").order("created_at", desc=True).range(offset, offset + limit - 1).execute()
    logs_data = logs_resp.data or []
    
    mapped_logs = []
    for log in logs_data:
        user_data = log.get("users") or {}
        severity = log.get("severity", "info").lower()
        
        status = "success"
        action_type = log.get("action_type", "")
        if "FAILED" in action_type or "FAILURE" in action_type:
            status = "failure"
        elif severity == "warning" and action_type not in ["USER_ROLE_CHANGE", "USER_STATUS_CHANGE"]:
            status = "warning"
        elif severity == "critical" and action_type not in ["USER_ROLE_CHANGE", "USER_STATUS_CHANGE"]:
            status = "failure"
        
        metadata = log.get("metadata") or {}
        metadata_email = metadata.get("email") if isinstance(metadata, dict) else None
        user_agent = metadata.get("user_agent") if isinstance(metadata, dict) else None
        
        user_email = user_data.get("email") or metadata_email or "system@tibsa.ai"
        
        user_name = user_data.get("full_name")
        if not user_name:
            if metadata_email:
                user_name = metadata_email.split("@")[0]
            else:
                user_name = "System"
        
        mapped_logs.append({
            "id": log.get("id"),
            "timestamp": log.get("created_at", ""),
            "user_email": user_email,
            "user_name": user_name,
            "user_role": user_data.get("role") or ("system" if not metadata_email else "user"),
            "user_agent": user_agent or "Unknown Device",
            "action": log.get("action_type", "system"),
            "resource": log.get("metadata", {}).get("resource") or "system",
            "details": log.get("message", ""),
            "ip_address": log.get("ip_address") or "0.0.0.0",
            "status": status
        })
        
    return {"logs": mapped_logs}

@router.get("/users/list", response_model=Dict[str, Any])
async def get_admin_users_list(
    limit: int = 100,
    offset: int = 0,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get paginated list of users for the User Management page.
    """
    # 1. Fetch users
    users_resp = supabase.table("users").select("*").order("created_at", desc=True).range(offset, offset + limit - 1).execute()
    users_data = users_resp.data or []
    
    # 2. Fetch scans to dynamically count user metrics
    try:
        scans_resp = supabase.table("scans").select("user_id, threat_level").execute()
        scans_data = scans_resp.data or []
    except Exception:
        scans_data = []

    user_scan_counts = {}
    user_threat_counts = {}
    for s in scans_data:
        uid = s.get("user_id")
        if uid:
            user_scan_counts[uid] = user_scan_counts.get(uid, 0) + 1
            threat = s.get("threat_level")
            if threat and threat.lower() not in ["safe", "none", "clear", "clean"]:
                user_threat_counts[uid] = user_threat_counts.get(uid, 0) + 1

    mapped_users = []
    now = datetime.now(timezone.utc)
    for u in users_data:
        uid = u.get("id")
        # Check active presence in-memory cache, then fallback to database if present
        last_login_str = ACTIVE_PRESENCE.get(uid) or u.get("last_seen")
        
        is_online = False
        if last_login_str:
            try:
                dt = datetime.fromisoformat(last_login_str.replace("Z", "+00:00"))
                is_online = (now - dt).total_seconds() <= 30
            except Exception:
                pass
                
        mapped_users.append({
            "id": uid,
            "email": u.get("email"),
            "full_name": u.get("full_name") or "Unknown User",
            "role": u.get("role", "user"),
            "is_active": u.get("is_active", True),
            "created_at": u.get("created_at"),
            "updated_at": u.get("updated_at"),
            "last_login": last_login_str,
            "is_online": is_online,
            "total_scans": user_scan_counts.get(uid, 0),
            "threats_found": user_threat_counts.get(uid, 0),
            "storage_used": 0
        })
        
    # Stable sort:
    # 1. Sort by last_login descending (most recent first, None/Never last)
    mapped_users.sort(key=lambda x: x["last_login"] or "1970-01-01T00:00:00", reverse=True)
    # 2. Sort by is_active descending (True first, False/Inactive pushed to the bottom)
    mapped_users.sort(key=lambda x: x["is_active"], reverse=True)

    return {"users": mapped_users}

@router.get("/users/growth", response_model=Dict[str, Any])
async def get_admin_users_growth(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get user registration growth over the last 6 months.
    """
    six_months_ago = datetime.now(timezone.utc) - timedelta(days=180)
    
    # Source: users table
    users_resp = supabase.table("users").select("created_at, is_active").gte("created_at", six_months_ago.isoformat()).execute()
    users_data = users_resp.data or []
    
    growth_dict = {}
    for i in range(5, -1, -1):
        dt = (datetime.now(timezone.utc) - timedelta(days=30*i))
        month_str = dt.strftime("%b")
        growth_dict[month_str] = {"month": month_str, "users": 0, "active": 0}
        
    for u in users_data:
        created_at_str = u.get("created_at")
        if created_at_str:
            try:
                if "." in created_at_str: dt = datetime.strptime(created_at_str.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                else: dt = datetime.strptime(created_at_str.split("+")[0], "%Y-%m-%dT%H:%M:%S")
                month_key = dt.strftime("%b")
                
                if month_key in growth_dict:
                    growth_dict[month_key]["users"] += 1
                    if u.get("is_active"):
                        growth_dict[month_key]["active"] += 1
            except Exception: pass
            
    return {"growth": list(growth_dict.values())}

@router.get("/threats/top", response_model=Dict[str, Any])
async def get_admin_top_threats(
    limit: int = 100,
    offset: int = 0,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get top paginated threats/findings.
    """
    findings_resp = supabase.table("findings").select("*").order("created_at", desc=True).range(offset, offset + limit - 1).execute()
    findings_data = findings_resp.data or []
    
    # Map findings to the analyst who initiated the scan
    user_mapping = {}  # investigation_id -> user_full_name
    inv_ids = {f.get("investigation_id") for f in findings_data if f.get("investigation_id")}
    
    if inv_ids:
        try:
            # Query investigations table directly to get user_id
            inv_resp = supabase.table("investigations").select("id, user_id").in_("id", list(inv_ids)).execute()
            inv_data = inv_resp.data or []
            
            inv_to_user = {}
            user_ids = set()
            for inv in inv_data:
                iid = inv.get("id")
                uid = inv.get("user_id")
                if iid and uid:
                    user_ids.add(uid)
                    inv_to_user[iid] = uid
            
            if user_ids:
                users_resp = supabase.table("users").select("id, full_name").in_("id", list(user_ids)).execute()
                users_data = users_resp.data or []
                user_names = {u.get("id"): u.get("full_name") for u in users_data if u.get("id")}
                
                for iid, uid in inv_to_user.items():
                    name = user_names.get(uid, "Unknown Analyst")
                    user_mapping[iid] = name
        except Exception as e:
            print(f"Failed to map threat users: {e}")

    mapped_threats = []
    for f in findings_data:
        asset_url = f.get("affected_url") or "Unknown Payload"
        iid = f.get("investigation_id")
        analyst_name = user_mapping.get(iid, "System")
        
        mapped_threats.append({
            "id": f.get("id"),
            "indicator": f.get("title") or "Unnamed Threat",
            "type": "url", # Based on our schema
            "threat_level": f.get("severity", "low").lower(),
            "detections": 1,
            "first_seen": f.get("created_at"),
            "last_seen": f.get("created_at"),
            "source": asset_url,
            "name": f.get("category", "General"),
            "score": 90 if str(f.get("severity")).lower() == "critical" else 50,
            "analyst_name": analyst_name
        })
        
    return {"threats": mapped_threats}

@router.get("/investigate/{context_type}/{value}", response_model=Dict[str, Any])
async def investigate_context(
    context_type: str,
    value: str,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get real investigation data for an IP or User.
    context_type: 'ip' or 'user'
    """
    result = {
        "geo": None,
        "internal_hits": [],
        "recent_activity": [],
        "devices": []
    }
    
    unique_devices = {}  # Key: parsed name, Value: raw user agent
    infra_investigations = []
    
    if context_type == "ip":
        # 1. Fetch real GeoIP data from free API
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(f"http://ip-api.com/json/{value}?fields=status,message,country,city,isp,org", timeout=5.0)
                if r.status_code == 200:
                    geo_data = r.json()
                    if geo_data.get("status") == "success":
                        result["geo"] = {
                            "isp": geo_data.get("isp") or geo_data.get("org") or "Unknown ISP",
                            "location": f"{geo_data.get('city', 'Unknown City')}, {geo_data.get('country', 'Unknown Country')}"
                        }
                    else:
                        result["geo"] = {
                            "isp": "Local/Private Network",
                            "location": "Internal IP"
                        }
        except Exception:
            result["geo"] = {"isp": "Lookup Failed", "location": "Unknown"}
            
        # 2. Internal Hits (Check if IP is associated with critical audit log failures)
        hits_resp = supabase.table("audit_logs").select("*").eq("ip_address", value).eq("severity", "critical").limit(5).execute()
        hits_data = hits_resp.data or []
        for hit in hits_data:
            result["internal_hits"].append({
                "type": "Critical Error",
                "details": hit.get("message", "Unknown event"),
                "timestamp": hit.get("created_at")
            })
            
        # 3. Recent Activity
        activity_resp = supabase.table("audit_logs").select("*, users(full_name)").eq("ip_address", value).order("created_at", desc=True).limit(10).execute()
        activity_data = activity_resp.data or []
        for log in activity_data:
            metadata = log.get("metadata") or {}
            ua = metadata.get("user_agent") if isinstance(metadata, dict) else None
            if ua and ua != "Unknown Device":
                unique_devices[ua] = ua
                
            result["recent_activity"].append({
                "action": log.get("action_type"),
                "timestamp": log.get("created_at"),
                "status": log.get("severity"),
                "user_agent": ua
            })
            
        # 4. Fetch additional unique devices from login_attempts table (helps populate historical records)
        try:
            attempts_resp = supabase.table("login_attempts").select("user_agent").eq("ip_address", value).limit(50).execute()
            for attempt in (attempts_resp.data or []):
                raw_ua = attempt.get("user_agent")
                if raw_ua:
                    parsed_ua = parse_user_agent(raw_ua)
                    if parsed_ua and parsed_ua != "Unknown Device":
                        unique_devices[parsed_ua] = raw_ua
        except Exception:
            pass

        # 5. Fetch related infra investigations for this IP
        try:
            infra_resp = supabase.table("infra_investigations") \
                .select("id, target, target_type, status, risk_score, started_at") \
                .eq("target", value) \
                .limit(10) \
                .execute()
            infra_investigations = infra_resp.data or []
        except Exception:
            pass
            
    elif context_type == "user":
        # 1. User Info
        user_resp = supabase.table("users").select("id, email, full_name, role, is_active").eq("full_name", value).limit(1).execute()
        user_id = None
        email = None
        if user_resp.data:
            u = user_resp.data[0]
            user_id = u.get("id")
            email = u.get("email")
            result["geo"] = {
                "isp": email,
                "location": f"Role: {u.get('role', 'user').upper()} | Status: {'Active' if u.get('is_active') else 'Inactive'}"
            }
            
            # Internal Hits
            if not u.get("is_active"):
                result["internal_hits"].append({
                    "type": "Account Status",
                    "details": "Account Deactivated",
                    "timestamp": "N/A"
                })
            
        # 3. Recent Activity by User ID
        if user_id:
            activity_resp = supabase.table("audit_logs").select("*").eq("user_id", user_id).order("created_at", desc=True).limit(10).execute()
            activity_data = activity_resp.data or []
            for log in activity_data:
                metadata = log.get("metadata") or {}
                ua = metadata.get("user_agent") if isinstance(metadata, dict) else None
                if ua and ua != "Unknown Device":
                    unique_devices[ua] = ua
                    
                result["recent_activity"].append({
                    "action": log.get("action_type"),
                    "timestamp": log.get("created_at"),
                    "status": log.get("severity"),
                    "user_agent": ua
                })
                
        # 4. Fetch additional unique devices from login_attempts table (helps populate historical records)
        if email:
            try:
                attempts_resp = supabase.table("login_attempts").select("user_agent").eq("email", email).limit(50).execute()
                for attempt in (attempts_resp.data or []):
                    raw_ua = attempt.get("user_agent")
                    if raw_ua:
                        parsed_ua = parse_user_agent(raw_ua)
                        if parsed_ua and parsed_ua != "Unknown Device":
                            unique_devices[parsed_ua] = raw_ua
            except Exception:
                pass

        # 5. Fetch related infra investigations for this user ID
        if user_id:
            try:
                infra_resp = supabase.table("infra_investigations") \
                    .select("id, target, target_type, status, risk_score, started_at") \
                    .eq("user_id", user_id) \
                    .limit(10) \
                    .execute()
                infra_investigations = infra_resp.data or []
            except Exception:
                pass
                
    result["devices"] = [{"name": name, "raw": raw} for name, raw in unique_devices.items()]
    result["infra_investigations"] = infra_investigations
    return result


@router.get("/presence", response_model=Dict[str, Any])
async def get_active_presence(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get active users and administrators presence status.
    Online if last_seen is within the last 30 seconds.
    """
    try:
        from datetime import datetime, timezone
        
        # Fetch all registered users (excluding last_seen to ensure 100% database-free column errors)
        res = supabase.table("users").select("id, email, full_name, role, is_active").execute()
        users_data = res.data or []
        
        active_users = []
        offline_users = []
        active_count = 0
        now = datetime.now(timezone.utc)
        
        for u in users_data:
            uid = u.get("id")
            # Retrieve from our robust in-memory presence cache
            last_seen_str = ACTIVE_PRESENCE.get(uid)
            is_online = False
            seconds_ago = 999999
            
            if last_seen_str:
                try:
                    # Parse timestamp cleanly
                    dt = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                    seconds_ago = int((now - dt).total_seconds())
                    is_online = seconds_ago <= 30
                except Exception:
                    pass
            
            user_entry = {
                "id": uid,
                "email": u.get("email"),
                "full_name": u.get("full_name") or "Unknown Analyst",
                "role": u.get("role") or "user",
                "is_active": u.get("is_active", True),
                "last_seen": last_seen_str,
                "seconds_ago": seconds_ago,
                "status": "online" if is_online else "offline"
            }
            
            if is_online:
                active_users.append(user_entry)
                active_count += 1
            else:
                offline_users.append(user_entry)
                
        # Sort active users: active status first, then most recently active first
        active_users.sort(key=lambda x: (not x["is_active"], x["seconds_ago"]))
        
        # Sort offline users: active status first, then most recently active first
        offline_users.sort(key=lambda x: (not x["is_active"], x["seconds_ago"]))
        
        return {
            "active_users": active_users,
            "offline_users": offline_users,
            "active_count": active_count
        }
    except Exception as e:
        return {
            "active_users": [],
            "offline_users": [],
            "active_count": 0,
            "error": str(e)
        }

# ─── System Settings CRUD endpoints ───────────────────────────
from pydantic import BaseModel
from fastapi.responses import JSONResponse

class SettingsUpdateRequest(BaseModel):
    toggles: List[Dict[str, Any]]
    inputs: List[Dict[str, Any]]

class WebhookTestRequest(BaseModel):
    webhook_url: str

@router.get("/settings")
async def get_system_settings(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get all system settings from Supabase. Fallbacks to defaults if the table does not exist.
    """
    defaults_dict = {
        "2fa": "true",
        "audit": "true",
        "auto_block": "true",
        "email_alerts": "false",
        "api_access": "true",
        "dark_mode": "true",
        "rate_limit": "150",
        "session_timeout": "30",
        "max_file_size": "50",
        "webhook_url": ""
    }
    
    settings_dict = defaults_dict.copy()
    
    try:
        res = supabase.table("system_settings").select("*").execute()
        if res.data:
            for item in res.data:
                settings_dict[item["key"]] = item["value"]
    except Exception:
        # Fallback gracefully if system_settings table does not exist yet
        pass

    return {
        "toggles": [
            { "key": "2fa", "label": "Enforce 2FA", "description": "Require all users to enable two-factor authentication", "enabled": settings_dict.get("2fa", "true") == "true" },
            { "key": "audit", "label": "Audit Logging", "description": "Log all admin and security-relevant actions", "enabled": settings_dict.get("audit", "true") == "true" },
            { "key": "auto_block", "label": "Auto-Block Threats", "description": "Automatically block IPs that exceed threat threshold", "enabled": settings_dict.get("auto_block", "true") == "true" },
            { "key": "email_alerts", "label": "Email Alerts", "description": "Send email notifications for critical security events", "enabled": settings_dict.get("email_alerts", "false") == "true" },
            { "key": "api_access", "label": "Public API Access", "description": "Allow external API access with API keys", "enabled": settings_dict.get("api_access", "true") == "true" },
            { "key": "dark_mode", "label": "Force Dark Mode", "description": "Enforce dark mode for all users", "enabled": settings_dict.get("dark_mode", "true") == "true" }
        ],
        "inputs": [
            { "key": "rate_limit", "label": "Rate Limit", "description": "Maximum API requests per minute per user (1-10000)", "value": settings_dict.get("rate_limit", "150"), "type": "number", "placeholder": "100", "min": 1, "max": 10000 },
            { "key": "session_timeout", "label": "Session Timeout", "description": "Minutes of inactivity before session expires (5-1440)", "value": settings_dict.get("session_timeout", "30"), "type": "number", "placeholder": "30", "min": 5, "max": 1440 },
            { "key": "max_file_size", "label": "Max Upload Size", "description": "Maximum file upload size in MB (1-500)", "value": settings_dict.get("max_file_size", "50"), "type": "number", "placeholder": "50", "min": 1, "max": 500 },
            { "key": "webhook_url", "label": "Webhook URL", "description": "URL for security event webhooks (must be valid HTTPS URL)", "value": settings_dict.get("webhook_url", ""), "type": "text", "placeholder": "https://hooks.example.com/alerts" }
        ]
    }

@router.post("/settings")
async def update_system_settings(
    payload: SettingsUpdateRequest,
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Update system settings in Supabase.
    """
    updates = []
    
    # Process toggles
    for toggle in payload.toggles:
        key = toggle.get("key")
        val = "true" if toggle.get("enabled") else "false"
        if key:
            updates.append({"key": key, "value": val})
            
    # Process inputs
    for inp in payload.inputs:
        key = inp.get("key")
        val = str(inp.get("value", ""))
        if key:
            updates.append({"key": key, "value": val})
            
    try:
        supabase.table("system_settings").upsert(updates).execute()
        return {"success": True, "message": "Settings updated successfully"}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"Failed to save settings. Please run the SQL script in 'database/07_settings.sql' inside your Supabase SQL Editor. Error details: {str(e)}"
            }
        )

@router.post("/settings/test-webhook")
async def test_webhook_connection(
    payload: WebhookTestRequest,
    _admin: dict = Depends(require_admin),
):
    """
    Test delivery of a JSON payload to a specified webhook URL.
    """
    url = payload.webhook_url
    if not (url.startswith("http://") or url.startswith("https://")):
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "URL must start with http:// or https://"}
        )
        
    try:
        async with httpx.AsyncClient() as client:
            test_payload = {
                "event": "test",
                "message": "TIBSA Webhook Test Connection Successful",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            resp = await client.post(url, json=test_payload, timeout=5.0)
            if 200 <= resp.status_code < 300:
                return {"success": True, "message": f"Webhook delivered successfully (Status: {resp.status_code})"}
            else:
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "message": f"Webhook returned failure status: {resp.status_code}"}
                )
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": f"Connection failed: {str(e)}"}
        )

@router.post("/settings/reset-feeds")
async def reset_threat_feeds(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Reset threat intelligence feeds in Supabase to defaults.
    """
    try:
        # Delete existing feeds (this cascade deletes indicators)
        supabase.table("threat_feeds").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        
        # Insert default feeds
        defaults = [
            {"name": "Abuse.ch URLhaus", "provider": "Abuse.ch", "category": "malware", "source_url": "https://urlhaus.abuse.ch/downloads/text/", "is_active": True, "indicators_count": 1420, "reliability_score": 95, "update_frequency": "Hourly"},
            {"name": "PhishTank Active Phishing", "provider": "CleanTalk", "category": "phishing", "source_url": "https://www.phishtank.com/", "is_active": True, "indicators_count": 850, "reliability_score": 92, "update_frequency": "Hourly"},
            {"name": "Emerging Threats Open IPs", "provider": "Proofpoint", "category": "c2", "source_url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "is_active": True, "indicators_count": 2400, "reliability_score": 88, "update_frequency": "Daily"},
            {"name": "Tor Exit Nodes List", "provider": "Tor Project", "category": "general", "source_url": "https://check.torproject.org/exit-addresses", "is_active": True, "indicators_count": 1150, "reliability_score": 99, "update_frequency": "Daily"},
            {"name": "AlienVault OTX", "provider": "AT&T Cybersecurity", "category": "apt", "source_url": "https://otx.alienvault.com/", "is_active": False, "indicators_count": 0, "reliability_score": 90, "update_frequency": "Daily"}
        ]
        
        supabase.table("threat_feeds").insert(defaults).execute()
        return {"success": True, "message": "Threat feeds reset to defaults successfully"}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"Failed to reset feeds: {str(e)}"}
        )

@router.post("/settings/purge-data")
async def purge_historical_scan_data(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Purge scan history older than 90 days from both SQLite and Supabase databases.
    """
    try:
        cutoff_str = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        
        # 1. Purge from Supabase scans
        supabase.table("scans").delete().lt("created_at", cutoff_str).execute()
        
        # 2. Purge from Supabase investigations
        supabase.table("investigations").delete().lt("started_at", cutoff_str).execute()
        
        # 3. Purge from SQLite (using SQLAlchemy)
        from sqlalchemy import delete
        from app.models.investigation import Investigation
        from app.models.finding import Finding
        from app.database.session import async_session
        cutoff_dt = datetime.utcnow() - timedelta(days=90)
        async with async_session() as session:
            async with session.begin():
                await session.execute(delete(Investigation).where(Investigation.started_at < cutoff_dt))
                await session.execute(delete(Finding).where(Finding.created_at < cutoff_dt))
                
        return {"success": True, "message": "Historical scan data purged successfully"}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"Failed to purge scan data: {str(e)}"}
        )

@router.get("/infra-analytics", response_model=Dict[str, Any])
async def get_admin_infra_analytics(
    _admin: dict = Depends(require_admin),
    supabase: Client = Depends(get_supabase),
):
    """
    Get detailed metrics for the Infrastructure Intelligence Analytics page.
    """
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_str = today.isoformat()

    try:
        infra_resp = supabase.table("infra_investigations").select("id, target, target_type, status, risk_score, started_at, completed_at, user_id").execute()
        infra_data = infra_resp.data or []
    except Exception:
        infra_data = []
        
    total_infra = len(infra_data)
    infra_today = sum(1 for i in infra_data if i.get("started_at") and i.get("started_at") >= today_str)
    infra_running = sum(1 for i in infra_data if i.get("status") in ("running", "pending"))
    infra_completed = sum(1 for i in infra_data if i.get("status") == "completed")
    infra_failed = sum(1 for i in infra_data if i.get("status") == "failed")
    
    completed_risk_scores = [i.get("risk_score") or 0.0 for i in infra_data if i.get("status") == "completed"]
    avg_risk_score = round(sum(completed_risk_scores) / len(completed_risk_scores), 1) if completed_risk_scores else 0.0
    high_risk_infra = sum(1 for i in infra_data if (i.get("risk_score") or 0.0) >= 60.0)

    # 1. IOC Type Distribution (IP, Domain, URL, Hash, Email)
    ioc_counts = {"ip": 0, "domain": 0, "url": 0, "hash": 0, "email": 0}
    for i in infra_data:
        ttype = (i.get("target_type") or "url").lower()
        if ttype in ioc_counts:
            ioc_counts[ttype] += 1
        else:
            ioc_counts[ttype] = ioc_counts.get(ttype, 0) + 1
            
    ioc_distribution = [{"name": k.upper(), "value": v} for k, v in ioc_counts.items()]

    # 2. Trends: Investigation Trends (last 30 days)
    trends_dict = {}
    for i in range(30, -1, -1):
        dt = (datetime.now(timezone.utc) - timedelta(days=i))
        date_key = dt.strftime("%b %d")
        trends_dict[date_key] = {"date": date_key, "count": 0, "high_risk": 0}
        
    for i in infra_data:
        started_at = i.get("started_at")
        if started_at:
            try:
                val = started_at.split(".")[0].split("+")[0]
                dt = datetime.strptime(val, "%Y-%m-%dT%H:%M:%S")
                date_key = dt.strftime("%b %d")
                if date_key in trends_dict:
                    trends_dict[date_key]["count"] += 1
                    if (i.get("risk_score") or 0.0) >= 60.0:
                        trends_dict[date_key]["high_risk"] += 1
            except Exception:
                pass
                
    trends_list = list(trends_dict.values())

    # 3. Top Investigated IOCs
    ioc_stats = {}
    for i in infra_data:
        target = i.get("target")
        if target:
            if target not in ioc_stats:
                ioc_stats[target] = {"target": target, "type": i.get("target_type", "url"), "count": 0, "max_risk": 0.0}
            ioc_stats[target]["count"] += 1
            risk = i.get("risk_score") or 0.0
            if risk > ioc_stats[target]["max_risk"]:
                ioc_stats[target]["max_risk"] = risk
                
    top_iocs = list(ioc_stats.values())
    top_iocs.sort(key=lambda x: x["count"], reverse=True)
    top_iocs = top_iocs[:10]

    # Map analyst names
    user_names = {}
    try:
        users_resp = supabase.table("users").select("id, full_name, email").execute()
        for u in (users_resp.data or []):
            user_names[u["id"]] = u.get("full_name") or u.get("email").split("@")[0]
    except Exception:
        pass

    # 4. Top High-Risk Investigations
    high_risk_list = []
    for i in infra_data:
        risk = i.get("risk_score") or 0.0
        if risk >= 60.0:
            uid = i.get("user_id")
            high_risk_list.append({
                "id": i.get("id"),
                "target": i.get("target"),
                "type": i.get("target_type"),
                "risk_score": risk,
                "status": i.get("status"),
                "started_at": i.get("started_at"),
                "analyst": user_names.get(uid, "System")
            })
    high_risk_list.sort(key=lambda x: x["risk_score"], reverse=True)
    top_high_risk = high_risk_list[:10]

    # 5. Recent Investigations
    recent_list = []
    for i in infra_data:
        uid = i.get("user_id")
        recent_list.append({
            "id": i.get("id"),
            "target": i.get("target"),
            "type": i.get("target_type"),
            "risk_score": i.get("risk_score") or 0.0,
            "status": i.get("status"),
            "current_stage": i.get("current_stage"),
            "progress_percent": i.get("progress_percent") or 0.0,
            "started_at": i.get("started_at"),
            "analyst": user_names.get(uid, "System")
        })
    recent_list.sort(key=lambda x: x["started_at"] or "", reverse=True)
    recent_infra = recent_list[:10]

    return {
        "stats": {
            "total": total_infra,
            "today": infra_today,
            "running": infra_running,
            "completed": infra_completed,
            "failed": infra_failed,
            "avgRiskScore": avg_risk_score,
            "highRiskCount": high_risk_infra
        },
        "iocDistribution": ioc_distribution,
        "trends": trends_list,
        "topIocs": top_iocs,
        "topHighRisk": top_high_risk,
        "recent": recent_infra
    }
