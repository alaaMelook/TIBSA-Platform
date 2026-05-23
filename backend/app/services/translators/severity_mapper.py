"""
Severity Mapper logic.
Converts any scanner-specific severity representation to standardized categories.
"""
def map_severity(raw_severity: str) -> str:
    """
    Standardizes varying severity string formats to high, medium, low, critical, or info.
    Examples:
        "High" -> "high"
        "medium risk" -> "medium"
        "Crit" -> "critical"
    """
    if not raw_severity:
        return "info"
        
    sev = str(raw_severity).lower().strip()
    
    if "critical" in sev or "crit" in sev:
        return "critical"
    elif "high" in sev:
        return "high"
    elif "medium" in sev or "med" in sev:
        return "medium"
    elif "low" in sev:
        return "low"
    elif "info" in sev or "informational" in sev:
        return "info"
        
    return "info"
