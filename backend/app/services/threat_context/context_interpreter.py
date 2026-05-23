"""
Threat Context Interpreter.
Maps vulnerability details to high-level security architecture categories.
"""
def interpret_context(title: str, raw_category: str) -> str:
    """
    Categorizes vulnerabilities into:
    - Client-Side Security
    - Session Security
    - Authentication Security
    - Authorization Security
    - API Security
    - Hardening
    - Information Disclosure
    - Injection Vulnerability
    """
    title_lower = title.lower()
    raw_cat_lower = raw_category.lower() if raw_category else ""
    
    # Matching rules
    if any(x in title_lower for x in ["csp", "content security policy", "xss", "cross-site scripting", "clickjacking"]):
        return "Client-Side Security"
    elif any(x in title_lower for x in ["cookie", "session", "secure flag", "httponly", "samesite"]):
        return "Session Security"
    elif any(x in title_lower for x in ["rate limit", "brute force", "auth", "password", "login"]):
        return "Authentication Security"
    elif any(x in title_lower for x in ["idor", "bac", "broken access", "privilege escalation"]):
        return "Authorization Security"
    elif any(x in title_lower for x in ["cors", "cross-origin", "api", "graphql", "rest"]):
        return "API Security"
    elif any(x in title_lower for x in ["sql injection", "sqli"]):
        return "Injection Vulnerability"
    elif any(x in title_lower for x in ["directory", "path traversal", "exposed", "sensitive data", "backup"]):
        return "Information Disclosure"
    elif any(x in title_lower for x in ["header", "hsts", "x-frame-options", "ssl", "tls", "csrf"]):
        return "Hardening"
        
    # Check raw category string
    if "vulnerability" in raw_cat_lower:
        return "Injection Vulnerability"
    elif "misconfiguration" in raw_cat_lower:
        return "Hardening"
    elif "hardening" in raw_cat_lower:
        return "Hardening"
    elif "session" in raw_cat_lower:
        return "Session Security"
    elif "auth" in raw_cat_lower:
        return "Authentication Security"
        
    return raw_category if raw_category else "Informational"
