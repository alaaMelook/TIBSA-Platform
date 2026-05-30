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
    
    # Matching rules ordered from specific to generic keywords
    if any(x in title_lower for x in ["csrf", "cross-site request forgery"]):
        return "Hardening"
    elif any(x in title_lower for x in ["csp", "content security policy", "xss", "cross-site scripting", "clickjacking"]):
        return "Client-Side Security"
    elif any(x in title_lower for x in ["sql injection", "sqli", "injection"]):
        return "Injection Vulnerability"
    elif any(x in title_lower for x in ["authz", "authorization", "access control", "permission", "privilege escalation", "idor", "bac", "broken access"]):
        return "Authorization Security"
    elif any(x in title_lower for x in ["auth", "authentication", "login", "password", "credentials", "rate limit", "brute force"]):
        return "Authentication Security"
    elif any(x in title_lower for x in ["cookie", "session", "secure flag", "httponly", "samesite"]):
        return "Session Security"
    elif any(x in title_lower for x in ["cors", "cross-origin", "api", "graphql", "rest", "ssrf", "server-side request forgery"]):
        return "API Security"
    elif any(x in title_lower for x in ["directory", "path traversal", "exposed", "sensitive data", "backup", "robots.txt", "sitemap"]):
        return "Information Disclosure"
    elif any(x in title_lower for x in ["header", "hsts", "x-frame-options", "ssl", "tls", "https", "http", "transport"]):
        return "Hardening"
        
    # Check raw category string
    if "injection" in raw_cat_lower:
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
