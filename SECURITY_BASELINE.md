# TIBSA Platform Security Baseline

This document outlines the security features, policies, and configurations implemented across the TIBSA Platform to ensure robust protection against OWASP Top 10 vulnerabilities, unauthorized access, and automated attacks.

## 1. Authentication & Session Management
- **Auth Strategy:** JWT Bearer tokens powered by Supabase Auth. Passwords and sessions are securely managed by the Supabase managed service.
- **Password Hashing:** Passwords are never stored in plaintext. They are automatically hashed using `bcrypt` by Supabase.
- **Strong Password Policy:** Enforced server-side using Pydantic validators (`backend/app/models/user.py`).
  - Minimum length: 12 characters.
  - Must contain at least one uppercase letter, lowercase letter, number, and special character.
- **User Enumeration Protection:** Generic error messages ("Invalid credentials", "Registration failed") are returned for both login and registration failures (`backend/app/services/auth_service.py`).
- **Session Management:** The frontend client manages the JWT tokens. Because tokens are sent via the `Authorization: Bearer <token>` header, the application is inherently protected against Cross-Site Request Forgery (CSRF).

## 2. Rate Limiting (Brute-Force Protection)
- **Tooling:** Implemented using `slowapi` on the FastAPI backend (`backend/app/utils/limiter.py`).
- **Limits Enforced:**
  - `POST /api/v1/auth/login`: 5 requests per minute.
  - `POST /api/v1/auth/register`: 3 requests per minute.
- **Error Handling:** Exceeding these limits returns a generic `429 Too Many Requests` response.

## 3. OWASP Top 10 Protections
- **Injection (SQLi):** Mitigated by the use of the Supabase ORM (PostgREST), which strictly uses parameterized queries and avoids direct SQL string concatenation.
- **Cross-Site Scripting (XSS):** The React/Next.js frontend natively escapes all dynamic content. No instances of unvalidated `dangerouslySetInnerHTML` are exposed to user input.
- **Cross-Site Request Forgery (CSRF):** Since JWTs are stored in the client and sent explicitly via the `Authorization` header rather than ambient cookies, CSRF attacks are neutralized.

## 4. Security Headers & CORS
- **Security Headers Middleware:** Added to `backend/app/main.py`.
  - `Content-Security-Policy`: Restricts scripts and styles to `self` (with inline allowance for Next.js compat).
  - `Strict-Transport-Security`: Enforces HTTPS (HSTS) with a max-age of 1 year.
  - `X-Frame-Options: DENY`: Prevents Clickjacking.
  - `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing.
  - `Referrer-Policy: strict-origin-when-cross-origin`: Protects referrer leakage.
  - `Permissions-Policy`: Disables geolocation, camera, and microphone.
- **Information Leakage:** The `Server` header is aggressively stripped from all API responses to hide the underlying framework.
- **CORS Policy:** Strict adherence to `settings.cors_origins_list` with no wildcard (`*`) allowed for authenticated endpoints.

## 5. Security Logging & Monitoring
- Dedicated security logging has been implemented in `backend/app/services/auth_service.py`.
- **Logged Events:** Successful logins, failed login attempts, successful registrations, and failed registration attempts.
- **Data Protection:** Passwords, JWTs, and sensitive personal data are **never** logged.

## 6. Testing the Security Baseline

Here are exact steps to verify the security controls:

### Test 1: Strong Password Policy
Try to register with a weak password (e.g., "password123"):
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123", "full_name": "Test User"}'
```
*Expected:* `422 Unprocessable Entity` with a message stating the password requirements.

### Test 2: Rate Limiting
Execute the login request 6 times rapidly:
```bash
for i in {1..6}; do curl -X POST http://localhost:8000/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"test@example.com","password":"ValidPass123!"}'; done
```
*Expected:* The 6th request will return `429 Too Many Requests`.

### Test 3: User Enumeration Protection
Attempt to login with a non-existent email:
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "doesnotexist@example.com", "password": "ValidPass123!"}'
```
*Expected:* `401 Unauthorized` with the generic message "Invalid credentials".

### Test 4: Security Headers
Inspect the headers of any API response:
```bash
curl -I http://localhost:8000/api/v1/health
```
*Expected:* Response includes `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and does **not** include a `Server` header.

## Files Modified
1. `backend/app/models/user.py` (Password validation logic)
2. `backend/app/utils/limiter.py` (Created slowapi instance)
3. `backend/app/main.py` (Headers middleware, rate limiter integration)
4. `backend/app/routers/auth.py` (Rate limit decorators)
5. `backend/app/services/auth_service.py` (Security logging & generic error messages)
6. `frontend/src/contexts/AuthContext.tsx` (Refactored to route auth through the secure backend endpoints)
