-- ============================================
-- TIBSA Schema 08: Admin Features
-- Run this in Supabase SQL Editor
-- ============================================

-- 1. API Integrations (Dynamic Scan Key Manager)
CREATE TABLE IF NOT EXISTS public.api_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name VARCHAR(50) UNIQUE NOT NULL,
    api_key TEXT NOT NULL,
    quota_limit_daily INT NOT NULL DEFAULT 1000,
    quota_used_today INT NOT NULL DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    last_checked_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Seed defaults for API Integrations
INSERT INTO public.api_integrations (service_name, api_key, quota_limit_daily, quota_used_today) VALUES
('virustotal', 'placeholder_vt_key', 500, 0),
('abuseipdb', 'placeholder_abuseip_key', 1000, 0),
('ip-api', 'placeholder_ipapi_key', 10000, 0)
ON CONFLICT (service_name) DO NOTHING;

-- 2. System Blocklist (Platform Firewall / WAF)
CREATE TABLE IF NOT EXISTS public.system_blocklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator VARCHAR(255) UNIQUE NOT NULL, -- e.g., '192.168.1.100' or 'malicious-domain.com'
    type VARCHAR(20) NOT NULL,               -- 'ip', 'domain', 'url'
    reason TEXT,
    blocked_by VARCHAR(50) DEFAULT 'system',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Seed initial test blocks
INSERT INTO public.system_blocklist (indicator, type, reason, blocked_by) VALUES
('198.51.100.42', 'ip', 'Brute force scans detected on auth endpoint', 'system'),
('phishing-attacker-node.net', 'domain', 'Known phishing host', 'system')
ON CONFLICT (indicator) DO NOTHING;

-- 3. Notification Routing Rules
CREATE TABLE IF NOT EXISTS public.notification_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_type VARCHAR(50) NOT NULL,    -- 'webhook', 'slack', 'discord', 'email'
    destination TEXT NOT NULL,            -- Webhook URL or Email address
    severity_level VARCHAR(20) NOT NULL,  -- 'critical_only', 'warning_above', 'all'
    event_category VARCHAR(50) NOT NULL,  -- 'system_alerts', 'malware_findings', 'user_activity'
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Seed a default notification rule
INSERT INTO public.notification_rules (channel_type, destination, severity_level, event_category, is_active) VALUES
('webhook', 'https://discord.com/api/webhooks/placeholder', 'critical_only', 'malware_findings', true)
ON CONFLICT DO NOTHING;

-- 4. Revoked Tokens (Active Session Blacklist)
CREATE TABLE IF NOT EXISTS public.revoked_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_signature TEXT UNIQUE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- ─── RLS Policies ─────────────────────────────
ALTER TABLE public.api_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_blocklist ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notification_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.revoked_tokens ENABLE ROW LEVEL SECURITY;

-- Integrations
DROP POLICY IF EXISTS "Allow select for authenticated" ON public.api_integrations;
CREATE POLICY "Allow select for authenticated" ON public.api_integrations
  FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "Allow all for service_role" ON public.api_integrations;
CREATE POLICY "Allow all for service_role" ON public.api_integrations
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Blocklist
DROP POLICY IF EXISTS "Allow select for authenticated" ON public.system_blocklist;
CREATE POLICY "Allow select for authenticated" ON public.system_blocklist
  FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "Allow all for service_role" ON public.system_blocklist;
CREATE POLICY "Allow all for service_role" ON public.system_blocklist
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Notification Rules
DROP POLICY IF EXISTS "Allow select for authenticated" ON public.notification_rules;
CREATE POLICY "Allow select for authenticated" ON public.notification_rules
  FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "Allow all for service_role" ON public.notification_rules;
CREATE POLICY "Allow all for service_role" ON public.notification_rules
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Revoked Tokens
DROP POLICY IF EXISTS "Allow select for authenticated" ON public.revoked_tokens;
CREATE POLICY "Allow select for authenticated" ON public.revoked_tokens
  FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "Allow all for service_role" ON public.revoked_tokens;
CREATE POLICY "Allow all for service_role" ON public.revoked_tokens
  FOR ALL TO service_role USING (true) WITH CHECK (true);
