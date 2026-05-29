-- ============================================
-- TIBSA Schema 07: System Settings
-- Run this in Supabase SQL Editor
-- ============================================

CREATE TABLE IF NOT EXISTS public.system_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.system_settings ENABLE ROW LEVEL SECURITY;

-- Enable Read for Authenticated Users
DROP POLICY IF EXISTS "Allow select for authenticated" ON public.system_settings;
CREATE POLICY "Allow select for authenticated" ON public.system_settings
  FOR SELECT TO authenticated USING (true);

-- Enable All for Service Role (which the backend uses)
DROP POLICY IF EXISTS "Allow all for service_role" ON public.system_settings;
CREATE POLICY "Allow all for service_role" ON public.system_settings
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Seed Initial Default Settings
INSERT INTO public.system_settings (key, value) VALUES
('2fa', 'true'),
('audit', 'true'),
('auto_block', 'true'),
('email_alerts', 'false'),
('api_access', 'true'),
('dark_mode', 'true'),
('rate_limit', '150'),
('session_timeout', '30'),
('max_file_size', '50'),
('webhook_url', '')
ON CONFLICT (key) DO NOTHING;
