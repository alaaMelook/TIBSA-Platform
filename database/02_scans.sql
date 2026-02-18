-- ============================================
-- TIBSA Schema 02: Scanning Engine
-- Run AFTER 01_users.sql
-- ============================================

-- Scans table
CREATE TABLE IF NOT EXISTS public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  scan_type TEXT NOT NULL CHECK (scan_type IN ('url', 'file')),
  target TEXT NOT NULL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  threat_level TEXT CHECK (threat_level IN ('safe', 'low', 'medium', 'high', 'critical')),
  created_at TIMESTAMPTZ DEFAULT now(),
  completed_at TIMESTAMPTZ
);

-- Scan Reports
CREATE TABLE IF NOT EXISTS public.scan_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE,
  summary TEXT,
  details JSONB DEFAULT '{}',
  indicators JSONB DEFAULT '[]',
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ─── RLS Policies ─────────────────────────────
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_reports ENABLE ROW LEVEL SECURITY;

-- Drop old policies
DROP POLICY IF EXISTS "Users can read own scans" ON public.scans;
DROP POLICY IF EXISTS "Users can create scans" ON public.scans;
DROP POLICY IF EXISTS "Service role full access on scans" ON public.scans;
DROP POLICY IF EXISTS "Users can read own reports" ON public.scan_reports;
DROP POLICY IF EXISTS "Service role full access on reports" ON public.scan_reports;

-- Scans: users see their own, service_role sees all
CREATE POLICY "Users can read own scans"
  ON public.scans FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create scans"
  ON public.scans FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Service role full access on scans"
  ON public.scans FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Reports: users see reports for their scans
CREATE POLICY "Users can read own reports"
  ON public.scan_reports FOR SELECT
  TO authenticated
  USING (scan_id IN (SELECT id FROM public.scans WHERE user_id = auth.uid()));

CREATE POLICY "Service role full access on reports"
  ON public.scan_reports FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);
