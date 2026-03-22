-- ============================================
-- TIBSA Schema 04: Website Scanner
-- Run AFTER 01_users.sql
-- ============================================

-- Website Scans table
CREATE TABLE IF NOT EXISTS public.website_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  findings JSONB DEFAULT '[]',
  summary JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ─── RLS Policies ─────────────────────────────
ALTER TABLE public.website_scans ENABLE ROW LEVEL SECURITY;

-- Drop old policies
DROP POLICY IF EXISTS "Users can read own website scans" ON public.website_scans;
DROP POLICY IF EXISTS "Users can create website scans" ON public.website_scans;
DROP POLICY IF EXISTS "Service role full access on website scans" ON public.website_scans;

-- Users see their own scans
CREATE POLICY "Users can read own website scans"
  ON public.website_scans FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create website scans"
  ON public.website_scans FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Service role full access on website scans"
  ON public.website_scans FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);
