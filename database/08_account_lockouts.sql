-- ============================================
-- TIBSA Schema 08: Account Lockouts
-- Tracks account lockouts after failed login attempts.
-- Run AFTER 01_users.sql in Supabase SQL Editor.
-- ============================================

CREATE TABLE IF NOT EXISTS public.account_lockouts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  locked_until TIMESTAMPTZ NOT NULL,
  attempt_count INTEGER DEFAULT 5,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Index for fast email lookups
CREATE INDEX IF NOT EXISTS idx_account_lockouts_email
  ON public.account_lockouts (email);

-- Index for cleanup queries
CREATE INDEX IF NOT EXISTS idx_account_lockouts_locked_until
  ON public.account_lockouts (locked_until);

-- Allow service role full access (backend manages this table)
ALTER TABLE public.account_lockouts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Service role full access lockouts" ON public.account_lockouts;
CREATE POLICY "Service role full access lockouts"
  ON public.account_lockouts FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);
