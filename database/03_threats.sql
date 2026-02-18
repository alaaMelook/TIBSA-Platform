-- ============================================
-- TIBSA Schema 03: Threat Intelligence
-- Run AFTER 01_users.sql
-- ============================================

-- Threat Feeds (external sources)
CREATE TABLE IF NOT EXISTS public.threat_feeds (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  source_url TEXT NOT NULL,
  is_active BOOLEAN DEFAULT true,
  last_updated TIMESTAMPTZ DEFAULT now()
);

-- Threat Indicators (IOCs — Indicators of Compromise)
CREATE TABLE IF NOT EXISTS public.threat_indicators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type TEXT NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'hash', 'email')),
  value TEXT NOT NULL,
  threat_level TEXT DEFAULT 'safe' CHECK (threat_level IN ('safe', 'low', 'medium', 'high', 'critical')),
  source TEXT,
  last_seen TIMESTAMPTZ DEFAULT now()
);

-- ─── RLS Policies ─────────────────────────────
ALTER TABLE public.threat_feeds ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_indicators ENABLE ROW LEVEL SECURITY;

-- Drop old policies
DROP POLICY IF EXISTS "Authenticated users can read feeds" ON public.threat_feeds;
DROP POLICY IF EXISTS "Service role full access on feeds" ON public.threat_feeds;
DROP POLICY IF EXISTS "Authenticated users can read indicators" ON public.threat_indicators;
DROP POLICY IF EXISTS "Service role full access on indicators" ON public.threat_indicators;

-- Feeds: readable by all, writable by service_role
CREATE POLICY "Authenticated users can read feeds"
  ON public.threat_feeds FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Service role full access on feeds"
  ON public.threat_feeds FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Indicators: readable by all, writable by service_role
CREATE POLICY "Authenticated users can read indicators"
  ON public.threat_indicators FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Service role full access on indicators"
  ON public.threat_indicators FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);
