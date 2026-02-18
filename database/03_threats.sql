-- ============================================
-- TIBSA Schema 03: Threat Intelligence
-- Run AFTER 01_users.sql
-- ============================================

-- Threat Feeds (external sources)
CREATE TABLE IF NOT EXISTS threat_feeds (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  source_url TEXT NOT NULL,
  is_active BOOLEAN DEFAULT true,
  last_updated TIMESTAMPTZ DEFAULT now()
);

-- Threat Indicators (IOCs — Indicators of Compromise)
CREATE TABLE IF NOT EXISTS threat_indicators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type TEXT NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'hash', 'email')),
  value TEXT NOT NULL,
  threat_level TEXT DEFAULT 'safe' CHECK (threat_level IN ('safe', 'low', 'medium', 'high', 'critical')),
  source TEXT,
  last_seen TIMESTAMPTZ DEFAULT now()
);

-- RLS policies
ALTER TABLE threat_feeds ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_indicators ENABLE ROW LEVEL SECURITY;

-- Threat feeds are readable by all authenticated users
CREATE POLICY "Authenticated users can read feeds"
  ON threat_feeds FOR SELECT
  USING (auth.role() = 'authenticated');

CREATE POLICY "Service role full access on feeds"
  ON threat_feeds FOR ALL
  USING (auth.role() = 'service_role');

-- Threat indicators are readable by all authenticated users
CREATE POLICY "Authenticated users can read indicators"
  ON threat_indicators FOR SELECT
  USING (auth.role() = 'authenticated');

CREATE POLICY "Service role full access on indicators"
  ON threat_indicators FOR ALL
  USING (auth.role() = 'service_role');
