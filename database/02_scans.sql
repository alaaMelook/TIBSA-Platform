-- ============================================
-- TIBSA Schema 02: Scanning Engine
-- Run AFTER 01_users.sql
-- ============================================

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  scan_type TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  threat_level TEXT CHECK (threat_level IN ('safe', 'low', 'medium', 'high', 'critical')),
  created_at TIMESTAMPTZ DEFAULT now(),
  completed_at TIMESTAMPTZ
);

-- Scan Reports
CREATE TABLE IF NOT EXISTS scan_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  summary TEXT,
  details JSONB DEFAULT '{}',
  indicators JSONB DEFAULT '[]',
  created_at TIMESTAMPTZ DEFAULT now()
);

-- RLS policies
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own scans"
  ON scans FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create scans"
  ON scans FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Service role full access on scans"
  ON scans FOR ALL
  USING (auth.role() = 'service_role');

CREATE POLICY "Users can read own reports"
  ON scan_reports FOR SELECT
  USING (scan_id IN (SELECT id FROM scans WHERE user_id = auth.uid()));

CREATE POLICY "Service role full access on reports"
  ON scan_reports FOR ALL
  USING (auth.role() = 'service_role');
