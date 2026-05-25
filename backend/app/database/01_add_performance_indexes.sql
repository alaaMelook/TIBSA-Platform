-- 01_add_performance_indexes.sql
-- Add these to your Supabase SQL Editor to improve dashboard loading times.

-- 1. Index for faster sorting of Users Management page
CREATE INDEX IF NOT EXISTS idx_users_created_at ON public.users(created_at DESC);

-- 2. Index for faster sorting of Audit Log and Activity Feed
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs(created_at DESC);

-- 3. Index for faster sorting of Top Threats and Threat Trends
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON public.findings(created_at DESC);

-- 4. Index for faster sorting of Scan Volume and Recent Investigations
CREATE INDEX IF NOT EXISTS idx_investigations_started_at ON public.investigations(started_at DESC);
