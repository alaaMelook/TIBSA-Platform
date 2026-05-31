-- =========================================================
-- TIBSA – Threat Infrastructure Intelligence Schema
-- Table: infra_investigations
-- Run in Supabase SQL Editor (Settings → SQL Editor)
-- =========================================================

-- 1. Create table
CREATE TABLE IF NOT EXISTS public.infra_investigations (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    target            TEXT        NOT NULL,
    target_type       TEXT        NOT NULL DEFAULT 'url',
        -- 'url' | 'domain' | 'ip' | 'hash' | 'email'
    status            TEXT        NOT NULL DEFAULT 'pending',
        -- 'pending' | 'running' | 'completed' | 'failed' | 'stopped'
    current_stage     TEXT        NOT NULL DEFAULT 'Pending',
    progress_percent  FLOAT       NOT NULL DEFAULT 0.0,
    risk_score        FLOAT       NOT NULL DEFAULT 0.0,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at      TIMESTAMPTZ,
    results           JSONB,          -- full InfraInvestigationResults blob
    error             TEXT,           -- top-level pipeline error (if any)
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Performance indexes
CREATE INDEX IF NOT EXISTS idx_infra_inv_user_id
    ON public.infra_investigations(user_id);

CREATE INDEX IF NOT EXISTS idx_infra_inv_status
    ON public.infra_investigations(status);

CREATE INDEX IF NOT EXISTS idx_infra_inv_started_at
    ON public.infra_investigations(started_at DESC);

CREATE INDEX IF NOT EXISTS idx_infra_inv_target
    ON public.infra_investigations(target);

CREATE INDEX IF NOT EXISTS idx_infra_inv_user_started
    ON public.infra_investigations(user_id, started_at DESC);

-- 3. Row Level Security
ALTER TABLE public.infra_investigations ENABLE ROW LEVEL SECURITY;

-- Authenticated users can only see their own rows
CREATE POLICY "infra_inv_select_own"
    ON public.infra_investigations FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

CREATE POLICY "infra_inv_insert_own"
    ON public.infra_investigations FOR INSERT
    TO authenticated
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "infra_inv_update_own"
    ON public.infra_investigations FOR UPDATE
    TO authenticated
    USING (auth.uid() = user_id);

CREATE POLICY "infra_inv_delete_own"
    ON public.infra_investigations FOR DELETE
    TO authenticated
    USING (auth.uid() = user_id);

-- Service-role backend has unrestricted access (bypasses JWT check)
CREATE POLICY "infra_inv_service_role_all"
    ON public.infra_investigations FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- 4. Updated-at trigger (keeps completed_at consistent)
-- No extra trigger needed; completed_at is set explicitly by the backend.
