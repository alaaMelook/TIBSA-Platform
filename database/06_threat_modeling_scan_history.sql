-- ============================================
-- TIBSA Schema 06: Threat Modeling Scan History
-- Run AFTER 05_threat_modeling.sql
-- ============================================

-- Threat Modeling Scan History
CREATE TABLE IF NOT EXISTS public.threat_modeling_scan_history (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    analysis_id     UUID        NOT NULL REFERENCES public.threat_model_analyses(id) ON DELETE CASCADE,

    -- Analysis Info
    project_name    TEXT        NOT NULL,
    app_type        TEXT        NOT NULL,

    -- Results Summary
    risk_score      INTEGER     NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_label      TEXT        NOT NULL CHECK (risk_label IN ('Low', 'Medium', 'High', 'Critical')),
    threat_count    INTEGER     NOT NULL DEFAULT 0,
    mitigation_count INTEGER    NOT NULL DEFAULT 0,

    -- Scan metadata
    status          TEXT        NOT NULL DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'failed')),
    error_message   TEXT,
    analysis_type   TEXT        DEFAULT 'legacy' CHECK (analysis_type IN ('legacy', 'comprehensive', 'stride')),

    -- Timing
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

-- Indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON public.threat_modeling_scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_analysis_id ON public.threat_modeling_scan_history(analysis_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_created_at ON public.threat_modeling_scan_history(created_at DESC);

-- ─── RLS Policies ─────────────────────────────────────────────
ALTER TABLE public.threat_modeling_scan_history ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can read own scan history" ON public.threat_modeling_scan_history;
DROP POLICY IF EXISTS "Users can insert own scan history" ON public.threat_modeling_scan_history;
DROP POLICY IF EXISTS "Service role full access on scan history" ON public.threat_modeling_scan_history;

-- Authenticated users can read their own scan history
CREATE POLICY "Users can read own scan history"
    ON public.threat_modeling_scan_history FOR SELECT
    TO authenticated
    USING (user_id = auth.uid());

-- Authenticated users can insert their own scan history
CREATE POLICY "Users can insert own scan history"
    ON public.threat_modeling_scan_history FOR INSERT
    TO authenticated
    WITH CHECK (user_id = auth.uid());

-- Service role has unrestricted access
CREATE POLICY "Service role full access on scan history"
    ON public.threat_modeling_scan_history FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
ALTER TABLE public.threat_model_analyses
ADD COLUMN analysis_type TEXT DEFAULT 'comprehensive';
