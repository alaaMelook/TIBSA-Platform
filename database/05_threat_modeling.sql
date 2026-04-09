-- ============================================
-- TIBSA Schema 05: Threat Modeling Analyses
-- Run AFTER 01_users.sql
-- ============================================

-- Threat Model Analyses
CREATE TABLE IF NOT EXISTS public.threat_model_analyses (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        REFERENCES public.users(id) ON DELETE SET NULL,

    -- Section 1 – Basic Info
    project_name         TEXT    NOT NULL,
    app_type             TEXT    NOT NULL CHECK (app_type IN ('Web', 'Mobile', 'API', 'Cloud')),
    uses_auth            BOOLEAN NOT NULL DEFAULT false,
    uses_database        BOOLEAN NOT NULL DEFAULT false,
    has_admin_panel      BOOLEAN NOT NULL DEFAULT false,
    uses_external_apis   BOOLEAN NOT NULL DEFAULT false,
    stores_sensitive_data BOOLEAN NOT NULL DEFAULT false,

    -- Section 2 – Tech Stack (stored as arrays)
    frameworks  TEXT[]  NOT NULL DEFAULT '{}',
    languages   TEXT[]  NOT NULL DEFAULT '{}',

    -- Section 3 – Deployment
    deploy_envs   TEXT[]  NOT NULL DEFAULT '{}',
    deploy_types  TEXT[]  NOT NULL DEFAULT '{}',

    -- Section 4 – Data & Protocols
    databases   TEXT[]  NOT NULL DEFAULT '{}',
    protocols   TEXT[]  NOT NULL DEFAULT '{}',

    -- Enhanced inputs for automated pipeline
    system_metadata     JSONB   NOT NULL DEFAULT '{}',
    architecture_diagram JSONB,
    assets              JSONB   NOT NULL DEFAULT '[]',
    entry_points        JSONB   NOT NULL DEFAULT '[]',
    trust_boundaries    JSONB   NOT NULL DEFAULT '[]',
    auth_questions      JSONB   NOT NULL DEFAULT '{}',
    data_questions      JSONB   NOT NULL DEFAULT '{}',
    control_questions   JSONB   NOT NULL DEFAULT '{}',

    -- Analysis Results
    risk_score  INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_label  TEXT    NOT NULL DEFAULT 'Low' CHECK (risk_label IN ('Low', 'Medium', 'High', 'Critical')),
    threats     JSONB   NOT NULL DEFAULT '[]',
    mitigations JSONB   NOT NULL DEFAULT '[]',
    heatmap_data JSONB  NOT NULL DEFAULT '[]',

    -- Metadata
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_threat_model_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_threat_model_updated_at ON public.threat_model_analyses;
CREATE TRIGGER trg_threat_model_updated_at
    BEFORE UPDATE ON public.threat_model_analyses
    FOR EACH ROW EXECUTE FUNCTION update_threat_model_updated_at();

-- ─── RLS Policies ─────────────────────────────────────────────
ALTER TABLE public.threat_model_analyses ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can read own analyses"   ON public.threat_model_analyses;
DROP POLICY IF EXISTS "Users can insert own analyses" ON public.threat_model_analyses;
DROP POLICY IF EXISTS "Users can delete own analyses" ON public.threat_model_analyses;
DROP POLICY IF EXISTS "Service role full access on threat_model_analyses" ON public.threat_model_analyses;

-- Authenticated users can read their own rows
CREATE POLICY "Users can read own analyses"
    ON public.threat_model_analyses FOR SELECT
    TO authenticated
    USING (user_id = auth.uid());

-- Authenticated users can insert (user_id filled server-side)
CREATE POLICY "Users can insert own analyses"
    ON public.threat_model_analyses FOR INSERT
    TO authenticated
    WITH CHECK (user_id = auth.uid());

-- Users can delete their own analyses
CREATE POLICY "Users can delete own analyses"
    ON public.threat_model_analyses FOR DELETE
    TO authenticated
    USING (user_id = auth.uid());

-- Service role has unrestricted access (used by the backend)
CREATE POLICY "Service role full access on threat_model_analyses"
    ON public.threat_model_analyses FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
