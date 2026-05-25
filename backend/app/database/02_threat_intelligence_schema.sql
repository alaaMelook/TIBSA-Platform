-- ==========================================
-- TIBSA Threat Intelligence Hub Schema
-- Execute this script in your Supabase SQL Editor
-- ==========================================

-- 1. Drop existing tables if they exist
DROP TABLE IF EXISTS public.threat_indicators CASCADE;
DROP TABLE IF EXISTS public.threat_feeds CASCADE;

-- 2. Create threat_feeds table
CREATE TABLE public.threat_feeds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    category TEXT NOT NULL, -- 'malware', 'phishing', 'c2', 'botnet', 'apt', 'general'
    source_url TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    indicators_count INTEGER NOT NULL DEFAULT 0,
    reliability_score INTEGER NOT NULL DEFAULT 85, -- 0 to 100%
    update_frequency TEXT NOT NULL DEFAULT 'Hourly', -- 'Hourly', 'Daily', 'Weekly'
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT now(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.threat_feeds ENABLE ROW LEVEL SECURITY;

-- Create Policies for threat_feeds
CREATE POLICY "Allow read for everyone" ON public.threat_feeds 
    FOR SELECT TO public USING (true);

CREATE POLICY "Allow all for authenticated/service role" ON public.threat_feeds 
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Allow inserts for authenticated" ON public.threat_feeds 
    FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Allow updates for authenticated" ON public.threat_feeds 
    FOR UPDATE TO authenticated USING (true);

CREATE POLICY "Allow deletes for authenticated" ON public.threat_feeds 
    FOR DELETE TO authenticated USING (true);


-- 3. Create threat_indicators table
CREATE TABLE public.threat_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_id UUID REFERENCES public.threat_feeds(id) ON DELETE CASCADE,
    indicator TEXT NOT NULL UNIQUE, -- The IP, domain, hash, or URL
    type TEXT NOT NULL, -- 'ip', 'domain', 'hash', 'url', 'email'
    threat_level TEXT NOT NULL, -- 'low', 'medium', 'high', 'critical'
    category TEXT NOT NULL DEFAULT 'general',
    detections INTEGER NOT NULL DEFAULT 1,
    source TEXT NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT now(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.threat_indicators ENABLE ROW LEVEL SECURITY;

-- Create Policies for threat_indicators
CREATE POLICY "Allow read indicators for everyone" ON public.threat_indicators 
    FOR SELECT TO public USING (true);

CREATE POLICY "Allow all indicators for service role" ON public.threat_indicators 
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Allow inserts indicators for authenticated" ON public.threat_indicators 
    FOR INSERT TO authenticated WITH CHECK (true);


-- 4. Seed Initial Premium Threat Intelligence Feeds
INSERT INTO public.threat_feeds (name, provider, category, source_url, is_active, indicators_count, reliability_score, update_frequency)
VALUES 
('Abuse.ch URLhaus', 'Abuse.ch', 'malware', 'https://urlhaus.abuse.ch/downloads/text/', true, 1420, 95, 'Hourly'),
('PhishTank Active Phishing', 'CleanTalk', 'phishing', 'https://www.phishtank.com/', true, 850, 92, 'Hourly'),
('Emerging Threats Open IPs', 'Proofpoint', 'c2', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', true, 2400, 88, 'Daily'),
('Tor Exit Nodes List', 'Tor Project', 'general', 'https://check.torproject.org/exit-addresses', true, 1150, 99, 'Daily'),
('AlienVault OTX', 'AT&T Cybersecurity', 'apt', 'https://otx.alienvault.com/', false, 0, 90, 'Daily')
ON CONFLICT (name) DO NOTHING;
