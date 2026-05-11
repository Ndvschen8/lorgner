-- ══════════════════════════════════════════════
-- LORGNER — SUPABASE SCHEMA
-- Run this entire file in the Supabase SQL Editor
-- Project: lorgner
--
-- HOW TO RUN:
-- 1. Go to supabase.com → your project
-- 2. Click "SQL Editor" in the left sidebar
-- 3. Paste this entire file
-- 4. Click "Run"
-- Everything will be created in order.
-- ══════════════════════════════════════════════


-- ══════════════════════════════════════════════
-- EXTENSIONS
-- ══════════════════════════════════════════════

-- UUID generation for primary keys
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- ══════════════════════════════════════════════
-- TABLE 1: MEMBERS
-- Extends Supabase Auth users with Lorgner-specific
-- membership data. Created automatically when a
-- user signs up via Stripe webhook.
-- ══════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.members (
  id              UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email           TEXT NOT NULL,
  full_name       TEXT,
  member_tier     TEXT NOT NULL DEFAULT 'founding'
                  CHECK (member_tier IN ('founding', 'standard', 'paused', 'cancelled')),
  monthly_rate    INTEGER NOT NULL DEFAULT 29,  -- in cents: 2900 = $29
  stripe_customer_id TEXT UNIQUE,
  stripe_subscription_id TEXT UNIQUE,
  member_since    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_active     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast lookups by email and Stripe ID
CREATE INDEX IF NOT EXISTS members_email_idx ON public.members(email);
CREATE INDEX IF NOT EXISTS members_stripe_customer_idx ON public.members(stripe_customer_id);

-- Auto-update updated_at on any row change
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER members_updated_at
  BEFORE UPDATE ON public.members
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ══════════════════════════════════════════════
-- TABLE 2: GLASSES
-- One row per pair per member.
-- photo_path points to Supabase Storage bucket.
-- ══════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.glasses (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL DEFAULT 'Unnamed Pair',
  brand       TEXT,
  model       TEXT,
  photo_path  TEXT,                    -- path in Supabase Storage: user_id/timestamp.jpg
  occasions   TEXT[] DEFAULT '{}',     -- ['work', 'evening', 'casual']
  tags        TEXT[] DEFAULT '{}',     -- ['classic', 'minimal', 'bold']
  lorgner_notes TEXT,                  -- accumulated notes from consultations
  last_recommended_at TIMESTAMPTZ,     -- last time Lorgner recommended this pair
  recommendation_count INTEGER DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast collection loads
CREATE INDEX IF NOT EXISTS glasses_user_id_idx ON public.glasses(user_id);
CREATE INDEX IF NOT EXISTS glasses_created_at_idx ON public.glasses(user_id, created_at);

CREATE TRIGGER glasses_updated_at
  BEFORE UPDATE ON public.glasses
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ══════════════════════════════════════════════
-- TABLE 3: SESSIONS
-- One row per consultation.
-- Tracks what was discussed, which pairs were
-- referenced, gaps identified, buy intent signals.
-- Primary data asset for Phase 2 decisions.
-- ══════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.sessions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  occasion        TEXT,                    -- what the member was dressing for
  ai_reply        TEXT,                    -- Lorgner's first response (preview)
  pair_count      INTEGER DEFAULT 0,       -- how many pairs were in the collection
  pair_names      TEXT[] DEFAULT '{}',     -- names of pairs in the collection
  gaps_found      INTEGER DEFAULT 0,       -- number of gaps Lorgner identified
  gap_occasions   TEXT[] DEFAULT '{}',     -- what occasion types had gaps
  buy_intent      BOOLEAN DEFAULT FALSE,   -- whether Lorgner suggested an acquisition
  message_count   INTEGER DEFAULT 0,       -- total messages in session
  duration_sec    INTEGER DEFAULT 0,       -- session length in seconds
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for session history and analytics
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON public.sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_created_at_idx ON public.sessions(created_at DESC);
CREATE INDEX IF NOT EXISTS sessions_buy_intent_idx ON public.sessions(buy_intent) WHERE buy_intent = TRUE;


-- ══════════════════════════════════════════════
-- TABLE 4: EVENTS
-- Lightweight event log for PostHog-style analytics
-- if you want to keep everything in Supabase.
-- Optional — skip if using PostHog directly.
-- ══════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS public.events (
  id          BIGSERIAL PRIMARY KEY,
  user_id     UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  event_name  TEXT NOT NULL,            -- 'glasses_uploaded', 'gap_detected', 'buy_intent'
  properties  JSONB DEFAULT '{}',       -- arbitrary event data
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS events_user_id_idx ON public.events(user_id);
CREATE INDEX IF NOT EXISTS events_name_idx ON public.events(event_name);
CREATE INDEX IF NOT EXISTS events_created_at_idx ON public.events(created_at DESC);


-- ══════════════════════════════════════════════
-- ROW LEVEL SECURITY (RLS)
-- This is the critical security layer.
-- Without RLS, any authenticated user could
-- read any other user's data using the anon key.
-- With RLS, every query is automatically filtered
-- to only return rows owned by the current user.
-- ══════════════════════════════════════════════

-- Enable RLS on all tables
ALTER TABLE public.members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.glasses  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.events   ENABLE ROW LEVEL SECURITY;

-- ── MEMBERS TABLE POLICIES ──

-- Members can only read their own row
CREATE POLICY "members_select_own"
  ON public.members
  FOR SELECT
  USING (auth.uid() = id);

-- Members can only update their own row
CREATE POLICY "members_update_own"
  ON public.members
  FOR UPDATE
  USING (auth.uid() = id);

-- Only service role (backend) can insert members
-- Frontend cannot create member rows directly
CREATE POLICY "members_insert_service_only"
  ON public.members
  FOR INSERT
  WITH CHECK (auth.role() = 'service_role');

-- ── GLASSES TABLE POLICIES ──

-- Members can only see their own glasses
CREATE POLICY "glasses_select_own"
  ON public.glasses
  FOR SELECT
  USING (auth.uid() = user_id);

-- Members can only add glasses to their own collection
CREATE POLICY "glasses_insert_own"
  ON public.glasses
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Members can only update their own glasses
CREATE POLICY "glasses_update_own"
  ON public.glasses
  FOR UPDATE
  USING (auth.uid() = user_id);

-- Members can only delete their own glasses
CREATE POLICY "glasses_delete_own"
  ON public.glasses
  FOR DELETE
  USING (auth.uid() = user_id);

-- ── SESSIONS TABLE POLICIES ──

-- Members can read their own session history
CREATE POLICY "sessions_select_own"
  ON public.sessions
  FOR SELECT
  USING (auth.uid() = user_id);

-- Members can create their own sessions
CREATE POLICY "sessions_insert_own"
  ON public.sessions
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Service role can insert sessions (from Railway proxy)
CREATE POLICY "sessions_insert_service"
  ON public.sessions
  FOR INSERT
  WITH CHECK (auth.role() = 'service_role');

-- ── EVENTS TABLE POLICIES ──

-- Members can only see their own events
CREATE POLICY "events_select_own"
  ON public.events
  FOR SELECT
  USING (auth.uid() = user_id);

-- Members can log their own events
CREATE POLICY "events_insert_own"
  ON public.events
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Service role can insert all events
CREATE POLICY "events_insert_service"
  ON public.events
  FOR INSERT
  WITH CHECK (auth.role() = 'service_role');


-- ══════════════════════════════════════════════
-- STORAGE BUCKET SETUP
-- Run these in the Supabase Storage settings
-- OR via the SQL editor (both work).
-- ══════════════════════════════════════════════

-- Create the glasses-photos bucket (PRIVATE)
-- Private means photos are not publicly accessible.
-- Access requires a signed URL generated server-side.
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'glasses-photos',
  'glasses-photos',
  FALSE,                              -- PRIVATE bucket
  5242880,                            -- 5MB file size limit
  ARRAY['image/jpeg', 'image/jpg', 'image/png', 'image/webp']
)
ON CONFLICT (id) DO NOTHING;

-- Storage RLS: members can only upload to their own folder
-- Path format: user_id/filename.jpg
CREATE POLICY "glasses_storage_upload_own"
  ON storage.objects
  FOR INSERT
  WITH CHECK (
    bucket_id = 'glasses-photos' AND
    auth.uid()::text = (storage.foldername(name))[1]
  );

-- Members can only read their own photos
CREATE POLICY "glasses_storage_select_own"
  ON storage.objects
  FOR SELECT
  USING (
    bucket_id = 'glasses-photos' AND
    auth.uid()::text = (storage.foldername(name))[1]
  );

-- Members can delete their own photos
CREATE POLICY "glasses_storage_delete_own"
  ON storage.objects
  FOR DELETE
  USING (
    bucket_id = 'glasses-photos' AND
    auth.uid()::text = (storage.foldername(name))[1]
  );


-- ══════════════════════════════════════════════
-- HELPER VIEWS
-- Useful for analytics queries in Supabase dashboard.
-- ══════════════════════════════════════════════

-- Collection summary per member
CREATE OR REPLACE VIEW public.member_collection_summary AS
SELECT
  m.id,
  m.email,
  m.member_tier,
  m.member_since,
  COUNT(g.id) AS pair_count,
  ARRAY_AGG(g.name ORDER BY g.created_at) AS pair_names,
  MAX(g.created_at) AS last_pair_added,
  COUNT(s.id) AS total_sessions,
  SUM(CASE WHEN s.buy_intent THEN 1 ELSE 0 END) AS buy_intent_sessions,
  SUM(s.gaps_found) AS total_gaps_identified
FROM public.members m
LEFT JOIN public.glasses g ON g.user_id = m.id
LEFT JOIN public.sessions s ON s.user_id = m.id
GROUP BY m.id, m.email, m.member_tier, m.member_since;

-- Gap analysis across all members
CREATE OR REPLACE VIEW public.gap_analysis AS
SELECT
  UNNEST(gap_occasions) AS gap_occasion,
  COUNT(*) AS frequency,
  COUNT(DISTINCT user_id) AS affected_members
FROM public.sessions
WHERE gaps_found > 0
GROUP BY UNNEST(gap_occasions)
ORDER BY frequency DESC;

-- Session depth analysis
CREATE OR REPLACE VIEW public.session_depth AS
SELECT
  DATE_TRUNC('day', created_at) AS session_date,
  COUNT(*) AS total_sessions,
  AVG(message_count) AS avg_messages,
  AVG(duration_sec) AS avg_duration_sec,
  SUM(CASE WHEN buy_intent THEN 1 ELSE 0 END) AS buy_intent_count,
  SUM(gaps_found) AS total_gaps
FROM public.sessions
GROUP BY DATE_TRUNC('day', created_at)
ORDER BY session_date DESC;


-- ══════════════════════════════════════════════
-- VERIFY SETUP
-- Run these queries to confirm everything worked.
-- ══════════════════════════════════════════════

-- Should return: members, glasses, sessions, events
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;

-- Should return all 4 tables with rls enabled = true
SELECT tablename, rowsecurity FROM pg_tables
WHERE schemaname = 'public';

-- Should return 10+ policies across all tables
SELECT tablename, policyname, cmd
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, cmd;
