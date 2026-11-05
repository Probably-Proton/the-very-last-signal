-- =============================================================================
-- CASE TLS-0017: CONSOLIDATED PRODUCTION REPAIR & COMMUNICATIONS MIGRATION
-- Safe, Non-Destructive, Idempotent Database Repair Script (v4.1.0)
-- =============================================================================
-- Fix for: ERROR: 42703: column "stage_number" does not exist
-- ROOT CAUSE: In the existing database, public.stage_completions was created with
-- columns (stage_id, points_earned). This updated script gracefully detects and
-- adds column aliases (stage_id / stage_number and points_earned / score) so
-- both schemas and all queries operate without errors.
-- =============================================================================

BEGIN;

-- 1. Ensure extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Ensure participants table has necessary tracking columns
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'participants' AND column_name = 'exclude_from_leaderboard'
  ) THEN
    ALTER TABLE public.participants ADD COLUMN exclude_from_leaderboard BOOLEAN NOT NULL DEFAULT FALSE;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'participants' AND column_name = 'max_size'
  ) THEN
    ALTER TABLE public.participants ADD COLUMN max_size INTEGER NOT NULL DEFAULT 5;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'participants' AND column_name = 'membership_open'
  ) THEN
    ALTER TABLE public.participants ADD COLUMN membership_open BOOLEAN NOT NULL DEFAULT TRUE;
  END IF;
END $$;

-- 3. Ensure stage_completions table exists and has all required column aliases
CREATE TABLE IF NOT EXISTS public.stage_completions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  participant_id UUID NOT NULL REFERENCES public.participants(id) ON DELETE CASCADE,
  stage_id INTEGER NOT NULL DEFAULT 1,
  completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  points_earned INTEGER NOT NULL DEFAULT 100,
  scoring_eligible BOOLEAN NOT NULL DEFAULT TRUE,
  CONSTRAINT uq_stage_completions_participant_stage UNIQUE (participant_id, stage_id)
);

-- Safely add missing columns on stage_completions if table existed previously with different names
DO $$
BEGIN
  -- 1. stage_id
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'stage_completions' AND column_name = 'stage_id'
  ) THEN
    ALTER TABLE public.stage_completions ADD COLUMN stage_id INTEGER DEFAULT 1;
  END IF;

  -- 2. stage_number (alias for stage_id)
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'stage_completions' AND column_name = 'stage_number'
  ) THEN
    ALTER TABLE public.stage_completions ADD COLUMN stage_number INTEGER DEFAULT 1;
  END IF;

  -- 3. points_earned
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'stage_completions' AND column_name = 'points_earned'
  ) THEN
    ALTER TABLE public.stage_completions ADD COLUMN points_earned INTEGER DEFAULT 100;
  END IF;

  -- 4. score (alias for points_earned)
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'stage_completions' AND column_name = 'score'
  ) THEN
    ALTER TABLE public.stage_completions ADD COLUMN score INTEGER DEFAULT 100;
  END IF;

  -- 5. scoring_eligible
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'stage_completions' AND column_name = 'scoring_eligible'
  ) THEN
    ALTER TABLE public.stage_completions ADD COLUMN scoring_eligible BOOLEAN DEFAULT TRUE;
  END IF;

  -- 6. time_spent_seconds
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'public' AND table_name = 'stage_completions' AND column_name = 'time_spent_seconds'
  ) THEN
    ALTER TABLE public.stage_completions ADD COLUMN time_spent_seconds INTEGER DEFAULT 0;
  END IF;
END $$;

-- Synchronize alias values so both legacy and modern column names are fully populated
UPDATE public.stage_completions
SET 
  stage_number = COALESCE(stage_number, stage_id, 1),
  stage_id = COALESCE(stage_id, stage_number, 1),
  points_earned = COALESCE(points_earned, score, 100),
  score = COALESCE(score, points_earned, 100);

-- Safe indexes on columns verified to exist
CREATE INDEX IF NOT EXISTS idx_stage_completions_participant_id ON public.stage_completions(participant_id);
CREATE INDEX IF NOT EXISTS idx_stage_completions_stage_id ON public.stage_completions(stage_id);
CREATE INDEX IF NOT EXISTS idx_stage_completions_stage_number ON public.stage_completions(stage_number);

-- 4. Fix calculate_participant_score & score_of functions
DROP FUNCTION IF EXISTS public.calculate_participant_score(UUID);
DROP FUNCTION IF EXISTS public.score_of(UUID);

CREATE OR REPLACE FUNCTION public.calculate_participant_score(p_participant_id UUID)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_score INTEGER := 0;
BEGIN
  -- Compute total points from stage_completions using whichever column is populated
  SELECT COALESCE(SUM(COALESCE(c.points_earned, c.score, 0)), 0)::INTEGER
  INTO v_score
  FROM public.stage_completions c
  WHERE c.participant_id = p_participant_id;

  -- Include location deduction choice bonus if table exists
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'location_choices') THEN
    v_score := v_score + COALESCE((
      SELECT CASE WHEN EXISTS(
        SELECT 1 FROM public.location_choices lc
        CROSS JOIN public.location_config cfg
        WHERE lc.participant_id = p_participant_id 
          AND lc.location_id = cfg.correct_location_id 
          AND cfg.enabled
      ) THEN 20 ELSE 0 END
    ), 0);
  END IF;

  -- Include manual staff score adjustments if table exists
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'score_adjustments') THEN
    v_score := v_score + COALESCE((
      SELECT SUM(delta) FROM public.score_adjustments WHERE participant_id = p_participant_id
    ), 0);
  END IF;

  RETURN GREATEST(0, v_score);
END;
$$;

CREATE OR REPLACE FUNCTION public.score_of(pid UUID)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  RETURN public.calculate_participant_score(pid);
END;
$$;

-- 5. Create Staff Announcements Table
CREATE TABLE IF NOT EXISTS public.announcements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT 'all', -- 'all', 'stage', 'team', 'player'
  target_value TEXT,
  created_by TEXT NOT NULL DEFAULT 'STAFF',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  pinned BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_announcements_created_at ON public.announcements(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_announcements_pinned ON public.announcements(pinned);

-- 6. Create Staff-to-Player Direct Conversations Tables
CREATE TABLE IF NOT EXISTS public.staff_conversations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  player_callsign TEXT NOT NULL,
  player_name TEXT NOT NULL,
  player_student_class TEXT,
  status TEXT NOT NULL DEFAULT 'open', -- 'open' or 'resolved'
  unread_staff_count INTEGER NOT NULL DEFAULT 0,
  unread_player_count INTEGER NOT NULL DEFAULT 0,
  last_message TEXT,
  last_message_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT uq_staff_conversations_callsign UNIQUE (player_callsign)
);

CREATE INDEX IF NOT EXISTS idx_staff_conversations_updated ON public.staff_conversations(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_staff_conversations_status ON public.staff_conversations(status);

CREATE TABLE IF NOT EXISTS public.staff_conversation_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES public.staff_conversations(id) ON DELETE CASCADE,
  sender_type TEXT NOT NULL, -- 'staff' or 'player'
  sender_callsign TEXT NOT NULL,
  sender_name TEXT NOT NULL,
  message TEXT NOT NULL,
  read_by_staff BOOLEAN NOT NULL DEFAULT FALSE,
  read_by_player BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_staff_conv_msgs_conv_id ON public.staff_conversation_messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_staff_conv_msgs_created ON public.staff_conversation_messages(created_at ASC);

-- 7. Fix & unify get_leaderboard RPC
-- Drop all prior function signatures to prevent 42P13 return type conflicts
-- We use a block to find and drop all variations of this function
DO $$ 
DECLARE
  r RECORD;
BEGIN
  FOR r IN (
    SELECT p.oid::regprocedure AS proc 
    FROM pg_proc p
    JOIN pg_namespace n ON p.pronamespace = n.oid
    WHERE p.proname = 'get_leaderboard' AND n.nspname = 'public'
  ) 
  LOOP
    EXECUTE 'DROP FUNCTION ' || r.proc || ' CASCADE';
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION public.get_leaderboard(p_kind TEXT DEFAULT 'all')
RETURNS TABLE (
  pos BIGINT,
  rank BIGINT,
  participant_id UUID,
  name TEXT,
  kind TEXT,
  score INTEGER,
  stages_completed INTEGER,
  current_stage INTEGER,
  completion_percentage INTEGER,
  last_progress TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  RETURN QUERY
  WITH participant_scores AS (
    SELECT 
      p.id AS p_id,
      COALESCE(p.name, (SELECT pr.username FROM public.profiles pr WHERE pr.id = p.solo_user_id)) AS p_name,
      p.kind::TEXT AS p_kind,
      COALESCE(public.calculate_participant_score(p.id), 0) AS p_score,
      COALESCE((
        SELECT COUNT(DISTINCT COALESCE(sc.stage_id, sc.stage_number))::INTEGER 
        FROM public.stage_completions sc 
        WHERE sc.participant_id = p.id
      ), 0) AS p_stages_completed,
      COALESCE(
        (SELECT MAX(completed_at) FROM public.stage_completions WHERE participant_id = p.id),
        p.created_at
      ) AS p_last_progress
    FROM public.participants p
    WHERE p.retired = FALSE
      AND COALESCE(p.exclude_from_leaderboard, FALSE) = FALSE
      AND (
        p_kind IS NULL 
        OR p_kind = 'all' 
        OR p.kind::TEXT = p_kind
      )
  )
  SELECT
    ROW_NUMBER() OVER (
      ORDER BY ps.p_score DESC, ps.p_stages_completed DESC, ps.p_last_progress ASC
    ) AS pos,
    ROW_NUMBER() OVER (
      ORDER BY ps.p_score DESC, ps.p_stages_completed DESC, ps.p_last_progress ASC
    ) AS rank,
    ps.p_id AS participant_id,
    COALESCE(ps.p_name, 'Investigator') AS name,
    ps.p_kind AS kind,
    ps.p_score AS score,
    ps.p_stages_completed AS stages_completed,
    LEAST(7, ps.p_stages_completed + 1) AS current_stage,
    ROUND((ps.p_stages_completed::NUMERIC / 7.0) * 100)::INTEGER AS completion_percentage,
    ps.p_last_progress AS last_progress
  FROM participant_scores ps
  ORDER BY pos ASC;
END;
$$;

-- 8. Game Settings Table & Safe Membership Function
CREATE TABLE IF NOT EXISTS public.game_settings (
  id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
  game_start TIMESTAMPTZ,
  membership_lock_at TIMESTAMPTZ,
  registration_open BOOLEAN NOT NULL DEFAULT TRUE,
  membership_open BOOLEAN NOT NULL DEFAULT TRUE,
  paused BOOLEAN NOT NULL DEFAULT FALSE,
  team_size_max INT NOT NULL DEFAULT 5,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'game_settings' AND column_name = 'registration_open') THEN
    ALTER TABLE public.game_settings ADD COLUMN registration_open BOOLEAN NOT NULL DEFAULT TRUE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'game_settings' AND column_name = 'membership_open') THEN
    ALTER TABLE public.game_settings ADD COLUMN membership_open BOOLEAN NOT NULL DEFAULT TRUE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'game_settings' AND column_name = 'membership_lock_at') THEN
    ALTER TABLE public.game_settings ADD COLUMN membership_lock_at TIMESTAMPTZ;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'game_settings' AND column_name = 'game_start') THEN
    ALTER TABLE public.game_settings ADD COLUMN game_start TIMESTAMPTZ;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'game_settings' AND column_name = 'team_size_max') THEN
    ALTER TABLE public.game_settings ADD COLUMN team_size_max INT NOT NULL DEFAULT 5;
  END IF;
END $$;

-- Safe initial seed if table is empty, or update existing settings
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.game_settings LIMIT 1) THEN
    INSERT INTO public.game_settings (registration_open, membership_open) VALUES (TRUE, TRUE);
  ELSE
    UPDATE public.game_settings
    SET 
      registration_open = COALESCE(registration_open, TRUE),
      membership_open = COALESCE(membership_open, TRUE),
      updated_at = now();
  END IF;
EXCEPTION WHEN OTHERS THEN
  NULL;
END $$;

-- Fixed membership_open function: does NOT prematurely lock team formation
CREATE OR REPLACE FUNCTION public.membership_open(p_participant_id UUID DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_reg_open BOOLEAN := TRUE;
  v_mem_open BOOLEAN := TRUE;
  v_lock_at TIMESTAMPTZ := NULL;
  v_part_open BOOLEAN := TRUE;
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'game_settings') THEN
    SELECT 
      COALESCE(registration_open, TRUE),
      COALESCE(membership_open, TRUE),
      membership_lock_at
    INTO v_reg_open, v_mem_open, v_lock_at
    FROM public.game_settings
    LIMIT 1;

    -- If explicitly locked via timestamp
    IF v_lock_at IS NOT NULL AND now() >= v_lock_at THEN
      RETURN FALSE;
    END IF;

    -- If explicitly toggled off
    IF v_reg_open = FALSE OR v_mem_open = FALSE THEN
      RETURN FALSE;
    END IF;
  END IF;

  -- If specific participant check requested
  IF p_participant_id IS NOT NULL THEN
    SELECT COALESCE(membership_open, TRUE)
    INTO v_part_open
    FROM public.participants
    WHERE id = p_participant_id;

    IF v_part_open = FALSE THEN
      RETURN FALSE;
    END IF;
  END IF;

  RETURN TRUE;
END;
$$;

-- 9. Support Tickets Table
CREATE TABLE IF NOT EXISTS public.support_tickets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  call_sign TEXT NOT NULL,
  full_name TEXT NOT NULL,
  student_class TEXT DEFAULT 'Class 9',
  subject TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'TECHNICAL',
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN',
  priority TEXT NOT NULL DEFAULT 'NORMAL',
  staff_response TEXT,
  staff_notes TEXT,
  resolved_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_support_tickets_call_sign ON public.support_tickets(lower(call_sign));
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON public.support_tickets(status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_created_at ON public.support_tickets(created_at DESC);

-- 10. Team Management RPCs (Non-destructive & Authoritative)
CREATE TABLE IF NOT EXISTS public.membership_events (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES public.profiles ON DELETE SET NULL,
  participant_id UUID REFERENCES public.participants ON DELETE SET NULL,
  action TEXT NOT NULL,
  actor_id UUID REFERENCES public.profiles ON DELETE SET NULL,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_membership_events_user_action ON public.membership_events (user_id, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_participants_invite_code ON public.participants (upper(invite_code)) WHERE kind = 'team';

CREATE OR REPLACE FUNCTION public.create_team(p_name TEXT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  u UUID := auth.uid();
  clean_name TEXT;
  cur public.participants;
  tid UUID;
  code TEXT;
  n INT := 0;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING errcode = '28000';
  END IF;

  IF NOT public.membership_open() THEN
    RETURN jsonb_build_object('status', 'locked', 'error', 'Team registration window has closed.');
  END IF;

  clean_name := trim(p_name);
  IF clean_name IS NULL OR char_length(clean_name) NOT BETWEEN 3 AND 40 OR lower(clean_name) IN (
    'admin','administrator','director','zodiac','cipher','organiser','organizer','system','moderator','owner','staff'
  ) THEN
    RETURN jsonb_build_object('status', 'invalid_name', 'error', 'Designation must be between 3 and 40 characters.');
  END IF;

  SELECT p.* INTO cur
  FROM public.participant_members m
  JOIN public.participants p ON p.id = m.participant_id
  WHERE m.user_id = u AND m.left_at IS NULL;

  IF FOUND AND cur.kind <> 'solo' THEN
    RETURN jsonb_build_object('status', 'already_in_team', 'error', 'You are already registered with an active unit.');
  END IF;

  IF EXISTS (SELECT 1 FROM public.participants WHERE kind = 'team' AND lower(trim(name)) = lower(clean_name) AND NOT retired) THEN
    RETURN jsonb_build_object('status', 'name_taken', 'error', 'A unit with this designation already exists.');
  END IF;

  LOOP
    code := 'TLS-' || upper(encode(gen_random_bytes(3), 'hex'));
    BEGIN
      INSERT INTO public.participants(kind, name, invite_code, created_by)
      VALUES ('team', clean_name, code, u)
      RETURNING id INTO tid;
      EXIT;
    EXCEPTION WHEN unique_violation THEN
      n := n + 1;
      IF n >= 10 THEN
        RAISE EXCEPTION 'Could not generate unique invite code.';
      END IF;
    END;
  END LOOP;

  -- If user was in a solo participant, retire it
  IF cur.id IS NOT NULL AND cur.kind = 'solo' THEN
    UPDATE public.participant_members SET left_at = now() WHERE participant_id = cur.id AND user_id = u;
    UPDATE public.participants SET retired = TRUE WHERE id = cur.id;
  END IF;

  -- Insert new team membership without referencing optional role column
  INSERT INTO public.participant_members(participant_id, user_id, joined_at)
  VALUES (tid, u, now());

  INSERT INTO public.membership_events(user_id, participant_id, action, actor_id, reason)
  VALUES (u, tid, 'create_team', u, 'Created unit ' || clean_name);

  RETURN jsonb_build_object(
    'status', 'ok',
    'participant_id', tid,
    'team_id', tid,
    'name', clean_name,
    'invite_code', code,
    'role', 'leader'
  );
END;
$$;

CREATE OR REPLACE FUNCTION public.join_team(p_code TEXT)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  u UUID := auth.uid();
  target public.participants;
  cur public.participants;
  clean_code TEXT;
  cur_members INT;
BEGIN
  IF u IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING errcode = '28000';
  END IF;

  IF NOT public.membership_open() THEN
    RETURN jsonb_build_object('status', 'locked', 'error', 'Team registration window has closed.');
  END IF;

  clean_code := upper(trim(p_code));

  SELECT * INTO target
  FROM public.participants
  WHERE upper(invite_code) = clean_code AND kind = 'team' AND NOT retired;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('status', 'invalid_code', 'error', 'Invalid unit invite credentials.');
  END IF;

  SELECT count(*)::INT INTO cur_members
  FROM public.participant_members
  WHERE participant_id = target.id AND left_at IS NULL;

  IF cur_members >= COALESCE(target.max_size, 5) THEN
    RETURN jsonb_build_object('status', 'team_full', 'error', 'Unit capacity (maximum 5 operatives) has been reached.');
  END IF;

  SELECT p.* INTO cur
  FROM public.participant_members m
  JOIN public.participants p ON p.id = m.participant_id
  WHERE m.user_id = u AND m.left_at IS NULL;

  IF FOUND THEN
    IF cur.id = target.id THEN
      RETURN jsonb_build_object('status', 'already_in_team', 'error', 'You are already a member of this unit.');
    ELSIF cur.kind = 'solo' THEN
      UPDATE public.participant_members SET left_at = now() WHERE participant_id = cur.id AND user_id = u;
      UPDATE public.participants SET retired = TRUE WHERE id = cur.id;
    ELSE
      RETURN jsonb_build_object('status', 'already_in_team', 'error', 'You must depart your current unit before enlisting in another.');
    END IF;
  END IF;

  -- Insert/update membership without referencing optional role column
  INSERT INTO public.participant_members(participant_id, user_id, joined_at, left_at)
  VALUES (target.id, u, now(), null)
  ON CONFLICT (participant_id, user_id)
  DO UPDATE SET left_at = null, joined_at = now();

  INSERT INTO public.membership_events(user_id, participant_id, action, actor_id, reason)
  VALUES (u, target.id, 'join', u, 'Enlisted in unit ' || target.name);

  RETURN jsonb_build_object(
    'status', 'ok',
    'participant_id', target.id,
    'team_id', target.id,
    'name', target.name,
    'role', 'member'
  );
END;
$$;

-- 11. Challenge Verification RPC with Strict Stage 1 & 2 Enforcement and Hourly Points
CREATE OR REPLACE FUNCTION public.submit_challenge(
  p_key TEXT,
  p_answer TEXT,
  p_username TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  norm_answer TEXT;
  norm_clean TEXT;
  v_stage_id INT;
  is_correct BOOLEAN := FALSE;
  v_points INT := 100;
  v_hours_elapsed INT := 0;
  v_part_id UUID;
  v_user_id UUID;
  v_ch_id UUID;
BEGIN
  norm_clean := lower(regexp_replace(COALESCE(p_answer, ''), '[^a-z0-9]', '', 'g'));
  norm_answer := trim(lower(COALESCE(p_answer, '')));

  -- Determine stage number from key
  IF p_key ILIKE '%stage1%' OR p_key ILIKE '%stage_1%' OR p_key = 'ch_s1_password' THEN
    v_stage_id := 1;
    -- Strictly accept only acrostic/telestich case keys
    IF norm_clean = 'zkcase' OR norm_clean = 'case17' THEN
      is_correct := TRUE;
    ELSE
      is_correct := FALSE;
    END IF;
  ELSIF p_key ILIKE '%stage2%' OR p_key ILIKE '%stage_2%' OR p_key = 'ch_s2_clearance' THEN
    v_stage_id := 2;
    -- Accept coordinates or house number
    IF norm_clean = '377887412245709' OR norm_clean = '3893' OR norm_clean = 'house3893' THEN
      is_correct := TRUE;
    ELSE
      is_correct := FALSE;
    END IF;
  ELSE
    v_stage_id := 1;
  END IF;

  IF NOT is_correct THEN
    RETURN jsonb_build_object(
      'status', 'incorrect',
      'message', 'ACCESS DENIED: Decryption verification failed.',
      'attempts_left', 4
    );
  END IF;

  -- Calculate hourly speed bonus: 100 + min(24, floor(hours since 09:00 IST / release))
  v_hours_elapsed := GREATEST(0, LEAST(24, EXTRACT(EPOCH FROM (now() - '2026-11-01 09:00:00+05:30'::TIMESTAMPTZ))::INT / 3600));
  v_points := 100 + v_hours_elapsed;

  -- Look up user and participant if authenticated or username supplied
  v_user_id := auth.uid();
  IF v_user_id IS NULL AND p_username IS NOT NULL THEN
    SELECT id INTO v_user_id FROM public.profiles WHERE lower(username) = lower(trim(p_username)) LIMIT 1;
  END IF;

  IF v_user_id IS NOT NULL THEN
    SELECT participant_id INTO v_part_id 
    FROM public.participant_members 
    WHERE user_id = v_user_id AND left_at IS NULL 
    LIMIT 1;

    IF v_part_id IS NULL THEN
      SELECT id INTO v_part_id FROM public.participants WHERE solo_user_id = v_user_id AND NOT retired LIMIT 1;
    END IF;

    IF v_part_id IS NOT NULL THEN
      -- Record completion populating both column aliases safely
      INSERT INTO public.stage_completions(participant_id, stage_id, stage_number, points_earned, score, completed_at, scoring_eligible)
      VALUES (v_part_id, v_stage_id, v_stage_id, v_points, v_points, now(), TRUE)
      ON CONFLICT DO NOTHING;
    END IF;
  END IF;

  RETURN jsonb_build_object(
    'status', 'correct',
    'message', 'CLEARANCE GRANTED: Cryptographic key match confirmed.',
    'points', v_points
  );
END;
$$;

-- 12. Row Level Security and Permissions
ALTER TABLE public.announcements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_conversations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_conversation_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.stage_completions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.game_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;

-- Allow read of public game settings and announcements
DROP POLICY IF EXISTS "Public can view announcements" ON public.announcements;
CREATE POLICY "Public can view announcements" ON public.announcements FOR SELECT USING (true);

DROP POLICY IF EXISTS "Public can view game_settings" ON public.game_settings;
CREATE POLICY "Public can view game_settings" ON public.game_settings FOR SELECT USING (true);

-- Allow public to create and view their support tickets
DROP POLICY IF EXISTS "Anyone can insert support tickets" ON public.support_tickets;
CREATE POLICY "Anyone can insert support tickets" ON public.support_tickets FOR INSERT WITH CHECK (true);

DROP POLICY IF EXISTS "Users view support tickets" ON public.support_tickets;
CREATE POLICY "Users view support tickets" ON public.support_tickets FOR SELECT USING (true);

-- Allow full access to service_role
DROP POLICY IF EXISTS "Service role full access on announcements" ON public.announcements;
CREATE POLICY "Service role full access on announcements" ON public.announcements FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on staff_conversations" ON public.staff_conversations;
CREATE POLICY "Service role full access on staff_conversations" ON public.staff_conversations FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on staff_conversation_messages" ON public.staff_conversation_messages;
CREATE POLICY "Service role full access on staff_conversation_messages" ON public.staff_conversation_messages FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on stage_completions" ON public.stage_completions;
CREATE POLICY "Service role full access on stage_completions" ON public.stage_completions FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on game_settings" ON public.game_settings;
CREATE POLICY "Service role full access on game_settings" ON public.game_settings FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on support_tickets" ON public.support_tickets;
CREATE POLICY "Service role full access on support_tickets" ON public.support_tickets FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Grants
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT SELECT ON public.announcements TO anon, authenticated;
GRANT SELECT ON public.game_settings TO anon, authenticated;
GRANT SELECT, INSERT ON public.support_tickets TO anon, authenticated;
GRANT ALL ON public.announcements TO service_role;
GRANT ALL ON public.staff_conversations TO anon, authenticated, service_role;
GRANT ALL ON public.staff_conversation_messages TO anon, authenticated, service_role;
GRANT ALL ON public.game_settings TO service_role;
GRANT ALL ON public.support_tickets TO service_role;
GRANT SELECT, INSERT, UPDATE ON public.stage_completions TO anon, authenticated;
GRANT ALL ON public.stage_completions TO service_role;

GRANT EXECUTE ON FUNCTION public.calculate_participant_score(UUID) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.score_of(UUID) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_leaderboard(TEXT) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.membership_open(UUID) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_team(TEXT) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.join_team(TEXT) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.submit_challenge(TEXT, TEXT, TEXT) TO anon, authenticated, service_role;

COMMIT;
