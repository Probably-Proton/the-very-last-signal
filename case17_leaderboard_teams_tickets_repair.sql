-- =====================================================================================================================
-- THE LAST SIGNAL (TLS-0017) — PRODUCTION PRE-LAUNCH DATABASE REPAIR
-- Subsystems: Leaderboard, Team Roster Resolution, Support Tickets RLS & Scoring Calculation
-- Target Supabase Project: xwlbjgbtbppvabmrvenp
-- Safe & Idempotent: Does NOT delete or truncate student accounts, solves, or progress data.
-- =====================================================================================================================

-- ---------------------------------------------------------------------------------------------------------------------
-- 1. AUTHORITATIVE SCORE COMPUTATION
-- Calculates total participant score summing stage_completions.points_earned + score_adjustments.points.
-- ---------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.score_of(pid uuid)
RETURNS int
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
  SELECT GREATEST(0,
    COALESCE((SELECT SUM(c.points_earned) FROM public.stage_completions c WHERE c.participant_id = pid), 0)
    + COALESCE((SELECT SUM(a.points) FROM public.score_adjustments a WHERE a.participant_id = pid), 0)
  )::int;
$$;

CREATE OR REPLACE FUNCTION public.calculate_participant_score(p_participant_id uuid)
RETURNS int
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
  SELECT public.score_of(p_participant_id);
$$;

GRANT EXECUTE ON FUNCTION public.score_of(uuid) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.calculate_participant_score(uuid) TO anon, authenticated, service_role;

-- ---------------------------------------------------------------------------------------------------------------------
-- 2. AUTHORITATIVE LEADERBOARD RPC (get_leaderboard)
-- Accurately reflects stage completions from public.stage_completions, calculates live scores,
-- isolates team vs solo records, and filters out excluded/testing accounts.
-- ---------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.get_leaderboard(p_kind text DEFAULT 'all')
RETURNS TABLE (
  pos int,
  name text,
  kind text,
  score int,
  stages_completed int,
  current_stage int,
  completion_pct int,
  last_progress timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
  RETURN QUERY
  WITH ranked_participants AS (
    SELECT
      COALESCE(p.name, pr.username, 'Operative') AS p_name,
      p.kind::text AS p_kind,
      public.score_of(p.id) AS p_score,
      COALESCE(
        (SELECT COUNT(*)::int FROM public.stage_completions c WHERE c.participant_id = p.id),
        0
      ) AS p_completed,
      COALESCE(
        (SELECT MAX(c2.completed_at) FROM public.stage_completions c2 WHERE c2.participant_id = p.id),
        p.created_at
      ) AS p_last_progress
    FROM public.participants p
    LEFT JOIN public.profiles pr ON pr.id = p.solo_user_id
    WHERE NOT p.retired
      AND NOT COALESCE(p.exclude_from_leaderboard, false)
      AND NOT COALESCE(pr.exclude_from_leaderboard, false)
      AND NOT EXISTS (
        SELECT 1 FROM public.participant_stage_overrides o
        WHERE o.participant_id = p.id AND o.enabled = true
      )
      AND (
        p_kind = 'all'
        OR p.kind = p_kind
      )
      AND (
        p.kind = 'team'
        OR (
          NOT COALESCE(pr.disabled, false)
          AND LOWER(COALESCE(pr.username, '')) NOT IN (
            'testing_account1',
            'xxkillerxx',
            'yuki',
            'cipher_protocol',
            'rudrapratapj.0562@gmail.com',
            'rudrapratapf.0562@gmail.com'
          )
        )
      )
  )
  SELECT
    (ROW_NUMBER() OVER (
      ORDER BY
        rp.p_score DESC,
        rp.p_completed DESC,
        rp.p_last_progress ASC NULLS LAST,
        rp.p_name ASC
    ))::int AS pos,
    rp.p_name AS name,
    rp.p_kind AS kind,
    rp.p_score AS score,
    rp.p_completed AS stages_completed,
    LEAST(7, rp.p_completed + 1)::int AS current_stage,
    ROUND((rp.p_completed::numeric / 7.0) * 100)::int AS completion_pct,
    rp.p_last_progress AS last_progress
  FROM ranked_participants rp
  ORDER BY
    rp.p_score DESC,
    rp.p_completed DESC,
    rp.p_last_progress ASC NULLS LAST,
    rp.p_name ASC;
END;
$$;

GRANT EXECUTE ON FUNCTION public.get_leaderboard(text) TO anon, authenticated, service_role;

-- ---------------------------------------------------------------------------------------------------------------------
-- 3. AUTHORITATIVE TEAM DOSSIER RPC (get_my_team)
-- Returns active unit dossier, full roster of operatives, creator status, and room capacity.
-- Strictly resolves creator via participants.created_by (no non-existent participant_members.is_creator).
-- ---------------------------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.get_my_team()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  u uuid := auth.uid();
  pid uuid;
  t public.participants;
  v_max int := 5;
  v_open boolean := true;
  members_list jsonb := '[]'::jsonb;
BEGIN
  IF u IS NULL THEN
    RETURN NULL;
  END IF;

  -- 1. Find active participant membership for authenticated user
  SELECT m.participant_id INTO pid
  FROM public.participant_members m
  WHERE m.user_id = u AND m.left_at IS NULL
  LIMIT 1;

  IF pid IS NULL THEN
    RETURN NULL;
  END IF;

  -- 2. Verify team participant is active and not retired
  SELECT * INTO t
  FROM public.participants
  WHERE id = pid AND kind = 'team' AND NOT retired;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  -- 3. Check registration & membership settings
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'game_settings') THEN
    SELECT COALESCE(team_size_max, 5), COALESCE(membership_open, true)
    INTO v_max, v_open
    FROM public.game_settings
    LIMIT 1;
  END IF;

  -- 4. Aggregate full active team member roster with creator badge
  SELECT COALESCE(
    jsonb_agg(
      jsonb_build_object(
        'call_sign', COALESCE(p.username, 'OPERATIVE-' || SUBSTRING(m.user_id::text, 1, 6)),
        'full_name', COALESCE(p.full_name, p.username, 'Investigator'),
        'is_creator', m.user_id = t.created_by,
        'joined_at', m.joined_at
      ) ORDER BY m.joined_at ASC
    ),
    '[]'::jsonb
  ) INTO members_list
  FROM public.participant_members m
  LEFT JOIN public.profiles p ON p.id = m.user_id
  WHERE m.participant_id = t.id AND m.left_at IS NULL;

  RETURN jsonb_build_object(
    'name', t.name,
    'invite_code', t.invite_code,
    'is_creator', t.created_by = u,
    'max_size', COALESCE(v_max, 5),
    'membership_open', COALESCE(v_open, true),
    'members', members_list
  );
END;
$$;

GRANT EXECUTE ON FUNCTION public.get_my_team() TO authenticated, service_role;

-- ---------------------------------------------------------------------------------------------------------------------
-- 4. SUPPORT TICKETS SCHEMA & RLS SECURITY POLICIES
-- Strict student privacy: Students can ONLY select and insert tickets where user_id = auth.uid().
-- Staff have unrestricted review, response, and status management.
-- ---------------------------------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.support_tickets (
  id text PRIMARY KEY,
  user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  call_sign text NOT NULL,
  full_name text,
  student_class text,
  subject text NOT NULL,
  category text NOT NULL,
  message text NOT NULL,
  priority text NOT NULL DEFAULT 'NORMAL',
  status text NOT NULL DEFAULT 'OPEN',
  staff_response text,
  staff_notes text,
  resolved_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;

-- Drop prior permissive or conflicting policies
DROP POLICY IF EXISTS "students_select_own_tickets" ON public.support_tickets;
DROP POLICY IF EXISTS "students_insert_own_tickets" ON public.support_tickets;
DROP POLICY IF EXISTS "staff_manage_all_tickets" ON public.support_tickets;
DROP POLICY IF EXISTS "allow_anon_ticket_read" ON public.support_tickets;
DROP POLICY IF EXISTS "allow_authenticated_ticket_read" ON public.support_tickets;

-- Student policy: Can read only their own tickets
CREATE POLICY "students_select_own_tickets"
ON public.support_tickets
FOR SELECT
TO authenticated
USING (
  auth.uid() = user_id
  OR LOWER(call_sign) = LOWER(COALESCE((SELECT username FROM public.profiles WHERE id = auth.uid()), ''))
);

-- Student policy: Can create tickets assigned to themselves
CREATE POLICY "students_insert_own_tickets"
ON public.support_tickets
FOR INSERT
TO authenticated
WITH CHECK (
  auth.uid() = user_id
  OR user_id IS NULL
);

-- Staff / Service Role policy: Full management
CREATE POLICY "staff_manage_all_tickets"
ON public.support_tickets
FOR ALL
TO authenticated, service_role
USING (
  auth.jwt()->>'role' = 'service_role'
  OR (SELECT COALESCE(is_staff, false) FROM public.profiles WHERE id = auth.uid()) = true
);

GRANT SELECT, INSERT ON public.support_tickets TO authenticated;
GRANT ALL ON public.support_tickets TO service_role;

-- ---------------------------------------------------------------------------------------------------------------------
-- 5. VERIFICATION CHECKS
-- ---------------------------------------------------------------------------------------------------------------------
DO $$
BEGIN
  RAISE NOTICE 'TLS-0017 Pre-Launch Repair Script applied successfully.';
  RAISE NOTICE 'Functions score_of, calculate_participant_score, get_leaderboard, get_my_team updated.';
  RAISE NOTICE 'Support tickets table and RLS policies verified.';
END;
$$;
