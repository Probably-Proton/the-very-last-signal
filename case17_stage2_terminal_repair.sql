-- =====================================================================================================================
-- THE LAST SIGNAL (CASE TLS-0017) — STAGE 2 CLEARANCE TERMINAL TARGETED REPAIR MIGRATION
-- File: case17_stage2_terminal_repair.sql
-- Purpose: Authoritative database registration and coordinate validation repair for Stage 2 Clearance Terminal.
-- Scope: Narrowly scoped to public.challenges (stage2_coords), challenge_answers hashes, and submit_challenge RPC.
-- Safe: Non-destructive, idempotent, preserves all existing tables, profiles, teams, scores, and support tickets.
--
-- EXECUTION INSTRUCTIONS:
-- 1. Open your Supabase Dashboard: https://supabase.com/dashboard/project/<your-project-id>
-- 2. Navigate to SQL Editor (left sidebar).
-- 3. Create a New Query and paste the contents of this file.
-- 4. Click "Run" to execute.
-- 5. Inspect output of the read-only verification query at the bottom to confirm 1 challenge with registered hashes.
-- =====================================================================================================================

-- ---------------------------------------------------------------------------------------------------------------------
-- 1. ENSURE STAGE 2 COORDINATE CIPHER CHALLENGE EXISTS AND IS ACTIVE
-- ---------------------------------------------------------------------------------------------------------------------
insert into public.challenges (key, label, kind, stage_id, requires_username, norm_mode, active, salt)
values ('stage2_coords', 'Negative Coordinates Terminal', 'puzzle', 2, false, 'coords', true, 'b2c3d4e5f60718a1')
on conflict (key) do update set
  stage_id = 2,
  requires_username = false,
  norm_mode = 'coords',
  active = true,
  salt = coalesce(public.challenges.salt, 'b2c3d4e5f60718a1');

-- ---------------------------------------------------------------------------------------------------------------------
-- 2. REGISTER CRYPTOGRAPHIC ANSWER HASHES FOR VALID COORDINATES AND CADASTRAL TARGET
-- Canonical coordinates: 37.78874, -122.45709
-- Acceptable variations: formatting with/without spaces, parentheses, cardinal signs, and house 3893
-- ---------------------------------------------------------------------------------------------------------------------
with ch as (
  select id, salt from public.challenges where key = 'stage2_coords'
)
insert into public.challenge_answers (challenge_id, answer_hash)
select ch.id, encode(extensions.digest(ch.salt || answers.v, 'sha256'), 'hex')
from ch
cross join (values
  ('37.78874,-122.45709'),
  ('(37.78874,-122.45709)'),
  ('37.78874,122.45709'),
  ('37.78874n,122.45709w'),
  ('37.78874°n,122.45709°w'),
  ('377887412245709'),
  ('3893'),
  ('house3893')
) as answers(v)
on conflict do nothing;

-- ---------------------------------------------------------------------------------------------------------------------
-- 3. SUBMISSION PIPELINE: submit_challenge()
-- Enforces:
-- - Strict Stage 1 completion prerequisite before Stage 2 submission (unless active stage override).
-- - IST timetable release verification.
-- - Robust coordinate stream verification (accepts valid coordinates, rejects invalid/empty).
-- - Single award: duplicate submissions return 'already_solved' with 0 duplicate points.
-- ---------------------------------------------------------------------------------------------------------------------
create or replace function public.submit_challenge(
  p_key text,
  p_answer text,
  p_username text default null
) returns jsonb language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare
  u uuid := auth.uid();
  pid uuid;
  gs public.game_settings;
  c public.challenges;
  v_challenge_found boolean := false;
  has_override boolean := false;
  is_prereq_completed boolean := false;
  used int;
  ok boolean := false;
  secret text;
  unorm text;
  anorm text;
  st public.stages;
  late boolean;
  v_pts int := 0;
  raw_norm text;
  clean_house text;
  clean_coords text;
  has_lat boolean;
  has_lon boolean;
begin
  -- 1. Authentication check
  if u is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;

  -- 2. Lookup participant
  pid := public.my_participant();
  if pid is null then
    return jsonb_build_object('status', 'unavailable');
  end if;

  -- 3. Lookup challenge
  select * into c from public.challenges where key = p_key and active;
  v_challenge_found := FOUND;

  if not v_challenge_found or c.stage_id is null then
    return jsonb_build_object('status', 'unavailable');
  end if;

  -- 4. Load game settings and check pause
  select * into gs from public.game_settings limit 1;
  if gs.paused then
    return jsonb_build_object('status', 'paused');
  end if;

  -- 5. Check stage override for participant
  select coalesce(
    (select enabled from public.participant_stage_overrides where participant_id = pid limit 1),
    false
  ) into has_override;

  -- 6. Check Stage Prerequisite: Participant must have completed stage (c.stage_id - 1)
  if c.stage_id = 1 then
    is_prereq_completed := true;
  else
    select exists (
      select 1 from public.stage_completions
      where participant_id = pid and stage_id = c.stage_id - 1
    ) into is_prereq_completed;
  end if;

  -- 7. Enforce dual release condition:
  -- Access granted only if has_override OR (PREVIOUS_STAGE_COMPLETED AND CURRENT_TIME >= RELEASE_TIMESTAMP)
  if not has_override then
    if not public.game_started() then
      return jsonb_build_object('status', 'unavailable');
    end if;

    -- Condition 1: Preceding stage completed
    if not is_prereq_completed then
      return jsonb_build_object('status', 'unavailable');
    end if;

    -- Condition 2: Release timestamp reached
    if now() < public.stage_open_at(c.stage_id) then
      return jsonb_build_object('status', 'unavailable');
    end if;
  end if;

  -- 8. Verify stage is enabled
  if not exists(select 1 from public.stages where id = c.stage_id and enabled)
     or (c.requires_challenge_id is not null and not exists(select 1 from public.solves where participant_id = pid and challenge_id = c.requires_challenge_id))
  then
    return jsonb_build_object('status', 'unavailable');
  end if;

  -- 9. Transaction advisory lock to prevent race conditions
  perform pg_advisory_xact_lock(hashtextextended(pid::text, 0));

  -- 10. Duplicate solve prevention
  if exists(select 1 from public.solves where participant_id = pid and challenge_id = c.id) then
    return jsonb_build_object('status', 'already_solved');
  end if;

  -- 11. Validate input formatting
  if p_answer is null or char_length(p_answer) not between 1 and 200
     or (c.requires_username and (p_username is null or char_length(p_username) not between 1 and 100))
  then
    return jsonb_build_object('status', 'invalid');
  end if;

  -- 12. Rate limit check (account level)
  if (select count(*) from public.attempts where user_id = u and created_at > now() - interval '1 minute') >= coalesce(gs.rate_limit_account_per_min, 8) then
    return jsonb_build_object('status', 'rate_limited');
  end if;

  -- 13. Attempt limits
  select count(*) into used from public.attempts where participant_id = pid and challenge_id = c.id and not voided;
  if c.attempt_limit is not null and used >= c.attempt_limit then
    return jsonb_build_object('status', 'attempts_exhausted');
  end if;

  -- 14. Answer verification
  if p_key = 'stage2_coords' then
    raw_norm := lower(trim(p_answer));
    clean_house := regexp_replace(raw_norm, '[^a-z0-9]', '', 'g');
    clean_coords := regexp_replace(raw_norm, '[()\[\]°\s]', '', 'g');
    has_lat := clean_coords like '%37.78874%';
    has_lon := clean_coords like '%122.45709%';

    if clean_house = '3893' or clean_house = 'house3893' or (has_lat and has_lon) then
      ok := true;
    else
      -- Check cryptographic hash in challenge_answers table
      secret := public.norm(p_answer, c.norm_mode);
      ok := exists(
        select 1 from public.challenge_answers
        where challenge_id = c.id
          and answer_hash = encode(extensions.digest(c.salt || secret, 'sha256'), 'hex')
      );
    end if;
  else
    if c.requires_username then
      unorm := public.norm(p_username, 'text');
      anorm := public.norm(p_answer, 'text');
      secret := unorm || '|' || anorm;
    else
      anorm := public.norm(p_answer, c.norm_mode);
      secret := anorm;
    end if;

    ok := exists(
      select 1 from public.challenge_answers
      where challenge_id = c.id
        and answer_hash = encode(extensions.digest(c.salt || secret, 'sha256'), 'hex')
    );
  end if;

  -- Record attempt
  insert into public.attempts(participant_id, user_id, challenge_id, correct, submitted)
  values (pid, u, c.id, ok, left(coalesce(p_username || ' / ', '') || p_answer, 200));

  if ok then
    -- Record solve
    insert into public.solves(participant_id, challenge_id, solved_by)
    values (pid, c.id, u)
    on conflict do nothing;

    -- Award stage completion
    select * into st from public.stages where id = c.stage_id;
    late := coalesce(now() > public.stage_close_at(c.stage_id), false);
    v_pts := case when late then 0 else coalesce(st.points, 100) end;

    insert into public.stage_completions(participant_id, stage_id, late, points_earned, completed_by)
    values (pid, c.stage_id, late, v_pts, u)
    on conflict do nothing;

    return jsonb_build_object(
      'status', 'correct',
      'stage_id', c.stage_id,
      'late', late,
      'points', v_pts
    );
  end if;

  return jsonb_build_object(
    'status', 'incorrect',
    'attempts_left', case when c.attempt_limit is null then null else c.attempt_limit - used - 1 end
  );
end;
$$;

grant execute on function public.submit_challenge(text, text, text) to authenticated, service_role;

-- ---------------------------------------------------------------------------------------------------------------------
-- 4. VERIFICATION AUDIT QUERY (Run to verify challenge registration and answers count)
-- ---------------------------------------------------------------------------------------------------------------------
select c.id, c.key, c.label, c.stage_id, c.active, count(ca.id) as registered_answer_hashes
from public.challenges c
left join public.challenge_answers ca on ca.challenge_id = c.id
where c.key = 'stage2_coords'
group by c.id, c.key, c.label, c.stage_id, c.active;
