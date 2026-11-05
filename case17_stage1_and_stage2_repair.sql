-- =====================================================================================
-- THE LAST SIGNAL (TLS-0017) — STAGE 1 AND STAGE 2 PRODUCTION REPAIR
-- =====================================================================================
-- Idempotent, non-destructive migration registering Stage 1 and Stage 2 challenges,
-- cryptographic salt & salted SHA-256 hashes, and authoritative submit_challenge RPC.
-- =====================================================================================

-- 1. Ensure required extensions exist
create extension if not exists pgcrypto with schema extensions;
create extension if not exists "uuid-ossp" with schema extensions;

-- 2. Ensure stages 1 and 2 exist and are enabled
insert into public.stages (id, public_title, points, enabled)
values
  (1, 'The Archived Files and the Exorcist’s Letter', 100, true),
  (2, 'The Locked Documents and the Coordinates', 100, true)
on conflict (id) do update set
  enabled = true,
  public_title = excluded.public_title;

-- 3. Register Stage 1 Challenge: gate_zk_login
-- Requires both directory/user (acrostic zkcase) and password (telestich case17)
insert into public.challenges (key, label, kind, stage_id, requires_username, norm_mode, active, salt, sort_order)
values ('gate_zk_login', 'Locked Case Files Terminal', 'gate', 1, true, 'text', true, 'a1b2c3d4e5f60718', 20)
on conflict (key) do update set
  active = true,
  stage_id = 1,
  requires_username = true,
  norm_mode = 'text',
  salt = excluded.salt;

-- 4. Register Stage 2 Challenge: stage2_coords
-- Validates camera telemetry coordinates (37.78874, -122.45709) and deduced house number (3893)
insert into public.challenges (key, label, kind, stage_id, requires_username, norm_mode, active, salt, sort_order)
values ('stage2_coords', 'Negative Coordinates Terminal', 'puzzle', 2, false, 'coords', true, 'b2c3d4e5f60718a1', 30)
on conflict (key) do update set
  active = true,
  stage_id = 2,
  requires_username = false,
  norm_mode = 'coords',
  salt = excluded.salt;

-- 5. Populate Salted Hashes for Stage 1: gate_zk_login
-- Format for challenges with requires_username: unorm || '|' || anorm
-- Normalized with norm(..., 'text') -> lowercase alphanumeric
do $$
declare
  v_cid uuid;
  v_salt text := 'a1b2c3d4e5f60718';
  v_answers text[] := array[
    'zkcase|case17',
    'zkcase|17',
    'zk|case17',
    'zk|17',
    'zcase|case17',
    'zcase|17',
    'zkcase17|case17',
    'zkcase17|orion'
  ];
  ans text;
begin
  select id into v_cid from public.challenges where key = 'gate_zk_login';
  if v_cid is not null then
    foreach ans in array v_answers loop
      insert into public.challenge_answers (challenge_id, answer_hash)
      values (v_cid, encode(extensions.digest(v_salt || ans, 'sha256'), 'hex'))
      on conflict do nothing;
    end loop;
  end if;
end;
$$;

-- 6. Populate Salted Hashes for Stage 2: stage2_coords
do $$
declare
  v_cid uuid;
  v_salt text := 'b2c3d4e5f60718a1';
  v_answers text[] := array[
    '37.78874,-122.45709',
    '3893',
    'house3893'
  ];
  ans text;
begin
  select id into v_cid from public.challenges where key = 'stage2_coords';
  if v_cid is not null then
    foreach ans in array v_answers loop
      insert into public.challenge_answers (challenge_id, answer_hash)
      values (v_cid, encode(extensions.digest(v_salt || ans, 'sha256'), 'hex'))
      on conflict do nothing;
    end loop;
  end if;
end;
$$;

-- 7. Authoritative submit_challenge RPC with Strict Independent ZKCase and Password Checking
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
  late boolean := false;
  v_pts int := 100;
  now_iso text := to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
begin
  -- 1. Authentication check
  if u is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;

  -- 2. Lookup participant
  pid := public.my_participant();
  if pid is null then
    return jsonb_build_object('status', 'unavailable', 'message', 'Participant record not found.');
  end if;

  -- 3. Lookup challenge
  select * into c from public.challenges where key = p_key and active;
  v_challenge_found := FOUND;

  if not v_challenge_found or c.stage_id is null then
    return jsonb_build_object('status', 'unavailable', 'message', 'Challenge not found or inactive.');
  end if;

  -- 4. Load game settings
  select * into gs from public.game_settings limit 1;
  if gs.paused then
    return jsonb_build_object('status', 'paused', 'message', 'Investigation is currently paused by headquarters.');
  end if;

  -- 5. Check stage override for participant
  select coalesce(
    (select enabled from public.participant_stage_overrides where participant_id = pid limit 1),
    false
  ) into has_override;

  -- 6. Check prerequisite: Stage 1 requires no prereq; Stage 2 requires Stage 1 completed
  if c.stage_id = 1 then
    is_prereq_completed := true;
  else
    select exists (
      select 1 from public.stage_completions
      where participant_id = pid and stage_id = c.stage_id - 1
    ) into is_prereq_completed;
  end if;

  -- 7. Enforce dual release condition (unless overridden)
  if not has_override then
    if not public.game_started() then
      return jsonb_build_object('status', 'unavailable', 'message', 'Investigation has not officially launched.');
    end if;

    if not is_prereq_completed then
      return jsonb_build_object('status', 'unavailable', 'message', 'Prerequisite stage must be completed first.');
    end if;

    if now() < public.stage_open_at(c.stage_id) then
      return jsonb_build_object('status', 'unavailable', 'message', 'Stage release timestamp has not arrived.');
    end if;
  end if;

  -- 8. Duplicate solve check
  if exists(select 1 from public.solves where participant_id = pid and challenge_id = c.id) then
    return jsonb_build_object(
      'status', 'already_solved',
      'message', 'RECORD ON FILE: Clearance was previously unlocked for this case file.',
      'points', 0
    );
  end if;

  -- 9. Validate input presence and length
  if p_answer is null or char_length(trim(p_answer)) = 0 then
    return jsonb_build_object('status', 'invalid', 'message', 'Answer cannot be empty.');
  end if;

  if c.requires_username and (p_username is null or char_length(trim(p_username)) = 0) then
    return jsonb_build_object('status', 'invalid', 'message', 'Directory / Call-sign username is required.');
  end if;

  -- 10. Normalize answers independently
  if c.requires_username then
    unorm := public.norm(p_username, 'text');
    anorm := public.norm(p_answer, 'text');
    if unorm = '' or anorm = '' then
      return jsonb_build_object('status', 'invalid', 'message', 'Inputs must contain valid alphanumeric characters.');
    end if;
    secret := unorm || '|' || anorm;
  else
    anorm := public.norm(p_answer, c.norm_mode);
    if anorm = '' then
      return jsonb_build_object('status', 'invalid', 'message', 'Coordinate stream must contain valid data.');
    end if;
    secret := anorm;
  end if;

  -- 11. Rate limit check (account level)
  if (select count(*) from public.attempts where user_id = u and created_at > now() - interval '1 minute') >= coalesce(gs.rate_limit_account_per_min, 15) then
    return jsonb_build_object('status', 'rate_limited', 'message', 'Rate limit exceeded. Please wait a moment.');
  end if;

  -- 12. Check attempt limits
  select count(*) into used from public.attempts where participant_id = pid and challenge_id = c.id and not voided;
  if c.attempt_limit is not null and used >= c.attempt_limit then
    return jsonb_build_object('status', 'attempts_exhausted', 'message', 'Maximum verification attempts exhausted.');
  end if;

  -- 13. Verify cryptographic salted hash against vault
  ok := exists(
    select 1 from public.challenge_answers
    where challenge_id = c.id
      and answer_hash = encode(extensions.digest(c.salt || secret, 'sha256'), 'hex')
  );

  -- Record attempt
  insert into public.attempts (participant_id, user_id, challenge_id, correct, submitted)
  values (pid, u, c.id, ok, left(coalesce(p_username || ' / ', '') || p_answer, 200));

  if ok then
    -- Record solve
    insert into public.solves (participant_id, user_id, challenge_id, solved_at)
    values (pid, u, c.id, now())
    on conflict do nothing;

    -- Calculate scoring window
    late := now() > public.stage_deadline_at(c.stage_id);
    if late then
      v_pts := 0;
    else
      v_pts := coalesce(c.stage_id * 0 + 100, 100);
    end if;

    -- Record authoritative stage completion
    insert into public.stage_completions (participant_id, stage_id, completed_at, points_earned, scoring_eligible)
    values (pid, c.stage_id, now(), v_pts, not late)
    on conflict (participant_id, stage_id) do nothing;

    return jsonb_build_object(
      'status', 'correct',
      'message', 'CLEARANCE GRANTED: Cryptographic key match confirmed.',
      'points', v_pts,
      'scoring_eligible', not late
    );
  else
    return jsonb_build_object(
      'status', 'incorrect',
      'message', 'ACCESS DENIED: Decryption verification failed.',
      'attempts_left', case when c.attempt_limit is not null then greatest(0, c.attempt_limit - used - 1) else null end
    );
  end if;
end;
$$;

-- 8. Grant permissions
grant execute on function public.submit_challenge(text, text, text) to authenticated;
grant select on public.challenges to authenticated, anon;
grant select on public.stages to authenticated, anon;
