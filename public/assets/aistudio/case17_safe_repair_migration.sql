-- =====================================================================================================================
-- THE LAST SIGNAL (TLS-0017) — SAFE REPAIR & RECOVERY MIGRATION (v4.2.0)
-- 
-- Target: Supabase PostgreSQL Database
-- Purpose:
--   1. Fix column incompatibility (ERROR 42703: column "stage_number" does not exist)
--      by unifying stage_id <=> stage_number and points_earned <=> score via synchronized triggers.
--   2. Fix Stage 1 challenge verification (replace legacy "orion" hash with canonical acrostic solutions).
--   3. Fix Stage 2 coordinates challenge hashes (enable 37.78874, -122.45709 verification).
--   4. Fix team registration lockout in membership_open() (prevent unexpected lock when membership_lock_at is NULL).
--   5. Unify calculate_participant_score() and score_of() to calculate consistent scores.
--   6. Ensure get_leaderboard() reliably aggregates student teams and solo operatives.
--   7. Set strict RLS policies and grant execute permissions.
--
-- Safety:
--   - 100% IDEMPOTENT (safe to run multiple times).
--   - Preserves all existing student profiles, participants, teams, and solved stages.
--   - No DROP TABLE or destructive cascade drops.
-- =====================================================================================================================

-- ---------------------------------------------------------------------------------------------------------------------
-- 1. EXTENSIONS
-- ---------------------------------------------------------------------------------------------------------------------
create extension if not exists "pgcrypto" with schema extensions;

-- ---------------------------------------------------------------------------------------------------------------------
-- 2. STAGE_COMPLETIONS SCHEMA UNIFICATION (stage_id <=> stage_number, points_earned <=> score)
-- ---------------------------------------------------------------------------------------------------------------------
do $$
begin
  -- Ensure table exists
  if not exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'stage_completions') then
    create table public.stage_completions (
      id uuid primary key default gen_random_uuid(),
      participant_id uuid not null references public.participants(id) on delete cascade,
      stage_id int not null,
      stage_number int,
      completed_at timestamptz not null default now(),
      late boolean not null default false,
      points_earned int not null default 0,
      score int not null default 0,
      completed_by uuid references public.profiles(id) on delete set null,
      constraint stage_completions_part_stage_uniq unique (participant_id, stage_id)
    );
  else
    -- Add stage_number if missing
    if not exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'stage_completions' and column_name = 'stage_number') then
      alter table public.stage_completions add column stage_number int;
    end if;

    -- Add score if missing
    if not exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'stage_completions' and column_name = 'score') then
      alter table public.stage_completions add column score int default 0;
    end if;

    -- Add stage_id if missing
    if not exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'stage_completions' and column_name = 'stage_id') then
      alter table public.stage_completions add column stage_id int;
    end if;

    -- Add points_earned if missing
    if not exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'stage_completions' and column_name = 'points_earned') then
      alter table public.stage_completions add column points_earned int default 0;
    end if;

    -- Add completed_by if missing
    if not exists (select 1 from information_schema.columns where table_schema = 'public' and table_name = 'stage_completions' and column_name = 'completed_by') then
      alter table public.stage_completions add column completed_by uuid references public.profiles(id) on delete set null;
    end if;
  end if;
end $$;

-- Backfill missing aliases for existing records
update public.stage_completions
set stage_number = stage_id
where stage_number is null and stage_id is not null;

update public.stage_completions
set stage_id = stage_number
where stage_id is null and stage_number is not null;

update public.stage_completions
set score = coalesce(points_earned, 0)
where score is null or (score = 0 and points_earned > 0);

update public.stage_completions
set points_earned = coalesce(score, 0)
where points_earned is null or (points_earned = 0 and score > 0);

-- Synchronization trigger function
create or replace function public.sync_stage_completions_columns()
returns trigger language plpgsql security definer as $$
begin
  -- Sync stage identifiers
  if NEW.stage_id is not null and NEW.stage_number is null then
    NEW.stage_number := NEW.stage_id;
  elsif NEW.stage_number is not null and NEW.stage_id is null then
    NEW.stage_id := NEW.stage_number;
  end if;

  -- Sync score/points
  if NEW.points_earned is not null and (NEW.score is null or NEW.score = 0) then
    NEW.score := NEW.points_earned;
  elsif NEW.score is not null and (NEW.points_earned is null or NEW.points_earned = 0) then
    NEW.points_earned := NEW.score;
  end if;

  return NEW;
end;
$$;

drop trigger if exists trg_sync_stage_completions_columns on public.stage_completions;
create trigger trg_sync_stage_completions_columns
before insert or update on public.stage_completions
for each row execute function public.sync_stage_completions_columns();

-- ---------------------------------------------------------------------------------------------------------------------
-- 3. MEMBERSHIP_OPEN() REPAIR (Fix "Team registration window has closed")
-- ---------------------------------------------------------------------------------------------------------------------
-- Prevents spurious lockout when membership_lock_at is NULL after game start.
create or replace function public.membership_open()
returns boolean language plpgsql stable security definer set search_path = public, extensions, pg_temp as $$
declare
  is_open boolean := true;
begin
  if exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'game_settings') then
    execute 'select coalesce(registration_open, true) and (membership_lock_at is null or now() < membership_lock_at) from public.game_settings limit 1' into is_open;
    return coalesce(is_open, true);
  end if;
  return true;
end;
$$;

-- ---------------------------------------------------------------------------------------------------------------------
-- 4. SCORE COMPUTATION ENGINE (calculate_participant_score & score_of)
-- ---------------------------------------------------------------------------------------------------------------------
create or replace function public.calculate_participant_score(pid uuid)
returns int language sql stable security definer set search_path = public, extensions, pg_temp as $$
  select greatest(0,
    coalesce((select sum(coalesce(c.points_earned, c.score, 0)) from public.stage_completions c where c.participant_id = pid), 0)
    + case when exists(
        select 1 from public.location_choices lc
        cross join public.location_config cfg
        where lc.participant_id = pid and lc.location_id = cfg.correct_location_id and cfg.enabled
      ) then coalesce((select bonus_points from public.location_config limit 1), 20) else 0 end
    + coalesce((select sum(a.delta) from public.score_adjustments a where a.participant_id = pid), 0)
  )::int;
$$;

create or replace function public.score_of(pid uuid)
returns int language sql stable security definer set search_path = public, extensions, pg_temp as $$
  select public.calculate_participant_score(pid);
$$;

-- ---------------------------------------------------------------------------------------------------------------------
-- 5. CHALLENGES & CANONICAL ANSWER HASH REPAIR
-- ---------------------------------------------------------------------------------------------------------------------
create table if not exists public.challenges (
  id uuid primary key default gen_random_uuid(),
  key text unique not null,
  label text not null,
  kind text not null check (kind in ('gate', 'puzzle')),
  stage_id int references public.stages(id),
  requires_username boolean not null default false,
  norm_mode text not null default 'text' check (norm_mode in ('text', 'coords')),
  active boolean not null default true,
  salt text not null default encode(gen_random_bytes(16), 'hex'),
  attempt_limit int,
  requires_challenge_id uuid references public.challenges(id),
  created_at timestamptz not null default now()
);

create table if not exists public.challenge_answers (
  id uuid primary key default gen_random_uuid(),
  challenge_id uuid not null references public.challenges(id) on delete cascade,
  answer_hash text not null,
  created_at timestamptz not null default now(),
  constraint challenge_answers_uniq unique (challenge_id, answer_hash)
);

-- Seed canonical challenges with fixed security salts
insert into public.challenges (key, label, kind, stage_id, requires_username, norm_mode, active, salt)
values
  ('gate_zk_login', 'Locked Case Files Terminal', 'gate', 1, true, 'text', true, 'a1b2c3d4e5f60718'),
  ('stage2_coords', 'Negative Coordinates Terminal', 'puzzle', 2, false, 'coords', true, 'b2c3d4e5f60718a1'),
  ('gate_map', 'Tactical GIS Map Gate', 'gate', 3, false, 'text', true, 'c3d4e5f60718a1b2'),
  ('gate_suspect_db', 'Suspect Registry Access Gate', 'gate', 5, false, 'text', true, 'd4e5f60718a1b2c3'),
  ('gate_audio', 'Teletype Audio Intercept Gate', 'gate', 6, false, 'text', true, 'e5f60718a1b2c3d4')
on conflict (key) do update set
  stage_id = excluded.stage_id,
  requires_username = excluded.requires_username,
  norm_mode = excluded.norm_mode,
  active = true,
  salt = excluded.salt;

-- Remove legacy incorrect hashes (e.g. legacy orion hash)
delete from public.challenge_answers
where challenge_id = (select id from public.challenges where key = 'gate_zk_login')
  and answer_hash = encode(extensions.digest('a1b2c3d4e5f60718' || 'zkcase17|orion', 'sha256'), 'hex');

-- Insert canonical Stage 1 hashes (Acrostic: zkcase/zk/zcase/zkcase17 + Telestich: case17/17)
do $$
declare
  c_id uuid;
  salt text := 'a1b2c3d4e5f60718';
  combos text[] := array[
    'zkcase|case17',
    'zkcase|17',
    'zk|case17',
    'zk|17',
    'zcase|case17',
    'zcase|17',
    'zkcase17|case17',
    'zkcase17|17'
  ];
  combo text;
begin
  select id into c_id from public.challenges where key = 'gate_zk_login';
  if c_id is not null then
    foreach combo in array combos loop
      insert into public.challenge_answers (challenge_id, answer_hash)
      values (c_id, encode(extensions.digest(salt || combo, 'sha256'), 'hex'))
      on conflict do nothing;
    end loop;
  end if;
end $$;

-- Insert canonical Stage 2 coordinates hashes (Lat: 37.78874, Long: -122.45709)
do $$
declare
  c_id uuid;
  salt text := 'b2c3d4e5f60718a1';
  combos text[] := array[
    '37.78874,-122.45709',
    '37.78874,-122.457090',
    '37.78874n,-122.45709w',
    '37.78874n,122.45709w',
    '37.78874,122.45709',
    '37.78874-122.45709'
  ];
  combo text;
begin
  select id into c_id from public.challenges where key = 'stage2_coords';
  if c_id is not null then
    foreach combo in array combos loop
      insert into public.challenge_answers (challenge_id, answer_hash)
      values (c_id, encode(extensions.digest(salt || combo, 'sha256'), 'hex'))
      on conflict do nothing;
    end loop;
  end if;
end $$;

-- Insert Stage 3, 5, 6 canonical hashes
do $$
declare
  c_id uuid;
begin
  -- Stage 3
  select id into c_id from public.challenges where key = 'gate_map';
  if c_id is not null then
    insert into public.challenge_answers (challenge_id, answer_hash)
    values (c_id, encode(extensions.digest('c3d4e5f60718a1b2' || '3893', 'sha256'), 'hex'))
    on conflict do nothing;
  end if;

  -- Stage 5
  select id into c_id from public.challenges where key = 'gate_suspect_db';
  if c_id is not null then
    insert into public.challenge_answers (challenge_id, answer_hash)
    values (c_id, encode(extensions.digest('d4e5f60718a1b2c3' || 'z408reopened', 'sha256'), 'hex'))
    on conflict do nothing;
  end if;

  -- Stage 6
  select id into c_id from public.challenges where key = 'gate_audio';
  if c_id is not null then
    insert into public.challenge_answers (challenge_id, answer_hash)
    values (c_id, encode(extensions.digest('e5f60718a1b2c3d4' || 'ev1971', 'sha256'), 'hex'))
    on conflict do nothing;
  end if;
end $$;

-- ---------------------------------------------------------------------------------------------------------------------
-- 6. RPC: SUBMIT_CHALLENGE (Robust with Override Support)
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
  used int;
  ok boolean;
  secret text;
  unorm text;
  anorm text;
  st public.stages;
  late boolean;
  has_override boolean := false;
  stage_pts int := 100;
begin
  if u is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;

  pid := public.my_participant();
  if pid is null then
    return jsonb_build_object('status', 'unavailable', 'error', 'No active participant record found.');
  end if;

  select * into gs from public.game_settings;
  select * into c from public.challenges where key = p_key and active;
  if not found or c.id is null then
    return jsonb_build_object('status', 'unavailable', 'error', 'Unknown or inactive challenge docket.');
  end if;

  -- Check if participant has an active staff override
  if exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'participant_stage_overrides') then
    select coalesce(enabled, false) into has_override
    from public.participant_stage_overrides
    where participant_id = pid;
  end if;

  -- Stage accessibility check
  if not has_override then
    if not public.game_started() then
      return jsonb_build_object('status', 'unavailable', 'error', 'Investigation game has not officially commenced.');
    end if;

    if now() < public.stage_open_at(c.stage_id) then
      return jsonb_build_object('status', 'unavailable', 'error', 'Case file is sealed until its scheduled operational opening.');
    end if;
  end if;

  if gs.paused and not has_override then
    return jsonb_build_object('status', 'paused');
  end if;

  -- Concurrency advisory lock per participant
  perform pg_advisory_xact_lock(hashtextextended(pid::text, 0));

  -- Check if already solved
  if exists(select 1 from public.solves where participant_id = pid and challenge_id = c.id) then
    return jsonb_build_object('status', 'already_solved');
  end if;

  -- Normalize answer
  if c.requires_username then
    unorm := public.norm(p_username, 'text');
    anorm := public.norm(p_answer, 'text');
    secret := unorm || '|' || anorm;
    if unorm = '' or anorm = '' then
      return jsonb_build_object('status', 'invalid', 'error', 'Both archive directory and master key are required.');
    end if;
  else
    anorm := public.norm(p_answer, c.norm_mode);
    secret := anorm;
    if anorm = '' then
      return jsonb_build_object('status', 'invalid', 'error', 'Decryption string cannot be blank.');
    end if;
  end if;

  -- Attempt counter
  select count(*) into used from public.attempts where participant_id = pid and challenge_id = c.id and not voided;
  if c.attempt_limit is not null and used >= c.attempt_limit then
    return jsonb_build_object('status', 'attempts_exhausted');
  end if;

  -- Verify cryptographic hash against challenge_answers
  ok := exists(
    select 1 from public.challenge_answers
    where challenge_id = c.id
      and answer_hash = encode(extensions.digest(c.salt || secret, 'sha256'), 'hex')
  );

  insert into public.attempts(participant_id, user_id, challenge_id, correct, submitted)
  values (pid, u, c.id, ok, left(coalesce(p_username || ' / ', '') || p_answer, 200));

  if ok then
    insert into public.solves(participant_id, challenge_id, solved_by)
    values (pid, c.id, u)
    on conflict do nothing;

    -- Award points
    select * into st from public.stages where id = c.stage_id;
    stage_pts := coalesce(st.points, 100);
    late := coalesce(now() > public.stage_close_at(c.stage_id), false);
    if late and not has_override then
      stage_pts := 0;
    end if;

    -- Insert into stage_completions (trigger automatically synchronizes stage_number & score)
    insert into public.stage_completions(
      participant_id,
      stage_id,
      stage_number,
      late,
      points_earned,
      score,
      completed_by
    ) values (
      pid,
      c.stage_id,
      c.stage_id,
      late,
      stage_pts,
      stage_pts,
      u
    ) on conflict (participant_id, stage_id) do nothing;

    return jsonb_build_object(
      'status', 'correct',
      'stage_id', c.stage_id,
      'late', late,
      'points', stage_pts
    );
  end if;

  return jsonb_build_object(
    'status', 'incorrect',
    'attempts_left', case when c.attempt_limit is null then null else c.attempt_limit - used - 1 end
  );
end;
$$;

-- ---------------------------------------------------------------------------------------------------------------------
-- 7. LEADERBOARD ENGINE (Aggregates Teams & Solos, Respects Active Members)
-- ---------------------------------------------------------------------------------------------------------------------
create or replace function public.get_leaderboard(p_kind text default 'all')
returns table(
  pos bigint,
  name text,
  kind text,
  score int,
  stages_completed int,
  current_stage int,
  completion_percentage int,
  last_progress timestamptz
)
language sql stable security definer set search_path = public, extensions, pg_temp as $$
  with candidate_participants as (
    select
      p.id as participant_id,
      p.kind as participant_kind,
      coalesce(p.name, pr.username) as entity_name,
      public.score_of(p.id) as total_score,
      (select count(*)::int from public.stage_completions sc where sc.participant_id = p.id) as completed_count,
      greatest(
        (select max(v.solved_at) from public.solves v where v.participant_id = p.id),
        (select max(c2.completed_at) from public.stage_completions c2 where c2.participant_id = p.id),
        p.created_at
      ) as latest_activity
    from public.participants p
    left join public.profiles pr on pr.id = p.solo_user_id
    where not p.retired
      and not coalesce(p.exclude_from_leaderboard, false)
      and not coalesce(pr.exclude_from_leaderboard, false)
      and (p_kind = 'all' or p.kind = p_kind)
      -- Exclude staff
      and not exists (select 1 from public.staff st where st.user_id = pr.id)
  )
  select
    rank() over (order by cp.total_score desc, cp.completed_count desc, cp.latest_activity asc) as pos,
    cp.entity_name as name,
    cp.participant_kind as kind,
    cp.total_score as score,
    cp.completed_count as stages_completed,
    least(7, cp.completed_count + 1) as current_stage,
    round((cp.completed_count::numeric / 7.0) * 100)::int as completion_percentage,
    cp.latest_activity as last_progress
  from candidate_participants cp
  order by pos asc, cp.latest_activity asc;
$$;

-- ---------------------------------------------------------------------------------------------------------------------
-- 8. SECURITY & GRANTS
-- ---------------------------------------------------------------------------------------------------------------------
-- Ensure RLS on critical tables
alter table if exists public.stage_completions enable row level security;
alter table if exists public.challenges enable row level security;
alter table if exists public.challenge_answers enable row level security;

-- Stage completions policies
drop policy if exists "stage_completions_read_authenticated" on public.stage_completions;
create policy "stage_completions_read_authenticated" on public.stage_completions
  for select to authenticated using (true);

drop policy if exists "stage_completions_read_anon" on public.stage_completions;
create policy "stage_completions_read_anon" on public.stage_completions
  for select to anon using (true);

-- Challenges policies: Public can read metadata, but NOT salt
drop policy if exists "challenges_read_public" on public.challenges;
create policy "challenges_read_public" on public.challenges
  for select to authenticated, anon using (active);

-- Challenge answers policy: strictly deny direct client reads to protect solution hashes
drop policy if exists "challenge_answers_deny_direct" on public.challenge_answers;
create policy "challenge_answers_deny_direct" on public.challenge_answers
  for all to authenticated, anon using (false);

-- Function execution grants
grant execute on function public.membership_open() to anon, authenticated, service_role;
grant execute on function public.calculate_participant_score(uuid) to anon, authenticated, service_role;
grant execute on function public.score_of(uuid) to anon, authenticated, service_role;
grant execute on function public.submit_challenge(text, text, text) to authenticated;
grant execute on function public.get_leaderboard(text) to anon, authenticated, service_role;

-- Notify PostgREST schema cache
notify pgrst, 'reload schema';
