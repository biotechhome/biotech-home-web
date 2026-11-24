-- =============================================================================
-- 0001_core.sql  --  Biotech Home: core schema, security helpers, grants, RLS
-- Target: PostgreSQL on Supabase.  All objects live in schema "public".
--
-- Design principles
--   * Login is mandatory: "anon" can only INSERT (and read approved) comments.
--   * Row Level Security (RLS) is enabled on EVERY table.
--   * "Automatic API grants" are OFF in this project, so every privilege the
--     API roles (anon / authenticated) need is granted explicitly below.
--   * Column-level grants are used wherever a role must not write every column.
--   * No secrets of any kind appear in this file.
--
-- The file is written to be re-runnable (idempotent): tables use IF NOT EXISTS,
-- functions use CREATE OR REPLACE, policies/triggers are dropped before being
-- created, and table privileges are revoked and re-granted from scratch.
-- NOTE: it has NOT been executed anywhere yet.
-- =============================================================================


-- =============================================================================
-- 1. TABLES
-- =============================================================================

-- 1.1 profiles: one row per authenticated user (1:1 with auth.users).
create table if not exists public.profiles (
  id           uuid primary key references auth.users (id) on delete cascade,
  role         text not null default 'student'
                 check (role in ('admin', 'student')),
  student_type text not null
                 check (student_type in ('offline', 'online')),
  student_code text unique,                       -- ID for offline students (nullable)
  full_name    text not null,
  mobile       text unique,
  email        text,
  status       text not null default 'pending'
                 check (status in ('pending', 'active', 'blocked')),
  created_at   timestamptz default now()
);

-- 1.2 batches: a class group (offline or online).
create table if not exists public.batches (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  kind       text check (kind in ('offline', 'online')),
  is_active  boolean default true,
  created_at timestamptz default now()
);

-- 1.3 batch_members: which students belong to which batch.
create table if not exists public.batch_members (
  batch_id   uuid not null references public.batches (id)  on delete cascade,
  student_id uuid not null references public.profiles (id) on delete cascade,
  primary key (batch_id, student_id)
);

-- 1.4 courses: the catalog. Paid courses need a course_access row.
create table if not exists public.courses (
  id          uuid primary key default gen_random_uuid(),
  title       text not null,
  description text,
  is_paid     boolean not null default true,
  price_bdt   integer default 0,
  is_active   boolean default true,
  created_at  timestamptz default now()
);

-- 1.5 course_access: which student may open which course (null expires_at = never expires).
create table if not exists public.course_access (
  student_id uuid not null references public.profiles (id) on delete cascade,
  course_id  uuid not null references public.courses (id)  on delete cascade,
  expires_at timestamptz,
  granted_at timestamptz default now(),
  primary key (student_id, course_id)
);

-- 1.6 payments: manual (e.g. bKash) payment claims, reviewed by an admin.
--     student_id / course_id intentionally have NO cascade: financial records
--     must not vanish silently when a profile or course is deleted.
create table if not exists public.payments (
  id            uuid primary key default gen_random_uuid(),
  student_id    uuid not null references public.profiles (id),
  course_id     uuid not null references public.courses (id),
  amount_bdt    integer not null,
  method        text default 'bkash',
  trx_id        text not null unique,             -- transaction ID; unique => no double claim
  sender_number text not null,
  status        text not null default 'pending'
                  check (status in ('pending', 'approved', 'rejected')),
  note          text,
  created_at    timestamptz default now(),
  reviewed_at   timestamptz,
  reviewed_by   uuid references public.profiles (id) on delete set null
);

-- 1.7 comments: public feedback box. Hidden until an admin approves it.
create table if not exists public.comments (
  id          uuid primary key default gen_random_uuid(),
  author_name text not null check (char_length(author_name) between 1 and 60),
  body        text not null check (char_length(body)        between 1 and 1000),
  is_visible  boolean default false,
  created_at  timestamptz default now()
);

-- 1.8 active_sessions: one row per user, used to allow a single active device.
create table if not exists public.active_sessions (
  user_id   uuid primary key references public.profiles (id) on delete cascade,
  device_id text not null,
  last_seen timestamptz default now()
);


-- =============================================================================
-- 2. INDEXES (foreign keys + hot lookup columns)
--    Primary keys / UNIQUE constraints already create their own indexes:
--    batch_members(batch_id) is covered by its PK prefix, and payments(trx_id)
--    is covered by its UNIQUE constraint, so no duplicate index is added there.
-- =============================================================================
create index if not exists idx_batch_members_student_id on public.batch_members (student_id);
create index if not exists idx_course_access_course_id  on public.course_access  (course_id);
create index if not exists idx_payments_student_id      on public.payments       (student_id);
create index if not exists idx_payments_course_id       on public.payments       (course_id);
create index if not exists idx_payments_reviewed_by     on public.payments       (reviewed_by);
create index if not exists idx_payments_status          on public.payments       (status);
create index if not exists idx_comments_visible_created on public.comments      (created_at desc)
  where is_visible;                                -- fast "latest approved comments"


-- =============================================================================
-- 3. SECURITY HELPER FUNCTIONS
--    SECURITY DEFINER lets them read profiles/course_access regardless of the
--    caller's RLS, which also avoids infinite recursion inside policies.
--    search_path is pinned to stop search-path hijacking.
-- =============================================================================

-- 3.1 is_admin(): true if the current user is an admin.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
  );
$$;

-- 3.2 has_course_access(cid): true if the current user may open course "cid".
--     Rule: an ACTIVE user has access when (a) the course is free (not paid), or
--     (b) they hold a non-expired course_access row for it.
--     Pending and blocked users get no access at all (see assumptions).
create or replace function public.has_course_access(cid uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
           select 1
           from public.profiles p
           where p.id = auth.uid()
             and p.status = 'active'
         )
     and (
           exists (
             select 1
             from public.courses c
             where c.id = cid
               and c.is_paid = false
           )
        or exists (
             select 1
             from public.course_access ca
             where ca.course_id  = cid
               and ca.student_id = auth.uid()
               and (ca.expires_at is null or ca.expires_at > now())
           )
         );
$$;

-- Functions are executable by PUBLIC by default; lock that down.
-- Only logged-in users need them (anon policies never call them).
revoke all on function public.is_admin()                from public, anon;
revoke all on function public.has_course_access(uuid)   from public, anon;
grant execute on function public.is_admin()              to authenticated;
grant execute on function public.has_course_access(uuid) to authenticated;


-- =============================================================================
-- 4. PROFILE PROTECTION TRIGGER
--    Column grants cannot tell "admin" from "student" (both use the same
--    database role "authenticated"), so this trigger is the real guard:
--    a non-admin may change only full_name and email on their own row.
--    Requests with no JWT (auth.uid() IS NULL: SQL editor, migrations, the
--    service role used by trusted server code) are not restricted.
-- =============================================================================
create or replace function public.profiles_guard_protected_columns()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if auth.uid() is not null and not public.is_admin() then
    if new.id           is distinct from old.id
    or new.role         is distinct from old.role
    or new.status       is distinct from old.status
    or new.student_type is distinct from old.student_type
    or new.student_code is distinct from old.student_code
    or new.mobile       is distinct from old.mobile
    or new.created_at   is distinct from old.created_at
    then
      raise exception 'Only an admin may change this profile field'
        using errcode = '42501';   -- insufficient_privilege
    end if;
  end if;
  return new;
end;
$$;

revoke all on function public.profiles_guard_protected_columns() from public, anon, authenticated;

drop trigger if exists trg_profiles_guard on public.profiles;
create trigger trg_profiles_guard
  before update on public.profiles
  for each row execute function public.profiles_guard_protected_columns();


-- =============================================================================
-- 5. ENABLE ROW LEVEL SECURITY ON EVERY TABLE
--    With RLS on and no matching policy, access is denied by default.
-- =============================================================================
alter table public.profiles        enable row level security;
alter table public.batches         enable row level security;
alter table public.batch_members   enable row level security;
alter table public.courses         enable row level security;
alter table public.course_access   enable row level security;
alter table public.payments        enable row level security;
alter table public.comments        enable row level security;
alter table public.active_sessions enable row level security;


-- =============================================================================
-- 6. GRANTS (table privileges; RLS then narrows them row by row)
--    Start from a clean slate so re-running the file yields the exact same state.
-- =============================================================================
grant usage on schema public to anon, authenticated;

revoke all on public.profiles, public.batches, public.batch_members,
              public.courses,  public.course_access, public.payments,
              public.comments, public.active_sessions
  from anon, authenticated;

-- profiles: read; update only the listed columns (the trigger in section 4 and
-- the RLS policies decide WHO may change WHICH of them).
-- No INSERT/DELETE: profiles are created by trusted server-side code.
grant select on public.profiles to authenticated;
grant update (full_name, email, mobile, student_code, student_type, role, status)
  on public.profiles to authenticated;

-- batches / batch_members / courses / course_access:
-- everything is granted to "authenticated"; RLS lets students read only what
-- they should and restricts all writes to admins.
grant select, insert, update, delete on public.batches        to authenticated;
grant select, insert, update, delete on public.batch_members  to authenticated;
grant select, insert, update, delete on public.courses        to authenticated;
grant select, insert, update, delete on public.course_access  to authenticated;

-- payments: students INSERT only the claim fields (status/review fields keep
-- their defaults); admins UPDATE only the review fields. No DELETE: audit trail.
grant select on public.payments to authenticated;
grant insert (student_id, course_id, amount_bdt, method, trx_id, sender_number, note)
  on public.payments to authenticated;
grant update (status, note, reviewed_at, reviewed_by)
  on public.payments to authenticated;

-- comments: anon may only INSERT (author_name, body) and read approved rows.
-- is_visible cannot be written on INSERT, so it always starts as false.
grant insert (author_name, body) on public.comments to anon, authenticated;
grant select                     on public.comments to anon, authenticated;
grant update (is_visible)        on public.comments to authenticated;  -- admin only via RLS
grant delete                     on public.comments to authenticated;  -- admin only via RLS

-- active_sessions: a user manages only their own row.
grant select, insert, update on public.active_sessions to authenticated;


-- =============================================================================
-- 7. ROW LEVEL SECURITY POLICIES
--    Policies of the same command are OR-ed together; a row is allowed when
--    any applicable policy passes.
-- =============================================================================

-- ---- profiles ---------------------------------------------------------------
drop policy if exists profiles_select_own   on public.profiles;
drop policy if exists profiles_select_admin on public.profiles;
drop policy if exists profiles_update_own   on public.profiles;
drop policy if exists profiles_update_admin on public.profiles;

-- A user reads their own row.
create policy profiles_select_own on public.profiles
  for select to authenticated
  using (id = auth.uid());

-- Admin reads every profile.
create policy profiles_select_admin on public.profiles
  for select to authenticated
  using (public.is_admin());

-- A user updates their own row (the guard trigger limits it to full_name/email).
create policy profiles_update_own on public.profiles
  for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

-- Admin updates any profile (role, status, student_type, ...).
create policy profiles_update_admin on public.profiles
  for update to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ---- batches ----------------------------------------------------------------
drop policy if exists batches_select_member on public.batches;
drop policy if exists batches_admin_all     on public.batches;

-- A student sees only batches they belong to.
create policy batches_select_member on public.batches
  for select to authenticated
  using (exists (
    select 1
    from public.batch_members bm
    where bm.batch_id   = batches.id
      and bm.student_id = auth.uid()
  ));

create policy batches_admin_all on public.batches
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ---- batch_members ----------------------------------------------------------
drop policy if exists batch_members_select_own on public.batch_members;
drop policy if exists batch_members_admin_all  on public.batch_members;

create policy batch_members_select_own on public.batch_members
  for select to authenticated
  using (student_id = auth.uid());

create policy batch_members_admin_all on public.batch_members
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ---- courses ----------------------------------------------------------------
drop policy if exists courses_select_active on public.courses;
drop policy if exists courses_admin_all     on public.courses;

-- Any logged-in user sees active courses (the catalog), paid or not.
-- This exposes catalog metadata only; protected CONTENT is guarded separately
-- by has_course_access() and private Storage.
create policy courses_select_active on public.courses
  for select to authenticated
  using (is_active = true);

-- Admin sees and manages everything, including inactive courses.
create policy courses_admin_all on public.courses
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ---- course_access ----------------------------------------------------------
drop policy if exists course_access_select_own on public.course_access;
drop policy if exists course_access_admin_all  on public.course_access;

-- A student reads only their own access rows. Writes: admin only.
create policy course_access_select_own on public.course_access
  for select to authenticated
  using (student_id = auth.uid());

create policy course_access_admin_all on public.course_access
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ---- payments ---------------------------------------------------------------
drop policy if exists payments_select_own    on public.payments;
drop policy if exists payments_select_admin  on public.payments;
drop policy if exists payments_insert_own    on public.payments;
drop policy if exists payments_update_admin  on public.payments;

create policy payments_select_own on public.payments
  for select to authenticated
  using (student_id = auth.uid());

create policy payments_select_admin on public.payments
  for select to authenticated
  using (public.is_admin());

-- A student can only file a PENDING claim for themselves.
create policy payments_insert_own on public.payments
  for insert to authenticated
  with check (student_id = auth.uid() and status = 'pending');

-- Only an admin may review (approve / reject). Students have no UPDATE policy.
create policy payments_update_admin on public.payments
  for update to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- ---- comments ---------------------------------------------------------------
drop policy if exists comments_insert_public   on public.comments;
drop policy if exists comments_select_visible  on public.comments;
drop policy if exists comments_select_admin    on public.comments;
drop policy if exists comments_update_admin    on public.comments;
drop policy if exists comments_delete_admin    on public.comments;

-- Anyone may submit a comment, but it always starts hidden.
create policy comments_insert_public on public.comments
  for insert to anon, authenticated
  with check (is_visible = false);

-- Everyone reads approved comments only.
create policy comments_select_visible on public.comments
  for select to anon, authenticated
  using (is_visible = true);

-- Admin must also see hidden comments to moderate them (and UPDATE needs it).
create policy comments_select_admin on public.comments
  for select to authenticated
  using (public.is_admin());

create policy comments_update_admin on public.comments
  for update to authenticated
  using (public.is_admin())
  with check (public.is_admin());

create policy comments_delete_admin on public.comments
  for delete to authenticated
  using (public.is_admin());

-- ---- active_sessions --------------------------------------------------------
drop policy if exists active_sessions_select_own on public.active_sessions;
drop policy if exists active_sessions_insert_own on public.active_sessions;
drop policy if exists active_sessions_update_own on public.active_sessions;

create policy active_sessions_select_own on public.active_sessions
  for select to authenticated
  using (user_id = auth.uid());

create policy active_sessions_insert_own on public.active_sessions
  for insert to authenticated
  with check (user_id = auth.uid());

create policy active_sessions_update_own on public.active_sessions
  for update to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- =============================================================================
-- End of 0001_core.sql
-- =============================================================================
