-- =============================================================================
-- 0002_signup_and_student_rules.sql  --  Biotech Home: student sign-up rules
--
-- What this migration does
--   1. Adds format checks on profiles (mobile, student_code, full_name).
--   2. Adds a trigger on auth.users that creates the profile of an ONLINE
--      student at sign-up. The new profile is always role='student',
--      student_type='online', status='pending'. The client can NEVER choose
--      role / status / student_type: those values are hard-coded here and the
--      client-controlled metadata is only read for full_name and mobile.
--   3. Accounts created by an admin (Edge Function, service role) carry the
--      server-only flag app_metadata.created_by_admin = true. The trigger skips
--      them; that function inserts the offline student's profile itself.
--
-- Login scheme (decided with the owner)
--   * Online student : mobile + password. The mobile number is turned into the
--                      technical e-mail  <mobile>@m.biotechhome.invalid
--                      (no real e-mail is sent, so "Confirm e-mail" must be OFF).
--   * Offline student: student ID + mobile + PIN. Created by the admin only.
--
-- Safe to re-run (idempotent).
-- =============================================================================


-- -----------------------------------------------------------------------------
-- 1. FORMAT CHECKS ON profiles
-- -----------------------------------------------------------------------------
alter table public.profiles drop constraint if exists profiles_mobile_format;
alter table public.profiles add constraint profiles_mobile_format
  check (mobile is null or mobile ~ '^01[3-9][0-9]{8}$');          -- Bangladesh mobile, 11 digits

alter table public.profiles drop constraint if exists profiles_student_code_format;
alter table public.profiles add constraint profiles_student_code_format
  check (student_code is null or student_code ~ '^[A-Za-z0-9-]{3,20}$');

alter table public.profiles drop constraint if exists profiles_full_name_len;
alter table public.profiles add constraint profiles_full_name_len
  check (char_length(btrim(full_name)) between 2 and 80);


-- -----------------------------------------------------------------------------
-- 2. SIGN-UP TRIGGER: create the profile of a new ONLINE student
-- -----------------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_name   text;
  v_mobile text;
begin
  -- Admin-created accounts (offline students): profile is inserted by the
  -- trusted Edge Function. app_metadata can only be set server-side.
  if coalesce(new.raw_app_meta_data ->> 'created_by_admin', '') = 'true' then
    return new;
  end if;

  -- Public sign-up: only full_name and mobile are read from client metadata.
  v_name   := btrim(coalesce(new.raw_user_meta_data ->> 'full_name', ''));
  v_mobile := coalesce(new.raw_user_meta_data ->> 'mobile', '');

  if char_length(v_name) < 2 or char_length(v_name) > 80 then
    raise exception 'Full name is required (2 to 80 characters)' using errcode = '22023';
  end if;

  if v_mobile !~ '^01[3-9][0-9]{8}$' then
    raise exception 'A valid 11-digit mobile number is required' using errcode = '22023';
  end if;

  -- The login e-mail must be the technical address built from the same mobile.
  if lower(coalesce(new.email, '')) <> v_mobile || '@m.biotechhome.invalid' then
    raise exception 'Sign-up must use the mobile-number login' using errcode = '22023';
  end if;

  insert into public.profiles (id, role, student_type, full_name, mobile, status)
  values (new.id, 'student', 'online', v_name, v_mobile, 'pending');

  return new;
end;
$$;

revoke all on function public.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- =============================================================================
-- End of 0002_signup_and_student_rules.sql
-- =============================================================================
