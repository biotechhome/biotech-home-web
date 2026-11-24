-- 0005: admin student form like the Flutter app (auto ID, batch, time, photo, optional fee)
-- ---------------------------------------------------------------------------
-- 1. Auto-increment student ID. The app is at 279, so the web continues at 280.
create sequence if not exists public.student_code_seq start 280;

create or replace function public.next_student_code()
returns text language sql security definer set search_path = public as
$$ select nextval('public.student_code_seq')::text $$;
revoke all on function public.next_student_code() from public, anon, authenticated;
grant execute on function public.next_student_code() to service_role;

-- 2. IDs are plain numbers (1, 2, ... 279): allow 1-20 characters.
alter table public.profiles drop constraint if exists profiles_student_code_format;
alter table public.profiles add constraint profiles_student_code_format
  check (student_code is null or student_code ~ '^[A-Za-z0-9-]{1,20}$');

-- 3. Siblings share a mobile number in the app, so offline students may share one.
--    Online students log in by mobile, so it stays unique among them.
alter table public.profiles drop constraint if exists profiles_mobile_key;
create unique index if not exists profiles_online_mobile_uq
  on public.profiles (mobile) where student_type = 'online';

-- 4. Class time (e.g. "২টা") and photo path. Not granted for update to clients:
--    only trusted server code (service_role) writes them.
alter table public.profiles add column if not exists class_time text;
alter table public.profiles add column if not exists photo_path text;

-- 5. Batches used in the app (more can be added from the admin page).
insert into public.batches (name, kind)
select v.name, 'offline' from (values ('ICT শনি সিরিজ'), ('শনি সিরিজ'), ('রবি সিরিজ')) as v(name)
where not exists (select 1 from public.batches b where b.name = v.name);

-- 6. Monthly fee records (offline students; the app's Paid / Due / Partial).
create table if not exists public.fee_payments (
  id          uuid primary key default gen_random_uuid(),
  student_id  uuid not null references public.profiles (id) on delete cascade,
  fee_month   text not null check (fee_month in
    ('January','February','March','April','May','June','July','August','September','October','November','December')),
  fee_year    integer not null check (fee_year between 2020 and 2100),
  status      text not null check (status in ('paid','due','partial')),
  amount_bdt  integer check (amount_bdt is null or amount_bdt >= 0),
  created_at  timestamptz not null default now(),
  unique (student_id, fee_month, fee_year)
);
create index if not exists idx_fee_payments_student on public.fee_payments (student_id);
alter table public.fee_payments enable row level security;
revoke all on public.fee_payments from anon, authenticated;
grant select, insert, update, delete on public.fee_payments to authenticated;   -- RLS below: admin writes
grant select, insert, update, delete on public.fee_payments to service_role;
drop policy if exists fee_select_own on public.fee_payments;
drop policy if exists fee_admin_all  on public.fee_payments;
create policy fee_select_own on public.fee_payments for select to authenticated using (student_id = auth.uid());
create policy fee_admin_all  on public.fee_payments for all    to authenticated using (public.is_admin()) with check (public.is_admin());

-- 7. Private bucket for student photos: <student uuid>/photo.jpg
insert into storage.buckets (id, name, public) values ('student-photos', 'student-photos', false)
on conflict (id) do nothing;
drop policy if exists sp_admin_all  on storage.objects;
drop policy if exists sp_read_own   on storage.objects;
create policy sp_admin_all on storage.objects for all to authenticated
  using (bucket_id = 'student-photos' and public.is_admin())
  with check (bucket_id = 'student-photos' and public.is_admin());
create policy sp_read_own on storage.objects for select to authenticated
  using (bucket_id = 'student-photos' and (storage.foldername(name))[1] = auth.uid()::text);
