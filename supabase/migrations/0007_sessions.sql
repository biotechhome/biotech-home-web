-- 0007: two sessions (HSC 2028 and HSC 2027) with their own ID series.
--   student_code (e.g. "28-279") is for the website only; the sync key with the
--   Flutter app is (session_year, app_id).
alter table public.profiles add column if not exists session_year integer check (session_year between 2020 and 2100);
alter table public.profiles add column if not exists app_id integer check (app_id > 0);
create unique index if not exists profiles_session_app_uq on public.profiles (session_year, app_id) where session_year is not null;

alter table public.batches add column if not exists session_year integer;
update public.batches set session_year = 2028 where session_year is null;
insert into public.batches (name, kind, session_year)
select v.name, 'offline', 2027 from (values ('শনি সিরিজ'),('রবি সিরিজ'),('স্পেশাল'),('Admission'),('ICT')) as v(name)
where not exists (select 1 from public.batches b where b.name = v.name and b.session_year = 2027);

-- Per-session auto-increment (replaces the single sequence from 0005).
create table if not exists public.student_counters (
  session_year integer primary key,
  next_no      integer not null check (next_no > 0)
);
insert into public.student_counters (session_year, next_no) values (2028, 280), (2027, 190)
on conflict (session_year) do nothing;
alter table public.student_counters enable row level security;
revoke all on public.student_counters from anon, authenticated;
grant select, insert, update on public.student_counters to service_role;

create or replace function public.next_student_no(p_session integer)
returns integer language sql security definer set search_path = public as
$$ update public.student_counters set next_no = next_no + 1
   where session_year = p_session returning next_no - 1 $$;
revoke all on function public.next_student_no(integer) from public, anon, authenticated;
grant execute on function public.next_student_no(integer) to service_role;

drop function if exists public.next_student_code();
drop sequence if exists public.student_code_seq;

-- Exams are per session (the two apps both have an exam #1): recreate (tables are still empty).
drop table if exists public.exam_marks;
drop table if exists public.exams;
create table public.exams (
  id           uuid primary key default gen_random_uuid(),
  session_year integer not null,
  app_id       integer not null,
  name         text not null,
  max_marks    integer not null check (max_marks > 0),
  created_at   timestamptz not null default now(),
  unique (session_year, app_id)
);
create table public.exam_marks (
  student_id uuid not null references public.profiles (id) on delete cascade,
  exam_id    uuid not null references public.exams (id)    on delete cascade,
  marks      integer check (marks is null or marks >= 0),
  present    boolean not null default true,
  primary key (student_id, exam_id)
);
create index idx_exam_marks_exam on public.exam_marks (exam_id);
alter table public.exams      enable row level security;
alter table public.exam_marks enable row level security;
revoke all on public.exams, public.exam_marks from anon, authenticated;
grant select, insert, update, delete on public.exams, public.exam_marks to authenticated;
grant select, insert, update, delete on public.exams, public.exam_marks to service_role;
create policy exams_read      on public.exams for select to authenticated using (true);
create policy exams_admin_all on public.exams for all    to authenticated using (public.is_admin()) with check (public.is_admin());
create policy marks_own       on public.exam_marks for select to authenticated using (student_id = auth.uid());
create policy marks_admin_all on public.exam_marks for all    to authenticated using (public.is_admin()) with check (public.is_admin());
