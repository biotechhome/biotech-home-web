-- 0006: exams, marks and daily attendance (data comes from the Flutter app)
create table if not exists public.exams (
  id         bigint primary key,                     -- same number as in the app
  name       text not null,
  max_marks  integer not null check (max_marks > 0),
  created_at timestamptz not null default now()
);
create table if not exists public.exam_marks (
  student_id uuid   not null references public.profiles (id) on delete cascade,
  exam_id    bigint not null references public.exams (id)    on delete cascade,
  marks      integer check (marks is null or marks >= 0),
  present    boolean not null default true,
  primary key (student_id, exam_id)
);
create table if not exists public.daily_attendance (
  student_id uuid not null references public.profiles (id) on delete cascade,
  att_date   date not null,
  status     text not null check (status in ('present','absent')),
  primary key (student_id, att_date)
);
create index if not exists idx_exam_marks_exam on public.exam_marks (exam_id);
create index if not exists idx_daily_att_date  on public.daily_attendance (att_date);

alter table public.exams            enable row level security;
alter table public.exam_marks       enable row level security;
alter table public.daily_attendance enable row level security;
revoke all on public.exams, public.exam_marks, public.daily_attendance from anon, authenticated;
grant select, insert, update, delete on public.exams, public.exam_marks, public.daily_attendance to authenticated;
grant select, insert, update, delete on public.exams, public.exam_marks, public.daily_attendance to service_role;

drop policy if exists exams_read       on public.exams;
drop policy if exists exams_admin_all  on public.exams;
drop policy if exists marks_own        on public.exam_marks;
drop policy if exists marks_admin_all  on public.exam_marks;
drop policy if exists att_own          on public.daily_attendance;
drop policy if exists att_admin_all    on public.daily_attendance;
create policy exams_read      on public.exams for select to authenticated using (true);
create policy exams_admin_all on public.exams for all    to authenticated using (public.is_admin()) with check (public.is_admin());
create policy marks_own       on public.exam_marks for select to authenticated using (student_id = auth.uid());
create policy marks_admin_all on public.exam_marks for all    to authenticated using (public.is_admin()) with check (public.is_admin());
create policy att_own         on public.daily_attendance for select to authenticated using (student_id = auth.uid());
create policy att_admin_all   on public.daily_attendance for all    to authenticated using (public.is_admin()) with check (public.is_admin());

-- the other batches that exist in the app
insert into public.batches (name, kind)
select v.name, 'offline' from (values ('স্পেশাল'), ('Admission'), ('ICT')) as v(name)
where not exists (select 1 from public.batches b where b.name = v.name);
