-- 0009: public merit list. Only exams the admin marks public_merit=true are exposed,
-- and only name, marks and rank (never mobile, id or fees). Not-logged-in visitors see the top 10 only.
alter table public.exams add column if not exists public_merit boolean not null default false;

create or replace function public.merit_exams()
returns table (id uuid, session_year integer, app_id integer, name text, max_marks integer)
language sql stable security definer set search_path = public as
$$ select e.id, e.session_year, e.app_id, e.name, e.max_marks from public.exams e where e.public_merit order by e.session_year desc, e.app_id $$;

create or replace function public.merit_list(p_session integer, p_exam uuid default null)
returns table (rank bigint, full_name text, marks integer, max_marks integer, percent numeric)
language sql stable security definer set search_path = public as
$$
  with src as (
    select p.id, p.full_name, m.marks, e.max_marks
    from public.exam_marks m
    join public.exams e on e.id = m.exam_id and e.public_merit and e.session_year = p_session
    join public.profiles p on p.id = m.student_id and p.status = 'active' and p.session_year = p_session
    where m.present and (p_exam is null or e.id = p_exam)
  ), agg as (
    select id, full_name, sum(marks)::integer as marks, sum(max_marks)::integer as max_marks from src group by id, full_name
  )
  , ranked as (
    select rank() over (order by (marks::numeric / nullif(max_marks, 0)) desc nulls last) as rank, full_name, marks, max_marks,
           round(marks * 100.0 / nullif(max_marks, 0), 1) as percent
    from agg
  )
  -- visitors who are not logged in only see the top 10 ranks; logged-in users see everyone (max 200 rows)
  select rank, full_name, marks, max_marks, percent from ranked
  where auth.uid() is not null or rank <= 10
  order by rank, full_name limit 200
$$;
revoke all on function public.merit_exams() from public;
revoke all on function public.merit_list(integer, uuid) from public;
grant execute on function public.merit_exams() to anon, authenticated;
grant execute on function public.merit_list(integer, uuid) to anon, authenticated;
