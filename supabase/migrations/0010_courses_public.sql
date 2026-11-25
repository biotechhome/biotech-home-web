-- 0010: let visitors (not logged in) see the list of active courses on the home page.
-- Course CONTENT stays protected by has_course_access(); only title/description/price are public.
grant select on public.courses to anon;
drop policy if exists courses_select_anon on public.courses;
create policy courses_select_anon on public.courses for select to anon using (is_active);
