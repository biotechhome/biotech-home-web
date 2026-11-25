-- Edge Functions run as service_role. Automatic API grants are OFF, so give it what it needs.
-- (Found during live testing: archive/PIN-reset failed because the profiles guard trigger calls is_admin();
--  content-access returned 404 because service_role could not read the new content tables.)
grant execute on function public.is_admin() to service_role;
grant select, insert, update, delete on public.course_items, public.course_item_files to service_role;
grant select on public.courses to service_role;
grant select on public.course_access to service_role;
