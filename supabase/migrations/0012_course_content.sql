-- Course content: videos (YouTube), books (PDF), notes (HTML), mind maps (image/PDF/HTML).
-- Secrets (YouTube id / storage path) live in course_item_files, admin-only. Students get them only
-- through the content-access Edge Function, which checks enrolment and returns short-lived signed URLs.
create table if not exists public.course_items(
  id uuid primary key default gen_random_uuid(),
  course_id uuid not null references public.courses(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 160),
  kind text not null check (kind in ('video','book','note','mindmap')),
  is_preview boolean not null default false,
  is_active boolean not null default true,
  sort_order int not null default 0,
  created_at timestamptz not null default now());
create index if not exists course_items_course_idx on public.course_items(course_id, sort_order);

create table if not exists public.course_item_files(
  item_id uuid primary key references public.course_items(id) on delete cascade,
  youtube_id text check (youtube_id ~ '^[A-Za-z0-9_-]{11}$'),
  file_path text check (file_path ~ '^[A-Za-z0-9/_.-]{1,200}$'),
  check ((youtube_id is not null) <> (file_path is not null)));

alter table public.course_items enable row level security;
alter table public.course_item_files enable row level security;
revoke all on public.course_items, public.course_item_files from public, anon, authenticated;
grant select on public.course_items to anon, authenticated;
grant insert, update, delete on public.course_items to authenticated;
grant select, insert, update, delete on public.course_item_files to authenticated;

drop policy if exists ci_read_anon on public.course_items;
create policy ci_read_anon on public.course_items for select to anon
  using (is_active and exists(select 1 from public.courses c where c.id = course_id and c.is_active));
drop policy if exists ci_read_auth on public.course_items;
create policy ci_read_auth on public.course_items for select to authenticated
  using ((is_active and exists(select 1 from public.courses c where c.id = course_id and c.is_active)) or public.is_admin());
drop policy if exists ci_admin_ins on public.course_items;
create policy ci_admin_ins on public.course_items for insert to authenticated with check (public.is_admin());
drop policy if exists ci_admin_upd on public.course_items;
create policy ci_admin_upd on public.course_items for update to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists ci_admin_del on public.course_items;
create policy ci_admin_del on public.course_items for delete to authenticated using (public.is_admin());
drop policy if exists cif_admin_all on public.course_item_files;
create policy cif_admin_all on public.course_item_files for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- private bucket, admin-only direct access (students only get signed URLs from the Edge Function)
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('course-content','course-content',false,52428800,
  array['application/pdf','text/html','image/png','image/jpeg','image/webp'])
on conflict (id) do update set public=false, file_size_limit=excluded.file_size_limit, allowed_mime_types=excluded.allowed_mime_types;
drop policy if exists cc_admin_select on storage.objects;
create policy cc_admin_select on storage.objects for select to authenticated using (bucket_id='course-content' and public.is_admin());
drop policy if exists cc_admin_insert on storage.objects;
create policy cc_admin_insert on storage.objects for insert to authenticated with check (bucket_id='course-content' and public.is_admin());
drop policy if exists cc_admin_update on storage.objects;
create policy cc_admin_update on storage.objects for update to authenticated using (bucket_id='course-content' and public.is_admin()) with check (bucket_id='course-content' and public.is_admin());
drop policy if exists cc_admin_delete on storage.objects;
create policy cc_admin_delete on storage.objects for delete to authenticated using (bucket_id='course-content' and public.is_admin());
