-- 0014: private open letters, home promos, content access grants, folder (bundle) content.

-- ===== A. open letters: hidden until the admin publishes =====
alter table public.open_letters alter column approved set default false;
drop policy if exists ol_insert on public.open_letters;
create policy ol_insert on public.open_letters for insert to anon, authenticated with check (approved = false);
update public.open_letters set approved = false where approved;

-- ===== B. home-page promos (photo cards / ad videos) =====
create table if not exists public.site_promos(
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('image','video')),
  title text not null check (char_length(btrim(title)) between 1 and 120),
  caption text check (caption is null or char_length(caption) <= 300),
  youtube_id text check (youtube_id ~ '^[A-Za-z0-9_-]{11}$'),
  image_path text check (image_path ~ '^[A-Za-z0-9/_.-]{1,200}$'),
  link_url text check (link_url is null or link_url ~ '^https://'),
  sort_order int not null default 0,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  check ((kind = 'video' and youtube_id is not null) or (kind = 'image' and image_path is not null)));
alter table public.site_promos enable row level security;
revoke all on public.site_promos from public, anon, authenticated;
grant select on public.site_promos to anon;
grant select, insert, update, delete on public.site_promos to authenticated, service_role;
drop policy if exists sprm_read_anon on public.site_promos;
create policy sprm_read_anon on public.site_promos for select to anon using (is_active);
drop policy if exists sprm_read_auth on public.site_promos;
create policy sprm_read_auth on public.site_promos for select to authenticated using (is_active or public.is_admin());
drop policy if exists sprm_admin on public.site_promos;
create policy sprm_admin on public.site_promos for all to authenticated using (public.is_admin()) with check (public.is_admin());

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('promo-images','promo-images',true,5242880,array['image/png','image/jpeg','image/webp'])
on conflict (id) do update set public=true, file_size_limit=excluded.file_size_limit, allowed_mime_types=excluded.allowed_mime_types;
drop policy if exists pi_admin_insert on storage.objects;
create policy pi_admin_insert on storage.objects for insert to authenticated with check (bucket_id='promo-images' and public.is_admin());
drop policy if exists pi_admin_update on storage.objects;
create policy pi_admin_update on storage.objects for update to authenticated using (bucket_id='promo-images' and public.is_admin()) with check (bucket_id='promo-images' and public.is_admin());
drop policy if exists pi_admin_delete on storage.objects;
create policy pi_admin_delete on storage.objects for delete to authenticated using (bucket_id='promo-images' and public.is_admin());
drop policy if exists pi_admin_select on storage.objects;
create policy pi_admin_select on storage.objects for select to authenticated using (bucket_id='promo-images' and public.is_admin());

-- ===== C. who may open a paid course: batch / student type / one student, with expiry and on-off =====
create table if not exists public.course_grants(
  id uuid primary key default gen_random_uuid(),
  course_id uuid not null references public.courses(id) on delete cascade,
  scope text not null check (scope in ('batch','type','student')),
  batch_id uuid references public.batches(id) on delete cascade,
  student_type text check (student_type in ('online','offline')),
  student_id uuid references public.profiles(id) on delete cascade,
  expires_at timestamptz,
  is_active boolean not null default true,
  note text check (note is null or char_length(note) <= 200),
  created_at timestamptz not null default now(),
  check ((scope='batch' and batch_id is not null and student_type is null and student_id is null)
      or (scope='type' and student_type is not null and batch_id is null and student_id is null)
      or (scope='student' and student_id is not null and batch_id is null and student_type is null)));
create index if not exists course_grants_course_idx on public.course_grants(course_id);
alter table public.course_grants enable row level security;
revoke all on public.course_grants from public, anon, authenticated;
grant select, insert, update, delete on public.course_grants to authenticated, service_role;
drop policy if exists cg_admin on public.course_grants;
create policy cg_admin on public.course_grants for all to authenticated using (public.is_admin()) with check (public.is_admin());

create or replace function public.student_has_course(p_student uuid, p_course uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(
    select 1 from public.profiles p
    where p.id = p_student and p.status = 'active' and (
      exists(select 1 from public.courses c where c.id = p_course and c.is_active and not c.is_paid)
      or exists(select 1 from public.course_access a where a.student_id = p_student and a.course_id = p_course
                and (a.expires_at is null or a.expires_at > now()))
      or exists(select 1 from public.course_grants g where g.course_id = p_course and g.is_active
                and (g.expires_at is null or g.expires_at > now()) and (
                     (g.scope = 'student' and g.student_id = p_student)
                  or (g.scope = 'type' and g.student_type = p.student_type)
                  or (g.scope = 'batch' and exists(select 1 from public.batch_members bm where bm.batch_id = g.batch_id and bm.student_id = p_student)))))); $$;
revoke all on function public.student_has_course(uuid, uuid) from public, anon, authenticated;
grant execute on function public.student_has_course(uuid, uuid) to service_role;

-- ===== D. whole-folder content (one item = one folder served through the content-access function) =====
alter table public.course_item_files add column if not exists bundle_path text;
alter table public.course_item_files add column if not exists bundle_entry text;
do $$ declare r record; begin
  for r in select conname from pg_constraint where conrelid = 'public.course_item_files'::regclass and contype = 'c'
           and pg_get_constraintdef(oid) ilike '%IS NOT NULL%' loop
    execute format('alter table public.course_item_files drop constraint %I', r.conname);
  end loop;
  for r in select conname from pg_constraint where conrelid = 'public.course_items'::regclass and contype = 'c'
           and pg_get_constraintdef(oid) ilike '%kind%' loop
    execute format('alter table public.course_items drop constraint %I', r.conname);
  end loop;
end $$;
alter table public.course_item_files drop constraint if exists cif_one_source;
alter table public.course_item_files add constraint cif_one_source check (num_nonnulls(youtube_id, file_path, bundle_path) = 1);
alter table public.course_item_files drop constraint if exists cif_bundle_fmt;
alter table public.course_item_files add constraint cif_bundle_fmt check (bundle_path is null or
  (bundle_path ~ '^bundles/[0-9a-f-]{36}$' and bundle_entry ~ '^[A-Za-z0-9/_.-]{1,200}$'));
alter table public.course_items drop constraint if exists course_items_kind_check;
alter table public.course_items add constraint course_items_kind_check check (kind in ('video','book','note','mindmap','bundle'));
update storage.buckets set allowed_mime_types = null, file_size_limit = 52428800 where id = 'course-content';
