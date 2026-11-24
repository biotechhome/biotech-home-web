-- 0008: breaking-news ticker, notice board and recent events (public read, admin write)
create table if not exists public.site_posts (
  id         uuid primary key default gen_random_uuid(),
  kind       text not null check (kind in ('ticker','notice','event')),
  title      text not null check (char_length(btrim(title)) between 3 and 140),
  body       text check (body is null or char_length(body) <= 1000),
  event_date date,
  is_active  boolean not null default true,
  created_at timestamptz not null default now()
);
create index if not exists idx_site_posts_kind on public.site_posts (kind, created_at desc);
alter table public.site_posts enable row level security;
revoke all on public.site_posts from anon, authenticated;
grant select on public.site_posts to anon;
grant select, insert, update, delete on public.site_posts to authenticated;
grant select, insert, update, delete on public.site_posts to service_role;
drop policy if exists sp_read_active on public.site_posts;
drop policy if exists sp_admin_all   on public.site_posts;
create policy sp_read_active on public.site_posts for select to anon, authenticated using (is_active or public.is_admin());
create policy sp_admin_all   on public.site_posts for all    to authenticated using (public.is_admin()) with check (public.is_admin());
