-- Open letters: anyone (no login) can submit; visible to everyone immediately; admin can hide/delete.
create table public.open_letters (
  id uuid primary key default gen_random_uuid(),
  author_name text not null check (char_length(btrim(author_name)) between 2 and 60),
  body text not null check (char_length(btrim(body)) between 3 and 1000),
  approved boolean not null default true,
  created_at timestamptz not null default now()
);
alter table public.open_letters enable row level security;

grant select on public.open_letters to anon, authenticated;
grant insert (author_name, body) on public.open_letters to anon, authenticated;
grant update (approved) on public.open_letters to authenticated;
grant delete on public.open_letters to authenticated;
grant select, insert, update, delete on public.open_letters to service_role;

create policy ol_insert on public.open_letters for insert to anon, authenticated with check (approved = true);
create policy ol_select_anon on public.open_letters for select to anon using (approved);
create policy ol_select_auth on public.open_letters for select to authenticated using (approved or public.is_admin());
create policy ol_update_admin on public.open_letters for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy ol_delete_admin on public.open_letters for delete to authenticated using (public.is_admin());
