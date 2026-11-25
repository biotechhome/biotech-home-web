-- 0011: visitors may read only the public columns of courses (not any column added later).
revoke select on public.courses from anon;
grant select (id, title, description, is_paid, price_bdt, is_active, created_at) on public.courses to anon;
